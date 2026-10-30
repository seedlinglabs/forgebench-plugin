"""Direct session-context delivery: the real native session ID and safe repository context, posted straight to
``/v1/sessions/meta`` with the owned reporting key. No CLI, no transcript, no usage counters.

Delivery is a bounded, coalescing outbox (one latest snapshot per session) drained by a short detached process,
so a hook never waits on the network. Context is *confirmed* only when the server answers with
``capture_contract: 1`` (backend dispatch B); otherwise it is reported as sent-but-unconfirmed."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import CONTRACT, SOURCE, netio, policy, store
from .common import (clean_text, file_lock, install_id, iso, now, parse_time, read_json, sha, subdir, write_json)

MAX_RECORDS = 256
MAX_BYTES = 1 << 20
TTL_SECONDS = 7 * 24 * 3600
MAX_ATTEMPTS = 8
BATCH = 50
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def _git(cwd: str, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=1.5,
                             env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def sanitize_remote(url: str) -> tuple[str, str]:
    """``(repo, repository)`` as a sanitized host/namespace/repo. Credentials, query and paths vanish."""
    url = url.strip()
    if not url:
        return "", ""
    scp = re.match(r"^[^@/\s:]+@([^:/\s]+):(.+)$", url) if "://" not in url else None
    if scp:
        host, path = scp.group(1), scp.group(2)
    else:
        try:
            parts = urlsplit(url)
        except ValueError:
            return "", ""
        host, path = parts.hostname or "", parts.path
    path = path.strip("/").removesuffix(".git")
    segments = [SAFE_NAME.sub("", s) for s in path.split("/") if s]
    segments = [s for s in segments if s]
    if not host or not segments:
        return "", ""
    repository = "/".join([SAFE_NAME.sub("", host).lower(), *segments])[:255]
    return segments[-1][:128], repository


def git_context(cwd: str) -> dict:
    if not cwd or not os.path.isdir(cwd):
        return {}
    branch = _git(cwd, "symbolic-ref", "--quiet", "--short", "HEAD")  # empty on detached HEAD / no repo
    repo, repository = sanitize_remote(_git(cwd, "config", "--get", "remote.origin.url"))
    out = {}
    if branch:
        out["branch"] = clean_text(branch, 255)
    if repo:
        out["repo"], out["repository"] = repo, repository
    return out


def _session_state_path(session_id: str) -> Path:
    return subdir("sessions") / f"{sha(session_id, 24)}.json"


def snapshot(event: str, payload: dict) -> dict | None:
    """The ``/meta`` session entry for a hook payload, or None when the payload lacks the native session ID."""
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
        return None
    state = read_json(_session_state_path(session_id), {}) or {}
    started = state.get("started_at") or iso()
    entry = {
        "source": SOURCE, "session_id": session_id, "started_at": started, "session_kind": "main",
        "context_state": "captured", "turn_count": 0, "usage_expected": False,
        **git_context(str(payload.get("cwd") or "")),
    }
    if event == "SessionEnd":
        entry["ended_at"] = iso()
    write_json(_session_state_path(session_id), {"started_at": started, "origin_event": event, "seen_at": iso()})
    return entry


def started_at(session_id: str) -> str:
    state = read_json(_session_state_path(session_id), {}) or {}
    return state.get("started_at") or iso()


# ------------------------------------------------------------------------------------------ outbox


def _box(origin: str) -> Path:
    return subdir("outbox", sha(origin))


def enqueue(origin: str, entry: dict) -> None:
    box = _box(origin)
    with file_lock(box / "queue"):
        path = box / f"{sha(entry['session_id'], 24)}.json"
        current = read_json(path, {}) or {}
        merged = dict(current.get("entry") or {})
        merged.update({k: v for k, v in entry.items() if v is not None})
        write_json(path, {"entry": merged, "enqueued_at": current.get("enqueued_at") or iso(), "attempts": 0,
                          "next_attempt_at": 0})
        _prune(box)


def _prune(box: Path) -> None:
    files = sorted((p for p in box.glob("*.json")), key=lambda p: p.stat().st_mtime)
    cutoff = time.time() - TTL_SECONDS
    total = 0
    for path in files:
        if path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)
    files = sorted((p for p in box.glob("*.json")), key=lambda p: p.stat().st_mtime, reverse=True)
    for index, path in enumerate(files):
        total += path.stat().st_size
        if index >= MAX_RECORDS or total > MAX_BYTES:
            path.unlink(missing_ok=True)


def pending(origin: str) -> int:
    return len(list(_box(origin).glob("*.json")))


def purge(origin: str) -> int:
    count = 0
    for path in _box(origin).glob("*.json"):
        path.unlink(missing_ok=True)
        count += 1
    return count


def _delivery_path(origin: str) -> Path:
    return subdir("delivery") / f"{sha(origin)}.json"


def delivery_state(origin: str) -> dict:
    return read_json(_delivery_path(origin), {}) or {}


def _record(origin: str, **changes) -> None:
    state = delivery_state(origin)
    state.update(changes)
    write_json(_delivery_path(origin), state)


def drain(origin: str, deadline_seconds: float = 20.0) -> dict:
    """Send due snapshots. One drain at a time per origin; stops on auth failure, honours Retry-After."""
    box = _box(origin)
    with file_lock(box / "drain", blocking=False) as acquired:
        if not acquired:
            return {"state": "busy"}
        key = store.key(origin, "reporting")
        if not key:
            _record(origin, last_status="not_connected", last_attempt_at=iso())
            return {"state": "not_connected"}
        stop_at = time.monotonic() + deadline_seconds
        device = install_id()
        decision = policy.capture_policy(origin, key, device)
        if decision["state"] == "auth_failed":
            _record(origin, last_status="auth_failed", last_attempt_at=iso())
            return {"state": "auth_failed"}
        if decision["state"] == "unreachable":
            _record(origin, last_status="policy_unreachable", last_attempt_at=iso())
            return {"state": "held", "reason": "policy_unreachable"}
        if decision.get("mode") == "off":
            dropped = purge(origin)
            _record(origin, last_status="capture_off", last_attempt_at=iso(), purged=dropped)
            return {"state": "capture_off", "purged": dropped}
        due = []
        for path in sorted(box.glob("*.json"), key=lambda p: p.stat().st_mtime):
            record = read_json(path, {}) or {}
            if record.get("entry") and float(record.get("next_attempt_at", 0)) <= time.time():
                due.append((path, record))
        sent = accepted = 0
        confirmed = None
        for start in range(0, len(due), BATCH):
            if time.monotonic() > stop_at:
                break
            chunk = due[start:start + BATCH]
            body = {"device_id": device, "capture_transport": "native", "sessions": [r["entry"] for _, r in chunk]}
            try:
                reply = netio.request(origin, "/v1/sessions/meta", method="POST", token=key, body=body, timeout=10)
            except netio.NetworkError as exc:
                _bump(chunk, 30)
                _record(origin, last_status=f"network_{exc.kind}", last_attempt_at=iso())
                return {"state": "retry", "reason": exc.kind}
            outcome = _handle_reply(origin, reply, chunk)
            if outcome.get("stop"):
                return outcome
            sent += len(chunk)
            accepted += outcome.get("accepted", 0)
            if outcome.get("confirmed") is not None:
                confirmed = outcome["confirmed"] if confirmed is None else (confirmed and outcome["confirmed"])
        return {"state": "ok", "sent": sent, "accepted": accepted, "confirmed": confirmed}


def _bump(chunk, seconds: float) -> None:
    for path, record in chunk:
        attempts = int(record.get("attempts", 0)) + 1
        if attempts >= MAX_ATTEMPTS:
            path.unlink(missing_ok=True)
            continue
        record["attempts"] = attempts
        record["next_attempt_at"] = time.time() + min(900.0, seconds * (2 ** attempts))
        write_json(path, record)


def _handle_reply(origin: str, reply: netio.Reply, chunk) -> dict:
    code = reply.error_code()
    if reply.status in (401, 403):
        _record(origin, last_status="auth_failed", last_attempt_at=iso(), last_error=code)
        return {"state": "auth_failed", "stop": True}
    if reply.status == 429:
        wait = 60.0
        try:
            wait = min(900.0, float(reply.headers.get("Retry-After", wait)))
        except (TypeError, ValueError):
            pass
        for path, record in chunk:
            record["next_attempt_at"] = time.time() + wait
            write_json(path, record)
        _record(origin, last_status="rate_limited", last_attempt_at=iso())
        return {"state": "retry", "reason": "rate_limited", "stop": True}
    if reply.status >= 500 or reply.status == 0:
        _bump(chunk, 30)
        _record(origin, last_status=f"http_{reply.status}", last_attempt_at=iso())
        return {"state": "retry", "reason": f"http_{reply.status}", "stop": True}
    if reply.status == 409 or 400 <= reply.status < 500:
        # a rejected snapshot is dropped: replaying it unchanged cannot succeed (ownership conflict, bad shape)
        for path, _ in chunk:
            path.unlink(missing_ok=True)
        _record(origin, last_status=f"rejected_{reply.status}", last_attempt_at=iso(), last_error=code)
        return {"state": "rejected", "accepted": 0, "confirmed": None}
    body = reply.body if isinstance(reply.body, dict) else {}
    accepted = int(body.get("accepted") or 0)
    confirmed = body.get("capture_contract") == CONTRACT
    if accepted <= 0:
        _bump(chunk, 30)  # zero accepted is not delivery
        _record(origin, last_status="zero_accepted", last_attempt_at=iso())
        return {"state": "retry", "accepted": 0, "confirmed": confirmed}
    for path, _ in chunk:
        path.unlink(missing_ok=True)
    _record(origin, last_status="delivered" if confirmed else "delivered_unconfirmed", last_attempt_at=iso(),
            last_success_at=iso(), contract_confirmed=bool(confirmed), last_accepted=accepted, last_error=None)
    return {"state": "ok", "accepted": accepted, "confirmed": confirmed}


def spawn_drain(origin: str) -> None:
    """Drain in a fully detached grandchild (double fork), so a cancelled hook cannot kill delivery."""
    if not hasattr(os, "fork"):
        return
    try:
        if os.fork() > 0:
            return
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        try:
            drain(origin)
        finally:
            os._exit(0)
    except OSError:
        return
