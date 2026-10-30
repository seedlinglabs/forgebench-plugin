"""Browser sign-in: one loopback + PKCE journey, redeemed directly against the selected deployment.

Reuses the control plane's existing reporting login (``/v1/auth/oidc/login`` -> ``/v1/auth/cli/exchange``).
The model-access leg rides the *proposed* plugin continuation on the same login (backend dispatch A): the
plugin asks for it with ``plugin_client``/``inference_challenge`` and trusts it only when the callback carries
``plugin_contract=1``. On a server that does not answer with that marker the connection is reporting-only and
model access is reported as unsupported; no second login is ever started on its own.

Secrets: verifiers live in the worker's memory only; codes and keys are never printed, logged or put in
argv or the state file. The state file holds sanitized progress for ``auth wait``.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import http.server
import os
import secrets
import signal
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser

from . import CONTRACT, SOURCE, netio, store
from .common import (HelperError, clean_text, install_id, iso, read_json, require_posix, subdir, write_json)

LOGIN_PATH = "/v1/auth/oidc/login"
EXCHANGE_PATH = "/v1/auth/cli/exchange"
REDEEM_PATH = "/v1/auth/cli/inference/redeem"
WHOAMI_PATH = "/v1/auth/whoami"
# Above the control plane's pending tenant-selection TTL (600 s), as the optional CLI does.
LOGIN_TIMEOUT = 630.0
TERMINAL = frozenset({"complete", "failed", "cancelled", "expired"})
IDENTITY_FIELDS = ("tenant_id", "tenant_slug", "tenant_name", "identity_id", "user_id", "email", "role")


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def login_url(origin: str, port: int, path_token: str, reporting_challenge: str, inference_challenge: str,
              descriptor: str) -> str:
    params = {
        "redirect": f"http://127.0.0.1:{port}/cb/{path_token}",
        "cli_challenge": reporting_challenge,
        "plugin_client": SOURCE,
        "inference_challenge": inference_challenge,
        "device_name": "Claude Code on this device",
        "hostname": descriptor,
    }
    return f"{origin}{LOGIN_PATH}?{urllib.parse.urlencode(params)}"


def _state_path(op: str):
    return subdir("auth") / f"{op}.json"


def _write_state(op: str, **changes) -> dict:
    current = read_json(_state_path(op), {}) or {}
    current.update(changes)
    write_json(_state_path(op), current)
    return current


def read_state(op: str) -> dict | None:
    if not op.isalnum():
        return None
    value = read_json(_state_path(op))
    return value if isinstance(value, dict) else None


def _pid_alive(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def public_state(state: dict) -> dict:
    return {k: state.get(k) for k in ("op", "status", "origin", "login_url", "expires_at", "result", "error")
            if state.get(k) is not None}


def begin(origin: str, open_browser: bool = True) -> dict:
    """Start (or reuse) the sign-in worker and return its sanitized state. Never blocks on the browser."""
    require_posix()
    for path in sorted(subdir("auth").glob("*.json")):
        old = read_json(path) or {}
        if old.get("status") in TERMINAL:
            if time.time() - path.stat().st_mtime > 3600:
                path.unlink(missing_ok=True)
        elif old.get("origin") == origin and _pid_alive(old.get("pid")) and old.get("login_url"):
            return public_state(old)
        elif not _pid_alive(old.get("pid")):
            _write_state(old.get("op", path.stem), status="failed",
                         error={"code": "worker_gone", "message": "an earlier sign-in worker exited"})
    op = secrets.token_hex(8)
    write_json(_state_path(op), {"op": op, "origin": origin, "status": "starting", "started_at": iso()})
    if os.fork() > 0:
        deadline = time.monotonic() + 10
        state = {}
        while time.monotonic() < deadline:
            state = read_state(op) or {}
            if state.get("login_url") or state.get("status") in TERMINAL:
                break
            time.sleep(0.05)
        if not state.get("login_url"):
            raise HelperError("auth_start_failed", "the sign-in listener did not start")
        if open_browser:
            try:
                webbrowser.open(state["login_url"])
            except Exception:  # noqa: BLE001 - the URL is returned for manual opening
                pass
        return public_state(state)
    # --- first child: detach fully (double fork) and become the worker ---
    try:
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        _worker(op, origin)
    except BaseException:  # noqa: BLE001
        try:
            _write_state(op, status="failed", error={"code": "worker_crashed", "message": "sign-in worker failed"})
        except Exception:  # noqa: BLE001
            pass
    finally:
        os._exit(0)


def wait(op: str, seconds: float) -> dict:
    deadline = time.monotonic() + max(0.0, seconds)
    while True:
        state = read_state(op)
        if state is None:
            raise HelperError("unknown_operation", "no such sign-in operation")
        if state.get("status") in TERMINAL:
            return public_state(state)
        if not _pid_alive(state.get("pid")) and state.get("status") not in ("starting",):
            _write_state(op, status="failed", error={"code": "worker_gone", "message": "the sign-in worker exited"})
            return public_state(read_state(op) or state)
        if time.monotonic() >= deadline:
            return public_state(state)
        time.sleep(0.25)


def cancel(op: str) -> dict:
    state = read_state(op)
    if state is None:
        raise HelperError("unknown_operation", "no such sign-in operation")
    if state.get("status") not in TERMINAL:
        _write_state(op, cancel_requested=True)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and _pid_alive(state.get("pid")):
            time.sleep(0.1)
        if _pid_alive(state.get("pid")):
            try:
                os.kill(state["pid"], signal.SIGTERM)
            except OSError:
                pass
        _write_state(op, status="cancelled")
    return public_state(read_state(op) or state)


# ----------------------------------------------------------------------------- worker


class _Callback(http.server.BaseHTTPRequestHandler):
    server_version = "forgebench-plugin"

    def log_message(self, *args):  # noqa: D102 - never log requests (they carry codes)
        return

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlsplit(self.path)
        owner = self.server.owner  # type: ignore[attr-defined]
        if url.path != f"/cb/{owner['path_token']}" or owner["result"] is not None:
            self._reply(404, "Not found", "This sign-in link is not valid.")
            return
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
        owner["result"] = query
        if query.get("code") or query.get("inference_code"):
            self._reply(200, "Signed in", "You are signed in. Return to Claude Code; you can close this tab.")
        else:
            self._reply(200, "Sign-in not completed", "Sign-in was not completed. Return to Claude Code.")

    def _reply(self, status: int, title: str, message: str) -> None:
        page = (f"<!doctype html><meta charset=utf-8><title>{title}</title>"
                f"<body style='font:16px system-ui;margin:3em'><h1>{title}</h1><p>{message}</p></body>").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


class _Server(socketserver.TCPServer):
    allow_reuse_address = True
    timeout = 0.5


def _fail(op: str, code: str, message: str, status: str = "failed") -> None:
    _write_state(op, status=status, error={"code": code, "message": message})


def _worker(op: str, origin: str) -> None:
    descriptor = install_id()
    reporting_verifier, reporting_challenge = pkce_pair()
    inference_verifier, inference_challenge = pkce_pair()
    path_token = secrets.token_hex(16)
    server = _Server(("127.0.0.1", 0), _Callback)
    server.owner = {"path_token": path_token, "result": None}  # type: ignore[attr-defined]
    port = server.server_address[1]
    expires = time.time() + LOGIN_TIMEOUT
    url = login_url(origin, port, path_token, reporting_challenge, inference_challenge, descriptor)
    _write_state(op, status="waiting", pid=os.getpid(), login_url=url,
                 expires_at=iso(_dt.datetime.fromtimestamp(expires, _dt.timezone.utc)))
    try:
        while server.owner["result"] is None:  # type: ignore[attr-defined]
            if time.time() > expires:
                _fail(op, "sign_in_timed_out", "sign-in was not completed in time", "expired")
                return
            if (read_json(_state_path(op), {}) or {}).get("cancel_requested"):
                _fail(op, "cancelled", "sign-in was cancelled", "cancelled")
                return
            server.handle_request()
    finally:
        server.server_close()
    result = server.owner["result"]  # type: ignore[attr-defined]
    _finish(op, origin, descriptor, result, reporting_verifier, inference_verifier)


def _finish(op: str, origin: str, descriptor: str, result: dict, reporting_verifier: str,
            inference_verifier: str) -> None:
    code = result.get("code")
    if not code:
        reason = clean_text(result.get("error"), 64) or "no_code"
        _fail(op, "sign_in_declined" if reason in ("access_denied", "cancelled") else "sign_in_failed",
              "sign-in was cancelled or refused" if reason in ("access_denied", "cancelled")
              else "the browser returned no authorization code")
        return
    _write_state(op, status="exchanging")
    try:
        reply = netio.request(origin, EXCHANGE_PATH, method="POST", timeout=15,
                              body={"code": code, "verifier": reporting_verifier, "hostname": descriptor})
    except netio.NetworkError as exc:
        _fail(op, "backend_unreachable", f"could not reach the deployment ({exc.kind})")
        return
    reporting_key = reply.body.get("api_key") if reply.ok and isinstance(reply.body, dict) else None
    if not reporting_key:
        _fail(op, reply.error_code() or f"exchange_http_{reply.status}", "the deployment refused the sign-in code")
        return
    reporting = {k: reply.body.get(k) for k in ("id", "prefix", "scopes", "created_at", "owner_identity_id")}
    reporting["api_key"] = reporting_key
    identity = _whoami(origin, reporting_key)
    contract = str(result.get("plugin_contract", "")) == str(CONTRACT)
    inference, inference_state, inference_note = None, "unsupported", (
        "this deployment does not offer the single-journey model grant (plugin_contract marker missing)")
    if contract:
        inference_code = result.get("inference_code")
        if inference_code:
            inference, inference_state, inference_note = _redeem(origin, inference_code, inference_verifier, identity)
        else:
            inference_state = clean_text(result.get("inference_error"), 48) or "not_granted"
            inference_note = {"no_eligible_key": "no eligible model key is available for you",
                              "access_denied": "model access was declined"}.get(inference_state,
                                                                                "model access was not granted")
    previous = store.load(origin) or {}
    store.save(origin, {
        "installation": descriptor, "identity": identity, "reporting": reporting, "inference": inference,
        "inference_state": inference_state, "inference_note": inference_note, "contract": int(contract),
        "connected_at": previous.get("connected_at") or iso(),
    })
    _write_state(op, status="complete", result={
        "origin": origin, "identity": identity, "reporting": "granted",
        "inference": "granted" if inference else inference_state, "inference_note": inference_note,
        "contract": int(contract)})


def _whoami(origin: str, key: str) -> dict:
    try:
        reply = netio.request(origin, WHOAMI_PATH, token=key, timeout=10)
    except netio.NetworkError:
        return {}
    if not reply.ok or not isinstance(reply.body, dict):
        return {}
    source = reply.body
    flat = dict(source)
    for nested in ("tenant", "identity", "user"):
        if isinstance(source.get(nested), dict):
            for k, v in source[nested].items():
                flat.setdefault(f"{nested}_{k}" if k in ("id", "slug", "name") else k, v)
    return {k: flat[k] for k in IDENTITY_FIELDS if isinstance(flat.get(k), (str, int))}


def _redeem(origin: str, code: str, verifier: str, identity: dict):
    try:
        reply = netio.request(origin, REDEEM_PATH, method="POST", timeout=15,
                              body={"code": code, "verifier": verifier})
    except netio.NetworkError:
        return None, "redeem_failed", "the model grant could not be redeemed"
    key = reply.body.get("api_key") if reply.ok and isinstance(reply.body, dict) else None
    if not key:
        return None, reply.error_code() or "redeem_failed", "the model grant was refused"
    other = _whoami(origin, key)
    for field in ("tenant_id", "identity_id"):
        if identity.get(field) and other.get(field) and identity[field] != other[field]:
            return None, "identity_mismatch", "the model key belongs to a different identity or workspace; discarded"
    if not other:
        return None, "unverified", "the model key could not be verified against the reporting identity; discarded"
    grant = {k: reply.body.get(k) for k in ("id", "prefix", "scopes", "created_at")}
    grant["api_key"] = key
    return grant, "granted", "model access granted"
