"""The helper's commands. Each returns a plain dict; ``forgebench_helper.py`` prints it as JSON or text."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import CONTRACT, SOURCE, auth, context, netio, policy, settingsmgr, store, tasks
from .common import (HelperError, clean_text, config_dir, data_dir, install_id, iso, now, parse_time,
                     posix_supported, python_ok, read_json, require_posix, sha, subdir, truthy, write_json)
from .origin import KNOWN_EDITIONS, Resolved, resolve

SCRIPTS = Path(__file__).resolve().parent.parent
MOD_FLOOR = (2, 1, 287)  # terminal mods are on by default from this release (official mods overview)
HOOK_FLOOR = (2, 1, 259)  # lowest client the hook-based path was exercised on (see tests/e2e notes in README)
STALE_AFTER = 24 * 3600


def parse_version(text: object) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return tuple(int(g) for g in match.groups()) if match else None  # type: ignore[return-value]


def detect_claude_version(explicit: str | None) -> tuple[tuple[int, int, int] | None, str]:
    if explicit:
        return parse_version(explicit), "reported by the caller"
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=5)
        return parse_version(out.stdout), "claude on PATH (advisory)"
    except (OSError, subprocess.SubprocessError):
        return None, "unknown"


def need_origin(args) -> str:
    pinned = getattr(args, "origin", None)
    if pinned:
        from .origin import normalize_origin

        origin = normalize_origin(pinned)
        if origin:
            return origin
        raise HelperError("invalid_origin", "the deployment URL is not a valid https origin")
    resolved: Resolved = resolve(getattr(args, "url", ""))
    if not resolved.origin:
        raise HelperError("invalid_origin",
                          "the configured Forgebench URL is unusable (https required; plain http only for loopback)")
    return resolved.origin


# ---------------------------------------------------------------------------------------- preflight


def preflight(args) -> dict:
    version, version_source = detect_claude_version(getattr(args, "claude_version", None))
    problems, notes = [], []
    if not posix_supported():
        problems.append("this helper supports macOS and Linux terminals; Windows is not qualified")
    if not python_ok():
        problems.append("Python 3.10 or newer is required to run the Forgebench helper")
    user = settingsmgr.read_layers()[0]
    if user.error:
        problems.append(f"{user.path} is not valid JSON ({user.error}); fix it before connecting")
    if version is None:
        notes.append("the Claude Code version could not be determined")
    elif version < HOOK_FLOOR:
        problems.append(f"Claude Code {'.'.join(map(str, version))} is older than the supported minimum "
                        f"{'.'.join(map(str, HOOK_FLOOR))}; upgrade before connecting")
    mod_ok = bool(version and version >= MOD_FLOOR)
    if version and not mod_ok:
        notes.append("plugin mods need Claude Code 2.1.287 or newer; the /forgebench:setup skill works here")
    return {
        "ok": not problems, "problems": problems, "notes": notes,
        "claude_version": ".".join(map(str, version)) if version else None, "version_source": version_source,
        "python": ".".join(map(str, sys.version_info[:3])), "platform": sys.platform,
        "forgebench_cli_required": False,
        "capabilities": {"context_hooks": bool(version and version >= HOOK_FLOOR), "settings_helpers": True,
                         "mod_pane": mod_ok},
    }


# ------------------------------------------------------------------------------------------- auth


def auth_begin(args) -> dict:
    origin = need_origin(args)
    pre = preflight(args)
    if not pre["ok"]:
        raise HelperError("preflight_failed", "; ".join(pre["problems"]))
    return auth.begin(origin, open_browser=not getattr(args, "no_browser", False))


def auth_wait(args) -> dict:
    return auth.wait(args.op, float(args.seconds))


def auth_cancel(args) -> dict:
    return auth.cancel(args.op)


# ------------------------------------------------------------------------------------------ apply


def apply(args) -> dict:
    require_posix()
    origin = need_origin(args)
    connection = store.load(origin)
    if not connection or not store.key(origin, "reporting"):
        raise HelperError("not_connected", "not signed in to this deployment; run the connect step first")
    key = store.key(origin, "reporting")
    device = install_id()
    skipped: dict[str, str] = {}
    want_gateway = not args.no_gateway
    want_telemetry = not args.no_telemetry
    if want_gateway and not store.key(origin, "inference"):
        want_gateway = False
        skipped["gateway"] = (connection.get("inference_note") or "no model grant") + \
            f" [{connection.get('inference_state', 'unsupported')}]"
    capture = None
    pol = policy.capture_policy(origin, key, device)
    if want_telemetry:
        if pol["state"] in ("unreachable", "auth_failed"):
            want_telemetry, skipped["telemetry"] = False, f"capture policy unavailable ({pol['state']}); not enabled"
        elif pol.get("mode") == "off":
            want_telemetry, skipped["telemetry"] = False, "capture is switched off for this device by policy"
        elif pol["state"] == "known" and pol.get("mode") == "local":
            want_telemetry = False
            skipped["telemetry"] = ("workspace policy requires local capture, which needs the optional Forgebench "
                                    "CLI; native telemetry was not enabled")
        elif pol["state"] == "known":
            capture = {"mode": pol["mode"], "revision": pol["revision"], "acked": False}
    traces = False
    if want_telemetry and getattr(args, "traces", "auto") != "off":
        delivery = policy.delivery(origin, key, device)
        traces = policy.traces_supported(delivery)
        if not traces:
            skipped["traces"] = {"unsupported": "this deployment does not store native traces yet (backend dispatch C/D)",
                                 "unreachable": "delivery diagnostics unreachable; traces kept off",
                                 "auth_failed": "credential rejected"}.get(delivery["state"],
                                                                           "native traces are not supported here")
    if not (want_gateway or want_telemetry):
        return {"applied": False, "written": [], "unchanged": [], "skipped": skipped, "conflicts": [],
                "pending_restart": False}
    entry, digest = settingsmgr.install_runtime(SCRIPTS, keep=_receipt_runtime())
    items = settingsmgr.desired(origin, entry, want_gateway, want_telemetry, traces)
    result = settingsmgr.apply(items, origin, digest, os.getcwd(), capture)
    result.update({"applied": bool(result["written"] or result["unchanged"]), "skipped": skipped,
                   "traces": traces, "capture_policy": {k: pol.get(k) for k in ("state", "mode", "revision")}})
    if result["pending_restart"]:
        result["next_step"] = "Restart Claude Code so the new configuration takes effect."
    return result


def _receipt_runtime() -> set[str]:
    receipt = settingsmgr.load_receipt()
    return {receipt["runtime"]} if receipt and receipt.get("runtime") else set()


# ------------------------------------------------------------------------------------------ logout


def logout(args) -> dict:
    origin = need_origin(args)
    result: dict = {"origin": origin}
    result["settings"] = settingsmgr.unapply()
    server = {}
    if args.revoke:
        for kind in ("reporting", "inference"):
            secret = store.key(origin, kind)
            if not secret:
                continue
            try:
                reply = netio.request(origin, "/v1/auth/cli/revoke", method="POST", token=secret, timeout=10)
                server[kind] = ("revoked" if reply.ok else
                                "unsupported_by_server" if reply.status in (404, 405) else f"failed_http_{reply.status}")
            except netio.NetworkError as exc:
                server[kind] = f"failed_{exc.kind}"
        result["server_revocation"] = server
        if server.get("inference") == "revoked":
            result["note"] = "the model grant was revoked; if it was shared with another tool, that tool loses it too"
    else:
        result["server_revocation"] = "not requested: server-side grants remain active until revoked in the console"
    result["purged_pending"] = context.purge(origin)
    result["credentials_removed"] = store.delete(origin)
    result["next_step"] = "Restart Claude Code. The Forgebench MCP connection is separate; disconnect it from /mcp."
    return result


# ----------------------------------------------------------------------------------------- tasks


def task(args) -> dict:
    origin = need_origin(args)
    key = store.key(origin, "reporting")
    if not key:
        raise HelperError("not_connected", "not signed in to this deployment")
    if args.task_command == "options":
        return tasks.options(origin, key, args.connection, args.query or "", args.offset, args.limit)
    if args.task_command == "validate":
        return tasks.validate(origin, key, args.connection, args.task)
    return tasks.declare(origin, key, session_id=args.session_id, started_at=context.started_at(args.session_id),
                         connection_id=args.connection, task_id=args.task, mechanism=args.mechanism)


# ------------------------------------------------------------------------------- native helper modes


def api_key(args) -> str:
    """apiKeyHelper: the model key, bound to the pinned deployment. Nothing else is ever printed."""
    origin = need_origin(args)
    secret = store.key(origin, "inference")
    if not secret:
        raise HelperError("no_model_key", "no model grant for this deployment; reconnect from Claude Code")
    return secret


def otel_headers(args) -> str:
    origin = need_origin(args)
    secret = store.key(origin, "reporting")
    if not secret:
        raise HelperError("not_connected", "no reporting grant for this deployment")
    return json.dumps({"Authorization": f"Bearer {secret}", "x-forgebench-device-id": install_id()})


# -------------------------------------------------------------------------------------------- hooks


def _read_payload() -> dict:
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return {}
        raw = sys.stdin.read(1 << 20)
        value = json.loads(raw) if raw.strip() else {}
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def hook(args) -> dict:
    """SessionStart / SessionEnd. Never fails the hook; prints at most one user-only systemMessage."""
    if not truthy(args.sync):
        return {}  # explicit opt-out: no payload read, no network, no files
    if not posix_supported() or not python_ok():
        return {}
    resolved = resolve(args.url)
    if not resolved.origin:
        return {}
    origin = resolved.origin
    payload = _read_payload()
    event = payload.get("hook_event_name") or args.event
    if event not in ("SessionStart", "SessionEnd"):
        return {}
    if not store.key(origin, "reporting"):
        return _nudge(origin) if event == "SessionStart" else {}
    if event == "SessionStart":
        settingsmgr.confirm_active()
        _refresh_runtime(origin)
        _maybe_ack(origin)
    entry = context.snapshot(event, payload)
    if entry is None:
        return {}
    context.enqueue(origin, entry)
    context.spawn_drain(origin)
    return {}


def _nudge(origin: str) -> dict:
    marker = subdir("hints") / f"{sha(origin)}.json"
    last = parse_time((read_json(marker, {}) or {}).get("at"))
    if last and (now() - last).total_seconds() < 24 * 3600:
        return {}
    write_json(marker, {"at": iso()})
    return {"systemMessage": "Forgebench is installed but not connected. Run /forgebench:setup connect "
                             "to sign in with your browser."}


def _refresh_runtime(origin: str) -> None:
    receipt = settingsmgr.load_receipt()
    if not receipt or receipt.get("origin") != origin:
        return
    digest = settingsmgr.bundle_digest(SCRIPTS)
    if receipt.get("runtime") == digest:
        return
    groups = {e["group"] for e in receipt["entries"]}
    traces = any(e["key"] == "OTEL_TRACES_EXPORTER" and e["value"] == "otlp" for e in receipt["entries"])
    entry, new_digest = settingsmgr.install_runtime(SCRIPTS, keep={receipt.get("runtime", "")})
    items = settingsmgr.desired(origin, entry, "gateway" in groups, "telemetry" in groups, traces)
    for item in items:
        # helper commands move with the runtime; only replace values that are still ours and unchanged
        old = next((e for e in receipt["entries"] if (e["scope"], e["key"]) == (item["scope"], item["key"])), None)
        if old and old["scope"] == "top" and old["value"] != item["value"]:
            user = settingsmgr.read_layers()[0]
            if user.data.get(item["key"]) == old["value"]:
                _rewrite_top(item["key"], old["value"], item["value"], new_digest)


def _rewrite_top(key: str, old: str, new: str, digest: str) -> None:
    path = settingsmgr.settings_path()
    from .common import atomic_write, file_lock

    with file_lock(path):
        settings = json.loads(path.read_text(encoding="utf-8"))
        receipt = settingsmgr.load_receipt()
        if settings.get(key) != old or not receipt:
            return
        settings[key] = new
        atomic_write(path, json.dumps(settings, indent=2) + "\n")
        for entry in receipt["entries"]:
            if entry["scope"] == "top" and entry["key"] == key:
                entry["value"] = new
        receipt["runtime"] = digest
        write_json(settingsmgr.receipt_path(), receipt)


def _maybe_ack(origin: str) -> None:
    receipt = settingsmgr.load_receipt()
    capture = (receipt or {}).get("capture")
    if not receipt or not capture or capture.get("acked") or os.environ.get("CLAUDE_CODE_ENABLE_TELEMETRY") != "1":
        return
    key = store.key(origin, "reporting")
    if key and policy.ack(origin, key, install_id(), {"state": "known", **capture}):
        capture["acked"] = True
        receipt["capture"] = capture
        write_json(settingsmgr.receipt_path(), receipt)


# ------------------------------------------------------------------------------------------ status


def status(args) -> dict:
    resolved = resolve(getattr(args, "url", ""))
    out: dict = {"deployment": {"origin": resolved.origin, "source": resolved.source,
                                "edition": resolved.edition},
                 "runtime": {"python": ".".join(map(str, sys.version_info[:3])), "python_ok": python_ok(),
                             "posix": posix_supported(), "forgebench_cli_required": False}}
    if not resolved.origin:
        out["state"] = "invalid_origin"
        return out
    origin = resolved.origin
    connection = store.load(origin)
    key = store.key(origin, "reporting")
    out["other_deployments"] = [o for o in store.origins() if o != origin]
    receipt = settingsmgr.load_receipt()
    layers = settingsmgr.read_layers(os.getcwd())
    owned = settingsmgr.owned_state(receipt, layers) if receipt and receipt.get("origin") == origin else {}
    out["configuration"] = {
        "gateway": owned.get("gateway", "absent"), "telemetry": owned.get("telemetry", "absent"),
        "restart_required": bool(receipt and receipt.get("pending_restart")),
        "other_deployment_configured": bool(receipt and receipt.get("origin") != origin),
        "settings_error": layers[0].error or None,
    }
    out["connection"] = {
        "signed_in": bool(key), "identity": (connection or {}).get("identity"),
        "model_access": (connection or {}).get("inference_state") if connection else None,
        "model_note": (connection or {}).get("inference_note") if connection else None,
        "backend_contract": (connection or {}).get("contract") if connection else None,
    }
    delivery = context.delivery_state(origin)
    last = parse_time(delivery.get("last_success_at"))
    out["context"] = {
        "enabled_by_option": truthy(getattr(args, "sync", "true")), "pending": context.pending(origin),
        "last_status": delivery.get("last_status"), "last_success_at": delivery.get("last_success_at"),
        "confirmed_by_backend": bool(delivery.get("contract_confirmed")) if delivery else None,
        "stale": bool(last and (now() - last).total_seconds() > STALE_AFTER),
    }
    if key and not getattr(args, "offline", False):
        out["connection"]["authenticated"] = _verify(origin, key)
        if out["connection"]["authenticated"] is True:
            device = install_id()
            pol = policy.capture_policy(origin, key, device)
            out["capture_policy"] = {k: pol.get(k) for k in ("state", "mode", "revision")}
            dv = policy.delivery(origin, key, device)
            out["backend_received"] = ({"signals": dv["signals"]} if dv["state"] == "ok" else
                                       {"state": dv["state"],
                                        "note": "per-signal receipts need the delivery diagnostics endpoint "
                                                "(backend dispatch D); not available here"})
            out["native_traces_supported"] = policy.traces_supported(dv)
    out["mcp"] = "separate OAuth connection; authenticate from /mcp (not shared with this sign-in)"
    out["states"] = _vocabulary(out)
    return out


def _verify(origin: str, key: str):
    try:
        reply = netio.request(origin, "/v1/auth/whoami", token=key, timeout=6)
    except netio.NetworkError:
        return None
    return True if reply.ok else (False if reply.status in (401, 403) else None)


def _vocabulary(out: dict) -> dict:
    conn, conf, ctx = out["connection"], out["configuration"], out["context"]
    states = {
        "installed": True,
        "configured": conf["gateway"] == "applied" or conf["telemetry"] == "applied",
        "restart_required": conf["restart_required"],
        "authenticated": conn.get("authenticated") if "authenticated" in conn else (conn["signed_in"] or False),
        "failed": ctx.get("last_status") in ("auth_failed",) or conn.get("authenticated") is False,
        "stale": ctx["stale"],
        "backend_received": bool(ctx["last_success_at"]),
    }
    return states
