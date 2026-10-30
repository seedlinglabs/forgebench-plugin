"""Capture policy and backend feature detection. Everything fails closed: an unknown answer never enables
collection, and a missing proposed endpoint is reported as 'unsupported by this deployment', not as success."""

from __future__ import annotations

import urllib.parse

from . import CONTRACT, SOURCE, netio

MODES = ("local", "otel", "both", "off")


def capture_policy(origin: str, key: str, device_id: str) -> dict:
    """``{state: 'known'|'legacy'|'unreachable'|'auth_failed', mode, revision}``.

    ``legacy`` is a server without policy rules (404 or revision 0 with no mode): the historical default."""
    query = urllib.parse.urlencode({"source": SOURCE, "device_id": device_id})
    try:
        reply = netio.request(origin, f"/v1/sessions/capture-policy?{query}", token=key, timeout=8)
    except netio.NetworkError:
        return {"state": "unreachable"}
    if reply.status in (401, 403):
        return {"state": "auth_failed"}
    if reply.status == 404:
        return {"state": "legacy", "mode": None, "revision": 0}
    if not reply.ok or not isinstance(reply.body, dict):
        return {"state": "unreachable"}
    effective = reply.body.get("effective") if isinstance(reply.body.get("effective"), dict) else {}
    mode = effective.get("mode") or reply.body.get("mode")
    revision = effective.get("revision", reply.body.get("revision", 0))
    if mode not in MODES:
        return {"state": "legacy", "mode": None, "revision": int(revision or 0)}
    return {"state": "known" if int(revision or 0) > 0 else "legacy", "mode": mode, "revision": int(revision or 0)}


def ack(origin: str, key: str, device_id: str, policy: dict, status: str = "applied") -> bool:
    if policy.get("state") != "known" or policy.get("mode") not in MODES:
        return False
    try:
        reply = netio.request(origin, "/v1/sessions/capture-policy/ack", method="POST", token=key, timeout=8, body={
            "revision": policy["revision"], "source": SOURCE, "device_id": device_id,
            "mode": policy["mode"], "status": status})
    except netio.NetworkError:
        return False
    return reply.ok


def delivery(origin: str, key: str, device_id: str, session_id: str | None = None) -> dict:
    """The proposed owner-only delivery leaf (backend dispatch D). ``{state: 'unsupported'}`` on an older server."""
    params = {"source": SOURCE, "device_id": device_id}
    if session_id:
        params["session_id"] = session_id
    try:
        reply = netio.request(origin, "/v1/sessions/usage/telemetry/delivery?" + urllib.parse.urlencode(params),
                              token=key, timeout=8)
    except netio.NetworkError:
        return {"state": "unreachable"}
    if reply.status in (401, 403):
        return {"state": "auth_failed"}
    if reply.status in (404, 405) or not reply.ok or not isinstance(reply.body, dict):
        return {"state": "unsupported"}
    if reply.body.get("capture_contract") != CONTRACT or not isinstance(reply.body.get("signals"), dict):
        return {"state": "unsupported"}
    return {"state": "ok", "signals": reply.body["signals"], "capture": reply.body.get("capture")}


def traces_supported(delivery_result: dict) -> bool:
    signal = (delivery_result.get("signals") or {}).get("native_traces")
    return delivery_result.get("state") == "ok" and isinstance(signal, dict) and signal.get("supported") is True
