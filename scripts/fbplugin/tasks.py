"""Explicit task (Jira) selection for the current native session, through the existing session-value routes.

A task is only ever *declared by the user* for a full native session ID; it is never inferred from a branch.
The routes currently authorise readers/admins, so a builder's owned reporting key may get 403: that is reported
as 'unavailable on this deployment (backend dispatch B)', not retried and not treated as an error loop."""

from __future__ import annotations

import urllib.parse

from . import SOURCE, netio
from .common import clean_text, iso

MECHANISMS = ("SessionStart", "PreToolUse", "ui", "cli")
BASE = "/v1/sessions/value"


def _classify(reply: netio.Reply) -> dict | None:
    code = reply.error_code()
    if reply.status == 401:
        return {"ok": False, "state": "auth_failed", "message": "sign in again (credential rejected)"}
    if reply.status == 403:
        return {"ok": False, "state": "unavailable",
                "message": "task selection is not enabled for this account on this deployment (backend dispatch B)",
                "code": code}
    if reply.status == 404:
        return {"ok": False, "state": "unsupported", "message": "this deployment has no task routes", "code": code}
    if reply.status == 409:
        return {"ok": False, "state": "rejected", "message": "this task was reviewed and rejected for the session",
                "code": code}
    if reply.status == 402:
        return {"ok": False, "state": "plan", "message": "task association is not included in the current plan",
                "code": code}
    if not reply.ok:
        return {"ok": False, "state": "failed", "message": f"the deployment answered HTTP {reply.status}", "code": code}
    return None


def _call(origin: str, key: str, path: str, method="GET", body=None) -> tuple[dict | None, netio.Reply | None]:
    try:
        return None, netio.request(origin, path, method=method, token=key, body=body, timeout=15)
    except netio.NetworkError as exc:
        return {"ok": False, "state": "unreachable", "message": f"could not reach the deployment ({exc.kind})"}, None


def options(origin: str, key: str, connection_id: str | None = None, query: str = "", offset: int = 0,
            limit: int = 20) -> dict:
    params = {"offset": max(0, offset), "limit": max(1, min(100, limit))}
    if connection_id:
        params["connection_id"] = connection_id
    if query:
        params["q"] = query
    failure, reply = _call(origin, key, f"{BASE}/task-options?{urllib.parse.urlencode(params)}")
    if failure:
        return failure
    refused = _classify(reply)
    if refused:
        return refused
    body = reply.body if isinstance(reply.body, dict) else {}
    tasks = [{k: t.get(k) for k in ("id", "connection_id", "external_id", "key", "title", "status", "url")}
             for t in (body.get("tasks") or body.get("items") or []) if isinstance(t, dict)]
    connections = [{k: c.get(k) for k in ("id", "name", "provider")} for c in (body.get("connections") or [])
                   if isinstance(c, dict)]
    return {"ok": True, "state": "ok", "connections": connections, "tasks": tasks}


def validate(origin: str, key: str, connection_id: str, task_id: str) -> dict:
    failure, reply = _call(origin, key, f"{BASE}/task-validation", "POST",
                           {"connection_id": connection_id, "task_id": clean_text(task_id, 128)})
    if failure:
        return failure
    refused = _classify(reply)
    if refused:
        return refused
    body = reply.body if isinstance(reply.body, dict) else {}
    return {"ok": bool(body.get("valid")), "state": "valid" if body.get("valid") else "invalid",
            "task_id": body.get("task_id"), "provider": body.get("provider"),
            "message": None if body.get("valid") else "the task could not be validated"}


def declare(origin: str, key: str, *, session_id: str, started_at: str, connection_id: str, task_id: str,
            mechanism: str = "ui") -> dict:
    if mechanism not in MECHANISMS:
        return {"ok": False, "state": "invalid", "message": "unknown declaration mechanism"}
    if not session_id or len(session_id) > 128:
        return {"ok": False, "state": "invalid", "message": "a full native session ID is required"}
    checked = validate(origin, key, connection_id, task_id)
    if not checked["ok"]:
        return {**checked, "declared": False}
    failure, reply = _call(origin, key, f"{BASE}/task-declarations", "POST", {
        "connection_id": connection_id, "task_id": clean_text(task_id, 128), "source": SOURCE,
        "session_id": session_id, "started_at": started_at or iso(), "mechanism": mechanism})
    if failure:
        return {**failure, "declared": False}
    refused = _classify(reply)
    if refused:
        return {**refused, "declared": False}
    body = reply.body if isinstance(reply.body, dict) else {}
    return {"ok": True, "state": "declared", "declared": True, "review_status": body.get("review_status"),
            "link_id": body.get("link_id")}
