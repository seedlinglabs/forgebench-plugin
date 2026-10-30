"""Bounded JSON HTTP to one validated Forgebench origin. No redirects, no secrets in errors."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .origin import normalize_origin

MAX_BODY = 1 << 20


class NetworkError(Exception):
    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind  # timeout | unreachable | tls | invalid_origin


@dataclass
class Reply:
    status: int
    body: object = None
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def error_code(self) -> str | None:
        """The nested ``detail.error`` / ``{'error': ...}`` / ``detail.code`` the control plane returns."""
        body = self.body
        if not isinstance(body, dict):
            return None
        detail = body.get("detail", body)
        if isinstance(detail, dict):
            for key in ("error", "code"):
                value = detail.get(key)
                if isinstance(value, str):
                    return value
                if isinstance(value, dict) and isinstance(value.get("code"), str):
                    return value["code"]
        if isinstance(body.get("error"), str):
            return body["error"]
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def request(origin: str, path: str, *, method: str = "GET", token: str | None = None, body: object = None,
            timeout: float = 10.0, headers: dict | None = None) -> Reply:
    base = normalize_origin(origin)
    if base is None:
        raise NetworkError("invalid_origin")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request_headers = {"Accept": "application/json", "User-Agent": "forgebench-claude-plugin"}
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    request_headers.update(headers or {})
    req = urllib.request.Request(base + path, data=data, method=method, headers=request_headers)
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            raw = response.read(MAX_BODY)
            status = response.status
            reply_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY) if exc.fp else b""
        status = exc.code
        reply_headers = dict(exc.headers.items()) if exc.headers else {}
    except urllib.error.URLError as exc:
        reason = str(getattr(exc, "reason", ""))
        raise NetworkError("tls" if "CERTIFICATE" in reason.upper() else "unreachable") from None
    except TimeoutError:
        raise NetworkError("timeout") from None
    except OSError:
        raise NetworkError("unreachable") from None
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    return Reply(status, parsed, reply_headers)
