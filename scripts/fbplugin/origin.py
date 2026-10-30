"""Deployment origin selection and validation (hosted default, staging, self-hosted, local)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

PRODUCTION = "https://api.forgebench.ai"
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
KNOWN_EDITIONS = {
    "https://api.forgebench.ai": "production",
    "https://api.staging.forgebench.ai": "staging",
    "https://api.dev.forgebench.ai": "dev",
}


def normalize_origin(value: object) -> str | None:
    """A bare ``scheme://host[:port]`` origin, or None. https only; http is allowed for loopback."""
    text = str(value or "").strip().rstrip("/")
    if not text or "${" in text:
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        parts.port  # noqa: B018 - validates the port
    except ValueError:
        return None
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        return None
    if parts.scheme == "https" and host:
        return f"https://{parts.netloc}"
    if parts.scheme == "http" and host in LOOPBACK:
        return f"http://{parts.netloc}"
    return None


@dataclass(frozen=True)
class Resolved:
    origin: str | None
    source: str  # option | managed_env | default | invalid
    edition: str


def resolve(option: object = "", env: dict | None = None) -> Resolved:
    """Pick the deployment: an explicit (non-default) ``forgebench_url`` option wins; while the option is still
    the production default, a managed ``FORGEBENCH_MCP_URL`` / ``FORGEBENCH_BASE_URL`` names the deployment;
    otherwise the hosted default. An unusable value resolves to nothing (nothing is sent anywhere)."""
    env = os.environ if env is None else env
    text = str(option or "").strip().rstrip("/")
    explicit = bool(text) and "${" not in text
    if explicit and text != PRODUCTION:
        origin = normalize_origin(text)
        return Resolved(origin, "option" if origin else "invalid", KNOWN_EDITIONS.get(origin or "", "custom"))
    for key in ("FORGEBENCH_BASE_URL", "FORGEBENCH_MCP_URL"):
        raw = str(env.get(key, "")).strip().rstrip("/")
        if raw:
            if key == "FORGEBENCH_MCP_URL":
                raw = raw.removesuffix("/mcp").rstrip("/")
            origin = normalize_origin(raw)
            return Resolved(origin, "managed_env" if origin else "invalid", KNOWN_EDITIONS.get(origin or "", "custom"))
    return Resolved(PRODUCTION, "default", "production")
