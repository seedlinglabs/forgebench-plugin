"""Private per-deployment credential storage. Owner-only files; secrets never leave this module's callers
except through the two native helper modes (apiKeyHelper, otelHeadersHelper)."""

from __future__ import annotations

from pathlib import Path

from .common import iso, read_json, sha, subdir, write_json

SECRET_FIELDS = ("api_key",)


def _path(origin: str) -> Path:
    return subdir("connections") / f"{sha(origin)}.json"


def load(origin: str) -> dict | None:
    record = read_json(_path(origin))
    if isinstance(record, dict) and record.get("origin") == origin:
        return record
    return None


def save(origin: str, record: dict) -> None:
    record = dict(record, origin=origin, updated_at=iso())
    write_json(_path(origin), record, 0o600)


def delete(origin: str) -> bool:
    try:
        _path(origin).unlink()
        return True
    except OSError:
        return False


def key(origin: str, kind: str) -> str | None:
    """``kind`` is ``reporting`` or ``inference``."""
    record = load(origin) or {}
    value = (record.get(kind) or {}).get("api_key")
    return value if isinstance(value, str) and value else None


def origins() -> list[str]:
    found = []
    for path in sorted(subdir("connections").glob("*.json")):
        record = read_json(path)
        if isinstance(record, dict) and isinstance(record.get("origin"), str):
            found.append(record["origin"])
    return found


def redacted(record: dict | None) -> dict:
    """A copy safe to print: secret values removed."""
    if not record:
        return {}
    out = {}
    for name, value in record.items():
        if isinstance(value, dict):
            out[name] = {k: v for k, v in value.items() if k not in SECRET_FIELDS}
        else:
            out[name] = value
    return out
