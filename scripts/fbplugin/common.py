"""Paths, private files, locks and small helpers shared by the helper commands."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

MIN_PYTHON = (3, 10)
DATA_DIRNAME = "forgebench-plugin"


class HelperError(Exception):
    """A failure with a stable code and a message that is safe to print."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def posix_supported() -> bool:
    return os.name == "posix" and hasattr(os, "fork") and hasattr(os, "setsid")


def require_posix() -> None:
    if not posix_supported():
        raise HelperError("unsupported_platform",
                          "this plugin's helper supports macOS and Linux terminals; Windows is not qualified")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime | None = None) -> str:
    return (moment or now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def config_dir() -> Path:
    """The Claude Code configuration directory this process was given (never a fixed ~/.claude)."""
    value = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    return Path(value).expanduser() if value else Path.home() / ".claude"


def data_dir() -> Path:
    """Private plugin state. Fixed under the config directory so the hooks, the mod, the skill and the
    settings helpers all agree (a mod cannot see ``CLAUDE_PLUGIN_DATA``)."""
    path = config_dir() / DATA_DIRNAME
    ensure_private_dir(path)
    return path


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        if path.is_symlink():
            raise HelperError("unsafe_path", f"refusing a symlinked state directory: {path.name}")
        os.chmod(path, 0o700)
    return path


def subdir(*names: str) -> Path:
    return ensure_private_dir(data_dir().joinpath(*names))


def atomic_write(path: Path, text: str, mode: int | None = None) -> None:
    """Replace *path* with *text* atomically, keeping an existing file's mode (else 0600)."""
    path = Path(path)
    if path.is_symlink():
        raise HelperError("unsafe_path", f"refusing to write through a symlink: {path.name}")
    if mode is None:
        try:
            mode = path.stat().st_mode & 0o777
        except OSError:
            mode = 0o600
    handle, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, value, mode: int | None = None) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode if mode is not None else 0o600)


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 10.0, blocking: bool = True):
    """An exclusive advisory lock on ``<path>.lock``. Yields False if a non-blocking attempt lost."""
    if os.name != "posix":
        yield True
        return
    import fcntl

    lock_path = Path(str(path) + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if not blocking or time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
        if not acquired and blocking:
            raise HelperError("locked", "another Forgebench plugin process holds the lock; try again")
        yield acquired
    finally:
        if acquired:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def sha(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def install_id() -> str:
    """A stable, nonsecret descriptor for this installation. Used as the exchange ``hostname`` and the
    telemetry ``device_id``; distinct from the optional CLI's hostname so a login never rotates its key."""
    path = subdir() / "install.json"
    value = read_json(path, {})
    existing = value.get("id") if isinstance(value, dict) else None
    if isinstance(existing, str) and re.fullmatch(r"claude-code-[0-9a-f]{12}", existing):
        return existing
    created = f"claude-code-{uuid.uuid4().hex[:12]}"
    write_json(path, {"id": created})
    return created


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value: object, limit: int = 255) -> str:
    return _CONTROL.sub("", str(value or "")).strip()[:limit]


def truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def python_ok() -> bool:
    return sys.version_info[:2] >= MIN_PYTHON


def parse_time(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
