#!/usr/bin/env python3
"""Run the forgebench CLI fully detached from a Claude Code hook, then exit.

Usage (what ``hooks/hooks.json`` runs, exec form, no shell)::

    forgebench_sync_launcher.py sync --quiet

The ``sync``, ``forgebench_cli_path`` and ``forgebench_url`` options are read from the
``CLAUDE_PLUGIN_OPTION_<KEY>`` environment Claude Code exports to hooks; when one is empty
or unsubstituted (the Claude desktop app skips ``userConfig`` defaults) the staged
manifest's default is used. The older positional form
``<sync> <forgebench-cli> sync --quiet --url <url>`` still works.

Option values lose whitespace and one layer of surrounding quotes. ``sync`` is ON for
true/1/yes/y/on/t/enabled (case-insensitive); empty or unsubstituted means "not set" and takes
the manifest default (on); anything else (false/0/no/n/off/f/disabled or any unrecognised
value) is off, since sync uploads coding sessions. A missing or corrupt manifest skips sync
silently: there is no built-in URL fallback, so a broken dev edition never syncs to production.
URLs must be https (http only for loopback) with no userinfo or whitespace. The CLI path is a
bare command name (PATH, ~/.local/bin) or an absolute path; relative paths with a separator are
refused. Empty argv behaves as ``sync --quiet``.

Why a launcher: a plugin's SessionEnd hook has a fixed ~1.5 s budget, and when
Claude Code cancels a hook it SIGTERMs the hook's whole process tree.
``start_new_session`` alone does not escape that; a double fork does (fork,
setsid, fork: the grandchild is reparented to init, so it is no longer a
descendant of the hook). This process forks and returns at once; the
grandchild reads the hook payload from stdin, then runs the CLI with it on
stdin, detached from the hook's stdout and stderr.

It never fails the hook: whatever goes wrong (CLI missing, bad arguments) the
exit status is 0 and nothing is printed. The ``--url`` value loses a trailing
slash, and plain ``http://`` is refused unless the host is loopback. POSIX only: without ``os.fork`` and
``os.setsid`` it exits 0 before reading or uploading anything. The Windows
detach (creationflags) is follow-up #1146 (#1060). Python 3.10+, stdlib only.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

PAYLOAD_LIMIT = 1 << 20
PAYLOAD_WAIT = 2.0  # seconds to wait for a hook payload nobody finishes writing
CLI_TIMEOUT = 300.0
SYNC_ON = frozenset({"true", "1", "yes", "y", "on", "t", "enabled"})
SYNC_OFF = frozenset({"false", "0", "no", "n", "off", "f", "disabled"})  # documentation: anything not ON is off
PRODUCTION_URL = "https://api.forgebench.ai"
MCP_URL_ENV = "FORGEBENCH_MCP_URL"
MCP_SUFFIX = "/mcp"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MANIFEST = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"


def manifest_default(key: str) -> str | None:
    """The staged manifest's default for option ``key`` (the edition's own).

    None when the manifest is missing or corrupt: there is deliberately no built-in fallback,
    so a broken dev or staging edition can never sync to production.
    """
    try:
        value = json.loads(MANIFEST.read_text())["userConfig"][key]["default"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if isinstance(value, bool):
        return str(value).lower()
    return value if isinstance(value, str) and value.strip() else None


def unquote(value: str) -> str:
    """``value`` stripped of whitespace and one layer of matching surrounding quotes."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1].strip()
    return value


def is_unset(value: str) -> bool:
    """Empty or an unsubstituted ``${...}``: the desktop app skipped the default."""
    value = unquote(value)
    return not value or value.startswith("${")


def option(key: str, env: dict | None = None) -> str | None:
    """Option ``key`` from ``CLAUDE_PLUGIN_OPTION_<KEY>``, else the manifest default (None if unreadable)."""
    value = (os.environ if env is None else env).get(f"CLAUDE_PLUGIN_OPTION_{key.upper()}", "")
    return manifest_default(key) if is_unset(value) else unquote(value)


def read_payload() -> bytes:
    """The hook JSON from stdin, bounded in size and time; empty on a terminal."""
    try:
        if os.isatty(0):
            return b""
        chunks: list[bytes] = []
        size = 0
        deadline = time.monotonic() + PAYLOAD_WAIT
        while size < PAYLOAD_LIMIT:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
                break
            chunk = os.read(0, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)[:PAYLOAD_LIMIT]
    except OSError:
        return b""


def resolve(cli: str) -> str | None:
    """``cli`` as an executable path.

    A bare name is looked up on PATH and ~/.local/bin; an absolute path is used as is; a
    relative path with a separator is refused (never resolved against the hook's cwd).
    """
    if os.sep in cli or "/" in cli:
        return cli if os.path.isabs(cli) and os.access(cli, os.X_OK) else None
    local_bin = os.path.join(os.path.expanduser("~"), ".local", "bin")
    return shutil.which(cli) or shutil.which(cli, path=local_bin)


def detach() -> bool:
    """Double fork. True in the grandchild; the other two processes never return."""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    return True


def sync_enabled(value: str) -> bool:
    """ON for true/1/yes/y/on/t/enabled (case-insensitive, quotes stripped).

    Empty or unsubstituted means "not set": the manifest default (true). Anything else,
    including the explicit off words and every unrecognised value, is off: sync uploads
    coding sessions, so ambiguity stays off.
    """
    if is_unset(value):
        value = manifest_default("sync") or ""
    return unquote(value).lower() in SYNC_ON


def sync_url(value: str, env_mcp_url: str = "") -> str | None:
    """The base URL to upload to, or None to refuse (nothing is uploaded).

    An empty (or unsubstituted) value, as the Claude desktop app passes when it
    skips userConfig defaults, falls back to the manifest default. A trailing slash is stripped (no ``//mcp``-style joins downstream). Session
    content is only sent over https; plain http is accepted for loopback hosts
    (the local stack) and refused for anything else. When the option is still the
    production default and the managed settings' ``FORGEBENCH_MCP_URL`` names a
    deployment, that deployment wins: the fallback for a Claude Code that does not
    honour the managed ``pluginConfigs`` entry.
    """
    url = unquote(value).rstrip("/")
    if is_unset(url):  # desktop app: option empty or unsubstituted
        url = (manifest_default("forgebench_url") or "").rstrip("/")
    env_url = unquote(env_mcp_url).rstrip("/")
    if url == PRODUCTION_URL and env_url:
        url = env_url.removesuffix(MCP_SUFFIX).rstrip("/")
    if not url or any(c.isspace() for c in url):
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        return None
    if "@" in parts.netloc:  # userinfo: https://x@evil.com
        return None
    if parts.scheme == "https" and host:
        return url
    if parts.scheme == "http" and host in LOOPBACK_HOSTS:
        return url
    return None


def url_flag(arg: str) -> tuple[str, str | None] | None:
    """``(spelling, value-or-None)`` when ``arg`` is ``--url`` or an unambiguous prefix of it.

    argparse accepts a long-option prefix that resolves to exactly one option of the
    subcommand (``--u``, ``--ur``), in both the ``--ur V`` and ``--ur=V`` forms. The
    ``sync`` subparser has no other ``--u...`` option, so each such spelling is the URL.
    Prefixes shorter than three characters (``--``) are not treated as one.
    """
    name, eq, value = arg.partition("=")
    if len(name) < 3 or not "--url".startswith(name):
        return None
    return name, (value if eq else None)


def with_url(args: list[str], env_mcp_url: str = "") -> list[str] | None:
    """``args`` with every ``--url`` value validated, in each spelling argparse resolves to it.

    Each value is read the way argparse reads it (the next token for ``--url V``, the
    text after ``=`` for ``--url=V``), so the URL the CLI uses is the one checked.
    None when any value must be refused.
    """
    checked: list[str] = []
    index = 0
    while index < len(args):
        flag = url_flag(args[index])
        if flag is None:
            checked.append(args[index])
            index += 1
            continue
        name, value = flag
        if value is None:
            # A trailing bare --url (empty value dropped by the host) takes the manifest default.
            url = sync_url(args[index + 1] if index + 1 < len(args) else "", env_mcp_url)
            if url is None:
                return None
            checked += [name, url]
            index += 2
        else:
            url = sync_url(value, env_mcp_url)
            if url is None:
                return None
            checked.append(f"{name}={url}")
            index += 1
    return checked


def can_detach() -> bool:
    return hasattr(os, "fork") and hasattr(os, "setsid")


def main(argv: list[str]) -> int:
    if not can_detach():
        return 0
    if not argv:  # host ignored the exec-form args: behave as the hook form
        argv = ["sync", "--quiet"]
    if argv[0] == "sync":
        # Hook form: options come from CLAUDE_PLUGIN_OPTION_* env vars, so a dropped empty
        # argument cannot shift anything. Defaults come from the staged manifest.
        sync, cli, url = option("sync"), option("forgebench_cli_path"), option("forgebench_url")
        if None in (sync, cli, url):
            return 0  # manifest missing or corrupt: never guess (a broken dev edition must not hit prod)
        rest = [*argv, "--url", url]
    elif len(argv) >= 2:
        sync, cli, *rest = argv  # legacy positional form: <sync> <cli> sync ...
    else:
        return 0
    if not sync_enabled(sync):
        return 0
    cli = option("forgebench_cli_path", {"CLAUDE_PLUGIN_OPTION_FORGEBENCH_CLI_PATH": cli})
    if cli is None:
        return 0
    checked = with_url(rest, os.environ.get(MCP_URL_ENV, ""))
    if checked is None:
        return 0  # an unusable or insecure upload URL: send nothing
    rest = checked
    try:
        detach()
    except OSError:
        return 0  # could not fork: drop this sync rather than fail the hook
    try:
        payload = read_payload()
        executable = resolve(cli)
        if executable is not None:
            subprocess.run(
                [executable, *rest],
                input=payload,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=CLI_TIMEOUT,
                check=False,
            )
    except Exception:  # noqa: BLE001 - a sync hook must never be noisy or fatal
        pass
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
