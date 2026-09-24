#!/usr/bin/env python3
"""MCP config-scan + live-dial probe (forgebench addition, not upstream).

Two phases, run as two separate invocations so a human gets to approve what
gets launched before anything is launched:

    python inspect_mcp_configs.py --discover-only [--root DIR] [--out discovered.json]
    python inspect_mcp_configs.py --dial [--skip NAME ...] --out observations.json

Phase 1 (``--discover-only``) scans a fixed table of well-known MCP client
config locations -- project-scoped (relative to ``--root``, default cwd) and
user-scoped (``Path.home()``) -- for Claude Code, Claude Desktop, Codex,
Cursor, VS Code, Windsurf, and Gemini CLI. It is pure file reads: no process
spawned, no socket opened. Its output tells you what WOULD be dialed and how
(command+args for a local/stdio server, a URL for a remote/http one) --
env-var and header NAMES only, never their values -- so a human can approve
or decline before anything runs.

Phase 2 (``--dial``) re-scans (cheap, and keeps secrets in-memory only,
never round-tripped through the phase-1 output file) and then actually
connects to each non-skipped server to call ``tools/list`` -- and ONLY
``tools/list``; no tool is ever invoked. This is an ACTIVE-SENSITIVE action
per ``references/safety-boundaries.md`` (it launches a configured subprocess,
or contacts a configured remote endpoint) and must not run without the
human approval ``--discover-only`` exists to get.

Output of ``--dial`` is written directly in the shape
``scripts/inspect_tools.py`` already accepts as ``observations.json``
(``mcpServers``: list of every discovered server NAME, dialed or not;
``mcpTools``: ``{server, tool}`` pairs, only for servers actually dialed
successfully) -- so nothing downstream (``capture_snapshot.py``,
``inspect_tools.py``, or forgebench's own ``mcp_inventory.py``) needs to
change at all.

This script covers only servers declared in a STATIC config file. A server
an agent framework (CrewAI, LangGraph, ...) wires up PROGRAMMATICALLY in
Python code is a different discovery problem with a different failure mode
(arbitrary source, not a known schema) -- see the sibling
``inspect_mcp_source.py`` for that. The two scripts share their
``ServerConfig`` shape and dial implementation via ``mcp_discovery_common.py``
so a server found either way goes through the identical consent/dial/
redaction pipeline from that point on.

Design choices adopted from evaluating Snyk agent-scan (Apache-2.0) against
this bundle's own zero-dependency, self-contained constraints -- see the
project's planning notes for the full comparison. In short: agent-scan's
harness coverage, comment-tolerant parsing, "try each known shape", and
per-server consent-before-spawn are all worth having; its dependency
footprint (``mcp[cli]``, ``pydantic``, ``detect-secrets``, ...) and its
requirement of a separate cloud account/token are not compatible with this
package's "stdlib only, fully self-contained" design, so those ideas are
reimplemented here with the standard library rather than adopting the tool
itself.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any

try:  # 3.11+. On 3.10 the ONE TOML location (Codex's config.toml) is reported, not read.
    import tomllib

    _TOML_DECODE_ERROR: type[Exception] = tomllib.TOMLDecodeError
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python 3.10
    tomllib = None  # type: ignore[assignment]
    _TOML_DECODE_ERROR = ValueError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_discovery_common as common  # noqa: E402

PROBE_ID = "mcp-config-scan-and-dial"
PROBE_VERSION = common.PROBE_VERSION

ServerConfig = common.ServerConfig


# =============================================================================
# Phase 1: discover -- read known config locations, extract server identity
# only (name + how to reach it). Never reads env/header VALUES into anything
# that gets returned to a caller; those are read fresh, in-memory-only, at
# dial time in Phase 2.
# =============================================================================


def _strip_json_comments(text: str) -> str:
    """Strip ``//`` and ``/* */`` comments, then trailing commas, both only
    outside string literals -- several MCP clients (VS Code especially)
    allow a JSONC-flavored config, and a strict ``json.loads`` silently
    rejects it. Two SEPARATE passes, comments first: a value like
    ``"foo", // trailing comment\\n}`` needs the comment gone before a
    trailing-comma check can see that the comma is followed (once
    whitespace-only content is skipped) by a closer -- collapsing both into
    one simultaneous pass would make that comma's own trailing ``//`` look
    like "not immediately followed by whitespace-then-closer" and leave it
    in by mistake (a real regression this had before this comment existed).
    Both passes independently track "am I inside a quoted string" so
    neither transform is ever fooled by a comment-looking or comma-looking
    sequence that's actually inside a string value -- e.g. a value like
    ``"fixed the bug, ] see PR"`` must survive byte-for-byte."""
    return _strip_trailing_commas(_strip_comments(text))


def _strip_comments(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    escape = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    escape = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            # Outside a string (comments are already gone by this pass, so
            # the only thing that can separate this comma from its closer
            # is whitespace): a trailing comma is real JSONC syntax only if
            # the next non-whitespace character is a closer.
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _read_config_file(path: Path) -> str | None:
    """Bytes -> text, or ``None`` for anything not worth failing the whole
    scan over: missing, too large, or not valid UTF-8. ``PermissionError``
    is deliberately NOT swallowed here -- it propagates so ``discover()``'s
    own handler can turn it into a warning rather than a silent skip (the
    same "log what's dropped" discipline as everywhere else in this
    codebase); every other read failure is quietly not-found-shaped."""
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > common._MAX_CONFIG_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except PermissionError:
        raise
    except (OSError, UnicodeDecodeError):
        return None


def _load_jsonc(path: Path) -> dict | None:
    text = _read_config_file(path)
    if text is None:
        return None
    try:
        return json.loads(_strip_json_comments(text))
    except (ValueError, TypeError):
        return None


class TomlUnavailable(Exception):
    """This Python has no ``tomllib`` (3.10) and the TOML file exists --
    raised so ``discover()`` can WARN about the skipped location instead of
    silently treating it as absent."""


def _load_toml(path: Path) -> dict | None:
    try:
        if not path.is_file() or path.stat().st_size > common._MAX_CONFIG_BYTES:
            return None
        if tomllib is None:
            raise TomlUnavailable(str(path))
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (PermissionError, TomlUnavailable):
        raise  # same reasoning as _read_config_file; TomlUnavailable -> discover() warns
    except (OSError, _TOML_DECODE_ERROR, UnicodeDecodeError):
        # tomllib.load() decodes the raw bytes as UTF-8 internally and
        # raises a bare UnicodeDecodeError (NOT its own TOMLDecodeError,
        # which is the only decode-shaped exception this used to catch) on
        # anything else, e.g. a latin-1-encoded ~/.codex/config.toml. Left
        # uncaught, this escaped discover() entirely (only PermissionError
        # is handled at that call site) and dropped every server from
        # every OTHER config location too, not just this one file -- same
        # "one bad file never drops the rest" discipline _read_config_file
        # (this module's sibling JSON/JSONC loader) already gives its own
        # UnicodeDecodeError case.
        return None


def _entry_to_server(name: str, entry: dict, source: str) -> ServerConfig | None:
    """One server entry (whatever key it was nested under) -> ServerConfig,
    or ``None`` if it has neither a launch command nor a URL -- "try each
    known shape" happens one level up; this is just "is this shape usable"."""
    if not isinstance(entry, dict):
        return None
    url = entry.get("url")
    if isinstance(url, str) and url:
        return ServerConfig(
            name=name,
            source=source,
            transport="http",
            url=url,
            headers=entry.get("headers") if isinstance(entry.get("headers"), dict) else {},
        )
    command = entry.get("command")
    if isinstance(command, str) and command:
        args = entry.get("args")
        env = entry.get("env")
        return ServerConfig(
            name=name,
            source=source,
            transport="stdio",
            command=command,
            args=[str(a) for a in args] if isinstance(args, list) else [],
            env=env if isinstance(env, dict) else {},
        )
    return None


def _servers_from_mapping(mapping: Any, source: str) -> list[ServerConfig]:
    if not isinstance(mapping, dict):
        return []
    out: list[ServerConfig] = []
    for name, entry in mapping.items():
        server = _entry_to_server(str(name), entry, source)
        if server is not None:
            out.append(server)
    return out


def _servers_from_json_doc(doc: dict, source: str, root: Path) -> list[ServerConfig]:
    """Try each known top-level shape in turn (agent-scan's "try known
    shapes until one fits" pattern, without a schema library): most clients
    key their server map ``mcpServers``; VS Code uses ``servers``; OpenHarness's
    JSON settings file uses ``mcp_servers`` (snake_case -- confirmed via
    source, HKUDS/OpenHarness's ``Settings`` model has no field alias, so
    the raw JSON key must match its Python field name exactly; do not
    confuse with OpenHarness's OTHER, camelCase ``mcpServers`` shape used
    for plugin manifests/project files, a different config entirely);
    Claude Code's user-level ``~/.claude.json`` additionally nests a
    per-project map under ``projects``, keyed by that project's absolute
    path -- which must be ``root`` (what the caller asked to scan), not
    ``Path.cwd()``: a caller scanning a different directory than the one
    it's running from (e.g. a monorepo loop) would otherwise silently miss
    every server declared under the directory it actually asked about."""
    out: list[ServerConfig] = []
    out.extend(_servers_from_mapping(doc.get("mcpServers"), source))
    out.extend(_servers_from_mapping(doc.get("servers"), source))
    out.extend(_servers_from_mapping(doc.get("mcp_servers"), source))
    projects = doc.get("projects")
    if isinstance(projects, dict):
        project_entry = projects.get(str(root))
        if isinstance(project_entry, dict):
            out.extend(_servers_from_mapping(project_entry.get("mcpServers"), source))
    return out


def _codex_servers(doc: dict, source: str) -> list[ServerConfig]:
    mcp_servers = doc.get("mcp_servers")
    return _servers_from_mapping(mcp_servers, source) if isinstance(mcp_servers, dict) else []


# (location label, kind, path-builder). kind selects the loader+extractor.
# path-builder takes ``root`` (the project root) and returns a candidate
# Path; a nonexistent one is silently skipped, so listing a path that
# doesn't apply on this OS/setup costs nothing.
def _config_locations(root: Path) -> list[tuple[str, str, Path]]:
    home = Path.home()
    return [
        ("claude-code (project)", "json", root / ".mcp.json"),
        ("claude-code (user)", "json", home / ".claude.json"),
        ("claude-desktop (macos)", "json",
         home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
        ("claude-desktop (linux)", "json", home / ".config" / "Claude" / "claude_desktop_config.json"),
        ("claude-desktop (windows)", "json",
         home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"),
        ("codex", "toml", home / ".codex" / "config.toml"),
        ("cursor (project)", "json", root / ".cursor" / "mcp.json"),
        ("cursor (user)", "json", home / ".cursor" / "mcp.json"),
        ("vscode (project)", "json", root / ".vscode" / "mcp.json"),
        ("windsurf", "json", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("gemini-cli", "json", home / ".gemini" / "settings.json"),
        # Confirmed via source (HKUDS/OpenHarness, config/paths.py +
        # config/settings.py): user-level only, top-level key is
        # `mcp_servers` (snake_case) -- see _servers_from_json_doc's own
        # docstring for why that needed a new branch there too, not just
        # this table row.
        ("openharness", "json", home / ".openharness" / "settings.json"),
    ]
    # Not included, on purpose (not silently -- see the plan/patch notes):
    # agent-scan's longer tail (openclaw, amp, kiro, opencode, antigravity,
    # amazon_q) isn't in this table because their exact config paths/shapes
    # weren't independently confirmed here; adding one is a one-line append
    # to this table plus, if its shape differs, a new branch in
    # _servers_from_json_doc -- not a redesign.


#: Locations inside the scanned project itself. Everything else in
#: ``_config_locations`` lives in the user's home directory and describes that
#: PERSON's own client setup, not the repository.
PROJECT_SCOPED_LABELS = frozenset({"claude-code (project)", "cursor (project)", "vscode (project)"})


def discover(root: Path, *, include_user_scope: bool = True) -> tuple[list[ServerConfig], list[str]]:
    """Every server found across every known config location. Returns
    (servers, warnings) -- one unreadable/oversized file never drops the
    others; a ``PermissionError`` on one location is caught right here.

    ``root`` is resolved to an absolute path up front: a relative
    ``--root`` would otherwise never string-match the absolute paths
    ``~/.claude.json``'s ``projects`` map is keyed by (see
    ``_servers_from_json_doc``), silently acting as if that project simply
    had no servers.

    A later config location's server NEVER silently replaces an earlier
    one of the same name -- table order in ``_config_locations`` currently
    puts project-scoped files first, so an untrusted, repo-controlled
    config can otherwise shadow a trusted, user-scoped server sharing its
    name with no signal that happened. Dedup itself is
    ``mcp_discovery_common.dedupe_servers`` (shared with
    ``inspect_mcp_source.py``): first-match-wins, and a collision across two
    DIFFERENT sources always produces a warning naming both.

    ``include_user_scope=False`` reads ONLY the project-scoped files
    (:data:`PROJECT_SCOPED_LABELS`): a repository scan that uploads its
    findings (packages/forgebench-plugin/scripts/forgebench_scan.py) must not
    even open the developer's personal client configs unless asked to."""
    root = root.resolve()
    candidates: list[tuple[ServerConfig, str]] = []
    warnings: list[str] = []

    for label, kind, path in _config_locations(root):
        if not include_user_scope and label not in PROJECT_SCOPED_LABELS:
            continue
        try:
            doc = _load_toml(path) if kind == "toml" else _load_jsonc(path)
        except PermissionError as exc:
            warnings.append(f"{label}: permission denied reading {path}: {exc}")
            continue
        except TomlUnavailable:
            warnings.append(f"{label}: not read -- reading {path.name} needs Python 3.11+ (tomllib)")
            continue
        if doc is None:
            continue
        found = (
            _codex_servers(doc, label) if kind == "toml" else _servers_from_json_doc(doc, label, root)
        )
        candidates.extend((server, label) for server in found)

    servers, dedupe_warnings = common.dedupe_servers(candidates)
    warnings.extend(dedupe_warnings)
    return servers, warnings


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--discover-only", action="store_true", help="scan config files only; never launch or contact anything"
    )
    mode.add_argument(
        "--dial", action="store_true", help="scan, then actually connect to each server for tools/list"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="project root to scan (default: cwd)")
    parser.add_argument("--out", type=Path, help="write JSON output here (default: stdout)")
    parser.add_argument(
        "--skip", action="append", default=[], metavar="NAME", help="server name to discover but not dial (repeatable)"
    )
    parser.add_argument(
        "--timeout", type=float, default=common._DEFAULT_TIMEOUT, help="per-server dial timeout in seconds"
    )
    args = parser.parse_args(argv[1:])

    servers, warnings = discover(args.root)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    if args.discover_only:
        # --out: the human consent listing on stdout, the JSON in the file.
        # No --out: the JSON IS stdout (what --out's help has always
        # promised, and what a "capture the JSON, never write a file" skill
        # flow needs), so the listing moves to stderr to keep stdout parseable.
        if args.out:
            common._print_consent_listing(servers)
            args.out.write_text(json.dumps(common._discovered_to_dict(servers), indent=2) + "\n")
        else:
            with contextlib.redirect_stdout(sys.stderr):
                common._print_consent_listing(servers)
            sys.stdout.write(json.dumps(common._discovered_to_dict(servers), indent=2) + "\n")
        return 0

    # --dial
    result = common._dial_all(servers, set(args.skip), args.timeout)
    for w in result.pop("_warnings"):
        print(f"warning: {w}", file=sys.stderr)
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(text + "\n")
        print(f"Wrote {len(result['mcpServers'])} server(s), {len(result['mcpTools'])} tool(s) to {args.out}")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
