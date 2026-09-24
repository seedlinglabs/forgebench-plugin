#!/usr/bin/env python3
"""forgebench repository scanner for hosted-MCP onboarding.

Finds the MCP servers and AI agents a repository declares and uploads a
minimal ``forgebench.scan/v1`` payload straight to the forgebench control
plane under a single-use ticket from ``forgebench_begin_scan``. The model
that ran this command only ever sees the counts and the sha256 printed at
the end — the repository's contents never travel through the conversation.

    python3 forgebench_scan.py --upload-url URL --ticket fbscan_...   # scan + upload
    python3 forgebench_scan.py --list-servers                          # consent listing, no upload
    python3 forgebench_scan.py --out scan.json                         # write the payload instead

What is read (all passive: files are parsed, never executed):

* project MCP client configs — ``.mcp.json``, ``.cursor/mcp.json``,
  ``.vscode/mcp.json`` (the developer's personal configs in the home
  directory only with ``--include-user-configs``);
* Python sources (stdlib ``ast``) and, when ``tree-sitter`` is installed,
  TypeScript/JavaScript sources, for agent and MCP-client declarations of the
  frameworks the vendored agent-harness-explorer scanners know (CrewAI,
  LangGraph, OpenAI Agents SDK, AutoGen, Google ADK, Mastra, Vercel AI SDK,
  ...). ``tests/``, ``test/``, ``examples/``, ``fixtures/``, ``docs/`` and
  coding-agent skill bundles (``.claude/skills``, ``.agents/skills``) are
  skipped by default — they declare agents that do not run in production;
  ``--include DIR`` re-includes one.

What is NEVER done without ``--dial NAME``: launching a configured MCP
server process or contacting a remote one. Only ``--dial`` learns a
server's tools (``initialize`` + ``tools/list`` — no tool is ever called),
and it must only be used for servers the user explicitly approved, one by
one; ``--list-servers`` prints what each would launch or contact.

What is NEVER uploaded: environment variable or header VALUES (key names
only), command lines, URLs (a server is identified by a hash of how it is
launched, or by its URL host), absolute paths, installed packages, OS or
runtime details. The server re-validates all of this against an allowlist
(``app.scans.payload``) and stores nothing else.

What is printed: counts, the payload's size and sha256, and the upload
result. Never a name, path, command, URL or value from the repository.

The discovery engines are forgebench's agent-harness-explorer scanners,
vendored byte-for-byte under ``_vendor/agent_harness_explorer/`` so the
plugin is self-contained wherever Claude Code copies it (see
``_vendor/README.md``). Standard library only; Python 3.10+.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 10):  # before ANY other import: the vendored scanners use 3.10 syntax
    sys.stderr.write(
        "forgebench scan: Python 3.10 or newer is required (this is Python "
        f"{sys.version_info[0]}.{sys.version_info[1]}). Install a newer python3 (for example "
        "`brew install python@3.12` or https://www.python.org/downloads/) and re-run with it.\n"
    )
    raise SystemExit(2)

sys.dont_write_bytecode = True  # never litter the (possibly read-only) plugin cache

import argparse  # noqa: E402
import configparser  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, Optional  # noqa: E402

SCANNER_VERSION = "0.1.0"
SCHEMA_ID = "forgebench.scan/v1"
TICKET_PREFIX = "fbscan_"
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
UPLOAD_TIMEOUT_S = 60.0

_HERE = Path(__file__).resolve().parent
VENDOR_DIR = _HERE / "_vendor" / "agent_harness_explorer"
VENDORED_FILES = (
    "mcp_discovery_common.py",
    "inspect_mcp_configs.py",
    "inspect_mcp_source.py",
    "inspect_ts_mcp_source.py",
)
sys.path.insert(0, str(VENDOR_DIR))

import inspect_mcp_configs as config_scan  # noqa: E402
import inspect_mcp_source as py_scan  # noqa: E402
import inspect_ts_mcp_source as ts_scan  # noqa: E402
import mcp_discovery_common as common  # noqa: E402

# Same patterns the server enforces (app.scans.payload) — anything that would
# fail there is dropped (and counted) here instead of failing the whole upload.
_KEY_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_FRAMEWORK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SEGMENT_BAD = re.compile(r"[^A-Za-z0-9._~-]+")
# The API may be served under a path prefix; the route itself must be this.
_UPLOAD_PATH = re.compile(r"(?:^|/)v1/scans/[0-9a-fA-F-]{36}/parts$")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


# =============================================================================
# Repository identity (stdlib file parsing — no git binary needed)
# =============================================================================
def find_git(start: Path) -> tuple[Optional[Path], Optional[Path], Optional[Path]]:
    """(toplevel, gitdir, commondir) of the repository containing ``start``.

    Handles both a plain ``.git`` directory and a worktree/submodule ``.git``
    FILE (``gitdir: ...``), whose refs and config live in the ``commondir``.
    """
    for d in (start, *start.parents):
        dotgit = d / ".git"
        try:
            if dotgit.is_dir():
                return d, dotgit, dotgit
            if dotgit.is_file():
                content = dotgit.read_text(encoding="utf-8", errors="replace").strip()
                if not content.startswith("gitdir:"):
                    return d, None, None
                gitdir = Path(content[len("gitdir:") :].strip())
                if not gitdir.is_absolute():
                    gitdir = (d / gitdir).resolve()
                commondir = gitdir
                marker = gitdir / "commondir"
                if marker.is_file():
                    commondir = (gitdir / marker.read_text(encoding="utf-8").strip()).resolve()
                return d, gitdir, commondir
        except OSError:
            return None, None, None
    return None, None, None


def read_remote_url(commondir: Path) -> Optional[str]:
    """``remote.origin.url`` (else the first remote's url) from the git config."""
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read(commondir / "config", encoding="utf-8")
    except (configparser.Error, OSError, UnicodeDecodeError):
        return None
    remotes = [s for s in parser.sections() if s.startswith('remote "')]
    remotes.sort(key=lambda s: (s != 'remote "origin"', s))
    for section in remotes:
        url = parser.get(section, "url", fallback=None)
        if url:
            return url.strip()
    return None


def read_head_commit(gitdir: Path, commondir: Path) -> Optional[str]:
    try:
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if re.fullmatch(r"[0-9a-f]{40,64}", head):
        return head
    if not head.startswith("ref:"):
        return None
    ref = head[4:].strip()
    for base in (gitdir, commondir):
        try:
            value = (base / ref).read_text(encoding="utf-8").strip()
            if re.fullmatch(r"[0-9a-f]{40,64}", value):
                return value
        except OSError:
            pass
    try:
        for line in (commondir / "packed-refs").read_text(encoding="utf-8").splitlines():
            sha, _, name = line.partition(" ")
            if name.strip() == ref and re.fullmatch(r"[0-9a-f]{40,64}", sha):
                return sha
    except OSError:
        pass
    return None


def _segment(value: str) -> str:
    return _SEGMENT_BAD.sub("-", value).strip("-.") or "x"


def normalize_remote(url: str) -> Optional[str]:
    """``host/owner/repo`` (lowercase, no scheme, credentials, port or ``.git``)
    for a git remote URL, or None for a local/unsupported one.

    ``git@github.com:Acme/Agents.git``, ``https://user:token@github.com/acme/agents``
    and ``ssh://git@github.com:22/acme/agents.git`` all become
    ``github.com/acme/agents`` — one stable identity however each developer
    cloned it, with any embedded credential dropped rather than hashed.
    """
    url = (url or "").strip()
    if not url:
        return None
    scp = re.match(r"^(?:[^@/]+@)?([A-Za-z0-9.-]+):(?!//)(.+)$", url)
    if scp and "://" not in url:
        host, path = scp.group(1), scp.group(2)
    else:
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return None
        if parts.scheme not in ("http", "https", "ssh", "git", "git+ssh", "ssh+git") or not parts.hostname:
            return None
        host, path = parts.hostname, parts.path
    host = host.lower().strip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        return None
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    segments = [_segment(s.lower()) for s in path.split("/") if s and s not in (".", "..")]
    if not segments:
        return None
    if len(segments) > 8:  # the server's origin_display allows 8 path segments
        segments = segments[:7] + [".".join(segments[7:])[:200]]
    return host + "/" + "/".join(s[:200] for s in segments)


def repo_identity(root: Path, origin_override: Optional[str]) -> tuple[dict[str, Any], str]:
    """(``repo`` payload block, path prefix of ``root`` inside the repository).

    Agent paths are made relative to the repository TOPLEVEL (not the scan
    root), so an agent's discovery identity is the same whichever directory
    the scanner was started from.
    """
    toplevel, gitdir, commondir = find_git(root)
    base_dir = toplevel or root
    origin = normalize_remote(origin_override) if origin_override else None
    if origin is None and commondir is not None:
        origin = normalize_remote(read_remote_url(commondir) or "")
    # The repository's NAME: the remote's last segment when there is one (a
    # worktree or clone directory can be called anything), else the directory.
    root_basename = origin.rsplit("/", 1)[-1] if origin else (_segment(base_dir.name) if base_dir.name else "repo")
    if origin is None:
        origin = f"local/{root_basename.lower()}"
    commit = read_head_commit(gitdir, commondir) if gitdir is not None and commondir is not None else None
    try:
        prefix = root.relative_to(base_dir).as_posix()
    except ValueError:
        prefix = ""
    prefix = "" if prefix in (".", "") else prefix
    repo = {
        "origin_hash": "sha256:" + hashlib.sha256(origin.encode("utf-8")).hexdigest(),
        "origin_display": origin,
        "commit": commit,
        "root_basename": root_basename,
    }
    return repo, prefix


# =============================================================================
# Server identity
# =============================================================================
_FIRST_ARG_LAUNCHERS = {"npx", "uvx", "bunx", "pnpm", "npm", "yarn", "pipx"}
_LAST_ARG_LAUNCHERS = {"docker", "podman"}
_INTERPRETERS = {"python", "pypy", "node", "deno", "bun", "ruby", "perl", "php", "java", "dotnet", "bash", "sh", "zsh"}
# Flags that consume the NEXT argument, per launcher family — so the value of
# "--with x" or "-e KEY=v" is never mistaken for the server's identity.
_VALUE_FLAGS = {
    "uv": {"--with", "--with-requirements", "--with-editable", "--python", "-p", "--directory", "--project",
           "--from", "--env-file", "--index", "--index-url", "--extra", "--group", "--package"},
    "npx": {"--package", "-p", "--call", "-c", "--cache", "--registry"},
    "docker": {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "--network", "--net", "-p",
               "--publish", "--entrypoint", "-w", "--workdir", "-u", "--user", "--platform", "-l", "--label",
               "--add-host", "--cap-add", "--pull", "--memory", "-m", "--cpus", "-h", "--hostname"},
    "node": {"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions"},
}
_VALUE_FLAGS["uvx"] = _VALUE_FLAGS["uv"]
_VALUE_FLAGS["podman"] = _VALUE_FLAGS["docker"]
for _runner in ("bunx", "pnpm", "npm", "yarn"):
    _VALUE_FLAGS[_runner] = _VALUE_FLAGS["npx"]


def _base(command: str) -> str:
    name = Path(str(command or "")).name.lower()
    name = re.sub(r"\.(exe|cmd|bat)$", "", name)
    return re.sub(r"^(python|pypy)[0-9.]*$", r"\1", name)


def _positionals(args: list[str], value_flags: set[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if not isinstance(arg, str) or not arg:
            continue
        if arg.startswith("-"):
            skip = "=" not in arg and arg in value_flags
            continue
        out.append(arg)
    return out


def _strip_package_version(spec: str) -> str:
    """``@scope/pkg@1.2.3`` -> ``@scope/pkg``; ``pkg==1.0`` -> ``pkg``."""
    spec = re.split(r"==|>=|<=|~=", spec, maxsplit=1)[0]
    at = spec.rfind("@")
    return spec[:at] if at > 0 else spec


def _strip_image_tag(image: str) -> str:
    image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        image = image[: len(image) - len(last)] + last.split(":", 1)[0]
    return image


def launch_identity(command: str, args: list[str]) -> str:
    """WHAT a stdio server runs, independent of machine and version.

    The launcher's basename plus the one argument that names the server
    (the package for npx/uvx, the image for docker, the script or ``-m``
    module for an interpreter), with versions, tags, directories and every
    other argument stripped — so the same server launched from two laptops,
    or bumped a patch version, keeps one identity, and no home-directory
    path or argument value is ever part of it.
    """
    base = _base(command)
    args = [a for a in args if isinstance(a, str)]
    positional = _positionals(args, _VALUE_FLAGS.get(base, set()))
    ident = ""
    if base in _FIRST_ARG_LAUNCHERS:
        if base in ("npm", "pnpm", "yarn") and positional[:1] in (["exec"], ["dlx"]):
            positional = positional[1:]
        ident = _strip_package_version(positional[0]) if positional else ""
    elif base == "uv":
        rest = positional[1:] if positional[:1] in (["run"], ["tool"]) else positional
        if rest[:1] == ["run"]:  # "uv tool run pkg"
            rest = rest[1:]
        ident = _strip_package_version(Path(rest[0]).name) if rest else ""
    elif base in _LAST_ARG_LAUNCHERS:
        # "docker run [opts] IMAGE [cmd...]": the image is the first positional after the subcommand.
        rest = positional[1:] if positional[:1] in (["run"], ["container"]) else positional
        ident = _strip_image_tag(rest[0]) if rest else ""
    elif base in _INTERPRETERS:
        if "-m" in args and args.index("-m") + 1 < len(args):
            ident = args[args.index("-m") + 1]
        else:
            ident = Path(positional[0]).name if positional else ""
    return f"{base}:{ident}" if ident else base


def pretty_server_name(command: str, args: list[str]) -> str:
    """A readable catalog name for a stdio server that was declared WITHOUT
    a name (the vendored scanner then synthesizes ``npx:@scope/pkg@1.2.3``).

    The synthesized form carries the version and launcher, so every version
    bump would register a "new" server and every qualified tool name
    (``mcp_<server>_<tool>``) would be full of punctuation. This keeps only
    what names the server: the package's last path component without scope
    or version, the image name without registry or tag, the script's stem.
    """
    identity = launch_identity(command, args)
    base, _, ident = identity.partition(":")
    if not ident:
        return base
    ident = ident.rstrip("/").rsplit("/", 1)[-1]
    if base in _INTERPRETERS or base == "uv":
        ident = re.sub(r"\.(py|js|mjs|cjs|ts|rb|sh)$", "", ident)
    return ident or base


def command_fingerprint(command: str, args: list[str]) -> str:
    identity = launch_identity(command, args)
    return "sha256:" + hashlib.sha256(f"stdio:{identity}".encode("utf-8")).hexdigest()[:32]


def url_host(url: str) -> Optional[str]:
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}.get(parts.scheme)
    return f"{host}:{port}" if port and port != default else host


# =============================================================================
# Discovery
# =============================================================================
class Findings:
    def __init__(self) -> None:
        self.servers: list[common.ServerConfig] = []
        self.agents: list[dict[str, Any]] = []
        self.agent_links: list[dict[str, Any]] = []
        self.base_tools: list[dict[str, Any]] = []
        self.unresolved: list[dict[str, Any]] = []
        self.gaps: list[str] = []
        self.truncated = False
        self.dropped = 0
        # (agent name, "file:line") -> framework, to label agent links precisely.
        self.agent_frameworks: dict[tuple[str, str], str] = {}


def _scrub(text: str, root: Path) -> str:
    """Scanner warnings quote absolute paths; keep only repo-relative ones."""
    out = text.replace(str(root) + os.sep, "").replace(str(root), ".")
    home = str(Path.home())
    if home and home != os.sep:
        out = out.replace(home, "~")
    return out[:480]


def _source_scan(module, root: Path, excludes: set[str], max_files: int, findings: Findings):
    records, agents, pending, base_tools, agent_unresolved, warnings = module.discover_source(root, excludes, max_files)
    servers, unresolved, dedupe_warnings, key_to_name = module.to_servers_and_unresolved(records)
    links = module.resolve_agent_links(pending, key_to_name, agent_unresolved)
    for w in [*warnings, *dedupe_warnings]:
        if py_scan.TRUNCATION_MARKER in w:
            findings.truncated = True
        findings.gaps.append(_scrub(w, root))
    return servers, unresolved, agents, links, base_tools, agent_unresolved


def discover(root: Path, args: argparse.Namespace) -> Findings:
    findings = Findings()
    excludes = (set(py_scan._DEFAULT_EXCLUDE_DIRS) - set(args.include)) | set(args.exclude)
    ts_excludes = (set(ts_scan._DEFAULT_EXCLUDE_DIRS) - set(args.include)) | set(args.exclude)

    candidates: list[tuple[common.ServerConfig, str]] = []
    config_servers, config_warnings = config_scan.discover(root, include_user_scope=args.include_user_configs)
    candidates.extend((s, s.source) for s in config_servers)
    findings.gaps.extend(_scrub(w, root) for w in config_warnings)

    py = _source_scan(py_scan, root, excludes, args.max_files, findings)
    results = [("python-source", py)]
    if getattr(ts_scan, "TREE_SITTER_AVAILABLE", False) and not args.no_typescript:
        results.append(("typescript-source", _source_scan(ts_scan, root, ts_excludes, args.max_files, findings)))
    elif not args.no_typescript:
        ts_files, _ = ts_scan.iter_source_files(root, ts_excludes, args.max_files)
        if ts_files:
            findings.gaps.append(
                f"{len(ts_files)} TypeScript/JavaScript file(s) were NOT scanned: install tree-sitter and "
                "tree-sitter-typescript (pip install tree-sitter tree-sitter-typescript) to include them."
            )

    for _, (servers, unresolved, agents, links, base_tools, agent_unresolved) in results:
        candidates.extend((s, s.source) for s in servers)
        for a in agents:
            findings.agent_frameworks[(a.name, f"{a.file}:{a.line}")] = a.framework
            findings.agents.append({"framework": a.framework, "declared_name": a.name, "file": a.file, "line": a.line})
        findings.agent_links.extend(links)
        findings.base_tools.extend(base_tools)
        for rec in unresolved:
            findings.unresolved.append(
                {
                    "framework": rec.framework,
                    "transport": rec.transport,
                    "file": rec.file,
                    "line": rec.line,
                    "unresolved_fields": list(rec.unresolved_fields),
                    "reason": next(iter(rec.unresolved_reason.values()), ""),
                }
            )
        for row in agent_unresolved:
            findings.unresolved.append(
                {"file": row.get("file"), "line": row.get("line"), "reason": f"agent '{row.get('agent')}': {row.get('reason')}"}
            )
    renames = _rename_synthesized(candidates)
    for server, _ in candidates:
        server.name = renames.get(server.name, server.name)
    for row in findings.agent_links:
        row["server"] = renames.get(row.get("server"), row.get("server"))
    findings.servers, dedupe_warnings = common.dedupe_servers(candidates)
    findings.gaps.extend(_scrub(w, root) for w in dedupe_warnings)
    return findings


def _rename_synthesized(candidates: list[tuple[common.ServerConfig, str]]) -> dict[str, str]:
    """{synthesized name: pretty name} for stdio servers declared without a
    name, applied to the servers AND to every agent link that points at them.

    A pretty name is only used when no other server in this scan already has
    it (or claimed it first, in sorted order) — two different images both
    called ``mcp`` keep their distinct synthesized names rather than being
    merged into one server by the name-based dedupe.
    """
    explicit = {s.name for s, _ in candidates if "name synthesized" not in (s.source or "")}
    renames: dict[str, str] = {}
    claimed: dict[str, str] = {}
    synthesized = sorted(
        {(s.name, s.command or "", tuple(s.args or [])) for s, _ in candidates
         if s.transport == "stdio" and "name synthesized from command" in (s.source or "")}
    )
    for name, command, args in synthesized:
        if name in renames:
            continue
        pretty = pretty_server_name(command, list(args))[:255]
        if pretty and pretty != name and pretty not in explicit and claimed.get(pretty, name) == name:
            claimed[pretty] = name
            renames[name] = pretty
    return renames


def dial(findings: Findings, names: list[str], timeout: float, root: Path) -> tuple[dict[str, list[str]], int]:
    """Dial ONLY the servers the user approved by name. (tools by server, failures)."""
    tools: dict[str, list[str]] = {}
    failed = 0
    wanted = set(names)
    for server in findings.servers:
        if server.name not in wanted:
            continue
        fn = common._dial_stdio if server.transport == "stdio" else common._dial_http
        status, names_found, warning = fn(server, timeout)
        if warning:
            findings.gaps.append(_scrub(warning, root))
        if status == "available":
            tools[server.name] = sorted(set(names_found))
        else:
            failed += 1
            findings.gaps.append(f"MCP server '{server.name}' could not be dialed ({status}); its tools are unknown.")
    return tools, failed


# =============================================================================
# Payload
# =============================================================================
def _rel(prefix: str, file: str) -> str:
    """A scanner path (relative to --root) made relative to the repository toplevel."""
    path = str(file or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return f"{prefix}/{path}" if prefix else path


def _clip(value: Any, limit: int = 255) -> Optional[str]:
    text = str(value or "").strip()
    return text[:limit] if text else None


def build_payload(root: Path, args: argparse.Namespace, findings: Findings, tools: dict[str, list[str]]) -> dict[str, Any]:
    repo, prefix = repo_identity(root, args.origin)
    servers: list[dict[str, Any]] = []
    for s in sorted(findings.servers, key=lambda x: x.name):
        name = _clip(s.name)
        if name is None:
            findings.dropped += 1
            continue
        entry: dict[str, Any] = {
            "name": name,
            "transport": "stdio" if s.transport == "stdio" else "http",
            "source": _clip(_scrub(s.source, root), 300),
            "env_keys": sorted(k for k in s.env if isinstance(k, str) and _KEY_NAME.match(k)),
            "header_keys": sorted(k for k in s.headers if isinstance(k, str) and _KEY_NAME.match(k)),
            "tools": [{"name": t} for t in tools.get(s.name, []) if 0 < len(t) <= 200],
        }
        if s.transport == "stdio":
            entry["command_fingerprint"] = command_fingerprint(s.command or "", list(s.args or []))
        else:
            host = url_host(s.url or "")
            if host is None:
                findings.dropped += 1
                continue
            entry["url_host"] = host
        servers.append(entry)

    agents = []
    for a in findings.agents:
        name = _clip(a["declared_name"])
        if name is None or not _FRAMEWORK.match(str(a["framework"])):
            findings.dropped += 1
            continue
        agents.append({"framework": a["framework"], "declared_name": name, "path": _rel(prefix, a["file"]), "line": a["line"]})

    frameworks = findings.agent_frameworks

    def _link(row: dict[str, Any], target: str) -> Optional[dict[str, Any]]:
        location = str(row.get("agent_location") or "")
        file, _, _line = location.rpartition(":")
        agent, value = _clip(row.get("agent")), _clip(row.get(target))
        if not (file and agent and value):
            return None
        out = {"agent": agent, "agent_path": _rel(prefix, file), target: value}
        fw = frameworks.get((row.get("agent"), location))
        if fw and _FRAMEWORK.match(fw):
            out["framework"] = fw
        return out

    links = [x for x in (_link(r, "server") for r in findings.agent_links) if x]
    base = [x for x in (_link(r, "tool") for r in findings.base_tools) if x]
    unresolved = []
    for u in findings.unresolved:
        entry = {k: v for k, v in u.items() if v not in (None, "", [])}
        if entry.get("file"):
            entry["path"] = _rel(prefix, entry.pop("file"))
        if isinstance(entry.get("reason"), str):
            entry["reason"] = _scrub(entry["reason"], root)[:200]
        unresolved.append(entry)
    gaps = list(dict.fromkeys(findings.gaps))
    if findings.dropped:
        gaps.append(f"{findings.dropped} declaration(s) were left out because a name or address could not be represented safely.")
    undialed = sum(1 for s in servers if not s["tools"])
    if undialed:
        gaps.append(
            f"{undialed} MCP server(s) were not dialed, so their tools are unknown (re-run with --dial NAME for "
            "servers the user approves, or report the tools you can see as self_observed findings)."
        )
    if not args.include_user_configs:
        gaps.append("Personal (home-directory) MCP client configs were not read (--include-user-configs).")
    return {
        "schema": SCHEMA_ID,
        "scanner": {"version": SCANNER_VERSION, "sha256": scanner_sha256()},
        "repo": repo,
        "mcp_servers": servers,
        "agents": agents,
        "agent_mcp_servers": links,
        "agent_base_tools": base,
        "unresolved": unresolved[:1000],
        "gaps": gaps[:1000],
    }


def scanner_sha256() -> str:
    """sha256 over this script and every vendored module, in a fixed order —
    the provenance the server records for "which scanner produced this"."""
    digest = hashlib.sha256()
    for path in (Path(__file__).resolve(), *(VENDOR_DIR / f for f in VENDORED_FILES)):
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# =============================================================================
# Upload
# =============================================================================
def check_upload_target(url: str, ticket: str, allow_insecure: bool) -> Optional[str]:
    """An error message, or None if the upload may proceed."""
    if not ticket.startswith(TICKET_PREFIX):
        return "the ticket must be the fbscan_... value returned by forgebench_begin_scan"
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "the upload URL is not a valid URL"
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return "the upload URL must be an http(s) URL"
    if not _UPLOAD_PATH.search(parts.path) or parts.query or parts.fragment or parts.username:
        return "the upload URL must be exactly the upload_url returned by forgebench_begin_scan"
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK_HOSTS and not allow_insecure:
        return "refusing to send the ticket over plain http to a non-local host (use https, or --allow-insecure-http)"
    return None


def upload(url: str, ticket: str, body: bytes) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {ticket}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"forgebench-scan/{SCANNER_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=UPLOAD_TIMEOUT_S) as resp:  # noqa: S310 - URL checked above
            return resp.status, _json(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json(exc.read())


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


# =============================================================================
# CLI
# =============================================================================
def print_server_listing(findings: Findings, root: Path) -> None:
    """The consent listing: what --dial would LAUNCH or CONTACT, per server.
    Values that look like secrets are redacted by the vendored display helpers."""
    if not findings.servers:
        print("No MCP servers found. Nothing was launched or contacted.")
        return
    print(f"MCP servers found: {len(findings.servers)}. Nothing has been launched or contacted.")
    for s in sorted(findings.servers, key=lambda x: x.name):
        if s.transport == "stdio":
            env = ", ".join(s.env_keys()) or "none"
            target = f"LAUNCHES: {s.display_command()} {' '.join(s.display_args())} (env keys: {env})"
        else:
            target = f"CONTACTS: {s.display_url()} (header keys: {', '.join(s.header_keys()) or 'none'})"
        print(f"  - {s.display_name()} [{_scrub(s.display_source(), root)}] {target}")
    print(
        "To learn a server's tools the scanner must launch or contact it. Ask the user which servers "
        "they approve, then re-run the upload command with --dial NAME for each approved server."
    )


def _counts_line(payload: dict[str, Any], dialed: int, truncated: bool) -> str:
    servers = payload["mcp_servers"]
    tools = sum(len(s["tools"]) for s in servers)
    return (
        f"forgebench scan: {len(servers)} MCP server(s) ({dialed} dialed, {tools} tool(s) known), "
        f"{len(payload['agents'])} agent(s), {len(payload['agent_mcp_servers'])} agent-to-server link(s), "
        f"{len(payload['agent_base_tools'])} base-tool link(s), {len(payload['unresolved'])} unresolved, "
        f"{len(payload['gaps'])} gap(s)" + (" — INCOMPLETE: the file cap was reached" if truncated else "") + "."
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forgebench_scan.py",
        description="Scan a repository for AI agents and MCP servers and upload the findings to forgebench.",
    )
    p.add_argument("--root", type=Path, default=Path.cwd(), help="repository directory to scan (default: cwd)")
    p.add_argument("--upload-url", help="the upload_url from forgebench_begin_scan")
    p.add_argument("--ticket", help="the fbscan_ ticket from forgebench_begin_scan (or env FORGEBENCH_SCAN_TICKET)")
    p.add_argument("--out", type=Path, help="write the payload JSON to this file (for forgebench_submit_scan_inline)")
    p.add_argument("--list-servers", action="store_true", help="list the MCP servers found (for consent) and exit")
    p.add_argument(
        "--dial",
        action="append",
        default=[],
        metavar="NAME",
        help="launch/contact this server to list its tools — ONLY with the user's explicit approval (repeatable)",
    )
    p.add_argument("--dial-timeout", type=float, default=8.0, help="seconds per dialed server (default 8)")
    p.add_argument("--include-user-configs", action="store_true", help="also read MCP configs in your home directory")
    p.add_argument("--include", action="append", default=[], metavar="DIR", help="re-include a default-excluded directory")
    p.add_argument("--exclude", action="append", default=[], metavar="DIR", help="also exclude this directory name or path")
    p.add_argument("--max-files", type=int, default=5000, help="source files to scan per language (default 5000)")
    p.add_argument("--origin", help="repository remote URL to use when git has none (e.g. a fresh checkout)")
    p.add_argument("--no-typescript", action="store_true", help="skip TypeScript/JavaScript scanning")
    p.add_argument("--allow-insecure-http", action="store_true", help="allow an http:// upload URL to a non-local host")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print("forgebench scan: --root is not a directory.", file=sys.stderr)
        return 2
    ticket = args.ticket or os.environ.get("FORGEBENCH_SCAN_TICKET") or ""
    uploading = bool(args.upload_url)
    if not (uploading or args.out or args.list_servers):
        print("forgebench scan: nothing to do — pass --upload-url and --ticket, --out FILE, or --list-servers.", file=sys.stderr)
        return 2
    if uploading:
        problem = check_upload_target(args.upload_url, ticket, args.allow_insecure_http)
        if problem:
            print(f"forgebench scan: {problem}.", file=sys.stderr)
            return 2

    findings = discover(root, args)
    if args.list_servers:
        print_server_listing(findings, root)
        return 0

    known = {s.name for s in findings.servers}
    unknown = [n for n in args.dial if n not in known]
    if unknown:
        print(f"forgebench scan: {len(unknown)} --dial name(s) match no discovered server; run --list-servers.", file=sys.stderr)
        return 2
    tools, failed = dial(findings, args.dial, args.dial_timeout, root) if args.dial else ({}, 0)

    payload = build_payload(root, args, findings, tools)
    body = canonical_bytes(payload)
    digest = hashlib.sha256(body).hexdigest()
    print(_counts_line(payload, len(tools), findings.truncated))
    if failed:
        print(f"{failed} dialed server(s) did not answer; their tools are unknown.")
    print(f"payload: {len(body)} bytes sha256={digest}")
    if len(body) > MAX_UPLOAD_BYTES:
        print("forgebench scan: the payload exceeds the 16 MiB scan cap; narrow --root and re-run.", file=sys.stderr)
        return 1

    if args.out:
        args.out.write_bytes(body + b"\n")
        print("payload written to the --out file.")
    if uploading:
        try:
            status, resp = upload(args.upload_url, ticket, body)
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            print(f"upload failed: could not reach forgebench ({type(reason).__name__}). "
                  "Re-run with --out FILE and use forgebench_submit_scan_inline instead.", file=sys.stderr)
            return 1
        if status == 201:
            print(
                f"uploaded: part {resp.get('part_id')} ({resp.get('parts_remaining')} part(s) and "
                f"{resp.get('bytes_remaining')} bytes left on this scan). Now call forgebench_review_scan."
            )
            return 0
        detail = resp.get("detail") if isinstance(resp.get("detail"), dict) else {}
        code = detail.get("code") or "error"
        message = str(detail.get("message") or "")[:300]
        print(f"upload failed: HTTP {status} {code}: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
