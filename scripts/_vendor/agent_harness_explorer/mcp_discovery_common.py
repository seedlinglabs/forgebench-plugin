"""Shared MCP-discovery machinery (forgebench addition, not upstream).

Extracted out of ``inspect_mcp_configs.py`` so a second discovery SOURCE
(``inspect_mcp_source.py``, which finds MCP servers declared programmatically
in a repo's own Python code rather than in a static config file) can reuse
the exact same ``ServerConfig`` shape, redaction/display helpers, and dial
implementation, instead of duplicating ~500 lines of already
adversarially-tested security-sensitive code. Neither script imports this
from the parent ``forgebench_session_reviewer`` package -- this whole bundle
is copied out of the installed package into a target repo's own
``.claude/skills/`` by ``install-bundle`` and has to keep working there with
no import path back to the parent package, the same "stdlib-only, fully
self-contained" constraint the rest of this bundle already lives under.

A DISCOVERY source's only job is producing ``ServerConfig`` objects (a
server's real address: command+args+env, or url+headers). What happens to
one after that -- the consent listing, the dial itself, the redaction of
every untrusted value along the way -- is identical regardless of whether
the server's address came from a config file or a static scan of Python
source, which is exactly why this module exists as a shared boundary rather
than being duplicated per source.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROBE_VERSION = "0.1.0"

# ``datetime.UTC`` is 3.11+. The hosted-MCP scanner
# (packages/forgebench-plugin/scripts/forgebench_scan.py, which vendors this
# module) promises Python >= 3.10 because that is what a developer laptop
# most often has; ``timezone.utc`` is the same object under another name.
UTC = timezone.utc

_PROTOCOL_VERSION = "2025-03-26"
_DEFAULT_TIMEOUT = 8.0
_MAX_CONFIG_BYTES = 20 * 1024 * 1024  # matches agent-scan's own cap
_MAX_TOOL_PAGES = 20  # defensive cap on tools/list cursor pagination
_MAX_TOOL_NAME_LEN = 200  # a real MCP tool name is a short identifier, not a smuggled payload


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# Display safety -- every string below can originate from an UNTRUSTED
# config file or source-code declaration (or, for tool names, an untrusted
# DIALED SERVER), and every function here is display/output-only: none of it
# ever touches the real values ServerConfig.args/url/env/headers hold, which
# is what the dial actually uses.
# =============================================================================

# Characters this deliberately strips: Unicode category Cc (control, e.g. an
# ANSI escape byte) and Cf (format, which includes the bidi override
# characters like U+202E RIGHT-TO-LEFT OVERRIDE) -- both are real terminal-
# injection vectors against the human approving what's about to be dialed
# (an ANSI sequence can rewrite/hide the visible line; a bidi override can
# visually reorder it into something misleading). Replaced with U+FFFD
# rather than dropped, so tampering is visible rather than silently erased.
def _sanitize_for_terminal(text: str) -> str:
    return "".join(ch if unicodedata.category(ch) not in ("Cc", "Cf") else "�" for ch in text)


# Flag/parameter names that make a --flag=value CLI arg or a URL query
# parameter worth treating as a secret, REGARDLESS of what the value itself
# looks like -- a generic "does this look like a known vendor's token
# format" pattern match (sk-..., AKIA..., etc.) would miss an ordinary
# internal/demo token that simply doesn't happen to match a well-known
# provider's shape, which is the common case, not the exception. This is a
# heuristic (documented, not solved -- same stance as this repo's own
# redaction.py takes for pasted-secret detection generally), not a
# guarantee: it catches an argument/param whose NAME says what it is.
_SENSITIVE_NAME_HINT = re.compile(r"(?i)key|token|secret|password|passwd|pwd|auth|credential")
_ARG_FLAG_VALUE = re.compile(r"^(--?[\w][\w-]*)=(.*)$", re.DOTALL)
_ARG_BARE_FLAG = re.compile(r"^--?[\w][\w-]*$")

# Ubiquitous, well-known env vars whose values are never a secret -- excluded
# from the dial-time exfiltration check (see its call site) so a common
# value like TERM_PROGRAM=vscode can't trip the "server echoed a secret"
# alarm just because it's >=6 chars and happens to be a substring of some
# unrelated, legitimate tool name.
_COMMON_BENIGN_ENV_NAMES = frozenset(
    {
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "OLDPWD", "TMPDIR",
        "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TERM", "TERM_PROGRAM",
        "TERM_PROGRAM_VERSION", "TERM_SESSION_ID", "COLORTERM", "EDITOR",
        "VISUAL", "PAGER", "DISPLAY", "SSH_AUTH_SOCK", "SSH_TTY", "TZ",
        "HOSTNAME", "HOSTTYPE", "OSTYPE", "MACHTYPE", "SHLVL", "PS1", "IFS",
        "XPC_SERVICE_NAME", "XPC_FLAGS", "__CFBundleIdentifier",
        "COMMAND_MODE", "LaunchInstanceID", "SECURITYSESSIONID",
        # Windows
        "USERPROFILE", "USERNAME", "COMPUTERNAME", "OS", "PROCESSOR_ARCHITECTURE",
        "SystemRoot", "SystemDrive", "ProgramFiles", "ProgramFiles(x86)",
        "ProgramData", "APPDATA", "LOCALAPPDATA", "PATHEXT", "NUMBER_OF_PROCESSORS",
        "windir", "ComSpec", "HOMEDRIVE", "HOMEPATH",
        # Common toolchain/version-manager roots -- also never a secret, and
        # just as prone to a short, common value as TERM_PROGRAM.
        "VIRTUAL_ENV", "CONDA_DEFAULT_ENV", "GOPATH", "GOROOT", "CARGO_HOME",
        "RUSTUP_HOME", "JAVA_HOME", "ANDROID_HOME", "NVM_DIR", "PYENV_ROOT",
        "RBENV_ROOT", "NODE_ENV",
    }
)
# Prefix-matched rather than a fixed name -- npm/yarn set a whole family of
# npm_config_* vars per-invocation, none of which are secrets.
_COMMON_BENIGN_ENV_PREFIXES = ("npm_config_", "npm_package_")

# A CONTAINER/subcommand launcher's identifying arg comes LAST -- e.g.
# "docker run -i --rm image:tag" has "run" (a subcommand, not an
# identifier) as its first non-flag arg and the image as its last.
_LAST_ARG_LAUNCHER_BASENAMES = frozenset({"docker", "docker.exe"})
# A PACKAGE-RUNNER launcher's identifying arg comes FIRST, right after any
# -y/--yes flags -- e.g. "npx -y @pkg/name /path/to/allowed/dir". Any
# TRAILING positional there is a runtime arg to the SERVER itself (an
# allowed filesystem path is the common one), not part of its identity --
# picking the LAST non-flag arg for these would grab that instead, collide
# two genuinely different servers that happen to share a mount root, and
# leak the path into the report besides.
_FIRST_ARG_LAUNCHER_BASENAMES = frozenset(
    {"npx", "npx.cmd", "uvx", "uvx.exe", "bunx", "bunx.cmd", "pnpm", "pnpm.cmd",
     "npm", "npm.cmd", "yarn", "yarn.cmd"}
)
# Basenames of generic package/container launchers whose own basename alone
# carries no identifying information (unlike an interpreter running a
# specific, already-named script) -- see synthesize_stdio_server_name.
GENERIC_LAUNCHER_BASENAMES = _LAST_ARG_LAUNCHER_BASENAMES | _FIRST_ARG_LAUNCHER_BASENAMES


def synthesize_stdio_server_name(command: Any, args: Any) -> str:
    """The server NAME for a stdio launch: ``command``'s basename, with a
    disambiguating arg folded in for a GENERIC launcher (npx/uvx/docker/...).

    Shared by both scanners (inspect_mcp_source.py / inspect_ts_mcp_source.py)
    rather than duplicated -- a one-sided fix to this logic in only one of
    them would make the two scanners disagree on a server's identity, which
    matters because merge_dial_results merges dial output from both by name.

    A launcher basename ALONE ("npx", "uvx", "docker", ...) collides across
    every genuinely different server started the same way: dedupe_servers()
    would then keep only the first and silently mis-link any agent declared
    against the dropped one to the survivor's, different, tool catalog. An
    interpreter running a specific, already-named script (python/node/...)
    doesn't have this problem -- the basename alone stays unambiguous for it.
    """
    base = Path(str(command or "")).name
    if not base:
        return base
    if base in GENERIC_LAUNCHER_BASENAMES:
        non_flags = [
            str(a) for a in (args or []) if isinstance(a, str) and a and not a.startswith("-")
        ]
        disambiguator = None
        if non_flags:
            disambiguator = non_flags[-1] if base in _LAST_ARG_LAUNCHER_BASENAMES else non_flags[0]
        if disambiguator:
            full = f"{base}:{disambiguator}"
            if len(full) <= 255:
                return full
            # A naive [:255] truncation would silently re-collide two
            # different, long disambiguators that happen to share a common
            # prefix past that point -- append a short hash of the FULL
            # (untruncated) string instead, so two different inputs stay
            # two different names even after the cut.
            digest = hashlib.sha256(full.encode()).hexdigest()[:8]
            return f"{full[:255 - len(digest) - 1]}~{digest}"
    return base


def _redact_netloc_userinfo(netloc: str) -> str:
    """A URL's ``netloc`` (``user:password@host:port``) is a THIRD place a
    real credential commonly lives, distinct from the query string and path
    the C2/H fixes already cover: a database connection string
    (``postgresql://user:password@host/db``, the shape
    ``@modelcontextprotocol/server-postgres`` and similar MySQL/MongoDB/Redis
    MCP servers use) puts it in the password slot; a Sentry DSN
    (``https://<key>@org.ingest.sentry.io/project``) puts the ENTIRE secret
    in the username slot with no password at all. Whichever slot it's
    actually in, the whole userinfo is replaced wholesale rather than
    guessing which half is the secret -- over-redacting an ordinary
    username costs far less than under-redacting a real credential (same
    stance the query-string/path redaction already takes)."""
    if "@" not in netloc:
        return netloc
    return "[REDACTED]@" + netloc.rsplit("@", 1)[1]


def _redact_url_userinfo(value: str) -> str:
    """If ``value`` parses as an absolute URL (any scheme, not just http(s)
    -- a connection string's ``postgresql://`` scheme is exactly the point)
    whose netloc carries userinfo, return it with that userinfo redacted.
    Anything that isn't URL-shaped, or has no userinfo, is returned
    unchanged. Used by ``_display_args`` for a bare positional CLI argument
    that happens to BE a full connection string (no ``--flag=`` prefix to
    hint at it at all) and for a ``--flag=<url>`` token whose flag name
    doesn't itself hint at a secret."""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or "@" not in parts.netloc:
        return value
    netloc = _redact_netloc_userinfo(parts.netloc)
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _display_args(args: list[str]) -> list[str]:
    """The full args list, safe to print/write. A CLI accepts a flag's
    value in two equally-common shapes, and both need redacting when the
    flag name hints at a secret: combined (``--flag=value``, one token,
    checkable per-arg in isolation) and split (``--flag``, ``value`` as two
    CONSECUTIVE tokens -- only catchable by looking at the whole list
    together, which is why this takes the list rather than being a
    per-arg function like ``_display_url``'s query/path handling)."""
    out = list(args)
    for i, arg in enumerate(out):
        match = _ARG_FLAG_VALUE.match(arg)
        if match and _SENSITIVE_NAME_HINT.search(match.group(1)):
            out[i] = f"{match.group(1)}=[REDACTED]"
            continue
        if _ARG_BARE_FLAG.match(arg) and _SENSITIVE_NAME_HINT.search(arg) and i + 1 < len(out):
            out[i + 1] = "[REDACTED]"

    # A separate, independent pass: any arg that's shaped like a URL
    # carrying credentials in its userinfo gets that redacted too,
    # regardless of whether a flag NAME hinted at a secret -- a database MCP
    # server commonly takes its whole connection string as a bare
    # positional arg (no flag at all to hint at anything), and a flag like
    # ``--db=<url>`` has no sensitive-sounding name even though its value
    # plainly carries one. Applied to a ``--flag=value`` token's own value
    # half so the flag name is preserved, and to a bare token directly.
    for i, arg in enumerate(out):
        match = _ARG_FLAG_VALUE.match(arg)
        if match:
            out[i] = f"{match.group(1)}={_redact_url_userinfo(match.group(2))}"
        else:
            out[i] = _redact_url_userinfo(arg)

    return [_sanitize_for_terminal(a) for a in out]


def _display_url(url: str) -> str:
    """A server URL, safe to print/write. Redacts any query parameter whose
    NAME hints at a secret (query strings are the common place for a
    URL-based credential), any path segment immediately following a
    sensitive-named one -- a simple-auth URL shape like
    ``https://host/api/token/<secret>/mcp`` carries its credential in the
    PATH, not a query param, and is just as real -- AND the netloc's own
    userinfo (``user:password@host``, or Sentry-DSN-style ``key@host``),
    the THIRD place a URL commonly carries a real credential; always strips
    terminal-injection characters regardless."""
    try:
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return _sanitize_for_terminal(url)
    redacted_pairs = [(k, "[REDACTED]" if _SENSITIVE_NAME_HINT.search(k) else v) for k, v in pairs]
    new_query = urllib.parse.urlencode(redacted_pairs, safe="[]")

    segments = parts.path.split("/")
    for idx in range(len(segments) - 1):
        if segments[idx] and _SENSITIVE_NAME_HINT.search(segments[idx]):
            segments[idx + 1] = "[REDACTED]"
    new_path = "/".join(segments)

    new_netloc = _redact_netloc_userinfo(parts.netloc)

    rebuilt = urllib.parse.urlunsplit((parts.scheme, new_netloc, new_path, new_query, parts.fragment))
    return _sanitize_for_terminal(rebuilt)


def _scrub_echoed_secrets(text: str, known_secret_values: list[str]) -> tuple[str, bool]:
    """Returns (scrubbed_text, was_suspicious). A DIALED server received
    real env/header values so it could actually start/authenticate --
    nothing about the protocol stops it (malicious, compromised, or just
    careless) from reading its own environment and echoing a value back in
    the one piece of its response this script persists verbatim: a tool
    name. Checked against the EXACT secret values this run itself handed
    that server, not a generic "looks like a secret" guess -- we know
    precisely what we gave it, so an exact-substring match is both precise
    (no false positives on an unrelated legitimate tool name) and complete
    for this specific exfiltration channel."""
    suspicious = False
    for value in known_secret_values:
        if value and len(value) >= 6 and value in text:
            text = text.replace(value, "[REDACTED]")
            suspicious = True
    return text, suspicious


def _sanitize_dialed_tool_names(
    raw_tools: list[Any], known_secret_values: list[str], server_name: str
) -> tuple[list[str], str | None]:
    """Every name in a ``tools/list`` response is untrusted input from the
    server we just dialed -- even though its config LOOKED legitimate at
    scan time, the live server can be malicious, compromised, or just
    careless, and we handed it real secrets (env/headers) so it could
    start/authenticate. Returns (clean_names, warning). Two independent
    checks: an implausibly long "tool name" is dropped outright (a real one
    is a short identifier, not a channel for smuggling data out); anything
    that echoes a secret THIS RUN handed the server gets that secret
    scrubbed and the whole run flagged -- this is a strong, specific signal
    of exactly the exfiltration attempt this function exists to catch, not
    an incidental issue to note quietly."""
    names: list[str] = []
    suspicious = False
    dropped_long = 0
    for tool in raw_tools:
        name = tool.get("name") if isinstance(tool, dict) else None
        if not isinstance(name, str) or not name:
            continue
        if len(name) > _MAX_TOOL_NAME_LEN:
            dropped_long += 1
            continue
        # This is the LEAST trusted input this script handles -- a name a
        # server we just dialed chose to send back, not something declared
        # in the repo's own source. Cc/Cf-sanitize it the same as every
        # other untrusted display field (ServerConfig.display_name() etc.)
        # before it flows into a report or terminal output, same reasoning
        # as the secret-echo scrub right below.
        name = _sanitize_for_terminal(name)
        cleaned, was_suspicious = _scrub_echoed_secrets(name, known_secret_values)
        suspicious = suspicious or was_suspicious
        names.append(cleaned)

    warning = None
    if suspicious:
        warning = (
            f"{server_name}: a tool name returned by tools/list echoed a secret value "
            "this run supplied via env/headers -- redacted here, but treat this server "
            "as potentially malicious or compromised and investigate it directly"
        )
    elif dropped_long:
        warning = (
            f"{server_name}: dropped {dropped_long} tool name(s) longer than "
            f"{_MAX_TOOL_NAME_LEN} characters (implausible for a real tool name)"
        )
    return names, warning


class ServerConfig:
    """One discovered MCP server, regardless of discovery source. ``env``/
    ``headers`` are the REAL values, kept only in memory for the dial call
    that needs them -- every public output path below reads
    ``env_keys()``/``header_keys()`` instead."""

    __slots__ = ("args", "command", "env", "headers", "name", "source", "transport", "url")

    def __init__(
        self,
        *,
        name: str,
        source: str,
        transport: str,
        command: str | None = None,
        args: list | None = None,
        env: dict | None = None,
        url: str | None = None,
        headers: dict | None = None,
    ) -> None:
        self.name = name
        self.source = source
        self.transport = transport
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.url = url
        self.headers = headers or {}

    def env_keys(self) -> list[str]:
        """Key NAMES only, never values -- and terminal-sanitized, since a
        malicious config could name an env var to carry injection chars."""
        return [_sanitize_for_terminal(k) for k in sorted(self.env.keys())]

    def header_keys(self) -> list[str]:
        return [_sanitize_for_terminal(k) for k in sorted(self.headers.keys())]

    def known_secret_values(self) -> list[str]:
        """Every real secret value THIS RUN handed this server via
        declared fields -- used only to check whether a dialed server
        echoed one back, never written anywhere. Complete for an HTTP
        server (only ``.headers`` ever reaches it). NOT complete for a
        stdio server on its own: ``_dial_stdio`` also forwards the full
        ambient environment to the child process, so it builds its own
        wider check directly rather than calling this."""
        return [*self.env.values(), *self.headers.values()]

    # -- display-only views: safe to print or write to --out; NEVER used for
    # the real dial, which reads .command/.args/.url/.env/.headers directly --
    def display_name(self) -> str:
        return _sanitize_for_terminal(self.name)

    def display_source(self) -> str:
        return _sanitize_for_terminal(self.source)

    def display_command(self) -> str:
        return _sanitize_for_terminal(self.command) if self.command else self.command

    def display_args(self) -> list[str]:
        return _display_args(self.args)

    def display_url(self) -> str:
        return _display_url(self.url) if self.url else self.url


def dedupe_servers(candidates: list[tuple[ServerConfig, str]]) -> tuple[list[ServerConfig], list[str]]:
    """First-declared-wins dedup by name, over an ordered list of
    ``(server, source_label)`` pairs.

    A later candidate whose name matches an earlier one from a DIFFERENT
    source produces a warning naming both (never silent shadowing) and is
    dropped; the same name repeated from the SAME source label is dropped
    silently (e.g. a config file that legitimately lists a server under two
    differently-shaped sections). Order of ``candidates`` is significant --
    callers build it in the precedence order they want "first" to mean."""
    servers: list[ServerConfig] = []
    warnings: list[str] = []
    seen: dict[str, str] = {}  # name -> the source label that won it

    for server, label in candidates:
        existing_source = seen.get(server.name)
        if existing_source is not None:
            if existing_source != label:
                warnings.append(
                    f"name collision: {server.name!r} from {label!r} is SHADOWED BY the "
                    f"same-named server already declared in {existing_source!r} (kept, "
                    "first-declared wins) -- if these are meant to be different servers, "
                    "rename one"
                )
            continue
        seen[server.name] = label
        servers.append(server)

    return servers, warnings


# =============================================================================
# Dial -- initialize + tools/list only, never tools/call.
# =============================================================================


def _try_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _dial_stdio(server: ServerConfig, timeout: float) -> tuple[str, list[str], str | None]:
    """Returns (status, tool_names, warning). ``status`` is "available",
    "restricted" (launched but the protocol/handshake failed), or
    "unverified" (couldn't even launch it, or it never responded).

    The spawned process inherits the FULL ambient environment
    (``os.environ``), not just ``server.env`` -- most real stdio servers
    (an ``npx``/``uvx``-launched process especially) need ordinary things
    like ``PATH``/``HOME`` to even start, so this can't be narrowed to
    ``server.env`` alone without breaking real dialing. That means the
    exfiltration surface the exfil-guard below has to cover is the WHOLE
    merged environment the child actually received, not just the
    declared portion -- an operator's or CI job's ambient secrets (cloud/CI
    credentials are the common case) are just as reachable by a malicious
    or compromised server as anything explicitly configured for it."""
    full_env = {**os.environ, **server.env}
    try:
        proc = subprocess.Popen(
            [server.command, *server.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=full_env,  # real values, in-memory only
        )
    except (OSError, ValueError) as exc:
        return "unverified", [], f"{server.name}: could not launch ({exc})"

    q: queue.Queue[str | None] = queue.Queue()

    def _pump() -> None:
        try:
            for line in iter(proc.stdout.readline, ""):
                if line.strip():
                    q.put(line)
        except Exception:  # noqa: BLE001, S110 -- reader thread must never raise
            pass
        q.put(None)

    threading.Thread(target=_pump, daemon=True).start()

    def _send(msg: dict) -> None:
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def _recv(want_id: int, deadline: float) -> dict:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no response before the deadline")
            try:
                line = q.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError("no response before the deadline") from exc
            if line is None:
                raise ConnectionError("the server closed its stdout")
            msg = _try_json(line)
            if isinstance(msg, dict) and msg.get("id") == want_id:
                return msg

    raw_tools: list[Any] = []
    status, warning = "available", None
    try:
        deadline = time.monotonic() + timeout
        _send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "forgebench-mcp-discovery", "version": PROBE_VERSION},
                },
            }
        )
        _recv(1, deadline)
        _send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        cursor, next_id = None, 2
        for _ in range(_MAX_TOOL_PAGES):
            params = {"cursor": cursor} if cursor else {}
            _send({"jsonrpc": "2.0", "id": next_id, "method": "tools/list", "params": params})
            resp = _recv(next_id, deadline)
            next_id += 1
            if resp.get("error"):
                raise RuntimeError(str(resp["error"]))
            result = resp.get("result") or {}
            raw_tools.extend(result.get("tools") or [])
            cursor = result.get("nextCursor")
            if not cursor:
                break
    except TimeoutError as exc:
        status, warning = "unverified", f"{server.name}: {exc}"
    except Exception as exc:  # noqa: BLE001 -- one bad server must not abort the run
        status, warning = "restricted", f"{server.name}: {exc}"
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:  # noqa: BLE001 -- cleanup must never raise past a dial attempt
            try:
                proc.kill()
            except Exception:  # noqa: BLE001, S110 -- best-effort; nothing left to do if even kill fails
                pass

    # The FULL environment the child actually received (ambient + declared),
    # not server.known_secret_values() -- see the docstring above for why.
    # Excludes _COMMON_BENIGN_ENV_NAMES, though: unfiltered, an ordinary env
    # var present on nearly every machine (TERM_PROGRAM, LANG, SHELL, ...)
    # whose value happens to be >=6 chars and a substring of some unrelated,
    # legitimate tool name (e.g. TERM_PROGRAM=vscode inside a tool literally
    # named "vscode_open_file") trips the exfiltration alarm on nothing.
    # A DENYLIST of known-benign names, not an allowlist of sensitive-looking
    # ones -- an allowlist would reopen exactly the gap
    # test_bug_f_end_to_end_via_real_stdio_dial_never_leaks_the_secret exists
    # to close: real secrets routinely sit in a var whose NAME gives no hint
    # at all (that test uses "LEAK_ME" on purpose), so detection has to stay
    # name-agnostic for everything except this small, well-known benign set.
    exfil_check_values = [
        v
        for k, v in full_env.items()
        if isinstance(v, str)
        and k not in _COMMON_BENIGN_ENV_NAMES
        and not k.startswith(_COMMON_BENIGN_ENV_PREFIXES)
    ]
    tools, exfil_warning = _sanitize_dialed_tool_names(raw_tools, exfil_check_values, server.name)
    return status, tools, warning or exfil_warning


def _http_parse_body(raw: str, content_type: str, want_id: Any) -> dict:
    if "text/event-stream" in content_type:
        current: list[str] = []
        for raw_line in raw.splitlines():
            line = raw_line.rstrip("\r")
            if line.startswith("data:"):
                current.append(line[5:].lstrip())
            elif not line and current:
                msg = _try_json("\n".join(current))
                current = []
                if isinstance(msg, dict) and msg.get("id") == want_id:
                    return msg
        if current:
            msg = _try_json("\n".join(current))
            if isinstance(msg, dict) and msg.get("id") == want_id:
                return msg
        raise RuntimeError("no JSON-RPC response frame in the SSE body")
    msg = _try_json(raw)
    if not isinstance(msg, dict):
        # Not TypeError: this propagates through _dial_http's own
        # (ConnectionError, RuntimeError, OSError) catch, which a bare
        # TypeError deliberately is not a member of -- letting a malformed
        # body crash the whole dial loop would be exactly the "one bad
        # server aborts everything" failure mode this module exists to avoid.
        raise RuntimeError(f"non-object JSON-RPC body: {raw[:200]!r}")  # noqa: TRY004
    return msg


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Same-origin credential-redirect guard (Bug J). The stdlib default
    opener's own ``HTTPRedirectHandler`` auto-follows 301/302/303/307/308
    and blindly re-sends every original request header -- including
    ``Authorization`` and any other operator-configured header -- to
    wherever the redirect points, even a completely different origin. A
    browser's ``fetch()`` strips credential-bearing headers on a
    cross-origin redirect; this does the same, treating every header the
    operator actually configured for THIS server (``server.headers`` --
    could be ``Authorization``, an API-key header, anything) as
    potentially sensitive, since guessing which one carries the real
    credential is exactly the kind of guess this codebase's redaction
    logic elsewhere (C1/C2/H/N) already refuses to make."""

    def __init__(self, sensitive_header_names: set[str]) -> None:
        super().__init__()
        self._sensitive = {h.lower() for h in sensitive_header_names}

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None or not self._sensitive:
            return new_req
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.scheme, old.hostname, old.port) != (new.scheme, new.hostname, new.port):
            for header_name in list(new_req.headers):
                if header_name.lower() in self._sensitive:
                    del new_req.headers[header_name]
        return new_req


def _dial_http(server: ServerConfig, timeout: float) -> tuple[str, list[str], str | None]:
    """Streamable HTTP (2025-03-26) — wire logic ported from
    apps/control-plane/app/mcp/client.py's LangfuseMCPClient (httpx there,
    stdlib urllib.request here — same headers, same SSE-or-JSON body
    handling, same cursor pagination)."""
    session: dict[str, Any] = {"id": 0, "session_id": None}
    # A per-dial opener, NOT the module-level default one -- see Bug J:
    # the default opener's redirect handling has no same-origin check at
    # all. Built once per server so `server.headers`' names (the operator's
    # own credential header names) are known to the redirect guard.
    opener = urllib.request.build_opener(_SameOriginRedirectHandler(set(server.headers)))

    def _headers() -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **server.headers,  # real values, in-memory only
        }
        if session["session_id"]:
            h["Mcp-Session-Id"] = session["session_id"]
        return h

    def _call(method: str, params: dict | None) -> dict:
        session["id"] += 1
        rpc_id = session["id"]
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            payload["params"] = params
        req = urllib.request.Request(
            server.url, data=json.dumps(payload).encode("utf-8"), headers=_headers(), method="POST"
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    session["session_id"] = sid
                content_type = (resp.headers.get("Content-Type") or "").lower()
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise PermissionError(f"{method}: unauthorized ({exc.code})") from exc
            raise RuntimeError(f"{method}: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(f"{method}: {exc.reason}") from exc

        msg = _http_parse_body(raw, content_type, rpc_id)
        if msg.get("error"):
            err = msg["error"] or {}
            raise RuntimeError(f"{method}: JSON-RPC error {err.get('code')}: {err.get('message')}")
        return msg.get("result") or {}

    def _notify(method: str) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        req = urllib.request.Request(
            server.url, data=json.dumps(payload).encode("utf-8"), headers=_headers(), method="POST"
        )
        try:
            opener.open(req, timeout=timeout).close()
        except Exception:  # noqa: BLE001, S110 -- advisory only, same as the reference client
            pass

    raw_tools: list[Any] = []
    try:
        _call(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "forgebench-mcp-discovery", "version": PROBE_VERSION},
            },
        )
        _notify("notifications/initialized")
        cursor = None
        for _ in range(_MAX_TOOL_PAGES):
            params = {"cursor": cursor} if cursor else {}
            result = _call("tools/list", params)
            raw_tools.extend(result.get("tools") or [])
            cursor = result.get("nextCursor")
            if not cursor:
                break
        tools, exfil_warning = _sanitize_dialed_tool_names(raw_tools, server.known_secret_values(), server.name)
        return "available", tools, exfil_warning
    except (PermissionError, TimeoutError) as exc:
        # PermissionError: no credentials for an auth-gated server, matches
        # stdio's "couldn't even get in" bucket. TimeoutError: urlopen's
        # socket timeout surfaces as this (directly, or as URLError's
        # .reason) -- "never got a response" is the same "unverified" as a
        # non-responding stdio process, not a confirmed protocol failure.
        return "unverified", [], f"{server.name}: {exc}"
    except (ConnectionError, RuntimeError, OSError) as exc:
        return "restricted", [], f"{server.name}: {exc}"


# =============================================================================
# Consent-listing / output rendering -- shared by every discovery source's CLI
# =============================================================================


def _print_consent_listing(servers: list[ServerConfig]) -> None:
    """Every field printed here came from an untrusted config file or
    source-code declaration, so every field goes through its
    ``display_*``/``*_keys()`` accessor (terminal-injection-sanitized, and
    for args/url, name-hinted-secret-redacted) -- never the raw
    ``.name``/``.command``/``.args``/``.url``, which stay unredacted for the
    real dial."""
    stdio = [s for s in servers if s.transport == "stdio"]
    http = [s for s in servers if s.transport == "http"]

    if stdio:
        print(f"Found {len(stdio)} local (stdio) MCP server(s) that would be LAUNCHED to list their tools:")
        for s in stdio:
            env_note = ", ".join(s.env_keys()) or "(none)"
            args_display = " ".join(s.display_args())
            print(
                f"  - {s.display_name()} [{s.display_source()}]: "
                f"{s.display_command()} {args_display}  (env vars: {env_note})"
            )
    if http:
        print(f"Found {len(http)} remote MCP server(s) that would be CONTACTED to list their tools:")
        for s in http:
            header_note = ", ".join(s.header_keys()) or "(none)"
            print(f"  - {s.display_name()} [{s.display_source()}]: {s.display_url()}  (headers: {header_note})")
    if not stdio and not http:
        print("No MCP servers found.")
        return

    print(
        "\nRelay the above to the user for a go/no-go -- per-server for the "
        "local ones (each spawns a configured command), one combined "
        "go/no-go for the remote ones (no process spawned, but still "
        "real network egress to a third-party endpoint) -- then re-run "
        "with --dial [--skip NAME ...]."
    )


def _discovered_to_dict(servers: list[ServerConfig]) -> dict:
    """Same display-only discipline as _print_consent_listing -- this is
    what ``--discover-only --out`` writes to disk, so it gets the same
    sanitized/redacted views, never the raw fields."""
    return {
        "stdio_servers": [
            {
                "name": s.display_name(),
                "source": s.display_source(),
                "command": s.display_command(),
                "args": s.display_args(),
                "env_keys": s.env_keys(),
            }
            for s in servers
            if s.transport == "stdio"
        ],
        "http_servers": [
            {
                "name": s.display_name(),
                "source": s.display_source(),
                "url": s.display_url(),
                "header_keys": s.header_keys(),
            }
            for s in servers
            if s.transport == "http"
        ],
    }


def _dial_all(servers: list[ServerConfig], skip: set[str], timeout: float) -> dict:
    mcp_servers: list[str] = []
    mcp_tools: list[dict] = []
    warnings: list[str] = []

    for server in servers:
        mcp_servers.append(server.name)
        if server.name in skip:
            warnings.append(f"{server.name}: skipped by user request, not dialed")
            continue
        dial = _dial_stdio if server.transport == "stdio" else _dial_http
        status, tools, warning = dial(server, timeout)
        if warning:
            warnings.append(warning)
        if status == "available":
            for tool_name in tools:
                mcp_tools.append({"server": server.name, "tool": tool_name})

    return {"mcpServers": mcp_servers, "mcpTools": mcp_tools, "_warnings": warnings}
