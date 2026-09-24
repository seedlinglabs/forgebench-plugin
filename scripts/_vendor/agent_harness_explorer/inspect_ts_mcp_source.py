#!/usr/bin/env python3
"""Static analysis for MCP servers and agent declarations in a repo's
TypeScript/JavaScript source (forgebench addition, not upstream) -- the
TS/JS sibling of ``inspect_mcp_source.py``, needed because that script's
``ast``-based approach only ever sees Python: Mastra and the Vercel AI SDK
are structurally invisible to it.

    python inspect_ts_mcp_source.py --discover-only [--root DIR] [--out discovered_source.json]
    python inspect_ts_mcp_source.py --dial [--skip NAME ...] [--merge-into observations.json] --out observations.json

Same two-phase shape, same output schema, and the same "never guess, never
mark unsupported for a partial probe" discipline as ``inspect_mcp_source.py``
(see ``references/safety-boundaries.md``) -- only the parsing layer differs.

Needs the optional ``typescript`` extra (``pip install
"forgebench-session-reviewer[typescript]"``), which pulls in ``tree-sitter``
+ ``tree-sitter-typescript``. This is the ONE deliberate exception to this
package's otherwise stdlib-only, zero-dependency design (see
``pyproject.toml``'s own comment on why that principle exists) -- kept
strictly opt-in so the core install is completely unaffected for anyone who
never touches a TypeScript/JavaScript repo. ``tree-sitter`` was chosen over
two other real candidates, both ruled out by research: shelling out to
Node's own TypeScript compiler (no precedent anywhere in this codebase,
can't be reliably assumed present -- CI containers, minimal images,
non-npm toolchains -- and a much bigger new trust surface than a pip
package), and every pure-Python JS/TS parser (``esprima``, ``pyjsparser``,
``calmjs.parse`` -- all either JS-only with zero TypeScript support, or
unmaintained since 2018-2019). ``tree-sitter``/``tree-sitter-typescript``
ship prebuilt wheels on every common platform (no C compiler, no Node.js
ever invoked) and are the same approach production static analyzers like
Semgrep use for TypeScript.

Phase 1 (``--discover-only``) walks the repo's own ``.ts``/``.tsx``/``.js``/
``.jsx`` files (never a vendored dependency tree -- see
``_DEFAULT_EXCLUDE_DIRS``) and parses each with tree-sitter, which -- like
Python's own ``ast`` module -- never executes anything. It looks for a known
table of MCP-client/agent constructor calls (Mastra, the Vercel AI SDK -- see
``KNOWN_MCP_SYMBOLS``/``KNOWN_AGENT_SYMBOLS``). Only LITERAL argument values
are ever extracted, plus one level of same-scope, unconditional
variable-alias resolution (see ``_resolve``): anything computed at runtime
(a function call, a template literal with interpolation, a value only
assigned inside an ``if``/``for``/``while``/``try`` block, a dynamic
function passed where a plain object is expected) is reported as unresolved
rather than guessed.

Phase 2 (``--dial``) reuses the EXACT same dial implementation
``inspect_mcp_source.py``/``inspect_mcp_configs.py`` do (all three import it
from ``mcp_discovery_common.py``) -- a server's real address, once found, is
dialed identically regardless of which language declared it.

Not included, on purpose (see this module's own "don't guess" stance):
CommonJS ``require()`` resolution, dynamic ``import()``, cross-file
re-export following, tsconfig path-alias resolution, a dynamic
``tools: (ctx) => {...}`` function (Mastra) -- reported unresolved, not
guessed -- and anything agent-relevant expressed purely inside JSX markup.
A third TS/JS framework is a one-line table append, exactly like the Python
scanner's own scalability claim.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_discovery_common as common  # noqa: E402
import inspect_mcp_source as _py_source  # noqa: E402 -- reuses its merge_dial_results, not a duplicate

try:
    import tree_sitter as ts
    import tree_sitter_typescript as tsts

    _TS_LANGUAGE = ts.Language(tsts.language_typescript())
    _TSX_LANGUAGE = ts.Language(tsts.language_tsx())
    TREE_SITTER_AVAILABLE = True
except ImportError:
    ts = None  # type: ignore[assignment]
    tsts = None  # type: ignore[assignment]
    _TS_LANGUAGE = None
    _TSX_LANGUAGE = None
    TREE_SITTER_AVAILABLE = False

PROBE_ID = "mcp-typescript-source-scan"
PROBE_VERSION = common.PROBE_VERSION

_MAX_SOURCE_FILES = 5000
_DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        ".next",
        ".turbo",
        "coverage",
        ".venv",
        "venv",
        "__pycache__",
        "site-packages",
    }
    # Same non-production declarations and skill bundles the Python scanner
    # skips -- see inspect_mcp_source._DEFAULT_EXCLUDE_DIRS for why.
    | {"tests", "test", "examples", "fixtures", "docs", ".claude/skills", ".agents/skills"}
)
# .tsx/.jsx use the SEPARATE tsx grammar (tree-sitter-typescript ships two
# grammars specifically because JSX markup is syntactically ambiguous with
# TS's own `<T>` type-assertion syntax) -- .ts/.js use the plain typescript
# grammar, which is a superset of JS minus that one ambiguity.
_EXTENSION_LANGUAGE = {
    ".ts": "typescript",
    ".js": "typescript",
    ".tsx": "tsx",
    ".jsx": "tsx",
}


# =============================================================================
# The framework catalog -- same flat-table discipline as inspect_mcp_source.py:
# a new framework using an ALREADY-KNOWN shape is a one-line append; a
# genuinely new shape gets one new small handler in SHAPE_HANDLERS.
# =============================================================================

# (module the symbol is imported FROM, imported/exported name, shape id,
#  name-holding kwarg or None, framework label)
KNOWN_MCP_SYMBOLS: tuple[tuple[str, str, str, str | None, str], ...] = (
    # Mastra: new MCPClient({ servers: { name: {command,args,env} | {url,...} } } )
    # -- servers is a plain object literal, not a nested constructor call, so
    # (unlike several Python wrapper shapes) there's nothing to defer to:
    # this shape extracts every server directly off the SAME call's own
    # `servers` field.
    ("@mastra/mcp", "MCPClient", "keyed_object_kwarg:servers", None, "mastra"),
    # Vercel AI SDK: createMCPClient({ transport: { type, url, ... } | ... })
    # or a stdio-shaped config -- confirmed via source: current stable name,
    # `experimental_createMCPClient` is a deprecated alias for the same
    # function, both map to the same row.
    ("@ai-sdk/mcp", "createMCPClient", "mcp_client_config_arg", None, "vercel-ai-sdk"),
    ("@ai-sdk/mcp", "experimental_createMCPClient", "mcp_client_config_arg", None, "vercel-ai-sdk"),
    # The official MCP SDK's own transport class -- confirmed via a real
    # repro: `createMCPClient({transport: stdioTransport})` where
    # `stdioTransport = new StdioClientTransport({command, args, env})` is
    # real, idiomatic code (assign-first, then reference), and every value
    # in it is fully literal -- this was a genuinely missing shape, not a
    # depth limit. `command`/`args`/`env` sit directly on THIS class's own
    # constructor argument, same "stdio_or_http_kwargs" shape any other
    # single-object-argument transport class uses. This class isn't
    # exclusive to any one framework -- "vercel-ai-sdk" here is a
    # best-effort attribution, not a certainty, same as the bare
    # `mcp.StdioServerParameters` row in inspect_mcp_source.py: any repo
    # importing this exact class is still a real MCP declaration worth
    # surfacing regardless of which higher-level framework it's paired with.
    ("@modelcontextprotocol/sdk/client/stdio.js", "StdioClientTransport", "stdio_or_http_kwargs", None, "vercel-ai-sdk"),
    # Same class-instance shape as StdioClientTransport above, just the SDK's
    # other two official transports -- same "not exclusive to one framework,
    # still a real MCP declaration" reasoning applies.
    ("@modelcontextprotocol/sdk/client/streamableHttp.js", "StreamableHTTPClientTransport", "stdio_or_http_kwargs", None, "vercel-ai-sdk"),
    ("@modelcontextprotocol/sdk/client/sse.js", "SSEClientTransport", "stdio_or_http_kwargs", None, "vercel-ai-sdk"),
)

# (module, exported name, tools-holding field name, name-holding field name
#  or None, framework label)
KNOWN_AGENT_SYMBOLS: tuple[tuple[str, str, str, str | None, str], ...] = (
    ("@mastra/core/agent", "Agent", "tools", "name", "mastra"),
    # Vercel AI SDK: `ToolLoopAgent` is the current, stable class;
    # `Experimental_Agent` is a confirmed `@deprecated` alias for the exact
    # same class -- both map to the same row. Neither has a name field;
    # falls back to the assigned variable, same convention used throughout
    # the Python scanner for identity-less constructs.
    ("ai", "ToolLoopAgent", "tools", None, "vercel-ai-sdk"),
    ("ai", "Experimental_Agent", "tools", None, "vercel-ai-sdk"),
    # generateText/streamText are plain FUNCTION calls, not classes -- an
    # inline, anonymous "agent" declaration, same treatment Claude Agent
    # SDK's ClaudeAgentOptions gets in the Python scanner (no identity
    # concept on the construct itself).
    ("ai", "generateText", "tools", None, "vercel-ai-sdk"),
    ("ai", "streamText", "tools", None, "vercel-ai-sdk"),
)

# `await <name>.<method>()` -- a passthrough call on an ALREADY-bound
# tool-set variable, forwarding its keys under a new name. Exactly the
# mechanism inspect_mcp_source.py's own _PASSTHROUGH_TOOL_METHOD_NAMES is,
# just enumerated per framework here since a bare method name has no
# import provenance of its own to verify in either language.
_PASSTHROUGH_TOOL_METHOD_NAMES = frozenset({"listTools", "listToolsets", "tools"})


@dataclass
class CallSiteRecord:
    framework: str
    shape: str
    file: str
    line: int
    transport: str
    resolved: dict[str, Any] = field(default_factory=dict)
    unresolved_fields: list[str] = field(default_factory=list)
    unresolved_reason: dict[str, str] = field(default_factory=dict)
    explicit_name: str | None = None
    index_in_call: int = 0

    def key(self) -> tuple[str, int, int]:
        return (self.file, self.line, self.index_in_call)

    def is_dial_eligible(self) -> bool:
        required = "command" if self.transport == "stdio" else "url"
        if not self.resolved.get(required):
            return False
        return not [f for f in self.unresolved_fields if f != "env"]


@dataclass
class AgentRecord:
    name: str
    framework: str
    file: str
    line: int


# =============================================================================
# Import resolution -- ES module named/default/namespace imports only (see
# module docstring for what's deliberately out of scope: require(),
# dynamic import(), re-exports, tsconfig path aliases).
# =============================================================================


class _ImportMap:
    def __init__(self) -> None:
        # local name -> (module, exported_name)
        self.named: dict[str, tuple[str, str]] = {}
        # local name -> module (the module's own default export)
        self.default: dict[str, str] = {}
        # local alias -> module (import * as alias)
        self.namespace: dict[str, str] = {}

    @classmethod
    def build(cls, root_node: Any) -> "_ImportMap":
        m = cls()
        for node in _walk_all(root_node):
            if node.type != "import_statement":
                continue
            source_node = node.child_by_field_name("source")
            module = _string_value(source_node) if source_node else None
            if module is None:
                continue  # a computed/templated module specifier -- never guessed
            clause = next((c for c in node.children if c.type == "import_clause"), None)
            if clause is None:
                continue  # a bare `import 'x';` side-effect import -- nothing to bind
            for child in clause.children:
                if child.type == "identifier":
                    m.default[_text(child)] = module
                elif child.type == "namespace_import":
                    alias = child.child_by_field_name is not None and next(
                        (c for c in child.children if c.type == "identifier"), None
                    )
                    if alias is not None:
                        m.namespace[_text(alias)] = module
                elif child.type == "named_imports":
                    for spec in child.children:
                        if spec.type != "import_specifier":
                            continue
                        name_node = spec.child_by_field_name("name")
                        alias_node = spec.child_by_field_name("alias")
                        if name_node is None:
                            continue
                        local = _text(alias_node) if alias_node is not None else _text(name_node)
                        m.named[local] = (module, _text(name_node))
        return m

    def resolve_call_origin(self, func_node: Any) -> tuple[str, str] | None:
        """A bare identifier (``Agent(...)``/``new Agent(...)``) resolves via
        a named or default import; ``ns.Symbol(...)`` resolves via a
        namespace import -- mirrors ``_ImportMap.resolve_call_symbol`` in
        inspect_mcp_source.py exactly (never a bare name/string match)."""
        if func_node.type == "identifier":
            name = _text(func_node)
            if name in self.named:
                return self.named[name]
            if name in self.default:
                return (self.default[name], "default")
            return None
        if func_node.type == "member_expression":
            obj = func_node.child_by_field_name("object")
            prop = func_node.child_by_field_name("property")
            if obj is not None and obj.type == "identifier" and prop is not None:
                ns_module = self.namespace.get(_text(obj))
                if ns_module is not None:
                    return (ns_module, _text(prop))
        return None


def _walk_all(node: Any):
    yield node
    for child in node.children:
        yield from _walk_all(child)


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


# tree-sitter's JS/TS grammar represents `\n`, `\\`, `\"`, `\uXXXX`, etc. as
# their own `escape_sequence` node, interleaved with `string_fragment`
# siblings -- NOT part of any fragment's text. A one-char escape maps
# directly; the rest are decoded by prefix below.
_SIMPLE_ESCAPES = {
    "\\n": "\n", "\\t": "\t", "\\r": "\r", "\\b": "\b", "\\f": "\f",
    "\\v": "\v", "\\0": "\0", "\\\\": "\\", "\\'": "'", '\\"': '"', "\\`": "`",
}


def _decode_escape_sequence(text: str) -> str | None:
    """One `escape_sequence` node's raw text (e.g. ``\\n``, ``\\\\``,
    ``\\u00e9``, ``\\x41``, ``\\u{1f600}``) to the single character it
    represents. A line-continuation escape (backslash immediately followed
    by a newline) contributes nothing to the string's value, so it decodes
    to "". Any other/unrecognised form returns None -- never a guess, same
    discipline as every other resolution helper in this scanner."""
    if text in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[text]
    if text in ("\\\n", "\\\r\n", "\\\r"):
        return ""
    if text.startswith("\\u{") and text.endswith("}"):
        try:
            return chr(int(text[3:-1], 16))
        except ValueError:
            return None
    if text.startswith("\\u") and len(text) == 6:
        try:
            return chr(int(text[2:], 16))
        except ValueError:
            return None
    if text.startswith("\\x") and len(text) == 4:
        try:
            return chr(int(text[2:], 16))
        except ValueError:
            return None
    # Per the ECMAScript spec, ANY other single-character escape (`\d`,
    # `\s`, `\$`, `\ ` ...) decodes to that literal character -- the
    # backslash is simply dropped, no special meaning. Common in a config
    # string embedding a regex, e.g. `"--pattern=\d+"`. A digit is
    # excluded and left unresolved: `\1`..`\7` are legacy octal escapes,
    # disallowed in strict-mode/module code and ambiguous to decode
    # correctly here, so failing closed (never guessing) is the safe call.
    if len(text) == 2 and text[0] == "\\" and not text[1].isdigit():
        return text[1]
    return None


def _string_value(node: Any) -> str | None:
    """A `string` node's real text content -- its `string_fragment`
    children verbatim, its `escape_sequence` children decoded to the
    character they represent, both in source order. A template literal WITH
    interpolation, any other node type, or an escape this scanner doesn't
    recognise all return None -- never guessed. Without decoding escapes,
    a value like `"C:\\\\tools\\\\server.exe"` silently lost every
    backslash (and `"--config={\\"db\\":1}"` every embedded quote) while
    still being reported as fully resolved -- exactly the mangled value a
    human would approve in the consent listing and `--dial` would execute."""
    if node is None:
        return None
    if node.type == "template_string":
        return None  # always treated as computed, even with zero substitutions -- v1 simplification
    if node.type != "string":
        return None
    parts: list[str] = []
    for child in node.children:
        if child.type == "string_fragment":
            parts.append(_text(child))
        elif child.type == "escape_sequence":
            decoded = _decode_escape_sequence(_text(child))
            if decoded is None:
                return None
            parts.append(decoded)
        elif getattr(child, "is_named", False):
            return None  # unexpected named child -- fail closed, don't guess
    return "".join(parts)


def _literal_eval(node: Any) -> tuple[Any, bool]:
    """(value, ok) for a fully-literal node -- string/number/boolean/null/
    array-of-literals/object-of-literals. Mirrors Python's
    ``ast.literal_eval`` scope exactly: a spread (`...x`) or computed key
    anywhere inside an object makes the WHOLE object unresolvable, same as
    a `**spread` does for a Python dict literal."""
    if node is None:
        return None, False
    if node.type == "string":
        value = _string_value(node)
        return (value, True) if value is not None else (None, False)
    if node.type == "number":
        text = _text(node)
        try:
            return (float(text) if "." in text else int(text)), True
        except ValueError:
            return None, False
    if node.type == "true":
        return True, True
    if node.type == "false":
        return False, True
    if node.type == "null":
        return None, True
    if node.type == "array":
        values = []
        for child in node.named_children:
            value, ok = _literal_eval(child)
            if not ok:
                return None, False
            values.append(value)
        return values, True
    if node.type == "object":
        result: dict[str, Any] = {}
        for pair in node.named_children:
            if pair.type != "pair":
                return None, False  # a spread_element or shorthand property -- not a plain literal
            key_node = pair.child_by_field_name("key")
            value_node = pair.child_by_field_name("value")
            if key_node is None or value_node is None:
                return None, False
            key = _string_value(key_node) if key_node.type == "string" else (
                _text(key_node) if key_node.type == "property_identifier" else None
            )
            if key is None:
                return None, False
            value, ok = _literal_eval(value_node)
            if not ok:
                return None, False
            result[key] = value
        return result, True
    return None, False


# A shorthand object property (`{ model }`, meaning `{ model: model }`) is a
# reference to a same-named variable, exactly like a bare `identifier` is --
# both are "identifier-like" for alias-resolution/unresolved-reason purposes.
_IDENTIFIER_LIKE = ("identifier", "shorthand_property_identifier")


def _unresolved_reason(node: Any) -> str:
    if node is None:
        return "not provided"
    kind = node.type
    if kind == "call_expression" or kind == "new_expression":
        return "computed by a function call, not a literal"
    if kind == "member_expression":
        return "an attribute access (e.g. process.env), not a literal"
    if kind == "template_string":
        return "a template literal, possibly with interpolation -- not a plain string literal"
    if kind in _IDENTIFIER_LIKE:
        return f"{_text(node)!r} is not assigned by a simple, unconditional literal in this scope"
    if kind in ("arrow_function", "function_expression", "function_declaration"):
        return "a dynamic function, not a literal value"
    if kind == "binary_expression":
        return "a computed expression (e.g. string concatenation), not a literal"
    return "not a literal value this scanner can resolve"


def _object_fields(node: Any) -> dict[str, Any] | None:
    """The AST nodes of an object literal's own fields (NOT recursively
    literal-evaluated) -- `{command: "npx", args: X}` -> {"command": &lt;string
    node&gt;, "args": &lt;X node&gt;}. None if `node` isn't a plain object literal at
    all (a spread makes it unresolvable, same as _dict_literal_fields in
    inspect_mcp_source.py).

    A SHORTHAND property (`{ model }`, meaning `{ model: model }`) is
    unambiguous -- unlike a spread, it never contributes an unknown set of
    keys -- so it resolves to a value node that's itself a reference to a
    same-named variable, exactly like an ordinary `identifier` value would
    be (see the ``shorthand_property_identifier`` branch in
    ``_unwrap_one_alias``/``_unresolved_reason``). Treating it as poison,
    the way this function originally did, meant a single `{ model, tools }`
    shorthand field silently invalidated resolution of every OTHER field in
    the same object -- confirmed as a real bug via a fixture using this
    exact, extremely common ES6+ shape."""
    if node is None or node.type != "object":
        return None
    fields: dict[str, Any] = {}
    for pair in node.named_children:
        if pair.type == "shorthand_property_identifier":
            fields[_text(pair)] = pair
            continue
        if pair.type != "pair":
            return None
        key_node = pair.child_by_field_name("key")
        value_node = pair.child_by_field_name("value")
        if key_node is None or value_node is None:
            return None
        if key_node.type == "string":
            key = _string_value(key_node)
        elif key_node.type == "property_identifier":
            key = _text(key_node)
        else:
            return None
        if key is None:
            return None
        fields[key] = value_node
    return fields


def _call_arguments_object(call_node: Any, scopes: list[dict]) -> Any | None:
    """The single object-literal argument of a call like
    ``new Agent({...})``/``generateText({...})`` -- resolves ONE alias hop
    if it was assigned to a variable first, same discipline as
    ``_resolve_dict_kwarg`` in inspect_mcp_source.py."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return None
    positional = [c for c in args_node.named_children]
    if not positional:
        return None
    return _unwrap_one_alias(positional[0], scopes)


def _unwrap_one_alias(node: Any, scopes: list[dict]) -> Any:
    if node is not None and node.type in _IDENTIFIER_LIKE:
        name = _text(node)
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
    return node


def _resolve(node: Any, scopes: list[dict]) -> tuple[Any, bool]:
    """One level of same-scope, unconditional alias resolution, THEN a
    literal-eval attempt -- mirrors inspect_mcp_source.py's own ``_resolve``
    exactly: an identifier resolves once against ``scopes`` if bound there,
    never chases a second hop."""
    value, ok = _literal_eval(node)
    if ok:
        return value, True
    unwrapped = _unwrap_one_alias(node, scopes)
    if unwrapped is not node:
        return _literal_eval(unwrapped)
    return None, False


# Statement types this scanner descends INTO looking for a conditional
# reassignment (never to resolve anything found there -- only to poison the
# outer name). Mirrors the Python scanner's own ast.If/For/While/Try/With
# set, JS/TS grammar's equivalents.
_CONDITIONAL_BLOCK_TYPES = frozenset({
    "if_statement", "for_statement", "for_in_statement", "while_statement",
    "do_statement", "try_statement", "switch_statement", "with_statement",
    "labeled_statement",
})


def _resolution_env(statements: list[Any]) -> dict[str, Any]:
    """Top-level `const X = <literal-ish expr>;` bindings in ONE scope,
    visible for one-hop alias resolution -- a name reassigned more than
    once at this SAME top level is excluded (never resolves to "whichever
    one happened to run"), same conditional-reassignment safety as the
    Python scanner's own ``_resolution_env``.

    That safety previously covered only a SECOND top-level `let`/`const`/
    plain assignment sharing this scope -- a reassignment written inside a
    NESTED if/for/while/try/switch block (``let url = PROD_URL; if (STAGE
    === "dev") { url = "http://localhost:1234" }``) was invisible: nothing
    here ever looked inside those blocks, so `url` resolved confidently to
    `PROD_URL` even though which value is actually in effect at any given
    call site depends on a branch this scanner does not evaluate -- exactly
    the imprecision the Python scanner's docstring (quoted above) already
    guards against, which this function's own docstring claimed to match
    without actually doing so. Any `identifier = ...` (plain or augmented)
    found anywhere inside one of ``_CONDITIONAL_BLOCK_TYPES`` now poisons
    that name the same way a second top-level binding does."""
    direct: dict[str, Any] = {}
    seen_twice: set[str] = set()
    for stmt in statements:
        if stmt.type in _CONDITIONAL_BLOCK_TYPES:
            for inner in _walk_all(stmt):
                if inner.type in ("assignment_expression", "augmented_assignment_expression"):
                    left = inner.child_by_field_name("left")
                    if left is not None and left.type == "identifier":
                        seen_twice.add(_text(left))
                elif inner.type == "variable_declarator":
                    name_node = inner.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        seen_twice.add(_text(name_node))
            continue
        if stmt.type != "lexical_declaration":
            continue
        for declarator in stmt.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value_node = declarator.child_by_field_name("value")
            if name_node is None or name_node.type != "identifier" or value_node is None:
                continue
            name = _text(name_node)
            if name in direct:
                seen_twice.add(name)
            direct[name] = value_node
    for name in seen_twice:
        direct.pop(name, None)
    return direct


# =============================================================================
# Shape handlers -- each takes (node, scopes) and returns a list of
# (server_name_or_None, transport, resolved_fields, unresolved_fields, reasons)
# =============================================================================


@dataclass
class _RawExtraction:
    explicit_name: str | None
    transport: str
    resolved: dict[str, Any]
    unresolved: list[str]
    reasons: dict[str, str]


def _extract_fields(field_nodes: dict[str, Any], names: tuple[str, ...], scopes: list[dict]):
    resolved: dict[str, Any] = {}
    unresolved: list[str] = []
    reasons: dict[str, str] = {}
    for name in names:
        node = field_nodes.get(name)
        if node is None:
            continue
        value, ok = _resolve(node, scopes)
        if ok:
            resolved[name] = value
        else:
            unresolved.append(name)
            reasons[name] = _unresolved_reason(node)
    return resolved, unresolved, reasons


def _entry_extraction(entry_fields: dict[str, Any], scopes: list[dict], server_name: str | None) -> _RawExtraction:
    is_http = "url" in entry_fields
    names = ("url", "headers") if is_http else ("command", "args", "env")
    resolved, unresolved, reasons = _extract_fields(entry_fields, names, scopes)
    return _RawExtraction(server_name, "http" if is_http else "stdio", resolved, unresolved, reasons)


def _extract_keyed_object_kwarg(call_node: Any, scopes: list[dict], kwarg_name: str) -> list[_RawExtraction]:
    """Mastra's ``new MCPClient({ servers: { name: {...}, ... } })`` -- the
    servers map is a plain object literal directly on the SAME call, so
    (unlike a nested constructor call) there's no double-report risk in
    extracting it right here."""
    call_args = _call_arguments_object(call_node, scopes)
    fields = _object_fields(call_args)
    if fields is None:
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "call argument was not a resolvable object literal"})]
    servers_node = fields.get(kwarg_name)
    servers = _object_fields(_unwrap_one_alias(servers_node, scopes)) if servers_node is not None else None
    if servers is None:
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": f"{kwarg_name}= was not a resolvable object literal"})]
    out: list[_RawExtraction] = []
    for server_name, entry_node in servers.items():
        # Deliberately NOT unwrapped here -- only the top-level `servers`
        # object gets one alias hop (above); a per-entry alias
        # (`fs: cfg` instead of an inline `fs: {...}`) is unsupported by
        # design, exactly matching inspect_mcp_source.py's own
        # `_extract_keyed_dict`, which never unwraps its own per-entry
        # value either. Two independent one-hop mechanisms (this one, and
        # `_extract_fields`'s own per-FIELD resolution inside an already-
        # inline entry) must never compose into a two-hop chain.
        entry_fields = _object_fields(entry_node)
        if entry_fields is None:
            out.append(
                _RawExtraction(
                    server_name, "stdio", {}, ["*"], {"*": f"{server_name!r}'s entry was not a resolvable object literal"}
                )
            )
            continue
        out.append(_entry_extraction(entry_fields, scopes, server_name))
    return out


def _extract_mcp_client_config_arg(
    call_node: Any, scopes: list[dict], import_map: "_ImportMap | None" = None
) -> list[_RawExtraction]:
    """Vercel AI SDK's ``createMCPClient({...})`` -- a flat config object
    (stdio: ``command``/``args``/``env``; http/sse: a nested ``transport:
    {url, ...}`` OR a direct ``url`` -- both forms seen in real code, so
    both are checked). ``transport`` can ALSO be a real transport class
    instance (``new StdioClientTransport({...})``), assigned to a variable
    first and referenced here (confirmed via a real repro) -- when it is,
    this returns NOTHING (deferred): that class has its OWN row and
    independently produces its own record via the generic recursive walk;
    extracting it again here would double-report the same server. The
    outer call's own tool-set binding still correctly inherits that
    record's key -- see ``_inherited_keys`` in ``scan_file``, the other
    half of this same mechanism.

    That deferral used to fire for ANY ``new`` expression or call, not just
    a CONFIRMED ``KNOWN_MCP_SYMBOLS`` transport class -- so ``transport:
    someCustomFactory()`` (or any transport constructor this scanner
    doesn't have a row for) silently produced NOTHING: no ``ServerConfig``,
    no ``unresolved_call_sites`` entry, no trace the declaration was ever
    there, unlike every other unparseable shape in this function, which
    reports ``["*"]`` unresolved. Only a call whose callee ``import_map``
    actually resolves to a ``KNOWN_MCP_SYMBOLS`` row is deferred now; any
    other call/constructor falls through to the honest unresolved case."""
    call_args = _call_arguments_object(call_node, scopes)
    fields = _object_fields(call_args)
    if fields is None:
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "call argument was not a resolvable object literal"})]
    if "command" in fields:
        return [_entry_extraction(fields, scopes, None)]
    transport_node = fields.get("transport")
    if transport_node is None:
        return [_RawExtraction(None, "http", {}, ["*"], {"*": "neither command= nor transport= was found"})]
    unwrapped_transport = _unwrap_one_alias(transport_node, scopes)
    if unwrapped_transport.type in ("new_expression", "call_expression"):
        func_node = unwrapped_transport.child_by_field_name("constructor") or unwrapped_transport.child_by_field_name(
            "function"
        )
        origin = (
            import_map.resolve_call_origin(func_node)
            if import_map is not None and func_node is not None
            else None
        )
        is_known_mcp_symbol = origin is not None and any(origin == (m, n) for m, n, *_ in KNOWN_MCP_SYMBOLS)
        if is_known_mcp_symbol:
            return []  # deferred -- the generic recursive walk independently records it
        return [
            _RawExtraction(
                None,
                "http",
                {},
                ["*"],
                {"*": "transport= is a call/constructor this scanner does not recognise as an MCP transport class"},
            )
        ]
    transport_fields = _object_fields(unwrapped_transport)
    if transport_fields is None:
        return [
            _RawExtraction(
                None, "http", {}, ["*"], {"*": "transport= was not a resolvable object literal, class instance, or bound alias"}
            )
        ]
    return [_entry_extraction(transport_fields, scopes, None)]


def _extract_stdio_or_http_kwargs(
    call_node: Any, scopes: list[dict], import_map: "_ImportMap | None" = None
) -> list[_RawExtraction]:
    """A class/function whose OWN single object-literal argument carries
    ``command``/``args``/``env`` (stdio) or ``url``/``headers`` (http)
    directly -- e.g. the official MCP SDK's ``StdioClientTransport``.
    Takes ``import_map`` only to match every ``SHAPE_HANDLERS`` entry's
    uniform calling convention; this shape never needs it."""
    fields = _object_fields(_call_arguments_object(call_node, scopes))
    if fields is None:
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "call argument was not a resolvable object literal"})]
    return [_entry_extraction(fields, scopes, None)]


SHAPE_HANDLERS: dict[str, Callable[[Any, list[dict], "_ImportMap | None"], list[_RawExtraction]]] = {
    "mcp_client_config_arg": _extract_mcp_client_config_arg,
    "stdio_or_http_kwargs": _extract_stdio_or_http_kwargs,
}
for _module, _name, _shape, _name_kwarg, _framework in KNOWN_MCP_SYMBOLS:
    if _shape.startswith("keyed_object_kwarg:"):
        _kwarg = _shape.split(":", 1)[1]
        SHAPE_HANDLERS[_shape] = (
            lambda kwarg: lambda node, scopes, import_map=None: _extract_keyed_object_kwarg(node, scopes, kwarg)
        )(_kwarg)


# =============================================================================
# Per-file scan
# =============================================================================


def _language_for(path: Path) -> Any | None:
    kind = _EXTENSION_LANGUAGE.get(path.suffix)
    if kind == "typescript":
        return _TS_LANGUAGE
    if kind == "tsx":
        return _TSX_LANGUAGE
    return None


def scan_file(path: Path, root: Path):
    """Returns (mcp_records, agents, agent_mcp_links_pending, agent_base_tools,
    agent_unresolved_tools, warnings) -- identical shape to
    inspect_mcp_source.py's own ``scan_file``."""
    warnings: list[str] = []
    empty: tuple = ([], [], [], [], [], warnings)
    language = _language_for(path)
    if language is None:
        return empty
    try:
        text = path.read_bytes()
    except OSError as exc:
        warnings.append(f"{path}: skipped (could not read: {exc})")
        return empty
    parser = ts.Parser(language)
    tree = parser.parse(text)
    if tree.root_node.has_error:
        warnings.append(f"{path}: skipped (syntax error -- not valid for its file extension)")
        return empty

    import_map = _ImportMap.build(tree.root_node)
    records: list[CallSiteRecord] = []
    agents: list[AgentRecord] = []
    agent_mcp_links_pending: list[dict] = []
    agent_base_tools: list[dict] = []
    agent_unresolved_tools: list[dict] = []
    tool_set_bindings: dict[str, list[tuple[str, int, int]]] = {}

    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_str = str(rel).replace(os.sep, "/")

    def _bind_tool_set(name: str, keys: list[tuple[str, int, int]]) -> None:
        if keys:
            tool_set_bindings.setdefault(name, []).extend(keys)

    def _inherited_keys(expr: Any, scopes: list[dict]) -> list[tuple[str, int, int]]:
        """``createMCPClient({transport: X})`` / ``new MCPClient({servers:
        {name: X}})`` where ``X`` (or one of a keyed-object's own entries)
        is a Name that's ALREADY a tool-set binding -- e.g. ``const t = new
        StdioClientTransport({...}); const client = await createMCPClient({
        transport: t});``. The relevant shape handlers deliberately produce
        NO new ``CallSiteRecord`` for a reference like this (to avoid
        double-reporting a nested call the generic recursive walk will also
        independently find) -- so the diff-based key capture in the
        ``lexical_declaration`` handler sees zero new records and would
        otherwise silently drop the link entirely. This is the other half
        of that design: the new alias must still inherit whatever the
        referenced binding already represents -- the exact TS-side
        counterpart of ``_inherited_adapter_keys`` in
        ``inspect_mcp_source.py``."""
        if expr.type not in ("call_expression", "new_expression"):
            return []
        func_node = expr.child_by_field_name("constructor") or expr.child_by_field_name("function")
        origin = import_map.resolve_call_origin(func_node) if func_node is not None else None
        if origin is None:
            return []
        shape = next((s for m, n, s, *_ in KNOWN_MCP_SYMBOLS if origin == (m, n)), None)
        if shape is None:
            return []
        fields = _object_fields(_call_arguments_object(expr, scopes)) or {}
        if shape == "mcp_client_config_arg":
            candidate = fields.get("transport") if "command" not in fields else None
            if candidate is not None and candidate.type in _IDENTIFIER_LIKE:
                return list(tool_set_bindings.get(_text(candidate), []))
            return []
        if shape.startswith("keyed_object_kwarg:"):
            servers_node = fields.get(shape.split(":", 1)[1])
            servers = _object_fields(_unwrap_one_alias(servers_node, scopes)) if servers_node is not None else None
            if servers is None:
                return []
            keys: list[tuple[str, int, int]] = []
            for server_name, entry_node in servers.items():
                if entry_node.type not in _IDENTIFIER_LIKE:
                    continue
                entry_keys = tool_set_bindings.get(_text(entry_node), [])
                keys.extend(entry_keys)
                # The inherited record was created at ITS OWN declaration
                # site (e.g. `const fsTransport = new
                # StdioClientTransport(...)`), with no way to know at that
                # point which map key it would later be assigned under --
                # so it fell back to a command/url-synthesized name. Now
                # that we DO know (`fs` here), backfill it retroactively,
                # matching the SAME "named by its map key" behavior an
                # inline entry (`fs: {command: ...}`) already gets for
                # free via `_entry_extraction`'s own `server_name` arg.
                # Only ever fills in a name that's still unset -- never
                # overwrites one a more specific source already provided.
                for record in records:
                    if record.key() in entry_keys and record.explicit_name is None:
                        record.explicit_name = server_name
            return keys
        return []

    def _record_tools_field(agent_name: str, agent_location: str, node: Any, line: int, scopes: list[dict]) -> None:
        if node is None:
            return
        # Covers BOTH `tools: tools` (an ordinary identifier value) and the
        # shorthand `{ tools }` (a shorthand_property_identifier, from
        # _object_fields) referencing the SAME kind of bound variable --
        # `new Agent({ id, name, tools })` after `const tools = await mcp.
        # listTools()` is real, common code, not just `tools: tools`.
        if node.type in _IDENTIFIER_LIKE and _text(node) not in tool_set_bindings:
            node = _unwrap_one_alias(node, scopes)
        if node.type in _IDENTIFIER_LIKE and _text(node) in tool_set_bindings:
            agent_mcp_links_pending.append(
                {"agent": agent_name, "agent_location": agent_location, "keys": tool_set_bindings[_text(node)]}
            )
            return
        fields = _object_fields(node)
        if fields is None:
            agent_unresolved_tools.append(
                {"agent": agent_name, "agent_location": agent_location, "file": rel_str, "line": line, "reason": _unresolved_reason(node)}
            )
            return
        for tool_name in fields:
            agent_base_tools.append({"agent": agent_name, "agent_location": agent_location, "tool": tool_name})

    def walk(node: Any, scopes: list[dict], assigned_to: str | None = None) -> None:
        if node.type in ("function_declaration", "arrow_function", "function_expression", "method_definition"):
            body = node.child_by_field_name("body")
            new_scopes = [*scopes, _resolution_env(body.named_children if body is not None else [])]
            for child in node.children:
                walk(child, new_scopes)
            return

        if node.type == "lexical_declaration":
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                name_node = declarator.child_by_field_name("name")
                value_node = declarator.child_by_field_name("value")
                if name_node is None or name_node.type != "identifier" or value_node is None:
                    for child in declarator.children:
                        walk(child, scopes)
                    continue
                target = _text(name_node)
                rhs = value_node.named_children[0] if value_node.type == "await_expression" and value_node.named_children else value_node

                if rhs.type == "call_expression":
                    func_node = rhs.child_by_field_name("function")
                    if func_node is not None and func_node.type == "member_expression":
                        obj = func_node.child_by_field_name("object")
                        prop = func_node.child_by_field_name("property")
                        if (
                            obj is not None
                            and obj.type == "identifier"
                            and prop is not None
                            and _text(obj) in tool_set_bindings
                            and _text(prop) in _PASSTHROUGH_TOOL_METHOD_NAMES
                        ):
                            _bind_tool_set(target, tool_set_bindings[_text(obj)])
                            continue

                before = len(records)
                walk(rhs, scopes, assigned_to=target)
                _bind_tool_set(target, [r.key() for r in records[before:]] + _inherited_keys(rhs, scopes))
            return

        if node.type in ("call_expression", "new_expression"):
            func_node = node.child_by_field_name("constructor") or node.child_by_field_name("function")
            origin = import_map.resolve_call_origin(func_node) if func_node is not None else None
            matched_mcp = False
            if origin is not None:
                for known_module, known_name, shape, name_field, framework in KNOWN_MCP_SYMBOLS:
                    if origin != (known_module, known_name):
                        continue
                    matched_mcp = True
                    for index, extraction in enumerate(SHAPE_HANDLERS[shape](node, scopes, import_map)):
                        records.append(
                            CallSiteRecord(
                                framework=framework,
                                shape=shape,
                                file=rel_str,
                                line=node.start_point[0] + 1,
                                transport=extraction.transport,
                                resolved=extraction.resolved,
                                unresolved_fields=extraction.unresolved,
                                unresolved_reason=extraction.reasons,
                                explicit_name=extraction.explicit_name,
                                index_in_call=index,
                            )
                        )
                    break
                if not matched_mcp:
                    for known_module, known_name, tools_field, name_field, framework in KNOWN_AGENT_SYMBOLS:
                        if origin != (known_module, known_name):
                            continue
                        call_args = _call_arguments_object(node, scopes)
                        fields = _object_fields(call_args) or {}
                        agent_name = None
                        if name_field is not None:
                            value, ok = _resolve(fields.get(name_field), scopes)
                            if ok and isinstance(value, str) and value:
                                agent_name = value
                        if agent_name is None:
                            agent_name = assigned_to or f"{rel_str}:{node.start_point[0] + 1}"
                        line = node.start_point[0] + 1
                        agents.append(AgentRecord(name=agent_name, framework=framework, file=rel_str, line=line))
                        _record_tools_field(agent_name, f"{rel_str}:{line}", fields.get(tools_field), line, scopes)
                        break
        for child in node.children:
            walk(child, scopes)

    walk(tree.root_node, [_resolution_env(tree.root_node.named_children)])
    return records, agents, agent_mcp_links_pending, agent_base_tools, agent_unresolved_tools, warnings


# =============================================================================
# File walk, name synthesis, output -- identical logic/shape to
# inspect_mcp_source.py's own (kept as near-duplicates rather than a shared
# module, since the two scanners' AST types are incompatible; the OUTPUT
# shape is what stays identical, which is what the rest of the pipeline
# actually depends on).
# =============================================================================


def iter_source_files(root: Path, exclude_dirs: set[str], max_files: int) -> tuple[list[Path], list[str]]:
    warnings: list[str] = []
    files: list[Path] = []
    truncated = False
    names, paths = _py_source.split_excludes(exclude_dirs)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        rel = Path(dirpath).relative_to(root).parts if Path(dirpath) != root else ()
        dirnames[:] = sorted(d for d in dirnames if not _py_source.is_excluded_dir((*rel, d), names, paths))
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.suffix not in _EXTENSION_LANGUAGE:
                continue
            try:
                if path.stat().st_size > common._MAX_CONFIG_BYTES:
                    warnings.append(f"{path}: skipped (larger than {common._MAX_CONFIG_BYTES} bytes)")
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= max_files:
                truncated = True
                break
        if truncated:
            break
    if truncated:
        warnings.append(_py_source.truncation_warning(max_files, "TS/JS"))
    return files, warnings


def discover_source(root: Path, exclude_dirs: set[str], max_files: int):
    files, warnings = iter_source_files(root, exclude_dirs, max_files)
    all_records: list[CallSiteRecord] = []
    all_agents: list[AgentRecord] = []
    all_links_pending: list[dict] = []
    all_base_tools: list[dict] = []
    all_unresolved_tools: list[dict] = []
    for path in files:
        records, agents, links_pending, base_tools, unresolved_tools, file_warnings = scan_file(path, root)
        all_records.extend(records)
        all_agents.extend(agents)
        all_links_pending.extend(links_pending)
        all_base_tools.extend(base_tools)
        all_unresolved_tools.extend(unresolved_tools)
        warnings.extend(file_warnings)
    return all_records, all_agents, all_links_pending, all_base_tools, all_unresolved_tools, warnings


def synthesize_name(record: CallSiteRecord) -> str:
    if record.explicit_name:
        return record.explicit_name
    if record.transport == "stdio":
        # Shared with inspect_mcp_source.py -- see
        # common.synthesize_stdio_server_name's own docstring for why this
        # must not be duplicated (a one-sided fix would make the two
        # scanners disagree on a server's identity, which matters because
        # merge_dial_results merges their output by name).
        name = common.synthesize_stdio_server_name(
            record.resolved.get("command"), record.resolved.get("args")
        )
        if name:
            return name
    else:
        import urllib.parse

        host = urllib.parse.urlsplit(str(record.resolved.get("url") or "")).hostname
        if host:
            return host
    return f"{record.file}:{record.line}"


def record_to_server_config(record: CallSiteRecord) -> common.ServerConfig:
    name = synthesize_name(record)
    naming_note = "" if record.explicit_name else f", name synthesized from {'command' if record.transport == 'stdio' else 'url'}"
    source = f"typescript-source:{record.framework} ({record.file}:{record.line}{naming_note})"
    if record.transport == "stdio":
        args = record.resolved.get("args") or []
        env = record.resolved.get("env") or {}
        return common.ServerConfig(
            name=name,
            source=source,
            transport="stdio",
            command=str(record.resolved["command"]),
            args=[str(a) for a in args] if isinstance(args, list) else [],
            env=env if isinstance(env, dict) else {},
        )
    headers = record.resolved.get("headers") or {}
    return common.ServerConfig(
        name=name,
        source=source,
        transport="http",
        url=str(record.resolved["url"]),
        headers=headers if isinstance(headers, dict) else {},
    )


def to_servers_and_unresolved(records: list[CallSiteRecord]):
    candidates: list[tuple[common.ServerConfig, str]] = []
    unresolved: list[CallSiteRecord] = []
    keys_to_server_name: dict[tuple[str, int, int], str] = {}
    for record in records:
        if record.is_dial_eligible():
            server = record_to_server_config(record)
            candidates.append((server, server.source))
            keys_to_server_name[record.key()] = server.name
        else:
            unresolved.append(record)
    servers, dedupe_warnings = common.dedupe_servers(candidates)
    return servers, unresolved, dedupe_warnings, keys_to_server_name


def resolve_agent_links(agent_mcp_links_pending: list[dict], keys_to_server_name: dict, agent_unresolved_tools: list[dict]):
    agent_mcp_servers: list[dict] = []
    for pending in agent_mcp_links_pending:
        names = sorted({keys_to_server_name[k] for k in pending["keys"] if k in keys_to_server_name})
        if names:
            for name in names:
                agent_mcp_servers.append({"agent": pending["agent"], "agent_location": pending["agent_location"], "server": name})
        else:
            key = pending["keys"][0] if pending["keys"] else ("", 0, 0)
            agent_unresolved_tools.append(
                {
                    "agent": pending["agent"],
                    "agent_location": pending["agent_location"],
                    "file": key[0],
                    "line": key[1],
                    "reason": "refers only to MCP server declaration(s) that could not be resolved to a "
                    "real, dial-eligible address",
                }
            )
    return agent_mcp_servers


def _redact_partial_resolution(record: CallSiteRecord) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "command" in record.resolved:
        out["command"] = common._sanitize_for_terminal(str(record.resolved["command"]))
    if "args" in record.resolved:
        args = record.resolved["args"]
        out["args"] = [common._sanitize_for_terminal(str(a)) for a in args] if isinstance(args, list) else []
    if "url" in record.resolved:
        out["url"] = common._sanitize_for_terminal(str(record.resolved["url"]))
    if "env" in record.resolved and isinstance(record.resolved["env"], dict):
        out["env_keys"] = sorted(record.resolved["env"].keys())
    if "headers" in record.resolved and isinstance(record.resolved["headers"], dict):
        out["header_keys"] = sorted(record.resolved["headers"].keys())
    return out


def _discovered_source_to_dict(servers, unresolved, agents, agent_mcp_servers, agent_base_tools, agent_unresolved_tools) -> dict:
    out = common._discovered_to_dict(servers)
    out["unresolved_call_sites"] = [
        {
            "framework": r.framework,
            "file": r.file,
            "line": r.line,
            "transport": r.transport,
            "unresolved_fields": r.unresolved_fields,
            "unresolved_reason": r.unresolved_reason,
            "resolved": _redact_partial_resolution(r),
        }
        for r in unresolved
    ]
    out["agents"] = [{"name": a.name, "framework": a.framework, "file": a.file, "line": a.line} for a in agents]
    out["agent_mcp_servers"] = agent_mcp_servers
    out["agent_base_tools"] = agent_base_tools
    out["agent_unresolved_tools"] = agent_unresolved_tools
    return out


def _require_tree_sitter() -> int | None:
    if TREE_SITTER_AVAILABLE:
        return None
    print(
        "TypeScript/JS scanning needs the optional 'typescript' extra -- "
        'pip install "forgebench-session-reviewer[typescript]"'
    )
    return 1


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    # required=True -- a bare, no-flag invocation must never silently fall
    # through to the --dial branch below (spawning every discovered stdio
    # server with full ambient env, no consent listing). Same mutually
    # exclusive/required shape as inspect_mcp_source.py's own parser.
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--discover-only", action="store_true", help="scan source only; never launch or contact anything"
    )
    mode.add_argument(
        "--dial", action="store_true", help="scan, then actually connect to each dial-eligible server for tools/list"
    )
    parser.add_argument("--skip", action="append", default=[])
    parser.add_argument("--merge-into", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--timeout", type=float, default=common._DEFAULT_TIMEOUT)
    parser.add_argument("--max-files", type=int, default=_MAX_SOURCE_FILES)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--include", action="append", default=[], help="re-include a default-excluded directory")
    args = parser.parse_args(argv[1:])

    early_exit = _require_tree_sitter()
    if early_exit is not None:
        return early_exit

    root = args.root.resolve()
    exclude_dirs = (set(_DEFAULT_EXCLUDE_DIRS) - set(args.include)) | set(args.exclude)
    records, agents, links_pending, base_tools, unresolved_tools, warnings = discover_source(
        root, exclude_dirs, args.max_files
    )
    servers, unresolved, dedupe_warnings, keys_to_server_name = to_servers_and_unresolved(records)
    agent_mcp_servers = resolve_agent_links(links_pending, keys_to_server_name, unresolved_tools)
    warnings = warnings + dedupe_warnings

    for w in warnings:
        print(w, file=sys.stderr)

    if args.discover_only:
        # Reuses the Python scanner's own per-server go/no-go listing rather
        # than a bare count -- required=True (see build_parser above) makes
        # --discover-only the ONLY reachable non-dial mode on this path, so
        # a plain count here would make the consent listing SKILL.md
        # requires before a --dial run entirely unreachable for TS/JS.
        listing = (servers, unresolved, agents, agent_mcp_servers, base_tools, unresolved_tools)
        out_dict = _discovered_source_to_dict(*listing)
        # Same stdout contract as inspect_mcp_source.py: without --out the JSON
        # is stdout and the human listing goes to stderr.
        if args.out:
            _py_source._print_source_consent_listing(*listing)
            args.out.write_text(json.dumps(out_dict, indent=2) + "\n")
        else:
            with contextlib.redirect_stdout(sys.stderr):
                _py_source._print_source_consent_listing(*listing)
            sys.stdout.write(json.dumps(out_dict, indent=2) + "\n")
        return 0

    # --dial
    result = common._dial_all(servers, set(args.skip), args.timeout)
    # Every dial-time warning (malicious-server detection, a server echoing
    # what looks like a secret, a launch failure, ...) lives ONLY in this
    # popped key -- leaving it in `result` means it's silently embedded in
    # the output JSON and never actually surfaced to whoever is running this.
    for w in result.pop("_warnings"):
        print(f"warning: {w}", file=sys.stderr)

    if args.merge_into:
        if not args.merge_into.exists():
            print(
                f"warning: --merge-into {args.merge_into} does not exist yet -- writing this run's results alone",
                file=sys.stderr,
            )
        else:
            try:
                existing = json.loads(args.merge_into.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Could not read --merge-into file {args.merge_into}: {exc}", file=sys.stderr)
                return 1
            merged, merge_warnings = _py_source.merge_dial_results(existing, result, "existing", "typescript-source")
            for w in merge_warnings:
                print(f"warning: {w}", file=sys.stderr)
            result = merged

    text = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(text + "\n")
        print(f"Wrote {len(result['mcpServers'])} server(s), {len(result['mcpTools'])} tool(s) to {args.out}")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
