#!/usr/bin/env python3
"""Static analysis for agent declarations in a repo's Java source (forgebench
addition, not upstream) -- the Java sibling of ``inspect_mcp_source.py`` and
``inspect_ts_mcp_source.py``, needed because neither of those ever opens a
``.java`` file: an agent built on the Forgebench Java SDK, Spring AI,
LangChain4j or Google ADK for Java is structurally invisible to them.

    python inspect_java_mcp_source.py --discover-only [--root DIR] [--out discovered_source.json]

Same output schema and the same "never guess" discipline as its siblings --
only the parsing layer differs, and it is standard library only: Java needs
no grammar package because everything this scanner reads is lexically
simple (``import`` statements, a ``Type.builder()`` chain, ``X.class``
literals, one annotation). The lexer below strips comments and keeps string,
text-block and char literals intact, so a framework name inside a comment or
a string is never mistaken for code. Nothing is compiled, loaded or run.

What becomes an agent (see ``KNOWN_NAMED_AGENTS`` / ``KNOWN_MODULE_AGENTS``):

* a NAMED declaration -- ``LlmAgent.builder().name("x")`` (Google ADK),
  ``AgentCreateParams.builder().name("x")`` (Forgebench Java SDK),
  ``AiServices.builder(Assistant.class)`` / ``AiServices.create(...)`` and an
  ``@AiService`` interface (LangChain4j). The name is a non-empty string
  LITERAL, or a ``final String`` constant declared once in the same file
  holding one. Only a builder with NO ``.name(...)`` call, completed with
  ``.build()`` in the same expression, falls back to the variable it is
  assigned to (the Python scanner's fallback for identity-less constructs).
  Anything else -- a ``.name(...)`` that is not literal, a builder finished
  in a later statement -- is reported, never guessed.
* a SERVICE that is itself the agent -- a build module (nearest ``pom.xml`` /
  ``build.gradle(.kts)``) that builds a ``Forgebench`` client, or a Spring AI
  ``ChatClient``. Those frameworks have no agent name in code: the agent's
  identity is the key the service runs with, one per deployable. The agent is
  named after the module: the pom's own ``artifactId``, Gradle's literal
  ``rootProject.name``, else the module directory when that is BELOW the scan
  root (the root's own directory name is wherever the repo was cloned to, so
  an unnamed root module is reported instead). A module using both counts
  once, as ``forgebench-java``.

Not included, on purpose: MCP client declarations in Java (the MCP Java SDK,
``langchain4j-mcp``, ``spring.ai.mcp.client`` properties). They are COUNTED and
reported as a gap so the caller can catalog them another way -- never
silently dropped and never half-parsed. Kotlin sources are counted the same
way. Agent-to-tool and agent-to-server links are not extracted, nor are a
statically imported ``builder()`` or explicit type arguments
(``LlmAgent.<T>builder()``).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_discovery_common as common  # noqa: E402
import inspect_mcp_source as _py_source  # noqa: E402 -- reuses its exclude matching and truncation warning

PROBE_ID = "mcp-java-source-scan"
PROBE_VERSION = common.PROBE_VERSION

_MAX_SOURCE_FILES = 5000
_DEFAULT_EXCLUDE_DIRS = frozenset(
    {".git", "target", "build", "out", "bin", ".gradle", ".mvn", ".idea", "node_modules"}
    # Same non-production declarations and skill bundles the Python scanner
    # skips -- see inspect_mcp_source._DEFAULT_EXCLUDE_DIRS. "test" also
    # covers Maven/Gradle's src/test tree.
    | {"tests", "test", "examples", "fixtures", "docs", ".claude/skills", ".agents/skills"}
)


# =============================================================================
# The framework catalog -- flat tables, same discipline as the siblings: a new
# framework using an already-known shape is a one-line append.
# =============================================================================

# (fully-qualified class, entry method, name source, framework label)
#   name source "name_call"  -> the chain's .name(<literal>) call
#   name source "class_arg"  -> the entry call's first argument, `Foo.class`
KNOWN_NAMED_AGENTS: tuple[tuple[str, str, str, str], ...] = (
    ("com.google.adk.agents.LlmAgent", "builder", "name_call", "google-adk"),
    ("com.google.adk.agents.SequentialAgent", "builder", "name_call", "google-adk"),
    ("com.google.adk.agents.ParallelAgent", "builder", "name_call", "google-adk"),
    ("com.google.adk.agents.LoopAgent", "builder", "name_call", "google-adk"),
    ("ai.forgebench.AgentCreateParams", "builder", "name_call", "forgebench-java"),
    ("dev.langchain4j.service.AiServices", "builder", "class_arg", "langchain4j"),
    ("dev.langchain4j.service.AiServices", "create", "class_arg", "langchain4j"),
)

# (fully-qualified annotation, framework label): the annotated type's own name.
KNOWN_AGENT_ANNOTATIONS: tuple[tuple[str, str], ...] = (
    ("dev.langchain4j.service.spring.AiService", "langchain4j"),
)

# (fully-qualified class, framework label), in precedence order: a module
# that references any of these IS an agent, named after the module. Only the
# first framework found in a module counts (one deployable, one key).
KNOWN_MODULE_AGENTS: tuple[tuple[str, str], ...] = (
    ("ai.forgebench.Forgebench", "forgebench-java"),
    ("org.springframework.ai.chat.client.ChatClient", "spring-ai"),
)

# Package prefixes of MCP client APIs this scanner deliberately does not
# parse (see the module docstring) -- counted and reported instead.
_MCP_CLIENT_PACKAGES = ("io.modelcontextprotocol.client", "dev.langchain4j.mcp", "org.springframework.ai.mcp")
_SPRING_MCP_PROPERTY = re.compile(r"spring\.ai\.mcp\.client")
# The same keys nested in YAML: `spring: / ai: / mcp: / client:`.
_SPRING_MCP_YAML_KEYS = tuple(re.compile(rf"^\s*{k}:\s*$", re.MULTILINE) for k in ("spring", "ai", "mcp", "client"))
_SPRING_CONFIG_NAMES = re.compile(r"^application(-[\w.-]+)?\.(ya?ml|properties)$")


@dataclass
class AgentRecord:
    name: str
    framework: str
    file: str
    line: int


# =============================================================================
# Lexer -- comments dropped; string/char literals and text blocks kept whole.
# =============================================================================
_TOKEN = re.compile(
    r'(?P<ws>\s+)'
    r'|(?P<line_comment>//[^\n]*)'
    # Unterminated comments and text blocks run to the end of the file: one
    # linear match, never a rescan from every later opener.
    r'|(?P<block_comment>/\*.*?(?:\*/|\Z))'
    r'|(?P<text_block>"""[ \t]*\n(?:\\.|[^\\"]|"(?!""))*(?:"""|\Z))'
    r'|(?P<string>"(?:[^"\\\n]|\\.)*")'
    r"|(?P<char>'(?:[^'\\\n]|\\.)+')"
    r'|(?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)'
    r'|(?P<number>\d[\w.]*)'
    r'|(?P<punct>.)',
    re.DOTALL,
)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "s": " ", '"': '"', "'": "'", "\\": "\\"}


@dataclass
class Tok:
    kind: str  # ident | string | punct (numbers and chars are kept as "other")
    text: str
    line: int
    #: For an opening bracket: the index of its closing partner (the last
    #: token if it is never closed).
    partner: int = -1


def _decode_string(raw: str) -> str | None:
    """A plain ``"..."`` literal's value, or None if it holds an escape this
    scanner will not interpret (octal, unicode) -- reported, not guessed."""
    out: list[str] = []
    i, body = 0, raw[1:-1]
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            nxt = body[i + 1] if i + 1 < len(body) else ""
            if nxt not in _ESCAPES:
                return None
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def tokenize(text: str) -> list[Tok]:
    tokens: list[Tok] = []
    line = 1
    for m in _TOKEN.finditer(text):
        kind, value = m.lastgroup, m.group()
        if kind in ("ident", "punct"):
            tokens.append(Tok(kind, value, line))
        elif kind == "string":
            tokens.append(Tok("string", value, line))
        elif kind in ("text_block", "char", "number"):
            tokens.append(Tok("other", value, line))
        line += value.count("\n")
    _pair_brackets(tokens)
    return tokens


def _pair_brackets(tokens: list[Tok]) -> None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[int] = []
    for j, tok in enumerate(tokens):
        if tok.kind != "punct":
            continue
        if tok.text in pairs:
            stack.append(j)
        elif stack and tok.text == pairs[tokens[stack[-1]].text]:
            tokens[stack.pop()].partner = j
    for j in stack:
        tokens[j].partner = len(tokens) - 1


# =============================================================================
# Per-file analysis
# =============================================================================
class _Imports:
    """Which simple names in this file refer to which fully-qualified types."""

    def __init__(self, tokens: list[Tok]) -> None:
        self.single: dict[str, str] = {}
        self.wildcard: set[str] = set()
        self.all: list[str] = []
        #: token indices inside import statements -- an import is not a use.
        self.spans: set[int] = set()
        i = 0
        while i < len(tokens):
            if tokens[i].kind == "ident" and tokens[i].text == "import" and (i == 0 or tokens[i - 1].text in (";", "}")):
                j = i + 1
                if j < len(tokens) and tokens[j].text == "static":
                    j += 1
                parts: list[str] = []
                while j < len(tokens) and tokens[j].text != ";":
                    parts.append(tokens[j].text)
                    j += 1
                name = "".join(parts)
                self.all.append(name)
                self.spans.update(range(i, j + 1))
                if name.endswith(".*"):
                    self.wildcard.add(name[:-2])
                elif name:
                    self.single[name.rsplit(".", 1)[-1]] = name
                i = j
            i += 1

    def refers_to(self, simple: str, fqn: str) -> bool:
        if self.single.get(simple) == fqn:
            return True
        package, _, cls = fqn.rpartition(".")
        return simple == cls and simple not in self.single and package in self.wildcard


def _qualified_at(tokens: list[Tok], i: int) -> tuple[str, int]:
    """The dotted name starting at ``tokens[i]`` (``a.b.C``) and the index of
    its LAST identifier. ``a.b.C.builder`` yields ``a.b.C.builder``; callers
    peel the member off themselves."""
    parts, j = [tokens[i].text], i
    while j + 2 < len(tokens) and tokens[j + 1].text == "." and tokens[j + 2].kind == "ident":
        parts.append(tokens[j + 2].text)
        j += 2
    return ".".join(parts), j


def _type_ref(tokens: list[Tok], i: int, imports: _Imports, fqn: str) -> int | None:
    """If a reference to type ``fqn`` STARTS at ``tokens[i]`` -- by its
    imported simple name or written out fully qualified -- the index of the
    type's own (last) identifier, else None."""
    tok = tokens[i]
    if tok.kind != "ident" or (i > 0 and tokens[i - 1].text == "."):
        return None
    if imports.refers_to(tok.text, fqn):
        return i
    if tok.text == fqn.split(".", 1)[0]:
        dotted, last = _qualified_at(tokens, i)
        n = fqn.count(".")
        if dotted == fqn or dotted.startswith(fqn + "."):
            return i + 2 * n if last >= i + 2 * n else None
    return None


def _matching(tokens: list[Tok], open_index: int) -> int:
    """Index of the bracket closing the one at ``open_index`` -- paired once
    per file by ``tokenize``, so an unbalanced file costs O(tokens), not
    O(tokens^2)."""
    return tokens[open_index].partner


def _chain_calls(tokens: list[Tok], open_paren: int) -> tuple[list[tuple[str, list[Tok]]], int]:
    """``X.entry(args).a(..).b(..)``: [("entry", args), ("a", ..), ...] and
    the index after the chain. ``open_paren`` is the entry call's ``(``."""
    calls: list[tuple[str, list[Tok]]] = []
    close = _matching(tokens, open_paren)
    calls.append((tokens[open_paren - 1].text, tokens[open_paren + 1 : close]))
    j = close + 1
    while (
        j + 2 < len(tokens)
        and tokens[j].text == "."
        and tokens[j + 1].kind == "ident"
        and tokens[j + 2].text == "("
    ):
        close = _matching(tokens, j + 2)
        calls.append((tokens[j + 1].text, tokens[j + 3 : close]))
        j = close + 1
    return calls, j


def _string_constants(tokens: list[Tok]) -> dict[str, str]:
    """Same-file ``final String NAME = "literal";`` constants -- the one level
    of indirection resolved, mirroring the siblings' single alias step. A
    name declared twice (shadowing, two classes) is dropped as ambiguous."""
    found: dict[str, str | None] = {}
    for i in range(len(tokens) - 4):
        if (
            tokens[i].text == "String"
            and tokens[i + 1].kind == "ident"
            and tokens[i + 2].text == "="
            and tokens[i + 3].kind == "string"
            and tokens[i + 4].text == ";"
            and any(t.text == "final" for t in tokens[max(0, i - 4) : i])
        ):
            name, value = tokens[i + 1].text, _decode_string(tokens[i + 3].text)
            found[name] = value if name not in found else None
    return {k: v for k, v in found.items() if v}


def _assigned_name(tokens: list[Tok], start: int) -> str | None:
    """``Type var = <expr starting at start>`` / ``var = ...`` -> var."""
    if start >= 2 and tokens[start - 1].text == "=" and tokens[start - 2].kind == "ident":
        return tokens[start - 2].text
    return None


def _literal_name(args: list[Tok], constants: dict[str, str]) -> tuple[str | None, str]:
    """(value, why-not) for a single-argument name call."""
    if len(args) == 1 and args[0].kind == "string":
        value = _decode_string(args[0].text)
        if value is None:
            return None, "name literal uses an escape this scanner does not decode"
        return (value, "") if value.strip() else (None, "name literal is empty")
    if len(args) == 1 and args[0].kind == "ident":
        if args[0].text in constants:
            return constants[args[0].text], ""
        return None, f"name comes from '{args[0].text}', which is not a same-file string constant"
    return None, "name is computed at runtime"


def _class_literal(args: list[Tok]) -> str | None:
    """``Foo.class`` / ``pkg.Foo.class`` as the FIRST argument -> Foo."""
    depth, first = 0, []
    for t in args:
        if t.text in "([{":
            depth += 1
        elif t.text in ")]}":
            depth -= 1
        elif t.text == "," and depth == 0:
            break
        first.append(t)
    if (
        len(first) >= 3
        and first[-1].text == "class"
        and first[-2].text == "."
        and first[-3].kind == "ident"
        and all(t.kind == "ident" or t.text == "." for t in first)
    ):
        return first[-3].text
    return None


_MODIFIERS = frozenset({"public", "protected", "private", "abstract", "static", "final", "sealed", "non", "-", "strictfp"})


def scan_tokens(tokens: list[Tok], rel: str) -> tuple[list[AgentRecord], dict[str, int], list[str], bool]:
    """(named agents, {module framework: first line}, warnings, uses MCP client API)."""
    imports = _Imports(tokens)
    constants = _string_constants(tokens)
    agents: list[AgentRecord] = []
    warnings: list[str] = []
    module_hits: dict[str, int] = {}

    for i in range(len(tokens)):
        if i in imports.spans:
            continue
        for fqn, entry, source, framework in KNOWN_NAMED_AGENTS:
            last = _type_ref(tokens, i, imports, fqn)
            if last is None or last + 3 >= len(tokens):
                continue
            if not (tokens[last + 1].text == "." and tokens[last + 2].text == entry and tokens[last + 3].text == "("):
                continue
            calls, _ = _chain_calls(tokens, last + 3)
            line = tokens[i].line
            if source == "class_arg":
                name = _class_literal(calls[0][1])
                if name:
                    agents.append(AgentRecord(name, framework, rel, line))
                else:
                    warnings.append(f"{rel}:{line}: {framework} agent's interface is not a `Type.class` literal; skipped")
                continue
            name_args = next((args for method, args in calls[1:] if method == "name"), None)
            if name_args is not None:
                name, why = _literal_name(name_args, constants)
            elif calls[-1][0] == "build":
                # An identity-less declaration: the assigned variable, as in the Python scanner.
                name, why = _assigned_name(tokens, i), "no .name(...) call and not assigned to a variable"
            else:
                name, why = None, "the builder chain is not completed with .build() in one expression"
            if name:
                agents.append(AgentRecord(name, framework, rel, line))
            else:
                warnings.append(f"{rel}:{line}: {framework} agent skipped: {why}")

        for fqn, framework in KNOWN_AGENT_ANNOTATIONS:
            if tokens[i].text == "@" and i + 1 < len(tokens):
                last = _type_ref(tokens, i + 1, imports, fqn)
                if last is None:
                    continue
                j = last + 1
                if j < len(tokens) and tokens[j].text == "(":
                    j = _matching(tokens, j) + 1
                # Further annotations (`@A(Foo.class)`) and modifiers up to the declared type.
                while j < len(tokens):
                    if tokens[j].text == "@" and j + 1 < len(tokens) and tokens[j + 1].kind == "ident":
                        _, j = _qualified_at(tokens, j + 1)
                        j += 1
                        if j < len(tokens) and tokens[j].text == "(":
                            j = _matching(tokens, j) + 1
                    elif tokens[j].text in _MODIFIERS:
                        j += 1
                    else:
                        break
                if j + 1 < len(tokens) and tokens[j].text in ("interface", "class") and tokens[j + 1].kind == "ident":
                    agents.append(AgentRecord(tokens[j + 1].text, framework, rel, tokens[i].line))

        for fqn, framework in KNOWN_MODULE_AGENTS:
            if framework not in module_hits and _type_ref(tokens, i, imports, fqn) is not None:
                module_hits[framework] = tokens[i].line

    uses_mcp = any(name.startswith(_MCP_CLIENT_PACKAGES) for name in imports.all)
    return agents, module_hits, warnings, uses_mcp


# =============================================================================
# Build modules
# =============================================================================
_GRADLE_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)|//[^\n]*", re.DOTALL)
_GRADLE_ROOT_NAME = re.compile(r"""rootProject\.name\s*=\s*["']([^"'$]+)["']""")


def _pom_artifact_id(pom: Path) -> str | None:
    try:
        root = ET.parse(pom).getroot()
    except (ET.ParseError, OSError):
        return None
    for child in root:  # the project's own artifactId, never <parent>'s
        if child.tag.rsplit("}", 1)[-1] == "artifactId" and (child.text or "").strip():
            text = child.text.strip()
            return None if "${" in text else text
    return None


def _gradle_name(directory: Path) -> str | None:
    for settings in ("settings.gradle.kts", "settings.gradle"):
        try:
            text = (directory / settings).read_text(encoding="utf-8", errors="replace")
            m = _GRADLE_ROOT_NAME.search(_GRADLE_COMMENT.sub("", text))
        except OSError:
            continue
        if m:
            return m.group(1).strip()
    return None


def module_of(path: Path, root: Path) -> tuple[Path, str | None]:
    """(module directory, module name) for a source file: the nearest
    ancestor holding a pom.xml or build.gradle(.kts), searched up to the
    repository top (a ``--root`` inside a module still finds its build file).

    The directory name is a fallback only for a module BELOW the scan root:
    the root's own name is wherever the user cloned to and names nothing, so
    an unnamed root module gives None and the caller reports it instead."""
    top = next((d for d in (root, *root.parents) if (d / ".git").exists()), root)
    for directory in path.parents:
        if directory != top and top not in directory.parents:
            break
        if (directory / "pom.xml").is_file():
            name = _pom_artifact_id(directory / "pom.xml")
        elif (directory / "build.gradle").is_file() or (directory / "build.gradle.kts").is_file():
            name = _gradle_name(directory)
        else:
            continue
        return directory, name or (directory.name if root in directory.parents else None)
    return root, None


# =============================================================================
# Discovery
# =============================================================================
def _in_source_package(rel: tuple[str, ...]) -> bool:
    """Inside ``src/<set>/java`` of a non-test source set, where a package may
    legitimately be called ``build``, ``out``, ``test`` or ``docs``."""
    for k in range(len(rel) - 2):
        if rel[k] == "src" and rel[k + 2] == "java" and rel[k + 1] not in ("test", "tests", "testFixtures"):
            return True
    return False


def iter_source_files(root: Path, exclude_dirs: set[str], max_files: int) -> tuple[list[Path], list[str]]:
    """``.java`` files to scan, plus warnings -- including the counted gaps
    (Kotlin sources, Spring AI MCP client properties) this scanner never parses."""
    warnings: list[str] = []
    files: list[Path] = []
    kotlin = 0
    spring_mcp: list[str] = []
    truncated = False
    names, paths = _py_source.split_excludes(exclude_dirs)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        rel = Path(dirpath).relative_to(root).parts if Path(dirpath) != root else ()
        dirnames[:] = sorted(
            d for d in dirnames if _in_source_package(rel) or not _py_source.is_excluded_dir((*rel, d), names, paths)
        )
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.suffix in (".kt", ".kts") and not filename.endswith(".gradle.kts"):
                kotlin += 1
                continue
            if _SPRING_CONFIG_NAMES.match(filename):
                try:
                    config = path.read_text(encoding="utf-8", errors="replace")
                    if _SPRING_MCP_PROPERTY.search(config) or all(k.search(config) for k in _SPRING_MCP_YAML_KEYS):
                        spring_mcp.append(path.relative_to(root).as_posix())
                except OSError:
                    pass
                continue
            if path.suffix != ".java":
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
        warnings.append(_py_source.truncation_warning(max_files, "Java"))
    if kotlin:
        warnings.append(f"{kotlin} Kotlin file(s) were NOT scanned: Kotlin agent declarations are not read yet.")
    if spring_mcp:
        warnings.append(
            f"{len(spring_mcp)} Spring config file(s) declare Spring AI MCP client connections, which this scanner "
            "does not read: report those servers as self_observed findings."
        )
    return files, warnings


def discover_source(root: Path, exclude_dirs: set[str], max_files: int, structure: dict | None = None):
    """Same six-tuple as the siblings' ``discover_source``. MCP call sites,
    agent-server links and base tools are always empty (see the docstring)."""
    files, warnings = iter_source_files(root, exclude_dirs, max_files)
    agents: list[AgentRecord] = []
    # module dir -> (module name, {framework: (rel file, line)})
    modules: dict[Path, tuple[str | None, dict[str, tuple[str, int]]]] = {}
    mcp_files = 0
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
        except OSError as exc:
            warnings.append(f"{rel}: could not be read ({exc.__class__.__name__})")
            continue
        named, module_hits, file_warnings, uses_mcp = scan_tokens(tokenize(text), rel)
        agents.extend(named)
        warnings.extend(file_warnings)
        mcp_files += uses_mcp
        if module_hits:
            directory, name = module_of(path, root)
            hits = modules.setdefault(directory, (name, {}))[1]
            for framework, line in module_hits.items():
                hits.setdefault(framework, (rel, line))
    precedence = [fw for _, fw in KNOWN_MODULE_AGENTS]
    for directory in sorted(modules):
        name, hits = modules[directory]
        framework = next(fw for fw in precedence if fw in hits)
        rel, line = hits[framework]
        if name:
            agents.append(AgentRecord(name, framework, rel, line))
        else:
            warnings.append(
                f"{rel}:{line}: {framework} service has no named Maven/Gradle module (no artifactId or "
                "rootProject.name); skipped -- report it as a fuzzy finding with the agent's real name."
            )
    if mcp_files:
        warnings.append(
            f"{mcp_files} Java file(s) use an MCP client API (MCP Java SDK, LangChain4j MCP or Spring AI MCP), "
            "which this scanner does not read: report those servers as self_observed findings."
        )
    return [], agents, [], [], [], warnings


def to_servers_and_unresolved(records: list[Any]):
    """No MCP call sites are extracted from Java (see the module docstring)."""
    return [], [], [], {}


def resolve_agent_links(agent_mcp_links_pending: list[dict], keys_to_server_name: dict, agent_unresolved_tools: list[dict]):
    return []


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--discover-only", action="store_true", required=True, help="scan source only")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--max-files", type=int, default=_MAX_SOURCE_FILES)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--include", action="append", default=[], help="re-include a default-excluded directory")
    args = parser.parse_args(argv[1:])

    root = args.root.resolve()
    exclude_dirs = (set(_DEFAULT_EXCLUDE_DIRS) - set(args.include)) | set(args.exclude)
    _, agents, _, _, _, warnings = discover_source(root, exclude_dirs, args.max_files)
    doc = common._discovered_to_dict([])
    doc["unresolved_call_sites"] = []
    doc["agents"] = [{"name": a.name, "framework": a.framework, "file": a.file, "line": a.line} for a in agents]
    doc["agent_mcp_servers"] = []
    doc["agent_base_tools"] = []
    doc["agent_unresolved_tools"] = []
    doc["agent_groups"] = []
    doc["warnings"] = warnings
    text = json.dumps(doc, indent=2) + "\n"
    listing = f"{len(agents)} Java agent declaration(s), {len(warnings)} warning(s)"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(listing)
    else:
        sys.stdout.write(text)
        print(listing, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
