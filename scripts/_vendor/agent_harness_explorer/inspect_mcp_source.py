#!/usr/bin/env python3
"""Static AST scan for MCP servers declared PROGRAMMATICALLY in a repo's own
Python source (forgebench addition, not upstream) -- e.g. a CrewAI or
LangGraph app that wires up ``MCPServerAdapter(...)``/
``MultiServerMCPClient({...})`` directly in code, rather than in any of the
static config files ``inspect_mcp_configs.py`` already knows how to read.

Same two-phase, two-invocation shape as that script, and the two are
deliberately interoperable:

    python inspect_mcp_source.py --discover-only [--root DIR] [--out discovered_source.json]
    python inspect_mcp_source.py --dial [--skip NAME ...] [--merge-into observations.json] --out observations.json

Phase 1 (``--discover-only``) walks the repo's own ``.py`` files (never a
vendored dependency tree -- see ``_DEFAULT_EXCLUDE_DIRS``) and parses each
with the stdlib ``ast`` module, which never executes anything -- this
carries LESS execution risk than even ``inspect_mcp_configs.py``'s own
(already passive) JSONC/TOML parsing. It looks for a known table of MCP-
client constructor calls (CrewAI, LangGraph's ``langchain-mcp-adapters``,
the OpenAI Agents SDK, AutoGen, Google ADK, Strands Agents, DSPy, Haystack,
smolagents, the OpenHands SDK, PydanticAI, Microsoft Agent Framework,
Semantic Kernel, the Claude Agent SDK, Letta, AG2 (both the current
package and the classic ``autogen`` fork), LlamaIndex, Agno, PraisonAI,
CAMEL-AI -- see ``KNOWN_MCP_SYMBOLS``).
Only LITERAL
argument values are ever extracted (``ast.literal_eval``, plus one level of
same-scope, unconditional variable-alias resolution -- see ``_resolve``):
anything computed at runtime (a function call, an import, an f-string with
interpolation, a value only assigned inside an ``if``/``for``/``while``/
``try``/``with``, or a name ALSO reassigned anywhere inside one of those
even if it has an unconditional assignment too) is reported as unresolved
rather than guessed, per this bundle's own "never guess, never mark
unsupported for a partial probe" rule (``references/safety-boundaries.md``).

A call site is only promoted to a dial-eligible ``ServerConfig`` once its
transport's required identity field (``command`` for stdio, ``url`` for
http) is resolved, AND no other field besides ``env`` is unresolved (an
unresolved ``args``/``headers`` could change dial behavior in a way this
scanner cannot verify, unlike ``env`` -- see the note on ``CallSiteRecord.
is_dial_eligible`` below). Everything else lands in a separate
``unresolved_call_sites`` list -- reported (file:line, framework, whatever
WAS resolved, redacted the same way a resolved server's fields are), never
dialed, never silently dropped.

Phase 2 (``--dial``) reuses the EXACT same dial implementation
``inspect_mcp_configs.py`` does (both import it from ``mcp_discovery_common.
py``) -- this script's only job is finding a server's real address; once
found, getting its real tool list is identical regardless of how the
address was found. ``--merge-into`` folds this script's dial output into an
existing ``observations.json`` (typically ``inspect_mcp_configs.py --dial``'s
own output) via ``merge_dial_results()``, producing the same shape
``scripts/inspect_tools.py`` already accepts -- no other script needs to
change for this new discovery source to plug in.

Not included, on purpose (see ``KNOWN_MCP_SYMBOLS``'s own comment and this
module's own "don't guess" stance): any framework/shape not independently
confirmed here, LlamaIndex's deprecated ``.from_tools()``/``ReActAgent``/
``OpenAIAgent`` idiom (superseded by ``FunctionAgent``, but still shows up
in older code) and its ``AgentWorkflow(agents=[...])`` multi-agent
construction path (never independently verified), cross-file variable
resolution, following a function call to see what it returns, tracing through a
lambda body (Strands' ``MCPClient(lambda: stdio_client(...))`` stdio
idiom -- its own inner ``StdioServerParameters`` call is still found
independently, just not linked back to that specific ``MCPClient`` call
site), following a classmethod call on a from-imported class name
(smolagents' ``ToolCollection.from_mcp(...)``), a second
``chat_client.create_agent(...)`` construction style Microsoft Agent
Framework may also support (unresolvable the same classmethod way),
linking Letta's opaque server-assigned ``tool_ids`` back to a specific
``mcp_servers.create(...)`` declaration (no derivable connection exists in
source at all), AG2's decorator-based ``register_for_llm``/
``register_for_execution`` tool registration (classic package only --
would need its own agent-instance-tracking mechanism), CAMEL-AI's
``MCPToolkit.create(...)`` async-factory idiom and a ``clients=[already_
bound_name, ...]`` list (both unresolvable the same classmethod/no-nested-
Call reason as smolagents' ``from_mcp``; only ``MCPToolkit(...)``'s own
direct construction and inline ``clients=[MCPClient(...), ...]`` are
matched) and ``config_path=`` (an external file this scanner does not
read), and ``.gitignore``-aware exclusion (a fixed, auditable exclude list
is used instead -- see ``_DEFAULT_EXCLUDE_DIRS``).

Deliberately NOT onboarded after real research (not silently skipped --
see the framework-onboarding session notes): classic LangChain (its
current, non-deprecated agent API, ``langchain.agents.create_agent``, is
architecturally the same LangGraph graph already covered above under a
second import path; the legacy ``AgentExecutor``/``initialize_agent`` API
is confirmed deprecated and relocated to a separate ``langchain-classic``
package) and MetaGPT (confirmed via source to have no MCP integration at
all, and its ``Role``-subclassing architecture is a poor fit for
constructor-call detection regardless -- same disposition as AG2-classic).
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import json
import os
import shlex
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_discovery_common as common  # noqa: E402

PROBE_ID = "mcp-programmatic-source-scan"
PROBE_VERSION = common.PROBE_VERSION

_MAX_SOURCE_FILES = 5000  # defensive cap, same role as _MAX_TOOL_PAGES/_MAX_CONFIG_BYTES elsewhere
# Directory NAMES never descended into, at any depth. The second group is not
# vendored code but code that DECLARES agents it does not run in production:
# test doubles, runnable examples, fixture repos and documentation snippets.
# Scanning them registered phantom agents (a CrewAI "Researcher" from a docs
# snippet is not a governed agent). A repo whose real agents live in one of
# these can re-include it with --include NAME.
_DEFAULT_EXCLUDE_DIRS = frozenset(
    {".venv", "venv", "node_modules", ".git", "__pycache__", "site-packages", "dist", "build"}
    | {"tests", "test", "examples", "fixtures", "docs"}
    # Root-relative PATHS (matched as a trailing path, at any depth): coding-
    # agent skill bundles vendor scanner scripts -- including this one --
    # whose docstrings and tables are full of framework call shapes.
    | {".claude/skills", ".agents/skills"}
)
#: Substring every file-cap warning carries, so callers (and tests) can tell a
#: TRUNCATED scan from a complete one without parsing prose.
TRUNCATION_MARKER = "--max-files cap"


# =============================================================================
# The framework catalog -- a flat data table, mirroring
# inspect_mcp_configs.py's own _config_locations(): a new framework using an
# ALREADY-KNOWN shape is a one-line append; a genuinely new shape gets one
# new small handler in SHAPE_HANDLERS, never a new branch in the walker.
#
# A "wrapper_*" shape (see SHAPE_HANDLERS + _WRAPPER_KWARG_BY_SHAPE below) is
# for a framework whose MCP object doesn't carry command/url itself, only
# passes them through to a nested constructor call in one of its own kwargs
# (Google ADK's McpToolset -> connection_params -> ... , arbitrary depth) --
# it extracts nothing itself, and needs no new SHAPE_HANDLERS logic beyond
# naming the one kwarg to recurse into; the nested call's own row does the
# real work, independently, via the generic recursive walk.
# =============================================================================

# (module the symbol is imported FROM, imported symbol name, shape id,
#  name kwarg or None, framework label)
KNOWN_MCP_SYMBOLS: tuple[tuple[str, str, str, str | None, str], ...] = (
    # StdioServerParameters is the bare MCP SDK's own class -- CrewAI's
    # documented way of connecting reuses it directly rather than wrapping
    # it, so "crewai" here is a best-effort attribution, not a certainty:
    # any other code that imports this exact class is still a real MCP
    # server declaration worth surfacing regardless of exact framework.
    ("mcp", "StdioServerParameters", "stdio_kwargs", None, "crewai"),
    ("crewai_tools", "MCPServerAdapter", "adapter_arg", None, "crewai"),
    ("langchain_mcp_adapters.client", "MultiServerMCPClient", "keyed_dict", None, "langgraph"),
    ("agents.mcp", "MCPServerStdio", "params_kwarg_stdio", None, "openai-agents"),
    ("agents.mcp", "MCPServerSse", "params_kwarg_http", "name", "openai-agents"),
    ("autogen_ext.tools.mcp", "StdioServerParams", "stdio_kwargs", None, "autogen"),
    ("autogen_ext.tools.mcp", "SseServerParams", "http_kwargs", None, "autogen"),
    # Google ADK: McpToolset(connection_params=...) accepts EITHER the bare
    # mcp SDK's own StdioServerParameters (1 hop, already covered by the
    # "mcp" row above) OR ADK's own StdioConnectionParams wrapper (2 hops:
    # McpToolset -> connection_params -> StdioConnectionParams ->
    # server_params -> the real StdioServerParameters). Both McpToolset and
    # StdioConnectionParams are pure wrappers here -- "wrapper_*" shapes
    # extract nothing themselves; the real identity-bearing call is found
    # by the generic recursive walk independently matching ITS OWN row,
    # exactly like adapter_arg already does for CrewAI's MCPServerAdapter.
    # Import path assumed to be the public `google.adk.tools.mcp_tool`
    # package (matching ADK's own documented usage), not the internal
    # submodule each class is actually defined in -- verified via
    # raw source on google/adk-python@main, not just docs.
    ("google.adk.tools.mcp_tool", "McpToolset", "wrapper_connection_params", None, "google-adk"),
    ("google.adk.tools.mcp_tool", "StdioConnectionParams", "wrapper_server_params", None, "google-adk"),
    # Sse/StreamableHTTP connection params carry url/headers directly (no
    # further nesting) -- confirmed for SseConnectionParams via source;
    # StreamableHTTPConnectionParams assumed to share the same shape (same
    # module, same "HTTP-family" sibling class family) but not itself
    # independently verified field-by-field.
    ("google.adk.tools.mcp_tool", "SseConnectionParams", "http_kwargs", None, "google-adk"),
    ("google.adk.tools.mcp_tool", "StreamableHTTPConnectionParams", "http_kwargs", None, "google-adk"),
    # Strands Agents: MCPClient's documented HTTP shortcut passes url/headers
    # directly as kwargs -- extracted via the bespoke strands_mcp_client
    # shape below, which produces NO record at all (not even an unresolved
    # one) when those kwargs are absent, since that's the OTHER documented
    # shape -- MCPClient(lambda: stdio_client(StdioServerParameters(...))) --
    # whose command/args live inside a lambda BODY this scanner does not
    # trace into. That inner StdioServerParameters(...) call still surfaces
    # on its own via its existing top-level row; it simply isn't linked back
    # to the Strands agent for this one idiom -- a known, accepted v1 gap,
    # not a silent drop (see strands_mcp_client's own docstring).
    ("strands.tools.mcp", "MCPClient", "strands_mcp_client", None, "strands"),
    # Haystack: MCPToolset(server_info=StdioServerInfo(...)) -- one hop,
    # command/args/env live DIRECTLY on StdioServerInfo (confirmed via
    # source, not just docs -- unlike ADK's two-level StdioConnectionParams,
    # no further nesting here). SSE/StreamableHTTP variants carry
    # url/headers directly on their own class the same way; the
    # StreamableHTTP one is assumed (not independently verified field-by-
    # field) to share the SSE class's shape, same judgment call already
    # made for ADK's StreamableHTTPConnectionParams.
    #
    # BOTH the short re-export path (`haystack_integrations.tools.mcp`)
    # AND the internal submodule path each class is actually DEFINED in
    # are real, valid import styles real repos use (confirmed by
    # adversarial testing against deepset-ai/itinerary-agent, which uses
    # the submodule path exclusively -- the short-path-only table
    # originally shipped here made every one of its MCPToolset calls
    # invisible). MCPToolset lives in `mcp_toolset.py`; the three
    # ServerInfo classes live in `mcp_tool.py`.
    ("haystack_integrations.tools.mcp", "MCPToolset", "wrapper_server_info", None, "haystack"),
    ("haystack_integrations.tools.mcp.mcp_toolset", "MCPToolset", "wrapper_server_info", None, "haystack"),
    ("haystack_integrations.tools.mcp", "StdioServerInfo", "stdio_kwargs", None, "haystack"),
    ("haystack_integrations.tools.mcp.mcp_tool", "StdioServerInfo", "stdio_kwargs", None, "haystack"),
    ("haystack_integrations.tools.mcp", "SSEServerInfo", "http_kwargs", None, "haystack"),
    ("haystack_integrations.tools.mcp.mcp_tool", "SSEServerInfo", "http_kwargs", None, "haystack"),
    ("haystack_integrations.tools.mcp", "StreamableHttpServerInfo", "http_kwargs", None, "haystack"),
    ("haystack_integrations.tools.mcp.mcp_tool", "StreamableHttpServerInfo", "http_kwargs", None, "haystack"),
    # smolagents: MCPClient(server_parameters) -- a single positional arg
    # that's either the bare mcp SDK's own StdioServerParameters call, or a
    # plain dict, or a list mixing both -- the EXACT shape `adapter_arg`
    # already handles for CrewAI's MCPServerAdapter; no new shape needed.
    # `ToolCollection.from_mcp(...)` (a classmethod call on a from-imported
    # class name) is a known, accepted v1 gap -- this scanner's import
    # resolution only follows `module_alias.symbol(...)` attribute calls
    # (from a plain `import X as alias`), not `ClassName.method(...)` calls
    # on a name that came from a `from X import ClassName` -- extending
    # that would be a broader, cross-cutting change to _ImportMap itself,
    # out of scope for onboarding one framework.
    ("smolagents", "MCPClient", "adapter_arg", None, "smolagents"),
    # PydanticAI: MCPToolset(client, headers=None) -- confirmed via source
    # (pydantic-ai 2.42.0): no transport= kwarg exists, and the legacy
    # MCPServerStdio/SSE/StreamableHTTP classes have been REMOVED from the
    # current package -- not added here, since they no longer exist to
    # match. `client` is positional; the bespoke pydantic_toolset_client
    # shape (above) handles both the bare-URL-string form and the nested-
    # transport-call form (deferred to the transport class's own row,
    # below, same anti-double-report principle as every other wrapper).
    ("pydantic_ai.mcp", "MCPToolset", "pydantic_toolset_client", None, "pydantic-ai"),
    # FastMCP's own transport classes (pydantic-ai's actual MCP dependency,
    # github.com/jlowin/fastmcp) -- StdioTransport carries command/args/env
    # directly; StreamableHttpTransport carries url/headers directly (both
    # confirmed via source). SSETransport was NOT independently verified
    # field-by-field -- not added, rather than guessed.
    ("fastmcp.client.transports", "StdioTransport", "stdio_kwargs", None, "pydantic-ai"),
    ("fastmcp.client.transports", "StreamableHttpTransport", "http_kwargs", None, "pydantic-ai"),
    # Microsoft Agent Framework: MCPStdioTool(name, command, *, args=None,
    # env=None, ...) -- name/command confirmed as real __init__ params
    # (positional-or-keyword); only the KEYWORD calling convention is
    # scanned here, matching every other stdio_kwargs row in this table.
    ("agent_framework", "MCPStdioTool", "stdio_kwargs", "name", "microsoft-agent-framework"),
    # Semantic Kernel: MCPStdioPlugin(name, command, *, args=None, env=None,
    # ...) -- same positional-or-keyword shape as MCPStdioTool above, same
    # keyword-only scanning convention.
    ("semantic_kernel.connectors.mcp", "MCPStdioPlugin", "stdio_kwargs", "name", "semantic-kernel"),
    # AG2 (the current, from-scratch `ag2` package, v1.0.4 -- re-verified
    # against the actual current PyPI wheel, not just GitHub main, since
    # an EARLIER pre-1.0 cut of this same package genuinely had none of
    # this): MCPToolkit(server, ...) -- `server` is positional. See
    # `_extract_ag2_mcp_toolkit`'s own docstring for why only the bare-
    # URL-string form is supported.
    ("ag2.tools", "MCPToolkit", "ag2_mcp_toolkit_server", None, "ag2"),
    # LlamaIndex: BasicMCPClient(command_or_url, args=None, env=None,
    # headers=None, ...) -- confirmed via source. See
    # _extract_llama_index_mcp_client's own docstring for the stdio-vs-
    # http dispatch.
    ("llama_index.tools.mcp", "BasicMCPClient", "llama_index_mcp_client", None, "llama-index"),
    # McpToolSpec(client=client) -- a WRAPPER referencing an existing
    # binding by kwarg, not a new declaration; see _INHERIT_KWARG_BY_SHAPE.
    ("llama_index.tools.mcp", "McpToolSpec", "mcp_toolspec_client", None, "llama-index"),
    # Agno: MCPTools(command=..., url=..., env=..., server_params=...) --
    # confirmed via source (agno.tools.mcp.MCPTools): `command=` (a single
    # shell-command STRING, not separate command/args) and `url=` are both
    # direct kwargs on the SAME class, dispatched by presence exactly like
    # every other "presence of url decides transport" shape in this table.
    # `server_params=` (a nested StdioServerParameters/SSEClientParams/
    # StreamableHTTPClientParams call) is deferred -- see
    # `_extract_agno_mcp_tools`'s own docstring. `name=` is a real kwarg
    # confirmed on this class, used the same way OpenAI Agents SDK's
    # MCPServerSse row uses one.
    ("agno.tools.mcp", "MCPTools", "agno_mcp_tools", "name", "agno"),
    # PraisonAI: MCP(command_or_string=None, args=None, *, command=None,
    # ...) -- confirmed via source (praisonaiagents.mcp.MCP). Both the
    # top-level re-export (`from praisonaiagents import MCP`, the form used
    # in every real example found) and the submodule path it's actually
    # defined in are real, valid import styles (same two-valid-paths
    # precedent as Haystack's MCPToolset).
    ("praisonaiagents", "MCP", "praisonai_mcp", None, "praisonai"),
    ("praisonaiagents.mcp", "MCP", "praisonai_mcp", None, "praisonai"),
    # CAMEL-AI: MCPClient(config) -- a single positional/kwarg `config`
    # dict (ServerConfig fields: command/args/env/cwd for stdio, url/
    # headers for http), confirmed via source (camel.utils.mcp_client).
    ("camel.utils.mcp_client", "MCPClient", "camel_mcp_client", None, "camel-ai"),
    # CAMEL-AI: MCPToolkit(clients=[...], config_path=..., config_dict=...)
    # -- a multi-server container, confirmed via source
    # (camel.toolkits.mcp_toolkit). See `_extract_camel_mcp_toolkit`'s own
    # docstring for how each of its three constructor idioms is handled.
    ("camel.toolkits", "MCPToolkit", "camel_mcp_toolkit", None, "camel-ai"),
)


@dataclass
class CallSiteRecord:
    """One MCP-server declaration found in source -- resolved fields,
    unresolved field names + why, never silently dropped."""

    framework: str
    shape: str
    file: str
    line: int
    transport: str
    resolved: dict[str, Any] = field(default_factory=dict)
    unresolved_fields: list[str] = field(default_factory=list)
    unresolved_reason: dict[str, str] = field(default_factory=dict)
    explicit_name: str | None = None
    # Disambiguates multiple servers produced by ONE call site sharing the
    # same (file, line) -- LangGraph's keyed_dict and CrewAI's list-of-params
    # shapes can both yield several CallSiteRecords from a single Call node.
    # (file, line) alone is not a unique key; (file, line, index_in_call) is.
    index_in_call: int = 0
    # Disambiguates TWO DIFFERENT Call nodes sharing the same LINE (e.g.
    # `first(MCPServerA()); second(MCPServerB())` on one line, or any two
    # matched calls packed onto one line by a formatter) -- index_in_call
    # alone restarts at 0 for each call, so both would otherwise collide on
    # the exact same (file, line, 0) key and the agent link meant for the
    # SECOND call would resolve to the FIRST call's server instead.
    col_offset: int = 0

    def key(self) -> tuple[str, int, int, int]:
        return (self.file, self.line, self.col_offset, self.index_in_call)

    def is_dial_eligible(self) -> bool:
        """True only when the transport's required identity field is
        resolved AND nothing else (besides ``env``) is unresolved.

        ``env`` is the one documented exception: ``_dial_stdio`` merges the
        full ambient ``os.environ`` into the spawned process regardless of
        what ``server.env`` declares (``mcp_discovery_common.py``'s own
        docstring), so an unresolved ``env=os.environ`` changes nothing
        about what the dial actually does. An unresolved ``args``/
        ``headers``/``command``/``url`` has no equivalent safety net --
        dialing with a guessed-empty value could connect to the wrong
        thing, or nothing at all, which would be a guess this scanner must
        not make."""
        required = "command" if self.transport == "stdio" else "url"
        if not self.resolved.get(required):
            return False
        return not [f for f in self.unresolved_fields if f != "env"]


@dataclass
class _RawExtraction:
    """A shape handler's raw output for ONE server (a call site can yield
    several -- CrewAI's list-of-params, LangGraph's keyed dict)."""

    explicit_name: str | None
    transport: str
    resolved: dict[str, Any]
    unresolved: list[str]
    reasons: dict[str, str]


# =============================================================================
# Agent declarations -- a SECOND catalog, same shape discipline as
# KNOWN_MCP_SYMBOLS. An agent call's tools-bearing argument is resolved
# against `tool_set_bindings` (see below) to split it into MCP-server links
# (M-N) vs. non-MCP "base" tools.
# =============================================================================

# (module, symbol, tools arg spec, name spec, framework, mcp_servers arg spec or None)
# A spec is ("kwarg", name) | ("position", index) | ("assigned_var",).
# OpenAI Agents SDK is the one framework with TWO tool-bearing params --
# `tools=` (native @function_tool only, per the SDK's own docs) and
# `mcp_servers=` (MCP servers only) -- so it gets a 6th, MCP-only spec; the
# other three frameworks mix both kinds in one list, disambiguated per element.
KNOWN_AGENT_SYMBOLS: tuple[tuple[str, str, tuple, tuple, str, tuple | None], ...] = (
    ("crewai", "Agent", ("kwarg", "tools"), ("kwarg", "role"), "crewai", None),
    ("langgraph.prebuilt", "create_react_agent", ("position", 1), ("assigned_var",), "langgraph", None),
    ("langchain.agents", "create_agent", ("position", 1), ("assigned_var",), "langgraph", None),
    ("agents", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "openai-agents-sdk", ("kwarg", "mcp_servers")),
    ("autogen_agentchat.agents", "AssistantAgent", ("kwarg", "tools"), ("position", 0), "autogen", None),
    # Google ADK: `Agent` is a documented TypeAlias for `LlmAgent`
    # (google/adk/agents/llm_agent.py) -- both spellings are real, distinct
    # import names a user's code can use, so both get their own row.
    ("google.adk.agents", "LlmAgent", ("kwarg", "tools"), ("kwarg", "name"), "google-adk", None),
    ("google.adk.agents", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "google-adk", None),
    ("strands", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "strands", None),
    # DSPy has no name-bearing kwarg for its agent construct -- falls back
    # to the assigned variable, same as LangGraph's create_react_agent.
    ("dspy", "ReAct", ("kwarg", "tools"), ("assigned_var",), "dspy", None),
    # Haystack's Agent has no name/identity kwarg at all (confirmed via its
    # full constructor signature) -- falls back to the assigned variable.
    ("haystack.components.agents", "Agent", ("kwarg", "tools"), ("assigned_var",), "haystack", None),
    # smolagents: a `name=` kwarg exists for USE as a managed/delegated
    # sub-agent, but isn't required -- ("kwarg", "name") is safe to use
    # unconditionally either way, since _resolve_name_spec already falls
    # back to the assigned variable whenever that kwarg wasn't passed.
    ("smolagents", "CodeAgent", ("kwarg", "tools"), ("kwarg", "name"), "smolagents", None),
    ("smolagents", "ToolCallingAgent", ("kwarg", "tools"), ("kwarg", "name"), "smolagents", None),
    # OpenHands SDK: `tools=` is an ordinary base-tools list; MCP wiring is
    # a SEPARATE `mcp_config=` kwarg whose value is a keyed servers-dict,
    # not a list of tool/MCP objects -- handled via
    # `_KEYED_DICT_KWARG_BY_AGENT` below, not `mcp_servers_spec` (which
    # assumes a list). No name kwarg on this API -- falls back to the
    # assigned variable.
    ("openhands.sdk", "Agent", ("kwarg", "tools"), ("assigned_var",), "openhands", None),
    # PydanticAI: `tools=` is ordinary; `toolsets=` is a SEPARATE, SIMULTANEOUS
    # bucket that mixes MCP and non-MCP toolsets -- handled via
    # `_MIXED_TOOLS_KWARG_BY_AGENT` (force_mcp=False), not
    # `mcp_servers_spec` (force_mcp=True), since an ordinary custom
    # toolset in that list is NOT an error the way it would be for the
    # OpenAI Agents SDK's MCP-only `mcp_servers=`.
    ("pydantic_ai", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "pydantic-ai", None),
    # Microsoft Agent Framework: confirmed via source to be plain `Agent`
    # (module `agent_framework`), NOT `ChatAgent` -- that name does not
    # exist in the current release. A separate `chat_client.create_agent
    # (...)` factory-method construction style may also exist in real
    # code; unresolvable by this scanner's import-based matching (a method
    # call on an arbitrary local variable has no import provenance to
    # verify) -- a known, accepted gap, not attempted here.
    ("agent_framework", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "microsoft-agent-framework", None),
    # Semantic Kernel: `plugins=` is the PRIMARY, direct spec; `kernel=`
    # (see `_FALLBACK_TOOLS_KWARG_BY_AGENT`) is tried ONLY when `plugins=`
    # wasn't given at all -- the decoupled style where plugins accumulate
    # on a separately-built Kernel via `.add_plugin(...)` calls instead.
    ("semantic_kernel.agents", "ChatCompletionAgent", ("kwarg", "plugins"), ("kwarg", "name"), "semantic-kernel", None),
    # Claude Agent SDK: no `Agent(tools=...)` shape exists at all --
    # confirmed via source, no name-bearing field anywhere on either
    # ClaudeAgentOptions or ClaudeSDKClient. Treat the options object
    # itself as "the agent" (falls back to whatever variable it's
    # assigned to for its display name, same as LangGraph/DSPy); its
    # `allowed_tools=` list is ordinary base tools (plain strings, not
    # objects -- see the Constant case added to _resolve_one_tool_element);
    # `mcp_servers=` is handled separately via _KEYED_DICT_KWARG_BY_AGENT,
    # not this row's mcp_servers_spec (which assumes a list, not a dict).
    ("claude_agent_sdk", "ClaudeAgentOptions", ("kwarg", "allowed_tools"), ("assigned_var",), "claude-agent-sdk", None),
    # AG2's CURRENT (v1.0.4) package: Agent(name, prompt=(), *, tools=(),
    # ...) -- `name` is the first positional arg, same convention already
    # used for AutoGen's own AssistantAgent row.
    ("ag2", "Agent", ("kwarg", "tools"), ("position", 0), "ag2", None),
    # Classic AG2/AutoGen (`autogen` PyPI package, source ag2ai/ag2-
    # classic -- confirmed as a SEPARATE, still actively-used package,
    # not merely historical, since the `ag2`/`autogen` split only
    # happened ~6 weeks before this was written): ConversableAgent/
    # AssistantAgent wire tools via `register_for_llm`/
    # `register_for_execution` DECORATOR calls made after construction,
    # never a constructor kwarg -- confirmed via source. There is no
    # `tools=` kwarg to read here at all, so the tools_spec below is
    # inert by design (`_spec_node` returns None, `_record_tools_arg`
    # no-ops on it) -- these rows exist ONLY for real, honest AGENT
    # discovery (name + framework + location); linking their tools is a
    # known, accepted gap (decorator-based registration has no
    # precedent in this scanner, and correctly attributing a decorated
    # function to a SPECIFIC agent instance would need its own new
    # tracking mechanism, out of scope here).
    ("autogen", "ConversableAgent", ("kwarg", "tools"), ("position", 0), "ag2-classic", None),
    ("autogen", "AssistantAgent", ("kwarg", "tools"), ("position", 0), "ag2-classic", None),
    # LlamaIndex: FunctionAgent(name=..., tools=[...], llm=..., ...) -- a
    # Pydantic model, so every field is a real kwarg (confirmed via
    # source); `name` defaults to "Agent" but is a real, settable field.
    # The legacy `.from_tools()` classmethod (ReActAgent/OpenAIAgent) and
    # the multi-agent `AgentWorkflow(agents=[...])` construction path are
    # both deliberately NOT covered -- the former is marked deprecated in
    # the codebase itself, the latter takes pre-built agent instances
    # rather than a raw tool list and was never independently verified.
    ("llama_index.core.agent.workflow", "FunctionAgent", ("kwarg", "tools"), ("kwarg", "name"), "llama-index", None),
    # Agno: a dataclass (init=False, custom __init__) -- confirmed via
    # source that `tools=` and `name=` are both real fields on its kwarg
    # surface.
    ("agno.agent", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "agno", None),
    # PraisonAI: `tools=` can hold a SINGLE MCP instance (not wrapped in a
    # list) or an ordinary list -- both already handled generically by
    # `_record_tools_arg`'s existing "a bare Call is one element" fallback,
    # no new mechanism needed. `name=` is a real, confirmed kwarg.
    ("praisonaiagents", "Agent", ("kwarg", "tools"), ("kwarg", "name"), "praisonai", None),
    # CAMEL-AI: ChatAgent has NO name-bearing kwarg (confirmed via source --
    # `agent_id` auto-generates a UUID when omitted, and `system_message` is
    # a prompt string, not an identity) -- falls back to the assigned
    # variable, same as Haystack's Agent/DSPy's ReAct.
    ("camel.agents", "ChatAgent", ("kwarg", "tools"), ("assigned_var",), "camel-ai", None),
)

# A wrapper function whose sole argument is itself an MCP declaration --
# AutoGen's mcp_server_tools(StdioServerParams(...)) is the one confirmed
# case. Recognized via the same _ImportMap resolution as KNOWN_MCP_SYMBOLS.
_TOOLSET_WRAPPER_FUNCS = frozenset({("autogen_ext.tools.mcp", "mcp_server_tools")})

# `X = <var>.get_tools()` (LangGraph's MultiServerMCPClient) was the first
# confirmed case of this pattern -- a zero-arg method call on an EXISTING
# tool-set binding that just forwards it under a new name, no new
# declaration. LlamaIndex's McpToolSpec adds two more real method names
# for the identical shape (`tool_spec.to_tool_list()` /
# `await tool_spec.to_tool_list_async()`) -- a set, not a single hardcoded
# name, so a future framework using yet another method name for the same
# idiom is a one-line addition, not a new branch.
_PASSTHROUGH_TOOL_METHOD_NAMES = frozenset({"get_tools", "to_tool_list", "to_tool_list_async"})


@dataclass
class AgentRecord:
    """One agent constructor call found in source."""

    name: str
    framework: str
    file: str
    line: int


# =============================================================================
# Import resolution -- a Call only matches the catalog if its resolved
# origin (module, symbol) is in KNOWN_MCP_SYMBOLS, never a bare name/string
# match (a same-named unrelated local function must never match).
# =============================================================================


class _ImportMap:
    def __init__(self) -> None:
        self.from_imports: dict[str, tuple[str, str]] = {}  # local name -> (module, symbol)
        self.module_aliases: dict[str, str] = {}  # local alias -> real module name

    @classmethod
    def build(cls, tree: ast.Module) -> "_ImportMap":
        m = cls()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if alias.name == "*":
                        continue  # wildcard: origin unresolvable, never followed
                    local = alias.asname or alias.name
                    m.from_imports[local] = (node.module, alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    m.module_aliases[local] = alias.name
        return m

    def resolve_call_symbol(self, call: ast.Call) -> tuple[str, str] | None:
        func = call.func
        if isinstance(func, ast.Name):
            return self.from_imports.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = self.module_aliases.get(func.value.id)
            if module:
                return (module, func.attr)
        return None


# =============================================================================
# Resolution -- one level, unconditional, same scope only.
# =============================================================================


def _resolution_env(body: list[ast.stmt]) -> dict[str, ast.expr]:
    """Names safe to resolve within ONE scope (module or function) body:
    those assigned via a single, direct, unconditional ``Assign`` statement
    in this exact body, and NEVER also reassigned anywhere inside a nested
    conditional/loop/exception block in this same body -- a name
    conditionally reassigned is excluded even where it ALSO has an
    unconditional assignment, because which value is actually in effect at
    any given call site depends on a branch this scanner does not evaluate;
    resolving to the unconditional value anyway would itself be a guess
    (always guessing "the conditional branch didn't run"). Known, accepted
    imprecision: a same-named variable inside a NESTED function definition
    within one of those blocks is treated as poisoning the outer name too
    (full scope tracking is out of scope) -- this only makes the scanner
    resolve LESS, never more, which is the safe direction."""
    direct: dict[str, ast.expr] = {}
    conditionally_assigned: set[str] = set()

    for stmt in body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            direct[stmt.targets[0].id] = stmt.value
        elif isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            for inner in ast.walk(stmt):
                if (
                    isinstance(inner, ast.Assign)
                    and len(inner.targets) == 1
                    and isinstance(inner.targets[0], ast.Name)
                ):
                    conditionally_assigned.add(inner.targets[0].id)
                elif isinstance(inner, (ast.AugAssign, ast.AnnAssign)) and isinstance(inner.target, ast.Name):
                    conditionally_assigned.add(inner.target.id)

    return {name: node for name, node in direct.items() if name not in conditionally_assigned}


# Sentinel a parameter name resolves to: any node ast.literal_eval rejects,
# so a lookup that finds it stops right there (see _resolve_one's "found in
# scope, literal_eval fails -> (None, False), no fall-through" behaviour)
# instead of leaking through to an outer scope's unrelated same-named global.
_UNRESOLVABLE_PARAM = ast.Name(id="<parameter>", ctx=ast.Load())


def _function_scope(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.expr]:
    """The resolution frame for one function body: its own direct,
    unconditional local assigns (``_resolution_env``) PLUS every one of its
    parameters, each pinned to ``_UNRESOLVABLE_PARAM``. A parameter's actual
    value at any given call site is a caller-side fact this static scanner
    does not evaluate -- without this, a parameter is simply ABSENT from the
    frame and a lookup for it falls through to whatever a module-level (or
    enclosing-function) global of the same name happens to hold, silently
    resolving to a value the call site never declared. Body assigns take
    precedence over the parameter placeholder so a param the body
    unconditionally reassigns before use is still resolved from that
    reassignment, same as any other local."""
    scope = {name: _UNRESOLVABLE_PARAM for name in _param_names(node.args)}
    scope.update(_resolution_env(node.body))
    return scope


def _param_names(args: ast.arguments) -> list[str]:
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def _resolve_one(node: ast.expr | None, scopes: list[dict[str, ast.expr]]) -> tuple[Any, bool]:
    """(value, ok) for ONE literal-or-aliased value: try literal_eval
    directly; if it's a bare Name, look it up ONCE (innermost scope first)
    and literal_eval THAT node -- never a second hop, never following
    imports or function calls. This is the base case _resolve() applies
    both to a whole field and to each element/value inside a List/Tuple/
    Dict field (see _resolve's own docstring for why)."""
    if node is None:
        return None, False
    try:
        return ast.literal_eval(node), True
    except (ValueError, TypeError, SyntaxError):
        pass
    if isinstance(node, ast.Name):
        for scope in reversed(scopes):
            if node.id in scope:
                try:
                    return ast.literal_eval(scope[node.id]), True
                except (ValueError, TypeError, SyntaxError):
                    return None, False
    return None, False


def _resolve(node: ast.expr | None, scopes: list[dict[str, ast.expr]]) -> tuple[Any, bool]:
    """(value, ok). Same one-hop alias rule as _resolve_one, PLUS: a List/
    Tuple/Dict that isn't already fully literal (``ast.literal_eval`` fails
    on it whole) is walked one level down, applying that exact same
    one-hop rule to each element/value independently -- e.g.
    ``args=[script_path]`` resolves ``script_path`` the same way
    ``command=script_path`` already would, just one level deeper into the
    list. Still never a second hop and still never guesses: an element
    that is itself an alias pointing at something non-literal (or at
    another alias) still fails, and failing on ANY element/value fails the
    whole field -- no partial lists, no partial dicts."""
    value, ok = _resolve_one(node, scopes)
    if ok:
        return value, True
    if isinstance(node, (ast.List, ast.Tuple)):
        values = []
        for elt in node.elts:
            elt_value, elt_ok = _resolve_one(elt, scopes)
            if not elt_ok:
                return None, False
            values.append(elt_value)
        return (tuple(values) if isinstance(node, ast.Tuple) else values), True
    if isinstance(node, ast.Dict):
        result: dict[Any, Any] = {}
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                return None, False  # a **spread -- structurally unresolvable
            key, key_ok = _resolve_one(key_node, scopes)
            val, val_ok = _resolve_one(value_node, scopes)
            if not (key_ok and val_ok):
                return None, False
            result[key] = val
        return result, True
    return None, False


def _unresolved_reason(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        return "computed by a function call, not a literal"
    if isinstance(node, ast.Attribute):
        return "an attribute access (e.g. os.environ), not a literal"
    if isinstance(node, ast.JoinedStr):
        return "an f-string with a non-literal interpolation"
    if isinstance(node, ast.Name):
        return f"{node.id!r} is not assigned by a simple, unconditional literal in this scope"
    if isinstance(node, ast.BinOp):
        return "a computed expression (e.g. string concatenation), not a literal"
    return "not a literal value this scanner can resolve"


def _call_kwargs(call: ast.Call) -> dict[str, ast.expr]:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}


def _dict_literal_fields(node: ast.expr | None) -> dict[str, ast.expr] | None:
    """``node``'s string-keyed entries, or ``None`` if it isn't (fully) a
    dict literal -- a ``**spread`` entry OR a non-literal (computed) key
    makes the WHOLE dict structurally unresolvable, since we can't know
    what key it actually contributes. Skipping a non-literal key instead of
    failing the whole dict used to make ``_dict_literal_fields({SERVER_KEY:
    {...}})`` (every key non-literal) silently return ``{}`` -- structurally
    IDENTICAL to a genuinely empty dict, so ``MultiServerMCPClient({SERVER_KEY:
    {...}})`` produced no server AND no ``unresolved_call_sites`` entry: the
    declaration vanished with no trace it was ever there."""
    if not isinstance(node, ast.Dict):
        return None
    fields: dict[str, ast.expr] = {}
    for key_node, value_node in zip(node.keys, node.values):
        if key_node is None:
            return None
        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
            return None
        fields[key_node.value] = value_node
    return fields


def _keyed_dict_literal_fields(node: ast.expr | None) -> tuple[dict[str, ast.expr], bool]:
    """Like ``_dict_literal_fields``, but for a dict keyed BY SERVER NAME
    (``MultiServerMCPClient({name: {...}, ...})``), where each entry is an
    INDEPENDENT server declaration, not a related field of one shared
    record the way ``_dict_literal_fields``'s callers use it (a single
    server's ``{command, args, env, ...}``, where a non-literal key can
    genuinely change what the whole record means and the all-or-nothing
    ``None`` is the right call).

    Here, one entry keyed by something computed (``{"weather": {...},
    dynamic_key: {...}}``) says nothing about whether ITS SIBLING entries
    are trustworthy -- reusing ``_dict_literal_fields``'s all-or-nothing
    ``None`` here made a single dynamically-keyed entry discard every
    OTHER, perfectly resolvable server in the same dict (e.g. losing
    ``"weather"`` too), which is worse than the ambiguous-empty-dict bug
    that all-or-nothing was originally introduced to fix.

    Returns ``(resolved, had_unresolved)`` -- the caller still needs
    ``had_unresolved`` to emit its own ``unresolved_call_sites`` marker for
    what got dropped, or a partially-resolved dict would silently lose the
    unresolvable entries with no trace, the same "vanished with no trace"
    failure mode ``_dict_literal_fields`` itself exists to avoid, just for
    a subset of entries instead of the whole dict."""
    if not isinstance(node, ast.Dict):
        return {}, True
    fields: dict[str, ast.expr] = {}
    had_unresolved = False
    for key_node, value_node in zip(node.keys, node.values):
        if key_node is None or not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
            had_unresolved = True
            continue
        fields[key_node.value] = value_node
    return fields, had_unresolved


def _resolve_dict_kwarg(call: ast.Call, kwarg_name: str, scopes: list[dict]) -> dict[str, ast.expr] | None:
    """The dict literal passed as ``kwarg_name=``, resolving ONE Name hop
    if it was assigned to a variable first (``p = {...}; f(params=p)``) --
    same one-level-alias rule as a scalar field."""
    node = _call_kwargs(call).get(kwarg_name)
    if node is None:
        return None
    if isinstance(node, ast.Name):
        for scope in reversed(scopes):
            if node.id in scope:
                node = scope[node.id]
                break
        else:
            return None
    return _dict_literal_fields(node)


def _extract_fields(
    field_nodes: dict[str, ast.expr], names: tuple[str, ...], scopes: list[dict]
) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    resolved: dict[str, Any] = {}
    unresolved: list[str] = []
    reasons: dict[str, str] = {}
    for name in names:
        node = field_nodes.get(name)
        if node is None:
            continue  # simply not provided -- not an error, just absent
        value, ok = _resolve(node, scopes)
        if ok:
            resolved[name] = value
        else:
            unresolved.append(name)
            reasons[name] = _unresolved_reason(node)
    return resolved, unresolved, reasons


# =============================================================================
# Shape handlers -- each takes (call, scopes) and returns a list of
# _RawExtraction, one per server the call site declares (almost always one;
# keyed_dict can yield several).
# =============================================================================


def _extract_stdio_kwargs(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    resolved, unresolved, reasons = _extract_fields(_call_kwargs(call), ("command", "args", "env"), scopes)
    return [_RawExtraction(None, "stdio", resolved, unresolved, reasons)]


def _extract_http_kwargs(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    resolved, unresolved, reasons = _extract_fields(_call_kwargs(call), ("url", "headers"), scopes)
    return [_RawExtraction(None, "http", resolved, unresolved, reasons)]


def _extract_params_kwarg_stdio(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    fields = _resolve_dict_kwarg(call, "params", scopes)
    if fields is None:
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "params= was not a resolvable dict literal"})]
    resolved, unresolved, reasons = _extract_fields(fields, ("command", "args", "env"), scopes)
    return [_RawExtraction(None, "stdio", resolved, unresolved, reasons)]


def _extract_params_kwarg_http(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    fields = _resolve_dict_kwarg(call, "params", scopes)
    if fields is None:
        return [_RawExtraction(None, "http", {}, ["*"], {"*": "params= was not a resolvable dict literal"})]
    resolved, unresolved, reasons = _extract_fields(fields, ("url", "headers"), scopes)
    return [_RawExtraction(None, "http", resolved, unresolved, reasons)]


def _unwrap_one_alias(node: ast.expr, scopes: list[dict]) -> ast.expr:
    if isinstance(node, ast.Name):
        for scope in reversed(scopes):
            if node.id in scope:
                bound = scope[node.id]
                if bound is _UNRESOLVABLE_PARAM:
                    # `_resolve_one`/`_resolve` stop here too (see the
                    # sentinel's own docstring) -- but they get that for
                    # free because `ast.literal_eval` naturally rejects an
                    # `ast.Name` node. This helper isn't literal_eval-based:
                    # it hands back the found node AS DATA, and the sentinel
                    # is itself a syntactically ordinary `ast.Name(id=
                    # "<parameter>")`, so without this check it would leak
                    # through as if it were the parameter's real value --
                    # e.g. `def build(tools): return Agent(tools=tools)`
                    # fabricating a base tool literally named "<parameter>"
                    # (the sentinel's own placeholder id) and reporting it
                    # as if it were something real the code declared.
                    # Returning the ORIGINAL node instead leaves the caller
                    # with the bare Name it started with -- still correctly
                    # unresolved, never a fabricated value.
                    return node
                return bound
    return node


def _dotted_name(node: ast.expr) -> str | None:
    """Canonical string key for a bare Name OR a chain of Attribute
    accesses rooted at one (``self.client`` -> ``"self.client"``) --
    confirmed via adversarial testing to be the MOST common real-world
    pattern for wrapping an SDK client inside a service class
    (``self.client = Letta(...)`` in ``__init__``, used from other
    methods), which the guarded-instance-tracking mechanisms
    (``_KERNEL_CONSTRUCTORS``/``_LETTA_CLIENT_CONSTRUCTORS``) would
    otherwise miss entirely -- not a mislink, total invisibility, since a
    bare-Name-only check never even matches an Attribute target/receiver
    at all. Returns ``None`` for anything else (a subscript, a call
    result, etc.) -- exactly the case this scanner must not guess at."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _extract_keyed_dict_fields(top: dict[str, ast.expr], scopes: list[dict]) -> list[_RawExtraction]:
    """The shared body of ``_extract_keyed_dict`` (below) -- an
    already-resolved ``{server_name: entry_dict_node, ...}`` mapping,
    regardless of WHERE that top-level dict literal came from. Reused by
    the OpenHands SDK's ``mcp_config=`` kwarg (a keyed servers-dict passed
    directly on the Agent's own call, not via any separate MCP-declaring
    call site at all -- see ``_record_keyed_dict_kwarg``).

    Each entry is either a dict literal (LangGraph's own
    ``MultiServerMCPClient({"name": {"command": ...}})`` shape) OR a
    CONSTRUCTOR CALL (the OpenHands SDK's own real shape, confirmed by
    adversarial testing against its own textbook example:
    ``mcp_config={"name": MCPServer(command=..., args=...)}`` -- every one
    of that SDK's own real-world entries is a call, never a plain dict,
    which the original dict-literal-only version of this function reported
    as "not a resolvable dict literal" for every single one). A call
    entry's kwargs are read directly, exactly as if they'd been a dict's
    own fields -- deliberately NOT via a top-level KNOWN_MCP_SYMBOLS row
    for a class like ``MCPServer`` (that would let the generic recursive
    walk independently match the SAME call a second time, since dict
    VALUES are walked as children regardless -- double-reporting one
    server as two)."""
    out: list[_RawExtraction] = []
    for server_name, entry_node in top.items():
        entry_fields = _dict_literal_fields(entry_node)
        if entry_fields is None and isinstance(entry_node, ast.Call):
            entry_fields = _call_kwargs(entry_node)
        if entry_fields is None:
            out.append(
                _RawExtraction(
                    server_name,
                    "stdio",
                    {},
                    ["*"],
                    {"*": f"{server_name!r}'s entry was neither a resolvable dict literal nor a constructor call"},
                )
            )
            continue
        transport_value, _ok = _resolve(entry_fields.get("transport"), scopes)
        is_http = "url" in entry_fields or (isinstance(transport_value, str) and "http" in transport_value)
        names = ("url", "headers") if is_http else ("command", "args", "env")
        resolved, unresolved, reasons = _extract_fields(entry_fields, names, scopes)
        out.append(_RawExtraction(server_name, "http" if is_http else "stdio", resolved, unresolved, reasons))
    return out


def _extract_keyed_dict(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``MultiServerMCPClient({name: {...}, ...})`` -- ONE call site,
    MULTIPLE servers, keyed by name directly. Positional-only in every real
    example found; not scanned as a kwarg."""
    if not call.args:
        return []
    node = _unwrap_one_alias(call.args[0], scopes)
    if not isinstance(node, ast.Dict):
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "the servers dict was not a resolvable literal"})]
    top, had_unresolved = _keyed_dict_literal_fields(node)
    out = _extract_keyed_dict_fields(top, scopes)
    if had_unresolved:
        # At least one entry's key was computed/non-literal -- report it
        # (rather than let it vanish with no trace) without discarding the
        # sibling entries in `top` that resolved fine.
        out.append(
            _RawExtraction(
                None,
                "stdio",
                {},
                ["*"],
                {"*": "one or more server entries had a non-literal (computed) key and were skipped"},
            )
        )
    return out


def _extract_adapter_arg(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``MCPServerAdapter(params)`` -- ``params`` is one dict/
    ``StdioServerParameters`` call, or a list mixing both. A nested
    ``StdioServerParameters(...)`` call is intentionally NOT extracted
    here: it independently matches its own top-level catalog entry
    (``mcp.StdioServerParameters`` -> ``stdio_kwargs``) via the generic
    walker, since a Call's own arguments get walked too -- extracting it
    again here would double-report the same server."""
    if not call.args:
        return []
    node = _unwrap_one_alias(call.args[0], scopes)
    items = node.elts if isinstance(node, (ast.List, ast.Tuple)) else [node]

    out: list[_RawExtraction] = []
    for item in items:
        resolved_item = _unwrap_one_alias(item, scopes)
        if isinstance(resolved_item, ast.Call):
            continue  # handled independently by its own top-level match
        fields = _dict_literal_fields(resolved_item)
        if fields is None:
            out.append(
                _RawExtraction(None, "stdio", {}, ["*"], {"*": "a server_params entry was not a resolvable dict literal"})
            )
            continue
        is_http = "url" in fields
        names = ("url", "headers") if is_http else ("command", "args", "env")
        resolved, unresolved, reasons = _extract_fields(fields, names, scopes)
        out.append(_RawExtraction(None, "http" if is_http else "stdio", resolved, unresolved, reasons))
    return out


def _extract_wrapper_noop(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """A pure passthrough wrapper (Google ADK's ``McpToolset``/
    ``StdioConnectionParams``) -- extracts nothing itself. The call it
    wraps (named in ``_WRAPPER_KWARG_BY_SHAPE`` below) independently
    matches its own top-level catalog row via the generic recursive walk,
    same principle ``_extract_adapter_arg`` already documents: extracting
    it again here would double-report the same server."""
    return []


def _extract_strands_mcp_client(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``strands.tools.mcp.MCPClient`` has two DOCUMENTED, mutually
    exclusive shapes: ``MCPClient(url=..., headers=...)`` (the HTTP
    shortcut, extracted directly below) or
    ``MCPClient(lambda: stdio_client(StdioServerParameters(...)))`` (the
    stdio idiom, whose identity lives inside a lambda BODY -- not a kwarg
    on this call at all, and not something this scanner traces into). When
    no ``url`` kwarg is present, this returns no extraction at all (not
    even an unresolved one) rather than a bogus "this call is missing its
    required field": the nested ``StdioServerParameters(...)`` call still
    surfaces on its own via its existing top-level row, so the real server
    is reported once, correctly -- just without a link back to this
    specific ``MCPClient`` call site (a known, accepted v1 gap, not a
    silent drop)."""
    kwargs = _call_kwargs(call)
    if "url" not in kwargs:
        return []
    resolved, unresolved, reasons = _extract_fields(kwargs, ("url", "headers"), scopes)
    return [_RawExtraction(None, "http", resolved, unresolved, reasons)]


def _extract_pydantic_mcp_toolset(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``pydantic_ai.mcp.MCPToolset(client, headers=None)`` -- confirmed
    via source: there is NO ``transport=`` kwarg. ``client`` is POSITIONAL
    and either a nested FastMCP transport call (``StdioTransport(...)`` /
    ``StreamableHttpTransport(...)`` -- deferred, produces nothing here,
    same anti-double-report principle as ``adapter_arg``/the ADK wrapper
    shapes: the nested call independently matches its own row) or a bare
    URL string/``AnyUrl``/``Path`` (the documented HTTP shortcut,
    extracted directly here and paired with the sibling ``headers=``
    kwarg)."""
    if not call.args:
        return []
    client = _unwrap_one_alias(call.args[0], scopes)
    if isinstance(client, ast.Call):
        return []
    url, ok = _resolve(client, scopes)
    if not (ok and isinstance(url, str) and url):
        return [
            _RawExtraction(
                None, "http", {}, ["*"], {"*": "client was not a resolvable URL string, nor a nested transport call"}
            )
        ]
    resolved, unresolved, reasons = _extract_fields(_call_kwargs(call), ("headers",), scopes)
    resolved["url"] = url
    return [_RawExtraction(None, "http", resolved, unresolved, reasons)]


def _extract_ag2_mcp_toolkit(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``ag2.tools.MCPToolkit(server: str | MCPServerConfig |
    MCPStdioServerConfig, ...)`` -- confirmed via source: ``server`` is
    POSITIONAL. A bare string is the documented URL shortcut, extracted
    directly; a nested Call (an ``MCPServerConfig``/``MCPStdioServerConfig``
    construction) is deferred, same anti-double-report principle as every
    other wrapper shape -- but NEITHER of those two config classes has its
    own row here, since their exact fields were never independently
    verified against source (unlike every other wrapped class in this
    table); a real repo using that form reports nothing rather than a
    guessed field name."""
    if not call.args:
        return []
    server = _unwrap_one_alias(call.args[0], scopes)
    if isinstance(server, ast.Call):
        return []
    url, ok = _resolve(server, scopes)
    if not (ok and isinstance(url, str) and url):
        return [
            _RawExtraction(
                None, "http", {}, ["*"], {"*": "server was not a resolvable URL string, nor a nested config call"}
            )
        ]
    return [_RawExtraction(None, "http", {"url": url}, [], {})]


def _extract_llama_index_mcp_client(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``llama_index.tools.mcp.BasicMCPClient(command_or_url, args=None,
    env=None, headers=None, ...)`` -- confirmed via source: a SINGLE
    overloaded identity argument (positional or ``command_or_url=`` kwarg)
    that's either a shell command (stdio) or a URL (http), dispatched
    internally by the SDK based on the string's own shape. Classifying an
    already-resolved LITERAL string this way isn't a guess about missing
    data -- it's the same kind of interpretation ``synthesize_name``
    already does elsewhere on a fully-known value -- so a bare
    ``http(s)://`` prefix decides transport here, same as everywhere else
    in this scanner "url present" already does."""
    node = call.args[0] if call.args else _call_kwargs(call).get("command_or_url")
    if node is None:
        return []
    value, ok = _resolve(_unwrap_one_alias(node, scopes), scopes)
    if not (ok and isinstance(value, str) and value):
        return [
            _RawExtraction(
                None, "stdio", {}, ["*"], {"*": "command_or_url was not a resolvable string literal"}
            )
        ]
    if value.startswith("http://") or value.startswith("https://"):
        resolved, unresolved, reasons = _extract_fields(_call_kwargs(call), ("headers",), scopes)
        resolved["url"] = value
        return [_RawExtraction(None, "http", resolved, unresolved, reasons)]
    resolved, unresolved, reasons = _extract_fields(_call_kwargs(call), ("args", "env"), scopes)
    resolved["command"] = value
    return [_RawExtraction(None, "stdio", resolved, unresolved, reasons)]


def _split_shell_command(value: str) -> tuple[str, list[str]] | None:
    """Splits a single shell-command STRING (Agno's ``MCPTools(command=)``,
    PraisonAI's ``MCP`` identity arg) into ``(program, argv)`` via
    ``shlex`` -- a deterministic, safe parse of an ALREADY fully-resolved
    literal, the same kind of interpretation LlamaIndex's URL-vs-command
    dispatch already does on a fully-known value (see
    ``_extract_llama_index_mcp_client``'s own docstring), not a guess about
    missing data. Needed because both frameworks accept ONE string where
    every other framework in this table takes command/args as two separate
    fields, and ``_dial_stdio`` itself requires them pre-split
    (``Popen([server.command, *server.args])``) -- storing the raw
    unsplit string as ``command`` would look resolved/dial-eligible but
    fail to launch. Returns ``None`` for a string that splits to nothing
    (still unresolved, not a guess)."""
    parts = shlex.split(value)
    if not parts:
        return None
    return parts[0], parts[1:]


def _extract_agno_mcp_tools(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``agno.tools.mcp.MCPTools(command=None, *, name=..., url=..., env=...,
    server_params=...)`` -- confirmed via source: ``command`` is positional-
    OR-keyword (the FIRST param), and confirmed via adversarial testing
    against agno-agi/agno's own real cookbook to be commonly passed
    POSITIONALLY (``MCPTools("npx -y ...")``, more common than the keyword
    form in that cookbook) -- both are scanned here, unlike most other
    kwarg-only shapes in this table. ``url=`` (SSE/streamable-http) and a
    resolved ``command`` (stdio, a single shell-command STRING, not
    separate command/args -- see ``_split_shell_command``) are each
    extracted directly when present. ``server_params=`` (a nested
    StdioServerParameters/SSEClientParams/StreamableHTTPClientParams call)
    is deferred -- same anti-double-report principle as every other
    wrapper shape: a recognized nested call (only the bare mcp SDK's own
    StdioServerParameters is independently verified here) matches its own
    top-level row."""
    kwargs = _call_kwargs(call)
    if "url" in kwargs:
        resolved, unresolved, reasons = _extract_fields(kwargs, ("url", "headers"), scopes)
        return [_RawExtraction(None, "http", resolved, unresolved, reasons)]
    command_node = call.args[0] if call.args else kwargs.get("command")
    if command_node is not None:
        value, ok = _resolve(command_node, scopes)
        if not (ok and isinstance(value, str) and value):
            return [_RawExtraction(None, "stdio", {}, ["command"], {"command": _unresolved_reason(command_node)})]
        split = _split_shell_command(value)
        if split is None:
            return [
                _RawExtraction(None, "stdio", {}, ["command"], {"command": "command resolved to an empty shell command"})
            ]
        resolved: dict[str, Any] = {"command": split[0], "args": list(split[1])}
        env_resolved, env_unresolved, env_reasons = _extract_fields(kwargs, ("env",), scopes)
        resolved.update(env_resolved)
        return [_RawExtraction(None, "stdio", resolved, env_unresolved, env_reasons)]
    if "server_params" in kwargs:
        return []
    return [
        _RawExtraction(
            None, "stdio", {}, ["*"], {"*": "none of a positional command, command=, url=, or server_params= was found"}
        )
    ]


def _extract_praisonai_mcp(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``praisonaiagents.mcp.MCP(command_or_string=None, args=None, *,
    command=None, timeout=60, ..., **kwargs)`` -- confirmed via source: a
    single overloaded identity argument (positional ``command_or_string``,
    or keyword ``command=``) is either a full shell-command STRING (stdio)
    or a URL string, auto-detected by an ``http(s)://``/``ws(s)://`` prefix
    -- same dispatch-on-an-already-resolved-literal principle as
    LlamaIndex's BasicMCPClient. Extra kwargs (``env=`` in every real
    example found) pass straight through to the underlying
    ``StdioServerParameters`` and are extracted here too. The separate,
    keyword-only two-argument form (``command=``, ``args=``) is also real
    (confirmed via source) and handled as its own branch; a positional
    ``args`` alongside a full command STRING was not observed in any real
    example, so it isn't scanned there -- an accepted, honest gap, not a
    guess."""
    kwargs = _call_kwargs(call)
    identity_node = call.args[0] if call.args else kwargs.get("command_or_string")
    if identity_node is not None:
        value, ok = _resolve(_unwrap_one_alias(identity_node, scopes), scopes)
        if not (ok and isinstance(value, str) and value):
            return [
                _RawExtraction(
                    None, "stdio", {}, ["*"], {"*": "command_or_string was not a resolvable string literal"}
                )
            ]
        if value.startswith(("http://", "https://", "ws://", "wss://")):
            return [_RawExtraction(None, "http", {"url": value}, [], {})]
        split = _split_shell_command(value)
        if split is None:
            return [
                _RawExtraction(
                    None, "stdio", {}, ["*"], {"*": "command_or_string resolved to an empty shell command"}
                )
            ]
        resolved: dict[str, Any] = {"command": split[0], "args": list(split[1])}
        env_resolved, env_unresolved, env_reasons = _extract_fields(kwargs, ("env",), scopes)
        resolved.update(env_resolved)
        return [_RawExtraction(None, "stdio", resolved, env_unresolved, env_reasons)]
    if "command" in kwargs:
        resolved, unresolved, reasons = _extract_fields(kwargs, ("command", "args", "env"), scopes)
        return [_RawExtraction(None, "stdio", resolved, unresolved, reasons)]
    return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "neither command_or_string nor command= was found"})]


def _extract_camel_mcp_client(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``camel.utils.mcp_client.MCPClient(config)`` -- ``config`` is a
    single positional-or-keyword dict literal (``ServerConfig`` fields:
    ``command``/``args``/``env``/``cwd`` for stdio, ``url``/``headers`` for
    http), confirmed via source."""
    node = call.args[0] if call.args else _call_kwargs(call).get("config")
    fields = _dict_literal_fields(_unwrap_one_alias(node, scopes)) if node is not None else None
    if fields is None:
        return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "config was not a resolvable dict literal"})]
    is_http = "url" in fields
    names = ("url", "headers") if is_http else ("command", "args", "env")
    resolved, unresolved, reasons = _extract_fields(fields, names, scopes)
    return [_RawExtraction(None, "http" if is_http else "stdio", resolved, unresolved, reasons)]


def _extract_camel_mcp_toolkit(call: ast.Call, scopes: list[dict]) -> list[_RawExtraction]:
    """``camel.toolkits.MCPToolkit(clients=[...], config_path=...,
    config_dict=...)`` -- confirmed via source to have three constructor
    idioms, all mutually exclusive in real usage:

    - ``config_dict={"mcpServers": {name: {...}, ...}}`` -- CAMEL's own
      documented config-file SHAPE, just passed inline as a dict literal
      instead of read from a file; reuses ``_extract_keyed_dict_fields``
      once the ``mcpServers`` key is found, the exact same per-entry
      dispatch LangGraph's ``MultiServerMCPClient`` already uses.
    - ``config_path=...`` -- a path to an EXTERNAL file; this scanner never
      reads files besides the ``.py`` source it's already parsing, so this
      is reported honestly as unresolved rather than guessed at (the one
      real example found in the wild used this form with a non-literal
      path expression, which would be unresolved either way).
    - ``clients=[MCPClient(...), ...]`` -- produces NO record of its own;
      each inline ``MCPClient(...)`` element independently matches its own
      top-level row via the generic recursive walk (same anti-double-
      report principle as every other wrapper shape), and the Assign/With
      alias-binding mechanism already captures whatever records that
      recursion produces via its own before/after diff -- no additional
      inherit-kwarg wiring needed for this specific list-of-inline-calls
      case. A ``clients=[already_bound_name, ...]`` list (a Name, not an
      inline Call) was not confirmed in any real example -- an accepted,
      honest gap, not a guess.
    """
    kwargs = _call_kwargs(call)
    if "config_dict" in kwargs:
        top = _dict_literal_fields(_unwrap_one_alias(kwargs["config_dict"], scopes))
        servers = _dict_literal_fields(top.get("mcpServers")) if top is not None and "mcpServers" in top else None
        if servers is not None:
            return _extract_keyed_dict_fields(servers, scopes)
        return [
            _RawExtraction(
                None, "stdio", {}, ["*"], {"*": "config_dict= was not a resolvable {'mcpServers': {...}} literal"}
            )
        ]
    if "config_path" in kwargs:
        return [
            _RawExtraction(
                None, "stdio", {}, ["*"], {"*": "config_path= points to an external config file this scanner does not read"}
            )
        ]
    if "clients" in kwargs:
        return []
    return [_RawExtraction(None, "stdio", {}, ["*"], {"*": "none of config_dict=, config_path=, or clients= was found"})]


SHAPE_HANDLERS: dict[str, Callable[[ast.Call, list[dict]], list[_RawExtraction]]] = {
    "stdio_kwargs": _extract_stdio_kwargs,
    "http_kwargs": _extract_http_kwargs,
    "params_kwarg_stdio": _extract_params_kwarg_stdio,
    "params_kwarg_http": _extract_params_kwarg_http,
    "keyed_dict": _extract_keyed_dict,
    "adapter_arg": _extract_adapter_arg,
    "wrapper_connection_params": _extract_wrapper_noop,
    "wrapper_server_params": _extract_wrapper_noop,
    "wrapper_server_info": _extract_wrapper_noop,
    "strands_mcp_client": _extract_strands_mcp_client,
    "pydantic_toolset_client": _extract_pydantic_mcp_toolset,
    "ag2_mcp_toolkit_server": _extract_ag2_mcp_toolkit,
    "llama_index_mcp_client": _extract_llama_index_mcp_client,
    # McpToolSpec(client=client) produces NO record of its own -- it
    # doesn't declare a server, it references an ALREADY-bound one via a
    # kwarg (see _INHERIT_KWARG_BY_SHAPE + the updated
    # _inherited_adapter_keys, not the wrapper-kwarg-recursion mechanism
    # every other "wrapper_*" shape uses, since `client` here is a bare
    # Name with no nested Call for the generic walk to independently find).
    "mcp_toolspec_client": _extract_wrapper_noop,
    "agno_mcp_tools": _extract_agno_mcp_tools,
    "praisonai_mcp": _extract_praisonai_mcp,
    "camel_mcp_client": _extract_camel_mcp_client,
    "camel_mcp_toolkit": _extract_camel_mcp_toolkit,
}

# Shapes guaranteed to produce exactly ONE extraction (index_in_call == 0)
# whenever they produce any at all -- safe for _predict_mcp_key (below) to
# key a not-yet-walked call site on. keyed_dict/adapter_arg can yield a
# variable count and are deliberately excluded (an inline
# tools=[MultiServerMCPClient({...})], with no intermediate variable, is an
# accepted gap rather than a guess).
_SINGLE_RECORD_SHAPES = frozenset(
    {
        "stdio_kwargs",
        "http_kwargs",
        "params_kwarg_stdio",
        "params_kwarg_http",
        "strands_mcp_client",
        "llama_index_mcp_client",
        "praisonai_mcp",
        "camel_mcp_client",
    }
)

# shape id -> the ONE kwarg name a "wrapper_*" shape recurses into, to find
# the real identity-bearing nested call. Kept as a side table (rather than
# a 6th KNOWN_MCP_SYMBOLS column) so adding a new wrapper shape never
# touches the existing table's row width.
_WRAPPER_KWARG_BY_SHAPE: dict[str, str] = {
    "wrapper_connection_params": "connection_params",
    "wrapper_server_params": "server_params",
    "wrapper_server_info": "server_info",
}

# shape id -> the ONE kwarg a shape reads to INHERIT an existing tool-set
# binding by NAME (not to defer to a nested Call's own independent match,
# which is what _WRAPPER_KWARG_BY_SHAPE is for) -- LlamaIndex's
# `McpToolSpec(client=client)`, where `client` is a bare Name already
# bound from `client = BasicMCPClient(...)` earlier. Consumed by
# `_inherited_adapter_keys` (below), the same place the existing
# adapter_arg-only, POSITIONAL-only inheritance already lives.
_INHERIT_KWARG_BY_SHAPE: dict[str, str] = {
    "mcp_toolspec_client": "client",
    # Agno's `MCPTools(server_params=...)` is a MIXED shape (it also
    # extracts directly for its url=/command= cases -- see
    # `_extract_agno_mcp_tools`), so it can't just be a pure
    # `_WRAPPER_KWARG_BY_SHAPE` entry the way ADK's/Haystack's wrapper
    # shapes are (that mechanism unconditionally recurses into the named
    # kwarg from `_predict_mcp_key`, which would wrongly treat a resolved
    # url=/command= call as "must recurse into server_params" too). Only
    # `_inherited_adapter_keys`'s own already-bound-Name inheritance is
    # needed here; `_predict_mcp_key`'s own `agno_mcp_tools` branch handles
    # the inline-nested-Call case separately.
    "agno_mcp_tools": "server_params",
}

# (module, symbol) -> the ONE kwarg on that AGENT'S OWN call whose value is
# a keyed servers-dict ({server_name: {...}, ...}), not a list of tool
# elements -- the OpenHands SDK's `Agent(mcp_config={...})` shape. Unlike
# `mcp_servers_spec` (a list processed by `_record_tools_arg`), this kwarg's
# value is never itself a Call site any other row could independently
# match, so there's no double-report risk in extracting it directly here.
_KEYED_DICT_KWARG_BY_AGENT: dict[tuple[str, str], str] = {
    ("openhands.sdk", "Agent"): "mcp_config",
    # ClaudeAgentOptions.mcp_servers: dict[str, McpServerConfig] -- a
    # Union of 4 TypedDicts (raw dicts, not objects), each with a `type`
    # discriminator ("stdio"/"sse"/"http"/"sdk") -- confirmed via source
    # (claude_agent_sdk/types.py). The discriminator is never read: same
    # as every other keyed-dict shape, presence of a `url` field alone
    # already disambiguates http from stdio; an "sdk" (in-process,
    # no address at all) entry simply resolves nothing and is correctly
    # excluded as not dial-eligible, never guessed at.
    ("claude_agent_sdk", "ClaudeAgentOptions"): "mcp_servers",
}

# (module, symbol) -> a SECOND, SIMULTANEOUS tools-bearing kwarg, processed
# with force_mcp=False (NOT the existing `mcp_servers_spec` mechanism's
# force_mcp=True) -- for a framework whose second argument is a general
# "toolset" container that legitimately mixes MCP AND ordinary non-MCP
# objects (PydanticAI's `toolsets=`), unlike the OpenAI Agents SDK's
# `mcp_servers=`, which is MCP-only BY THE SDK'S OWN CONTRACT. Using
# force_mcp=True here would misreport every ordinary custom toolset a
# developer writes as "could not be linked to a known MCP server" --
# treating it like `tools=` instead (force_mcp=False) reports it as an
# honest base tool when it isn't MCP, same as everywhere else.
_MIXED_TOOLS_KWARG_BY_AGENT: dict[tuple[str, str], str] = {
    ("pydantic_ai", "Agent"): "toolsets",
}

# (module, symbol) -> an ALTERNATE tools-bearing kwarg to try ONLY when the
# row's primary tools_spec kwarg wasn't given at all -- Semantic Kernel's
# `ChatCompletionAgent(plugins=[...])` (direct, primary) vs
# `ChatCompletionAgent(kernel=kernel_var)` (the decoupled style: plugins
# accumulate on a separately-built `Kernel` via `.add_plugin()` calls, see
# `_KERNEL_CONSTRUCTORS` below, then the agent just references that
# variable). Not a second SIMULTANEOUS bucket like `_MIXED_TOOLS_KWARG_
# BY_AGENT` -- a real codebase uses one style or the other, never both.
_FALLBACK_TOOLS_KWARG_BY_AGENT: dict[tuple[str, str], str] = {
    ("semantic_kernel.agents", "ChatCompletionAgent"): "kernel",
}

# (module, symbol) rows recognized as constructing a Kernel-like object --
# ONLY a variable assigned from one of THESE verified, import-resolved
# calls is ever treated as kernel-typed (see `_kernel_typed_names_stack`
# below), specifically to avoid the false-positive risk of matching
# `.add_plugin(...)` on an unrelated class that merely happens to share
# that method name: unlike every other match in this scanner, an
# attribute-method call has no import provenance of its own to verify, so
# the RECEIVER's own construction is what's verified instead.
_KERNEL_CONSTRUCTORS: frozenset[tuple[str, str]] = frozenset({("semantic_kernel", "Kernel")})

# Same verified-construction guard, for Letta's REST client -- ONLY a
# variable assigned from one of THESE calls is ever trusted for the
# `<name>.mcp_servers.create(...)` / `<name>.agents.create(...)` method
# chains below (see letta_client_typed_names_stack), for the identical
# false-positive reason _KERNEL_CONSTRUCTORS exists.
_LETTA_CLIENT_CONSTRUCTORS: frozenset[tuple[str, str]] = frozenset({("letta_client", "Letta")})


def _predict_mcp_key(
    node: ast.expr | None, import_map: "_ImportMap", scopes: list[dict], rel_str: str
) -> tuple[str, int, int, int] | None:
    """For a tools-list element that is itself an INLINE MCP-wrapper call
    (never assigned to a variable first, e.g. ``tools=[McpToolset(...)]``)
    -- predict the (file, line, index) key its CallSiteRecord will have
    once the generic recursive walk independently visits and matches it,
    WITHOUT creating any record here (that stays the generic walk's job
    alone, same anti-double-report principle as ``_extract_adapter_arg``).
    A "wrapper_*" shape recurses one hop into its own designated kwarg to
    find the real identity-bearing call (handles arbitrary wrapper depth,
    e.g. Google ADK's McpToolset -> StdioConnectionParams -> the real
    StdioServerParameters); a shape in ``_SINGLE_RECORD_SHAPES`` predicts
    itself directly, but ``strands_mcp_client``/``pydantic_toolset_client``'s
    own conditionals (no record at all without a ``url`` kwarg / without a
    resolvable positional client) are re-checked here too, since a
    prediction that assumed a record which never actually gets created
    would silently mislink the agent to nothing. Returns ``None`` (no
    prediction -- caller falls back to ordinary base/unresolved handling)
    for anything not confirmed predictable this way."""
    if not isinstance(node, ast.Call):
        return None
    origin = import_map.resolve_call_symbol(node)
    if origin is None:
        return None
    for known_module, known_symbol, shape, _name_kwarg, _framework in KNOWN_MCP_SYMBOLS:
        if origin != (known_module, known_symbol):
            continue
        if shape in _WRAPPER_KWARG_BY_SHAPE:
            inner = _call_kwargs(node).get(_WRAPPER_KWARG_BY_SHAPE[shape])
            if inner is None:
                return None
            return _predict_mcp_key(_unwrap_one_alias(inner, scopes), import_map, scopes, rel_str)
        if shape == "strands_mcp_client" and "url" not in _call_kwargs(node):
            return None
        if shape == "agno_mcp_tools":
            call_kwargs = _call_kwargs(node)
            if "url" in call_kwargs or "command" in call_kwargs or node.args:
                return (rel_str, node.lineno, node.col_offset, 0)
            if "server_params" in call_kwargs:
                # `tools=[MCPTools(server_params=StdioServerParameters(...))]`
                # -- an inline nested Call, never assigned to a variable
                # first; recurse into it, same as every `_WRAPPER_KWARG_BY_
                # SHAPE` entry already does. (The already-bound-Name variant
                # of this same kwarg is a separate, With/Assign-time-only
                # concern -- see `_INHERIT_KWARG_BY_SHAPE`'s own entry for
                # this shape.)
                return _predict_mcp_key(
                    _unwrap_one_alias(call_kwargs["server_params"], scopes), import_map, scopes, rel_str
                )
            return None
        if shape == "llama_index_mcp_client" and not node.args and "command_or_url" not in _call_kwargs(node):
            return None
        if shape in ("pydantic_toolset_client", "ag2_mcp_toolkit_server"):
            # Same "positional client/server arg, defer if it's a nested
            # Call" logic for both -- PydanticAI's MCPToolset and AG2's
            # MCPToolkit share the identical shape.
            if not node.args:
                return None
            inner = _unwrap_one_alias(node.args[0], scopes)
            if isinstance(inner, ast.Call):
                # Deferred to the nested transport call, exactly like the
                # extractor itself defers -- recurse to find ITS predicted
                # key, don't treat "deferred" as "unpredictable".
                return _predict_mcp_key(inner, import_map, scopes, rel_str)
            return (rel_str, node.lineno, node.col_offset, 0)
        if shape in _SINGLE_RECORD_SHAPES:
            return (rel_str, node.lineno, node.col_offset, 0)
        return None
    return None


def _spec_node(call: ast.Call, spec: tuple) -> ast.expr | None:
    """The AST node a ("kwarg", name) | ("position", index) spec points at,
    or None if that argument wasn't given."""
    kind = spec[0]
    if kind == "kwarg":
        return _call_kwargs(call).get(spec[1])
    if kind == "position":
        idx = spec[1]
        return call.args[idx] if idx < len(call.args) else None
    return None


def _resolve_one_tool_element(
    node: ast.expr,
    lookup_tool_set: Callable[[str], list[tuple[str, int, int, int]] | None],
    import_map: "_ImportMap",
    scopes: list[dict],
    rel_str: str,
) -> tuple[str, str | list[tuple[str, int, int, int]]]:
    """One element of a tools-bearing argument -> ("mcp_keys", [(file,line,index), ...]) |
    ("base", display name) | ("unresolved", reason). A bare Name is checked
    against ``lookup_tool_set`` FIRST (is this variable an MCP tool-set,
    searching the current lexical scope outward?); only a Name that ISN'T
    one is treated as a base tool -- never the other way around, since a
    Name we can't place at all is exactly the case this scanner must not
    guess at. A bare Call is checked against ``_predict_mcp_key`` next (is
    this an INLINE MCP-wrapper call, e.g. ``tools=[McpToolset(...)]``, never
    assigned to a variable first?) -- only a Call ``_predict_mcp_key``
    can't place at all falls through to a "base" tool named after the
    call's own function/attribute name, same as before this existed.

    Deliberately returns raw (file, line, index) keys, not server NAMES: a
    server's final name is only known once every file has been scanned and
    ``dedupe_servers()`` has run globally (a name collision resolved in
    favor of an earlier-declared file could otherwise be missed here) --
    see ``resolve_agent_links`` for the second pass that turns these keys
    into names."""
    if isinstance(node, ast.Name):
        keys = lookup_tool_set(node.id)
        if keys is not None:
            return ("mcp_keys", keys)
        return ("base", node.id)
    if isinstance(node, ast.Attribute):
        # `kernel=self.kernel` (Semantic Kernel's decoupled style) --
        # `self.kernel` is checked against `lookup_tool_set` via its
        # dotted name FIRST, same precedence rule as the bare-Name case
        # above, now that _bind_tool_set can hold dotted-attribute keys
        # too (see Bug S / _dotted_name). Previously this branch never
        # consulted the binding at all, so an instance-attribute
        # reference silently became a meaningless "base tool named
        # kernel" even when it WAS a real, populated tool-set.
        dotted = _dotted_name(node)
        if dotted is not None:
            keys = lookup_tool_set(dotted)
            if keys is not None:
                return ("mcp_keys", keys)
        return ("base", node.attr)
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        # A bare string literal IS the identity itself, no object to
        # inspect further -- Claude Agent SDK's `allowed_tools=["Read"]`
        # and Letta's `tool_ids=["tool-abc123"]` are both plain lists of
        # tool-name/ID strings, never objects like every other framework's
        # tools= list. Without this case, a Constant fell through to the
        # final "unresolved" branch below, treating a perfectly literal,
        # already-resolved name as if it were something ambiguous.
        return ("base", node.value)
    if isinstance(node, ast.Call):
        predicted = _predict_mcp_key(node, import_map, scopes, rel_str)
        if predicted is not None:
            return ("mcp_keys", [predicted])
        if isinstance(node.func, ast.Name):
            return ("base", node.func.id)
        if isinstance(node.func, ast.Attribute):
            return ("base", node.func.attr)
        return ("unresolved", "an unnamed call expression")
    if isinstance(node, ast.Starred):
        # CAMEL-AI's ``tools=[*mcp_toolkit.get_tools()]`` (an inline,
        # zero-arg passthrough method call, never assigned to a variable
        # first -- the existing `_PASSTHROUGH_TOOL_METHOD_NAMES` mechanism
        # only ever ran from the ``ast.Assign`` handler before this;
        # ``get_tools`` is already in that set, added for LangGraph's own
        # MultiServerMCPClient.get_tools(), so no new method name is needed,
        # only this new call site for consulting it) OR
        # ``tools=[*tools]`` (a plain ALREADY-bound tool-set variable,
        # unpacked inline -- the ``X = client.get_tools()`` assign-time
        # passthrough already bound ``tools`` before this list was ever
        # reached, so a bare Name here only needs the ordinary lookup).
        #
        # Confirmed via adversarial testing against camel-ai/camel's own
        # real source: `tools=[*SomeToolkit().get_tools()]` (or `*x` for an
        # already-bound plain variable) is CAMEL's own GENERAL idiom for
        # ANY toolkit, not just MCP ones (``AudioAnalysisToolkit()``,
        # ``BrowserToolkit()``, dozens of others) -- an unrecognized one
        # here must fall back to an honest "base" tool the exact same way
        # an ordinary (non-starred) unrecognized Call/Name already does
        # everywhere else in this function, never "unresolved" (that's
        # reserved for something genuinely undeterminable, e.g. a truly
        # dynamic expression -- a plain, non-MCP toolkit call is neither).
        inner = node.value
        if isinstance(inner, ast.Name):
            keys = lookup_tool_set(inner.id)
            if keys is not None:
                return ("mcp_keys", keys)
            return ("base", inner.id)
        if isinstance(inner, ast.Call):
            if (
                isinstance(inner.func, ast.Attribute)
                and inner.func.attr in _PASSTHROUGH_TOOL_METHOD_NAMES
                and isinstance(inner.func.value, ast.Name)
            ):
                keys = lookup_tool_set(inner.func.value.id)
                if keys is not None:
                    return ("mcp_keys", keys)
            predicted = _predict_mcp_key(inner, import_map, scopes, rel_str)
            if predicted is not None:
                return ("mcp_keys", [predicted])
            if isinstance(inner.func, ast.Name):
                return ("base", inner.func.id)
            if isinstance(inner.func, ast.Attribute):
                return ("base", inner.func.attr)
            return ("unresolved", "a starred (*) unnamed call expression")
        return ("unresolved", _unresolved_reason(inner))
    return ("unresolved", _unresolved_reason(node))


# =============================================================================
# Per-file scan
# =============================================================================


def scan_file(
    path: Path, root: Path
) -> tuple[list[CallSiteRecord], list[AgentRecord], list[dict], list[dict], list[dict], list[str]]:
    """Returns (mcp_records, agents, agent_mcp_links_pending, agent_base_tools,
    agent_unresolved_tools, warnings). ``agent_mcp_links_pending`` is
    ``[{"agent": name, "keys": [(file, line), ...]}]`` -- raw MCP call-site
    keys, not yet resolved to final server names (see
    ``resolve_agent_links``, which needs the full cross-file picture after
    dedup). The other two are already dict-shaped (agent/tool name, or
    reason) since nothing downstream needs the AST nodes back."""
    warnings: list[str] = []
    empty: tuple = ([], [], [], [], [], warnings)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        warnings.append(f"{path}: skipped (could not read: {exc})")
        return empty
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        warnings.append(f"{path}: skipped (SyntaxError: {exc.msg} at line {exc.lineno})")
        return empty

    import_map = _ImportMap.build(tree)
    records: list[CallSiteRecord] = []
    agents: list[AgentRecord] = []
    agent_mcp_links_pending: list[dict] = []
    agent_base_tools: list[dict] = []
    agent_unresolved_tools: list[dict] = []
    # variable name (within whatever LEXICAL scope declared it) -> the
    # (file, line, index_in_call) keys of the MCP CallSiteRecord(s) it
    # represents. Scope-STACKED, one frame per module/function body (frame 0
    # is the module, pushed once below `walk` is defined; a new frame is
    # pushed/popped exactly when `walk` enters/leaves a FunctionDef/
    # AsyncFunctionDef). A single, file-wide dict here (as this used to be,
    # deliberately, on the theory that "over-scoping this would just resolve
    # less, the safe direction") turned out to be unsafe in the OTHER
    # direction too: two unrelated functions reusing an ordinary name like
    # `tools` would silently share one function's real MCP binding, falsely
    # linking the other function's agent to a server it never declared while
    # dropping its real base tool entirely (Bug L). Reads search innermost to
    # outermost -- a module-level binding stays visible from inside a
    # function, matching real Python name resolution, which keeps this
    # exactly as permissive as before for the legitimate case. Writes only
    # ever touch the CURRENT (innermost) frame, so a nested function's own
    # local variable of the same name can never be written into (or read
    # stale data out of) an unrelated, already-exited sibling scope.
    tool_set_bindings_stack: list[dict[str, list[tuple[str, int, int, int]]]] = [{}]

    def _lookup_tool_set(name: str) -> list[tuple[str, int, int, int]] | None:
        for frame in reversed(tool_set_bindings_stack):
            if name in frame:
                # A copy, never the stored list itself -- a caller further
                # down this same walk (e.g. the `+`-chain merge below) reads
                # this into ITS OWN new list via extend()/`+`, but handing
                # back the frame's own list-by-reference would let any
                # future accidental in-place mutation of that result corrupt
                # every other binding still pointing at the same name.
                return list(frame[name])
        return None

    def _bind_tool_set(
        name: str, keys: list[tuple[str, int, int, int]], *, accumulate: bool = False
    ) -> None:
        # A DOTTED name (`self.kernel`, from _dotted_name) is an
        # INSTANCE ATTRIBUTE with object lifetime, not call-frame
        # lifetime -- e.g. `self.kernel.add_plugin(...)` called from
        # one method, then `kernel=self.kernel` referenced from
        # ANOTHER. Written into frame 0 (the module frame, never
        # popped) instead of the current innermost frame so it
        # survives across sibling methods, same reasoning as
        # _mark_kernel_typed/_mark_letta_client_typed. Each successive
        # `.add_plugin(...)` call genuinely ADDS a plugin to the SAME
        # kernel instance over its lifetime, so a dotted name keeps
        # accumulating -- and a call site that (this time) resolved to
        # zero plugins adds nothing, but must not touch what the
        # instance already accumulated from earlier calls.
        #
        # `accumulate=True` covers the one caller where the RECEIVER is a
        # BARE (non-dotted) local variable but the call is still a mutating
        # METHOD call, not an assignment -- `kernel.add_plugin(...)` on a
        # plain local `kernel`. That call site is adding to the same kernel
        # object across repeated calls exactly like the dotted case, so it
        # must accumulate too, into the CURRENT frame (a bare local's
        # lifetime is call-frame scoped, unlike a dotted attribute's).
        # Without this distinction, a bare name would always fall into the
        # rebind branch below and a second `add_plugin(...)` call with an
        # unresolvable plugin arg would wipe out the plugins added by the
        # first.
        if "." in name or accumulate:
            if keys:
                frame = tool_set_bindings_stack[0] if "." in name else tool_set_bindings_stack[-1]
                frame.setdefault(name, []).extend(keys)
            return

        # A bare local Name is different: it's bound by assignment (or a
        # `with ... as name:` alias), so a second binding REBINDS it --
        # rebinding it (two sequential `with MCPServerAdapter(...) as
        # tools:` blocks, the canonical CrewAI idiom) means it now
        # refers ONLY to the new value, exactly like a real
        # reassignment. Accumulating here left every earlier binding's
        # server list still attached, so both `with` blocks' agents
        # ended up linked to both servers. Critically, this must rebind
        # even when `keys` comes back EMPTY (`tools = [1]`, or any RHS
        # this walk couldn't resolve to an MCP declaration) -- a real
        # Python reassignment discards the variable's old value
        # unconditionally, so gating this on `if keys:` (as this used to)
        # left the PREVIOUS binding's server list attached to `name`
        # after it had genuinely been reassigned to something else.
        frame = tool_set_bindings_stack[-1]
        if keys:
            frame[name] = list(keys)
        else:
            frame.pop(name, None)

    def _binop_operand_keys(expr: ast.expr) -> list[tuple[str, int, int, int]] | None:
        """Haystack's documented ``Toolset`` merge idiom -- ``all_tools =
        maps_toolset + routing_toolset`` -- combines two ALREADY-bound
        tool-set variables via ``+``. Resolves a `+`-chain of plain Names
        into the union of their keys, but returns None (never a PARTIAL
        union) the moment any operand isn't a Name pointing to a known
        tool-set binding -- a mix of a real toolset and something else
        (``mcp_tools + [custom_tool]``, the existing intentionally-
        unresolved case) is exactly the kind of guess this scanner must
        not make; it keeps failing exactly as before for that case."""
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = _binop_operand_keys(expr.left)
            right = _binop_operand_keys(expr.right)
            if left is None or right is None:
                return None
            return left + right
        if isinstance(expr, ast.Name):
            return _lookup_tool_set(expr.id)
        return None

    # Scope-stacked the SAME way as tool_set_bindings_stack (pushed/popped
    # in lockstep, at the identical FunctionDef/AsyncFunctionDef points
    # below) -- tracks ONLY names assigned from a verified, import-resolved
    # _KERNEL_CONSTRUCTORS call (e.g. `k = Kernel()`). This is the guard
    # against the false-positive risk of a bare `.add_plugin(...)` method
    # name match: an unrelated class that happens to expose the same
    # method name is never treated as a Kernel, because IT was never
    # constructed via one of these specific, verified calls.
    kernel_typed_names_stack: list[set[str]] = [set()]

    def _mark_kernel_typed(name: str) -> None:
        # Deliberately does NOT pre-create an (empty) tool_set_bindings
        # entry -- a `kernel=k` reference where `k` never received any
        # `.add_plugin(...)` call falls back to the SAME "base tool named
        # k" honesty every other unrecognized Name already gets, rather
        # than a confusing "unresolved MCP reference" for a kernel that
        # was always meant to carry zero tools.
        #
        # A DOTTED name (`self.kernel`, from `_dotted_name`) is an
        # INSTANCE ATTRIBUTE, not a local variable -- it has object
        # lifetime, not call-frame lifetime (`self.kernel = Kernel()` in
        # `__init__`, `.add_plugin(...)` called from a DIFFERENT method
        # entirely, is the realistic, common case). Written into frame 0
        # (the module frame, never popped) instead of the current
        # innermost frame so it stays visible across sibling methods --
        # unlike a bare local Name, which keeps the existing, precise
        # per-function scoping (Bug L's fix) completely unchanged.
        frame = kernel_typed_names_stack[0] if "." in name else kernel_typed_names_stack[-1]
        frame.add(name)

    def _is_kernel_typed(name: str) -> bool:
        return any(name in frame for frame in reversed(kernel_typed_names_stack))

    # Same structure as kernel_typed_names_stack, kept as a SEPARATE stack
    # (not a generalized "instance kind" map) so the already-tested Kernel
    # mechanism above is never touched -- Letta's client has its own two
    # method-chain shapes to recognize (`.mcp_servers.create(...)` /
    # `.agents.create(...)`), unrelated to `.add_plugin(...)`.
    letta_client_typed_names_stack: list[set[str]] = [set()]

    def _mark_letta_client_typed(name: str) -> None:
        # Same file-scope-for-dotted-names reasoning as _mark_kernel_typed.
        frame = letta_client_typed_names_stack[0] if "." in name else letta_client_typed_names_stack[-1]
        frame.add(name)

    def _is_letta_client_typed(name: str) -> bool:
        return any(name in frame for frame in reversed(letta_client_typed_names_stack))

    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_str = str(rel).replace(os.sep, "/")

    def _resolve_name_spec(call: ast.Call, spec: tuple, scopes: list[dict], assigned_to: str | None) -> str:
        if spec[0] != "assigned_var":
            node = _spec_node(call, spec)
            value, ok = _resolve(node, scopes)
            if ok and isinstance(value, str) and value:
                return value
        if assigned_to:
            return assigned_to
        return f"{rel_str}:{call.lineno}"

    def _record_tools_arg(
        agent_name: str, agent_location: str, node: ast.expr | None, call_line: int, force_mcp: bool, scopes: list[dict]
    ) -> None:
        """``agent_location`` (``file:line`` of the matched Agent(...) call
        itself) is the real correlation key -- ``agent_name`` alone is NOT
        unique (two different agents very plausibly share a display name,
        e.g. two CrewAI crews each with their own "Researcher" role), so
        every emitted row carries both: the location for unambiguous
        grouping, the name for a human to actually read."""
        if node is None:
            return
        # One level of the SAME same-scope, unconditional alias resolution
        # used everywhere else in this file (`_unwrap_one_alias`) -- covers
        # `tools = [custom_tool]; Agent(tools=tools)` (a plain local variable
        # holding a base-tool list, not an MCP tool-set at all): without
        # this, the bare Name `tools` would report itself as the base tool's
        # display name instead of what it actually points to. Only applied
        # when `node` ISN'T already a tracked tool-set binding -- checking
        # tool_set_bindings must always win first (a `with ... as tools:`
        # alias is never present in this same-scope table at all, since it
        # isn't an ast.Assign, but `tools = adapter.tools`'s `tools` IS both
        # a tool_set_binding AND a resolvable same-scope alias; unwrapping it
        # here first would resolve straight past the binding into `adapter
        # .tools`'s own Attribute node and misreport it as a base tool named
        # "tools").
        if isinstance(node, ast.Name) and _lookup_tool_set(node.id) is None:
            node = _unwrap_one_alias(node, scopes)
        if isinstance(node, ast.BinOp):
            # `tools=maps_toolset + routing_toolset` used INLINE, no
            # intermediate variable -- same `+`-merge idiom as the
            # assignment case (_binop_operand_keys), same "never a partial
            # union" rule: `mcp_tools + [custom_tool]` still falls through
            # to the unresolved report below exactly as before, since
            # `[custom_tool]` isn't a Name pointing to a tool-set binding.
            binop_keys = _binop_operand_keys(node)
            if binop_keys is not None:
                agent_mcp_links_pending.append({"agent": agent_name, "agent_location": agent_location, "keys": binop_keys})
                return
        if not isinstance(node, (ast.List, ast.Tuple)) and not isinstance(
            node, (ast.Name, ast.Attribute, ast.Call)
        ):
            # A BinOp (mcp_tools + [custom]) or anything else not a literal
            # list/name/attribute/call -- not split, reported honestly.
            agent_unresolved_tools.append(
                {
                    "agent": agent_name,
                    "agent_location": agent_location,
                    "file": rel_str,
                    "line": call_line,
                    "reason": _unresolved_reason(node),
                }
            )
            return
        elements = node.elts if isinstance(node, (ast.List, ast.Tuple)) else [node]
        for element in elements:
            kind, value = _resolve_one_tool_element(element, _lookup_tool_set, import_map, scopes, rel_str)
            if kind == "mcp_keys":
                agent_mcp_links_pending.append({"agent": agent_name, "agent_location": agent_location, "keys": value})
            elif kind == "base" and force_mcp:
                # mcp_servers= elements are always MCP objects on this
                # framework's own contract -- a Name that isn't a tracked
                # tool-set binding still isn't a base tool here.
                agent_unresolved_tools.append(
                    {
                        "agent": agent_name,
                        "agent_location": agent_location,
                        "file": rel_str,
                        "line": call_line,
                        "reason": f"{value!r} could not be linked to a known MCP server declaration",
                    }
                )
            elif kind == "base":
                agent_base_tools.append({"agent": agent_name, "agent_location": agent_location, "tool": value})
            else:
                agent_unresolved_tools.append(
                    {
                        "agent": agent_name,
                        "agent_location": agent_location,
                        "file": rel_str,
                        "line": call_line,
                        "reason": value,
                    }
                )

    def _record_keyed_dict_kwarg(agent_name: str, agent_location: str, node: ast.expr | None, scopes: list[dict]) -> None:
        """The OpenHands SDK's ``mcp_config={"server_name": {...}, ...}``
        shape -- a keyed servers-dict passed DIRECTLY as a kwarg on the
        agent's own call, never a separate MCP-declaring call site the
        generic recursive walk could independently match. Safe to create
        real CallSiteRecords right here, synchronously (no double-report
        risk the way an inline nested Call would carry, since a dict
        literal is never itself matched against KNOWN_MCP_SYMBOLS)."""
        if node is None:
            return
        if isinstance(node, ast.Name) and _lookup_tool_set(node.id) is None:
            node = _unwrap_one_alias(node, scopes)
        top = _dict_literal_fields(node)
        if top is None:
            agent_unresolved_tools.append(
                {
                    "agent": agent_name,
                    "agent_location": agent_location,
                    "file": rel_str,
                    "line": node.lineno if hasattr(node, "lineno") else 0,
                    "reason": "mcp_config= was not a resolvable dict literal",
                }
            )
            return
        before = len(records)
        for index, extraction in enumerate(_extract_keyed_dict_fields(top, scopes)):
            records.append(
                CallSiteRecord(
                    framework="openhands",
                    shape="keyed_dict_kwarg",
                    file=rel_str,
                    line=node.lineno,
                    transport=extraction.transport,
                    resolved=extraction.resolved,
                    unresolved_fields=extraction.unresolved,
                    unresolved_reason=extraction.reasons,
                    explicit_name=extraction.explicit_name,
                    index_in_call=index,
                    col_offset=node.col_offset,
                )
            )
        new_keys = [r.key() for r in records[before:]]
        if new_keys:
            agent_mcp_links_pending.append({"agent": agent_name, "agent_location": agent_location, "keys": new_keys})

    def _inherited_adapter_keys(expr: ast.expr) -> list[tuple[str, int, int, int]]:
        """``MCPServerAdapter(X)`` where ``X`` (or an element of X, if a
        list) is a Name that's ALREADY a tool-set binding -- e.g.
        ``params = StdioServerParameters(...); with MCPServerAdapter(params)
        as tools:``. ``_extract_adapter_arg`` deliberately produces NO new
        CallSiteRecord for an aliased reference like this (to avoid
        double-reporting an inline nested call that generic recursion would
        also find) -- so the diff-based key capture in ``walk``'s With/
        Assign handlers sees zero new records and would otherwise silently
        drop the link entirely. This is the other half of that design: the
        new alias must still inherit whatever the referenced binding
        already represents.

        Also handles the KWARG-based variant of the same idea (see
        ``_INHERIT_KWARG_BY_SHAPE``) -- LlamaIndex's ``McpToolSpec(client=
        client)``, where ``client`` is a bare Name, not a positional arg,
        and there's no list-of-Names form to consider (this constructor
        only ever takes ONE MCP client).

        Also handles the identical gap for every ``_WRAPPER_KWARG_BY_SHAPE``
        shape (Google ADK's ``McpToolset(connection_params=...)``, Haystack's
        ``MCPToolset(server_info=...)``, Agno's ``MCPTools(server_params=
        ...)``) -- confirmed via adversarial testing against agno-agi/agno's
        own real cookbook (``server_params = StdioServerParameters(...);
        async with MCPTools(server_params=server_params) as mcp_tools:``):
        the wrapped call was walked and bound to ``server_params`` on an
        EARLIER, separate statement, so the generic recursive walk's "the
        nested call independently matches its own row" story (what
        ``_WRAPPER_KWARG_BY_SHAPE`` exists for -- see its own docstring) never
        fires for THIS reference, since ``server_params`` here is a bare
        Name, not a nested Call at all -- the exact same shape of gap
        ``_INHERIT_KWARG_BY_SHAPE`` already exists to cover."""
        if not isinstance(expr, ast.Call):
            return []
        origin = import_map.resolve_call_symbol(expr)
        if origin is None:
            return []
        shape = next((s for m, sym, s, *_ in KNOWN_MCP_SYMBOLS if origin == (m, sym)), None)
        if shape == "adapter_arg" and expr.args:
            arg = expr.args[0]
            if isinstance(arg, ast.Name):
                return list(_lookup_tool_set(arg.id) or [])
            if isinstance(arg, (ast.List, ast.Tuple)):
                keys: list[tuple[str, int, int, int]] = []
                for elt in arg.elts:
                    if isinstance(elt, ast.Name):
                        keys.extend(_lookup_tool_set(elt.id) or [])
                return keys
            return []
        if shape in _INHERIT_KWARG_BY_SHAPE:
            arg = _call_kwargs(expr).get(_INHERIT_KWARG_BY_SHAPE[shape])
            if isinstance(arg, ast.Name):
                return list(_lookup_tool_set(arg.id) or [])
            return []
        if shape in _WRAPPER_KWARG_BY_SHAPE:
            arg = _call_kwargs(expr).get(_WRAPPER_KWARG_BY_SHAPE[shape])
            if isinstance(arg, ast.Name):
                return list(_lookup_tool_set(arg.id) or [])
            return []
        return []

    def walk(node: ast.AST, scopes: list[dict[str, ast.expr]], assigned_to: str | None = None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            new_scopes = [*scopes, _function_scope(node)]
            # A fresh, empty tool_set_bindings frame for this function's OWN
            # local variables -- popped again once this function's body is
            # fully walked, so a name bound inside it (e.g. a generic `tools`
            # local) can never leak into or be mistaken for an unrelated
            # sibling function's own same-named local (Bug L).
            tool_set_bindings_stack.append({})
            kernel_typed_names_stack.append(set())
            letta_client_typed_names_stack.append(set())
            try:
                for child in ast.iter_child_nodes(node):
                    walk(child, new_scopes)
            finally:
                tool_set_bindings_stack.pop()
                kernel_typed_names_stack.pop()
                letta_client_typed_names_stack.pop()
            return

        if isinstance(node, (ast.With, ast.AsyncWith)):
            # `with MCPServerAdapter(...) as tools:` -- the one shape this
            # walker previously had zero visibility into: the "as NAME"
            # alias was never read, so nothing downstream could ever
            # correlate an Agent(tools=tools) call back to the server(s)
            # `tools` represents. Walking context_expr with assigned_to set
            # covers both a direct MCP match and an Agent(...) match (rare
            # inside a `with`, but handled the same way either way).
            for item in node.items:
                alias = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else None
                if alias is not None:
                    # Clear any binding an EARLIER `with ... as {alias}:` in
                    # this same scope left behind before this block's
                    # (possibly empty/unresolvable) result is computed --
                    # `with ... as name:` REBINDS `name`, so if this block's
                    # context_expr doesn't resolve to anything, `alias` must
                    # become unknown again rather than silently keep
                    # pointing at the earlier block's servers. `_bind_tool_set`
                    # itself now also rebinds a bare Name to empty/unresolved
                    # correctly, making this pop belt-and-suspenders rather
                    # than load-bearing -- kept anyway since it costs nothing
                    # and documents the intent right at the alias site.
                    tool_set_bindings_stack[-1].pop(alias, None)
                before = len(records)
                walk(item.context_expr, scopes, assigned_to=alias)
                if alias is not None:
                    new_keys = [r.key() for r in records[before:]] + _inherited_adapter_keys(item.context_expr)
                    _bind_tool_set(alias, new_keys)
            for child in node.body:
                walk(child, scopes)
            return

        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute):
            # `self.client = Letta(...)` / `self.kernel = Kernel()` --
            # confirmed via adversarial testing to be the most common
            # real-world pattern for wrapping an SDK client inside a
            # service class, and previously TOTALLY invisible (not a
            # mislink -- the old bare-Name-only target check simply never
            # matched an Attribute target at all, so the guarded-
            # instance-constructor check below never even ran). ONLY
            # those two guarded-construction cases are handled here, via
            # `_dotted_name` (the same key the `.add_plugin()`/
            # `.mcp_servers.create()`/`.agents.create()` call-recognition
            # checks below now also use). Deliberately does NOT return --
            # an Attribute target already fell through to the generic
            # recursion at the very end of `walk()` before this branch
            # existed (the old check just never matched it), so any
            # nested MCP declaration inside `rhs` (e.g. `self.adapter =
            # MCPServerAdapter(StdioServerParameters(...))`) must keep
            # being found that same way. Everything else this whole
            # Assign-handling block does for a plain local Name
            # (tool_set_bindings, the `+` merge idiom, name-fallback
            # attribution, etc.) is a real but separate, broader gap,
            # deliberately out of scope for this fix.
            dotted = _dotted_name(node.targets[0])
            rhs = node.value.value if isinstance(node.value, ast.Await) else node.value
            if dotted is not None and isinstance(rhs, ast.Call):
                origin = import_map.resolve_call_symbol(rhs)
                if origin in _KERNEL_CONSTRUCTORS:
                    _mark_kernel_typed(dotted)
                elif origin in _LETTA_CLIENT_CONSTRUCTORS:
                    _mark_letta_client_typed(dotted)

        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            rhs = node.value.value if isinstance(node.value, ast.Await) else node.value

            # `X = adapter.tools` / `X = client.get_tools()` -- a pure
            # lookup against an existing binding, no new call to walk.
            if isinstance(rhs, ast.Attribute) and rhs.attr == "tools" and isinstance(rhs.value, ast.Name):
                existing = _lookup_tool_set(rhs.value.id)
                if existing:
                    _bind_tool_set(target, existing)
                return
            if (
                isinstance(rhs, ast.Call)
                and isinstance(rhs.func, ast.Attribute)
                and rhs.func.attr in _PASSTHROUGH_TOOL_METHOD_NAMES
                and isinstance(rhs.func.value, ast.Name)
            ):
                existing = _lookup_tool_set(rhs.func.value.id)
                if existing:
                    _bind_tool_set(target, existing)
                return

            # `X = mcp_server_tools(StdioServerParams(...))` -- a wrapper
            # whose sole argument is itself an MCP declaration; walk THAT
            # (one alias hop unwrapped), not the wrapper call itself.
            if isinstance(rhs, ast.Call):
                origin = import_map.resolve_call_symbol(rhs)
                if origin in _TOOLSET_WRAPPER_FUNCS and rhs.args:
                    before = len(records)
                    walk(_unwrap_one_alias(rhs.args[0], scopes), scopes)
                    new_keys = [r.key() for r in records[before:]]
                    _bind_tool_set(target, new_keys)
                    return
                # `k = Kernel()` (Semantic Kernel) -- mark `target` as
                # kernel-typed so a LATER `target.add_plugin(...)` call is
                # trusted (see _KERNEL_CONSTRUCTORS's own docstring on why
                # this verified-construction gate exists at all). No
                # records of its own; Kernel() isn't an MCP declaration.
                if origin in _KERNEL_CONSTRUCTORS:
                    _mark_kernel_typed(target)
                    return
                # `client = Letta()` -- same guarded-construction pattern,
                # trusting LATER `target.mcp_servers.create(...)` /
                # `target.agents.create(...)` method chains.
                if origin in _LETTA_CLIENT_CONSTRUCTORS:
                    _mark_letta_client_typed(target)
                    return

            # `all_tools = maps_toolset + routing_toolset` (Haystack's
            # documented Toolset `+` merge idiom) -- BEFORE the generic
            # walk below, since walking a bare BinOp of two Names is a
            # no-op (Names have no children), which would otherwise leave
            # `target` unbound entirely and reveal the raw, un-mergeable
            # BinOp expression the moment it's later referenced.
            if isinstance(rhs, ast.BinOp):
                binop_keys = _binop_operand_keys(rhs)
                if binop_keys is not None:
                    _bind_tool_set(target, binop_keys)
                    return

            # Ordinary assignment -- walk the RHS normally. Covers a direct
            # `X = MCPServerAdapter(...)` (manual, non-`with` usage -- the
            # produced record(s) get attributed to `target` below the same
            # way the `with` case does) and `X = Agent(...)` (assigned_to
            # feeds that framework's name-fallback rule).
            before = len(records)
            walk(rhs, scopes, assigned_to=target)
            new_keys = [r.key() for r in records[before:]] + _inherited_adapter_keys(rhs)
            _bind_tool_set(target, new_keys)
            return

        if isinstance(node, ast.Call):
            # `kernel.add_plugin(MCPStdioPlugin(...))` (Semantic Kernel) --
            # a plain attribute-method call on a LOCAL variable has no
            # import provenance `resolve_call_symbol` could ever confirm
            # (unlike everything else this scanner matches), so the
            # receiver's own verified construction is what's trusted
            # instead (see _KERNEL_CONSTRUCTORS/_mark_kernel_typed). Walks
            # the plugin arg itself (mirroring the mcp_server_tools wrapper
            # precedent above) and returns -- skipping the generic
            # recursion below for THIS node, since that one child is
            # already handled; nothing about the OUTER add_plugin() call
            # itself is ever a real MCP/agent declaration.
            _kernel_receiver = _dotted_name(node.func.value) if isinstance(node.func, ast.Attribute) else None
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_plugin"
                and _kernel_receiver is not None
                and _is_kernel_typed(_kernel_receiver)
            ):
                # `plugin` is the real (confirmed) first-param name, but
                # usable as either positional or keyword -- check both.
                plugin_arg = node.args[0] if node.args else _call_kwargs(node).get("plugin")
                if plugin_arg is not None:
                    before = len(records)
                    walk(_unwrap_one_alias(plugin_arg, scopes), scopes)
                    new_keys = [r.key() for r in records[before:]]
                    # `add_plugin(...)` is a mutating method call, not a
                    # rebind, even when `_kernel_receiver` is a bare local
                    # name (a `self.`-qualified receiver already
                    # accumulates via the dotted branch on its own) -- see
                    # _bind_tool_set's own docstring on `accumulate`.
                    _bind_tool_set(_kernel_receiver, new_keys, accumulate=True)
                    return

            # Letta: `client.mcp_servers.create(server_name=..., config=
            # {...})` -- a real MCP server declaration IS present in
            # source (confirmed via source: `config`'s fields are direct
            # command/args/env or url, never further nested), just never
            # reachable via import-resolved matching (a two-level
            # attribute-method chain on a local variable). Same verified-
            # construction trust model as `.add_plugin()` above. Produces
            # ONE CallSiteRecord directly -- this exact call shape is
            # never independently matched by anything else, so there is
            # no double-report risk in creating it here.
            _letta_mcp_receiver = (
                _dotted_name(node.func.value.value)
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute)
                else None
            )
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "create"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "mcp_servers"
                and _letta_mcp_receiver is not None
                and _is_letta_client_typed(_letta_mcp_receiver)
            ):
                config_fields = _resolve_dict_kwarg(node, "config", scopes)
                server_name, name_ok = _resolve(_call_kwargs(node).get("server_name"), scopes)
                explicit_name = server_name if (name_ok and isinstance(server_name, str) and server_name) else None
                if config_fields is None:
                    records.append(
                        CallSiteRecord(
                            framework="letta",
                            shape="letta_mcp_server_create",
                            file=rel_str,
                            line=node.lineno,
                            transport="stdio",
                            resolved={},
                            unresolved_fields=["*"],
                            unresolved_reason={"*": "config= was not a resolvable dict literal"},
                            explicit_name=explicit_name,
                            col_offset=node.col_offset,
                        )
                    )
                else:
                    is_http = "url" in config_fields
                    names = ("url", "headers") if is_http else ("command", "args", "env")
                    resolved, unresolved, reasons = _extract_fields(config_fields, names, scopes)
                    records.append(
                        CallSiteRecord(
                            framework="letta",
                            shape="letta_mcp_server_create",
                            file=rel_str,
                            line=node.lineno,
                            transport="http" if is_http else "stdio",
                            resolved=resolved,
                            unresolved_fields=unresolved,
                            unresolved_reason=reasons,
                            explicit_name=explicit_name,
                            col_offset=node.col_offset,
                        )
                    )
                return

            # Letta: `client.agents.create(name=..., tool_ids=[...])` --
            # a real agent declaration. `tool_ids` are opaque, server-
            # assigned STRING IDs (confirmed via source: plain
            # `Optional[SequenceNotStr[str]]`) with no derivable
            # connection back to a `mcp_servers.create(...)` call's
            # `server_name` anywhere in source -- reported as ordinary
            # base tools (an honest v1 gap: agent + server declarations
            # both surface, cross-referencing them does not, since the
            # source genuinely doesn't contain that link).
            _letta_agents_receiver = (
                _dotted_name(node.func.value.value)
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute)
                else None
            )
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "create"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "agents"
                and _letta_agents_receiver is not None
                and _is_letta_client_typed(_letta_agents_receiver)
            ):
                name_value, name_ok = _resolve(_call_kwargs(node).get("name"), scopes)
                if name_ok and isinstance(name_value, str) and name_value:
                    agent_name = name_value
                elif assigned_to:
                    agent_name = assigned_to
                else:
                    agent_name = f"{rel_str}:{node.lineno}"
                agents.append(AgentRecord(name=agent_name, framework="letta", file=rel_str, line=node.lineno))
                _record_tools_arg(
                    agent_name,
                    f"{rel_str}:{node.lineno}",
                    _call_kwargs(node).get("tool_ids"),
                    node.lineno,
                    force_mcp=False,
                    scopes=scopes,
                )
                return

            origin = import_map.resolve_call_symbol(node)
            matched_mcp = False
            if origin is not None:
                for known_module, known_symbol, shape, name_kwarg, framework in KNOWN_MCP_SYMBOLS:
                    if origin != (known_module, known_symbol):
                        continue
                    matched_mcp = True
                    for index, extraction in enumerate(SHAPE_HANDLERS[shape](node, scopes)):
                        name = extraction.explicit_name
                        if name is None and name_kwarg:
                            value, ok = _resolve(_call_kwargs(node).get(name_kwarg), scopes)
                            if ok and isinstance(value, str) and value:
                                name = value
                        records.append(
                            CallSiteRecord(
                                framework=framework,
                                shape=shape,
                                file=rel_str,
                                line=node.lineno,
                                transport=extraction.transport,
                                resolved=extraction.resolved,
                                unresolved_fields=extraction.unresolved,
                                unresolved_reason=extraction.reasons,
                                explicit_name=name,
                                index_in_call=index,
                                col_offset=node.col_offset,
                            )
                        )
                    break
                if not matched_mcp:
                    for known_module, known_symbol, tools_spec, name_spec, framework, mcp_servers_spec in (
                        KNOWN_AGENT_SYMBOLS
                    ):
                        if origin != (known_module, known_symbol):
                            continue
                        agent_name = _resolve_name_spec(node, name_spec, scopes, assigned_to)
                        agent_location = f"{rel_str}:{node.lineno}"
                        agents.append(
                            AgentRecord(name=agent_name, framework=framework, file=rel_str, line=node.lineno)
                        )
                        primary_tools_node = _spec_node(node, tools_spec)
                        if primary_tools_node is None:
                            # Try the alternate kwarg ONLY when the primary
                            # one wasn't given at all -- e.g. Semantic
                            # Kernel's ChatCompletionAgent(kernel=k) instead
                            # of ChatCompletionAgent(plugins=[...]); never
                            # both (see _FALLBACK_TOOLS_KWARG_BY_AGENT).
                            fallback_kwarg = _FALLBACK_TOOLS_KWARG_BY_AGENT.get((known_module, known_symbol))
                            if fallback_kwarg is not None:
                                primary_tools_node = _call_kwargs(node).get(fallback_kwarg)
                        _record_tools_arg(
                            agent_name,
                            agent_location,
                            primary_tools_node,
                            node.lineno,
                            force_mcp=False,
                            scopes=scopes,
                        )
                        if mcp_servers_spec is not None:
                            _record_tools_arg(
                                agent_name,
                                agent_location,
                                _spec_node(node, mcp_servers_spec),
                                node.lineno,
                                force_mcp=True,
                                scopes=scopes,
                            )
                        mixed_kwarg = _MIXED_TOOLS_KWARG_BY_AGENT.get((known_module, known_symbol))
                        if mixed_kwarg is not None:
                            # A SECOND, SIMULTANEOUS bucket (not either/or
                            # like the fallback above) that legitimately
                            # mixes MCP and ordinary tools -- force_mcp=
                            # False, unlike mcp_servers_spec's True, so a
                            # non-MCP toolset element is an honest base
                            # tool rather than a false "unresolved" error.
                            _record_tools_arg(
                                agent_name,
                                agent_location,
                                _call_kwargs(node).get(mixed_kwarg),
                                node.lineno,
                                force_mcp=False,
                                scopes=scopes,
                            )
                        keyed_dict_kwarg = _KEYED_DICT_KWARG_BY_AGENT.get((known_module, known_symbol))
                        if keyed_dict_kwarg is not None:
                            _record_keyed_dict_kwarg(
                                agent_name, agent_location, _call_kwargs(node).get(keyed_dict_kwarg), scopes
                            )
                        break
        for child in ast.iter_child_nodes(node):
            walk(child, scopes)

    try:
        walk(tree, [_resolution_env(tree.body)])
    except ValueError as exc:
        # e.g. `shlex.split()` on a command string with an unbalanced quote
        # (`"No closing quotation"`) -- a malformed LITERAL in the source
        # being scanned, not a bug in this scanner. Previously uncaught: it
        # escaped `scan_file` entirely and aborted the WHOLE multi-file scan
        # (`discover_source`'s loop has no try around this call) over one
        # bad string in one file. Skipped and warned about exactly like a
        # SyntaxError above, so the rest of this file's already-collected
        # records are kept and every other file still gets scanned.
        warnings.append(f"{path}: skipped rest of file (could not parse a literal: {exc})")
    # A forward reference -- an Agent defined before the MCP declaration
    # its tool-set variable is later assigned from, in the same file -- is
    # a known, accepted gap: `tool_set_bindings` only has entries for
    # assignments already walked (top-to-bottom, matching normal Python
    # execution order), so this only makes the scanner resolve LESS, never
    # more, the safe direction per this script's existing philosophy.
    return records, agents, agent_mcp_links_pending, agent_base_tools, agent_unresolved_tools, warnings


# =============================================================================
# File walk -- .py files only, excluded dirs never even descended into.
# =============================================================================


def split_excludes(exclude_dirs: set[str]) -> tuple[set[str], list[tuple[str, ...]]]:
    """(directory names, path suffixes) -- an entry containing ``/`` is a
    PATH (``.claude/skills``) matched against the trailing components of a
    directory's root-relative path; any other entry is a bare NAME."""
    names = {e for e in exclude_dirs if "/" not in e.strip("/")}
    paths = [tuple(p for p in e.strip("/").split("/") if p) for e in exclude_dirs if "/" in e.strip("/")]
    return names, paths


def is_excluded_dir(rel_parts: tuple[str, ...], names: set[str], paths: list[tuple[str, ...]]) -> bool:
    if rel_parts and rel_parts[-1] in names:
        return True
    return any(len(rel_parts) >= len(p) and rel_parts[-len(p) :] == p for p in paths)


def truncation_warning(max_files: int, what: str) -> str:
    """The file-cap warning. LOUD on purpose: a truncated scan looks exactly
    like a complete one unless someone reads this, and every agent in the
    files it never reached is silently missing from the results."""
    return (
        f"INCOMPLETE SCAN: stopped after {max_files} {what} file(s) ({TRUNCATION_MARKER}); "
        "agents and MCP servers declared in the remaining files are MISSING from these "
        "results. Re-run with a narrower --root or a higher --max-files."
    )


def iter_python_files(root: Path, exclude_dirs: set[str], max_files: int) -> tuple[list[Path], list[str]]:
    warnings: list[str] = []
    files: list[Path] = []
    truncated = False
    names, paths = split_excludes(exclude_dirs)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        rel = Path(dirpath).relative_to(root).parts if Path(dirpath) != root else ()
        dirnames[:] = sorted(d for d in dirnames if not is_excluded_dir((*rel, d), names, paths))
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            path = Path(dirpath) / filename
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
        warnings.append(truncation_warning(max_files, ".py"))
    return files, warnings


def discover_source(
    root: Path, exclude_dirs: set[str], max_files: int
) -> tuple[list[CallSiteRecord], list[AgentRecord], list[dict], list[dict], list[dict], list[str]]:
    """Returns (mcp_records, agents, agent_mcp_links_pending, agent_base_tools,
    agent_unresolved_tools, warnings), aggregated across every scanned file.
    ``agent_mcp_links_pending`` still needs ``resolve_agent_links()`` (called
    from ``_main`` once ``to_servers_and_unresolved()`` has produced the
    final, post-dedup server names)."""
    files, warnings = iter_python_files(root, exclude_dirs, max_files)
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


# =============================================================================
# Name synthesis + ServerConfig construction
# =============================================================================


def synthesize_name(record: CallSiteRecord) -> str:
    if record.explicit_name:
        return record.explicit_name
    if record.transport == "stdio":
        # Shared with inspect_ts_mcp_source.py -- see
        # common.synthesize_stdio_server_name's own docstring for why this
        # must not be duplicated (a one-sided fix would make the two
        # scanners disagree on a server's identity).
        name = common.synthesize_stdio_server_name(
            record.resolved.get("command"), record.resolved.get("args")
        )
        if name:
            return name
    else:
        host = urllib.parse.urlsplit(str(record.resolved.get("url") or "")).hostname
        if host:
            return host
    return f"{record.file}:{record.line}"


def record_to_server_config(record: CallSiteRecord) -> common.ServerConfig:
    name = synthesize_name(record)
    naming_note = "" if record.explicit_name else f", name synthesized from {'command' if record.transport == 'stdio' else 'url'}"
    source = f"python-source:{record.framework} ({record.file}:{record.line}{naming_note})"
    if record.transport == "stdio":
        args = record.resolved.get("args") or []
        env = record.resolved.get("env") or {}
        return common.ServerConfig(
            name=name,
            source=source,
            transport="stdio",
            command=str(record.resolved["command"]),
            args=[str(a) for a in args] if isinstance(args, (list, tuple)) else [],
            # An unresolved env resolves to {} here (nothing else to put),
            # which is fine -- the real dial merges the full ambient env in
            # regardless of what's declared. A RESOLVED env is used as-is.
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


def to_servers_and_unresolved(
    records: list[CallSiteRecord],
) -> tuple[list[common.ServerConfig], list[CallSiteRecord], list[str], dict[tuple[str, int, int, int], str]]:
    candidates: list[tuple[common.ServerConfig, str]] = []
    unresolved: list[CallSiteRecord] = []
    keys_to_server_name: dict[tuple[str, int, int, int], str] = {}
    for record in records:
        if record.is_dial_eligible():
            server = record_to_server_config(record)
            candidates.append((server, server.source))
            # Valid even for a candidate dedupe_servers() later drops as a
            # duplicate: dedup never RENAMES, it only drops a later
            # same-named entry, so the dropped one's name is identical to
            # the survivor's -- an agent link pointing at either key
            # resolves to the one true name either way.
            keys_to_server_name[record.key()] = server.name
        else:
            unresolved.append(record)
    servers, dedupe_warnings = common.dedupe_servers(candidates)
    return servers, unresolved, dedupe_warnings, keys_to_server_name


def resolve_agent_links(
    agent_mcp_links_pending: list[dict],
    keys_to_server_name: dict[tuple[str, int, int, int], str],
    agent_unresolved_tools: list[dict],
) -> list[dict]:
    """Second pass: turn each pending ``{"agent": name, "agent_location": ...,
    "keys": [(file,line,index), ...]}`` entry into real ``{"agent": name,
    "agent_location": ..., "server": name}`` rows, now that every file has
    been scanned and final server names are known. A key with no matching
    server (its MCP declaration was never dial-eligible, so it never got a
    name at all) is NOT silently dropped -- it's added to
    ``agent_unresolved_tools`` instead, since it's neither a real server
    link nor a base tool."""
    agent_mcp_servers: list[dict] = []
    for pending in agent_mcp_links_pending:
        names = sorted({keys_to_server_name[k] for k in pending["keys"] if k in keys_to_server_name})
        if names:
            for name in names:
                agent_mcp_servers.append(
                    {"agent": pending["agent"], "agent_location": pending["agent_location"], "server": name}
                )
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


# =============================================================================
# Output -- partial resolutions get the SAME redaction discipline as a
# resolved server's own display_* fields, since a hardcoded literal secret
# can live in a field that isn't the one blocking dial-eligibility.
# =============================================================================


def _redact_partial_resolution(record: CallSiteRecord) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "command" in record.resolved:
        out["command"] = common._sanitize_for_terminal(str(record.resolved["command"]))
    if "args" in record.resolved:
        args = record.resolved["args"]
        out["args"] = common._display_args([str(a) for a in args]) if isinstance(args, (list, tuple)) else []
    if "url" in record.resolved:
        out["url"] = common._display_url(str(record.resolved["url"]))
    if "env" in record.resolved and isinstance(record.resolved["env"], dict):
        out["env_keys"] = sorted(record.resolved["env"].keys())
    if "headers" in record.resolved and isinstance(record.resolved["headers"], dict):
        out["header_keys"] = sorted(record.resolved["headers"].keys())
    return out


def _print_source_consent_listing(
    servers: list[common.ServerConfig],
    unresolved: list[CallSiteRecord],
    agents: list[AgentRecord],
    agent_mcp_servers: list[dict],
    agent_base_tools: list[dict],
    agent_unresolved_tools: list[dict],
) -> None:
    common._print_consent_listing(servers)
    if unresolved:
        print(
            f"\nFound {len(unresolved)} more programmatic MCP declaration(s) that could NOT be "
            "safely auto-configured (a value is computed at runtime, not a literal, or could vary "
            "by a branch this scan does not evaluate) -- hand-add these to observations.json "
            "yourself if you can confirm their real values (see references/harness-hints.md):"
        )
        for rec in unresolved:
            redacted = _redact_partial_resolution(rec)
            known_bits = ", ".join(f"{k}={v}" for k, v in redacted.items()) or "(nothing usable resolved)"
            print(
                f"  - {rec.framework} [{rec.file}:{rec.line}]: unresolved: "
                f"{', '.join(rec.unresolved_fields)} -- resolved so far: {known_bits}"
            )

    if not agents:
        return
    print(f"\nFound {len(agents)} agent declaration(s):")
    # Grouped by (agent, agent_location), NOT agent name alone -- two
    # different agents very plausibly share a display name (e.g. two CrewAI
    # crews each with their own "Researcher" role), and agent_location
    # (the matched call site's own file:line) is what actually disambiguates
    # them.
    servers_by_agent: dict[tuple[str, str], list[str]] = {}
    for row in agent_mcp_servers:
        servers_by_agent.setdefault((row["agent"], row["agent_location"]), []).append(row["server"])
    base_tools_by_agent: dict[tuple[str, str], list[str]] = {}
    for row in agent_base_tools:
        base_tools_by_agent.setdefault((row["agent"], row["agent_location"]), []).append(row["tool"])
    for agent in agents:
        location = f"{agent.file}:{agent.line}"
        server_names = ", ".join(sorted(set(servers_by_agent.get((agent.name, location), [])))) or "(none)"
        base_names = ", ".join(sorted(set(base_tools_by_agent.get((agent.name, location), [])))) or "(none)"
        print(
            f"  - {agent.name} ({agent.framework}) [{agent.file}:{agent.line}]: "
            f"MCP servers: {server_names}; base tools: {base_names}"
        )
    if agent_unresolved_tools:
        print(f"  {len(agent_unresolved_tools)} tool reference(s) could not be resolved -- see --out JSON for detail.")


def _discovered_source_to_dict(
    servers: list[common.ServerConfig],
    unresolved: list[CallSiteRecord],
    agents: list[AgentRecord],
    agent_mcp_servers: list[dict],
    agent_base_tools: list[dict],
    agent_unresolved_tools: list[dict],
) -> dict:
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
    out["agents"] = [
        {"name": a.name, "framework": a.framework, "file": a.file, "line": a.line} for a in agents
    ]
    out["agent_mcp_servers"] = agent_mcp_servers
    out["agent_base_tools"] = agent_base_tools
    out["agent_unresolved_tools"] = agent_unresolved_tools
    return out


def merge_dial_results(existing: dict, new: dict, existing_label: str, new_label: str) -> tuple[dict, list[str]]:
    """Union two ``--dial``-shaped ``{"mcpServers": [...], "mcpTools": [...]}``
    dicts into one. A cross-source name collision keeps the EXISTING entry
    (by convention: config-file discovery is the more authoritative signal
    of what a client will actually launch) and warns, naming both sources --
    same "never silently shadow" discipline as ``dedupe_servers()``. This is
    just an automated version of the merge-by-hand ``harness-hints.md``
    already documents for the manual "unknown/custom harness" fallback."""
    # Not seeded from existing/new's own "_warnings" -- both callers already
    # pop that key before ever calling this, so it would always be empty;
    # this function's own collision warnings (below) are the real output.
    warnings: list[str] = []
    merged_servers = list(existing.get("mcpServers", []))
    existing_names = set(merged_servers)
    kept_new_names: set[str] = set()

    for name in new.get("mcpServers", []):
        if name in existing_names:
            warnings.append(
                f"name collision merging {new_label} into {existing_label}: {name!r} kept from "
                f"{existing_label}, discarded from {new_label} -- if these are meant to be "
                "different servers, rename one"
            )
            continue
        merged_servers.append(name)
        existing_names.add(name)
        kept_new_names.add(name)

    merged_tools = list(existing.get("mcpTools", []))
    seen_tools = {(t.get("server"), t.get("tool")) for t in merged_tools}
    for tool in new.get("mcpTools", []):
        if tool.get("server") not in kept_new_names:
            continue  # its server was discarded as a collision, or wasn't declared at all
        key = (tool.get("server"), tool.get("tool"))
        if key in seen_tools:
            continue
        merged_tools.append(tool)
        seen_tools.add(key)

    return {"mcpServers": merged_servers, "mcpTools": merged_tools}, warnings


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--discover-only", action="store_true", help="scan .py source only; never launch or contact anything"
    )
    mode.add_argument(
        "--dial", action="store_true", help="scan, then actually connect to each dial-eligible server for tools/list"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="project root to scan (default: cwd)")
    parser.add_argument("--out", type=Path, help="write JSON output here (default: stdout)")
    parser.add_argument(
        "--skip", action="append", default=[], metavar="NAME", help="server name to discover but not dial (repeatable)"
    )
    parser.add_argument(
        "--timeout", type=float, default=common._DEFAULT_TIMEOUT, help="per-server dial timeout in seconds"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="DIR",
        help="additional directory name to exclude from the scan (repeatable)",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="DIR",
        help="re-include a directory the defaults exclude (tests, examples, fixtures, docs, ...; repeatable)",
    )
    parser.add_argument(
        "--max-files", type=int, default=_MAX_SOURCE_FILES, help="stop scanning after this many .py files"
    )
    parser.add_argument(
        "--merge-into",
        type=Path,
        help="(--dial only) fold results into this existing observations.json",
    )
    args = parser.parse_args(argv[1:])

    exclude_dirs = (set(_DEFAULT_EXCLUDE_DIRS) - set(args.include)) | set(args.exclude)
    root = args.root.resolve()
    records, agents, links_pending, agent_base_tools, agent_unresolved_tools, warnings = discover_source(
        root, exclude_dirs, args.max_files
    )
    servers, unresolved, dedupe_warnings, keys_to_server_name = to_servers_and_unresolved(records)
    warnings.extend(dedupe_warnings)
    agent_mcp_servers = resolve_agent_links(links_pending, keys_to_server_name, agent_unresolved_tools)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    if args.discover_only:
        out_dict = _discovered_source_to_dict(
            servers, unresolved, agents, agent_mcp_servers, agent_base_tools, agent_unresolved_tools
        )
        listing = (servers, unresolved, agents, agent_mcp_servers, agent_base_tools, agent_unresolved_tools)
        # --out: human listing on stdout, JSON in the file. No --out: the JSON
        # IS stdout (as --out's help always said), listing on stderr, so a
        # caller can capture a parseable document without writing a file.
        if args.out:
            _print_source_consent_listing(*listing)
            args.out.write_text(json.dumps(out_dict, indent=2) + "\n")
        else:
            with contextlib.redirect_stdout(sys.stderr):
                _print_source_consent_listing(*listing)
            sys.stdout.write(json.dumps(out_dict, indent=2) + "\n")
        return 0

    # --dial
    result = common._dial_all(servers, set(args.skip), args.timeout)
    for w in result.pop("_warnings"):
        print(f"warning: {w}", file=sys.stderr)

    if args.merge_into:
        if not args.merge_into.exists():
            print(f"warning: --merge-into {args.merge_into} does not exist yet -- writing this run's results alone", file=sys.stderr)
        else:
            try:
                existing = json.loads(args.merge_into.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Could not read --merge-into file {args.merge_into}: {exc}", file=sys.stderr)
                return 1
            result, merge_warnings = merge_dial_results(existing, result, str(args.merge_into), "python-source scan")
            for w in merge_warnings:
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
