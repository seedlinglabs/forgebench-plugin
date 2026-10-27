# Vendored discovery engines

`agent_harness_explorer/` holds byte-for-byte copies of five forgebench-authored
scanner modules from
`packages/cli-session-reviewer/forgebench_session_reviewer/bundles/agent-harness-explorer/scripts/`:

| File | Role in `forgebench_scan.py` |
|---|---|
| `mcp_discovery_common.py` | `ServerConfig`, redaction/display helpers, the consent-gated stdio/HTTP dial |
| `inspect_mcp_configs.py` | project MCP client configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) |
| `inspect_mcp_source.py` | Python agent + MCP-client declarations (stdlib `ast`) |
| `inspect_ts_mcp_source.py` | TypeScript/JavaScript declarations (only when `tree-sitter` is installed) |
| `inspect_java_mcp_source.py` | Java agent declarations (stdlib lexer; no MCP call sites) |

**Why a copy and not an import.** Claude Code copies an installed plugin into
its own cache directory (`~/.claude/plugins/cache/...`), so the scanner can
only rely on files inside `packages/forgebench-plugin/`. A path back into
`packages/cli-session-reviewer/` would work in this monorepo and break for
every real user.

**The bundle is the source of truth.** Fix scanners THERE, then copy:

```sh
B=packages/cli-session-reviewer/forgebench_session_reviewer/bundles/agent-harness-explorer/scripts
V=packages/forgebench-plugin/scripts/_vendor/agent_harness_explorer
for f in mcp_discovery_common.py inspect_mcp_configs.py inspect_mcp_source.py inspect_ts_mcp_source.py inspect_java_mcp_source.py; do
  cp "$B/$f" "$V/$f"
done
```

`packages/forgebench-plugin/tests/test_forgebench_scan.py::test_vendored_scanners_match_the_bundle`
fails when the two drift. `forgebench_scan.py` hashes this script plus these
five files into the payload's `scanner.sha256`, so the control plane records
exactly which scanner produced every upload.
