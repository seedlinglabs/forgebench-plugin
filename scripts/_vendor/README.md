# Vendored discovery engines

`agent_harness_explorer/` holds byte-for-byte copies of four forgebench-authored
scanner modules:

| File | Role in `forgebench_scan.py` |
|---|---|
| `mcp_discovery_common.py` | `ServerConfig`, redaction/display helpers, the consent-gated stdio/HTTP dial |
| `inspect_mcp_configs.py` | project MCP client configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) |
| `inspect_mcp_source.py` | Python agent + MCP-client declarations (stdlib `ast`) |
| `inspect_ts_mcp_source.py` | TypeScript/JavaScript declarations (only when `tree-sitter` is installed) |

**Why a copy and not an import.** Claude Code copies an installed plugin into
its own cache directory (`~/.claude/plugins/cache/...`), so the scanner can
only rely on files inside the plugin.

**Do not edit these files here.** They are synced from forgebench's source.
`forgebench_scan.py` hashes this script plus these four files into the
payload's `scanner.sha256`, so the control plane records exactly which scanner
produced every upload.
