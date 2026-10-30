"""Standalone Forgebench helper for the Claude Code plugin (Python 3.10+, standard library only).

It never imports, downloads, locates or runs the Forgebench CLI, and it never reads the CLI's
credential files, environment-variable credentials or Claude Code's MCP token cache.
"""

CONTRACT = 1  # the proposed backend contract revision this client speaks (plugin_contract / capture_contract)
SOURCE = "claude_code"
