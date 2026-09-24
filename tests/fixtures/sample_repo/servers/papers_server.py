#!/usr/bin/env python3
"""A minimal stdio MCP server used by the scanner tests' --dial path (fixture).

Answers ``initialize`` and one ``tools/list`` page; never runs a tool.
"""
import json
import sys

TOOLS = [
    {"name": "search_papers", "description": "Search papers", "annotations": {"readOnlyHint": True}},
    {"name": "delete_paper", "description": "Delete a paper"},
]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("id") is None:
        continue
    if msg.get("method") == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name": "papers"}}
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
    elif msg.get("method") == "tools/list":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}
    else:
        resp = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "not found"}}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
