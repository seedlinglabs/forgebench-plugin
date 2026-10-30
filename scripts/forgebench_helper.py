#!/usr/bin/env python3
"""Forgebench helper for the Claude Code plugin (Python 3.10+, standard library only).

Runs the plugin's own hooks, skill and mod commands and the two native credential helpers Claude Code invokes
directly. It does not need, find or run the Forgebench CLI.

  hook <event> --sync <bool> --url <url>     SessionStart / SessionEnd context delivery (stdin: hook JSON)
  auth begin|wait|cancel                     browser sign-in
  apply | logout | status | preflight        configuration and state
  task options|validate|declare              explicit task selection
  api-key / otel-headers --origin <origin>   native helper modes: print a credential to Claude Code, nothing else
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fbplugin import commands  # noqa: E402
from fbplugin.common import HelperError  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forgebench_helper", description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, origin=False):
        p.add_argument("--url", default="", help="forgebench_url plugin option")
        if origin:
            p.add_argument("--origin", default="", help="pinned deployment origin")
        return p

    h = common(sub.add_parser("hook"))
    h.add_argument("event", choices=["SessionStart", "SessionEnd"])
    h.add_argument("--sync", default="true")
    common(sub.add_parser("preflight")).add_argument("--claude-version", default=None)
    s = common(sub.add_parser("status"))
    s.add_argument("--offline", action="store_true")
    s.add_argument("--sync", default="true")
    s.add_argument("--claude-version", default=None)
    a = sub.add_parser("auth")
    asub = a.add_subparsers(dest="auth_command", required=True)
    b = common(asub.add_parser("begin"))
    b.add_argument("--no-browser", action="store_true")
    b.add_argument("--claude-version", default=None)
    w = asub.add_parser("wait")
    w.add_argument("--op", required=True)
    w.add_argument("--seconds", default="20")
    c = asub.add_parser("cancel")
    c.add_argument("--op", required=True)
    ap = common(sub.add_parser("apply"))
    ap.add_argument("--no-gateway", action="store_true")
    ap.add_argument("--no-telemetry", action="store_true")
    ap.add_argument("--traces", choices=["auto", "off"], default="auto")
    lo = common(sub.add_parser("logout"))
    lo.add_argument("--revoke", action="store_true")
    t = sub.add_parser("task")
    tsub = t.add_subparsers(dest="task_command", required=True)
    to = common(tsub.add_parser("options"), True)
    to.add_argument("--connection", default=None)
    to.add_argument("--query", default="")
    to.add_argument("--offset", type=int, default=0)
    to.add_argument("--limit", type=int, default=20)
    tv = common(tsub.add_parser("validate"), True)
    tv.add_argument("--connection", required=True)
    tv.add_argument("--task", required=True)
    td = common(tsub.add_parser("declare"), True)
    td.add_argument("--connection", required=True)
    td.add_argument("--task", required=True)
    td.add_argument("--session-id", required=True)
    td.add_argument("--mechanism", default="ui", choices=["SessionStart", "PreToolUse", "ui", "cli"])
    for name in ("api-key", "otel-headers"):
        common(sub.add_parser(name), True)
    return parser


def render(data: dict, indent: int = 0) -> str:
    pad = "  " * indent
    lines = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{pad}{key}:")
            lines.append(render(value, indent + 1))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            lines.append(f"{pad}{key}:")
            for item in value:
                lines.append(f"{pad}  - " + ", ".join(f"{k}={v}" for k, v in item.items()))
        elif value is not None and value != [] and value != "":
            lines.append(f"{pad}{key}: {value}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    command = args.command
    try:
        if command in ("api-key", "otel-headers"):
            # Claude Code reads stdout as the credential: on any failure print nothing there.
            try:
                value = commands.api_key(args) if command == "api-key" else commands.otel_headers(args)
            except HelperError as exc:
                sys.stderr.write(f"forgebench: {exc.message}\n")
                return 1
            sys.stdout.write(value + "\n")
            return 0
        if command == "hook":
            try:
                result = commands.hook(args)
            except Exception:  # noqa: BLE001 - a hook must never be noisy or fatal
                return 0
            if result:
                sys.stdout.write(json.dumps(result) + "\n")
            return 0
        handlers = {
            "preflight": commands.preflight, "status": commands.status, "apply": commands.apply,
            "logout": commands.logout, "task": commands.task,
            "auth": {"begin": commands.auth_begin, "wait": commands.auth_wait,
                     "cancel": commands.auth_cancel}.get(getattr(args, "auth_command", ""), None),
        }
        result = handlers[command](args)
    except HelperError as exc:
        payload = {"ok": False, "error": exc.code, "message": exc.message}
        sys.stdout.write((json.dumps(payload) if args.json else render(payload)) + "\n")
        return 2
    sys.stdout.write((json.dumps(result, indent=2) if args.json else render(result)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
