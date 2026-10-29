"""Tests for the plugin's sync hooks: ``hooks/hooks.json``, ``userConfig``,
``.mcp.json`` and ``scripts/forgebench_sync_launcher.py``.

The manifest tests pin the shape Claude Code reads (exec-form hooks, only the
three default sync hooks, URL, CLI path, sync switch and MCP URL from
``userConfig``, a production default, no MCP URL default). The launcher tests run the script the way a hook does, as a
subprocess, against a fake CLI that records what it received and writes marker
files: the launcher must return well inside the 1.5 s SessionEnd budget, hand
the hook payload to the CLI on stdin, and leave the CLI running after the
hook's whole process tree is killed (a double fork, not just a new session).
With sync off, or without fork/setsid, it must exit before reading the payload
or starting anything.

POSIX only: the Windows detach is follow-up #1146 (#1060).

Run: ``python3 -m pytest packages/forgebench-plugin/tests`` (Python >= 3.10, pytest).
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
LAUNCHER = PLUGIN / "scripts" / "forgebench_sync_launcher.py"
HOOK_BUDGET = 1.5  # seconds: the fixed SessionEnd budget for plugin hooks
PROD_URL = "https://api.forgebench.ai"

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX detach only; Windows is tracked in #1060")


def _json(rel: str) -> dict:
    return json.loads((PLUGIN / rel).read_text(encoding="utf-8"))


def _hook_entries() -> dict[str, list[dict]]:
    """event -> flat list of {matcher, hook} for every hook in hooks.json."""
    out: dict[str, list[dict]] = {}
    for event, groups in _json("hooks/hooks.json")["hooks"].items():
        out[event] = [
            {"matcher": group.get("matcher"), "hook": hook} for group in groups for hook in group["hooks"]
        ]
    return out


# --- manifests -----------------------------------------------------------------------------------


def test_only_the_three_default_sync_hooks():
    entries = _hook_entries()
    assert set(entries) == {"SessionStart", "SessionEnd", "PostToolUse"}  # no Stop (--on-stop) etc.
    for event, [entry] in entries.items():
        assert entry["matcher"] == ("Skill" if event == "PostToolUse" else None), event
    flat = json.dumps(_json("hooks/hooks.json"))
    for forbidden in ("--on-stop", "task_context", "task-context", "session_association", "session-association"):
        assert forbidden not in flat, forbidden


def test_hooks_are_exec_form_and_call_the_launcher():
    for event, [entry] in _hook_entries().items():
        hook = entry["hook"]
        assert hook["type"] == "command", event
        assert hook["command"] == "${CLAUDE_PLUGIN_ROOT}/scripts/forgebench_sync_launcher.py", event
        # Exec form: arguments are a list, not a shell string.
        assert hook["args"] == [
            "${user_config.sync}",
            "${user_config.forgebench_cli_path}",
            "sync",
            "--quiet",
            "--url",
            "${user_config.forgebench_url}",
        ], event
        assert set(hook) == {"type", "command", "args"}, event
    assert LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK), "the hook command must be executable"
    assert LAUNCHER.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3\n")


def test_user_config_declares_url_cli_path_sync_and_mcp_url():
    plugin = _json(".claude-plugin/plugin.json")
    config = plugin["userConfig"]
    assert set(config) == {"forgebench_url", "forgebench_cli_path", "sync", "mcp_url"}
    assert config["forgebench_url"]["default"] == PROD_URL
    assert config["forgebench_cli_path"]["default"] == "forgebench"
    assert config["sync"]["type"] == "boolean" and config["sync"]["default"] is True  # D15: on for compatibility
    # D15: no default, so a skipped MCP stays unset; the CLI or a managed rollout supplies the URL.
    assert config["mcp_url"]["type"] == "string" and "default" not in config["mcp_url"]
    for key, option in config.items():
        assert option["type"] in {"string", "boolean"} and option["title"] and option["description"], key
        assert option.get("required") is False, key
        assert not option.get("sensitive"), f"{key}: Track B needs no sensitive option (keep it out of the keychain)"
    # Hooks live in hooks/hooks.json and the server in .mcp.json, found at their default paths.
    for field in ("hooks", "mcpServers"):
        assert field not in plugin, field
    # Every ${user_config.KEY} the plugin uses is declared.
    used = set()
    for rel in ("hooks/hooks.json", ".mcp.json"):
        text = (PLUGIN / rel).read_text(encoding="utf-8")
        used |= {part.split("}")[0] for part in text.split("${user_config.")[1:]}
    assert used == set(config)


def test_mcp_json_url_comes_from_user_config_never_the_dev_default():
    servers = _json(".mcp.json")["mcpServers"]
    assert list(servers) == ["forgebench"]
    # The whole URL is the option, not the base URL plus /mcp: an unset mcp_url skips MCP
    # without clearing the base URL the sync hooks upload to.
    assert servers["forgebench"] == {"type": "http", "url": "${user_config.mcp_url}"}
    for rel in (".mcp.json", "hooks/hooks.json", ".claude-plugin/plugin.json"):
        assert "dev.forgebench.ai" not in (PLUGIN / rel).read_text(encoding="utf-8"), rel


# --- launcher ------------------------------------------------------------------------------------


@pytest.fixture
def fake_cli(tmp_path: Path):
    """A CLI that records argv and stdin, lingers ``$FAKE_CLI_SECONDS`` and then writes ``done``."""
    script = tmp_path / "fake-forgebench"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            printf '%s\\n' "$*" > "{tmp_path}/argv"
            cat > "{tmp_path}/stdin"
            touch "{tmp_path}/started"
            sleep "${{FAKE_CLI_SECONDS:-0}}"
            touch "{tmp_path}/done"
            """
        )
    )
    script.chmod(0o755)
    return script


def _wait_for(path: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.02)
    return path.exists()


def _run_launcher(
    cli: str,
    *,
    sync: str = "true",
    payload: bytes = b"",
    seconds: float = 0,
    env: dict | None = None,
    url: str = "https://x.test",
    args: list[str] | None = None,
):
    started = time.monotonic()
    forwarded = args if args is not None else ["sync", "--quiet", "--url", url]
    result = subprocess.run(  # pipes: the run only returns once every holder of them has let go
        [sys.executable, str(LAUNCHER), sync, cli, *forwarded],
        input=payload,
        capture_output=True,
        env={**os.environ, "FAKE_CLI_SECONDS": str(seconds), **(env or {})},
        timeout=30,
    )
    return result, time.monotonic() - started


def _descendants(root: int) -> list[int]:
    rows = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True, check=True).stdout
    children: dict[int, list[int]] = {}
    for line in rows.splitlines():
        pid, ppid = (int(x) for x in line.split())
        children.setdefault(ppid, []).append(pid)
    found, queue = [], [root]
    while queue:
        for child in children.get(queue.pop(), []):
            found.append(child)
            queue.append(child)
    return found


@posix_only
def test_launcher_returns_at_once_silently_and_passes_args_and_payload(fake_cli, tmp_path):
    payload = b'{"hook_event_name": "SessionEnd", "session_id": "abc"}'
    result, elapsed = _run_launcher(str(fake_cli), payload=payload, seconds=3)
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
    assert elapsed < HOOK_BUDGET - 0.5, f"launcher took {elapsed:.2f}s with the CLI still running"
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == "sync --quiet --url https://x.test"
    assert (tmp_path / "stdin").read_bytes() == payload
    assert not (tmp_path / "done").exists(), "the CLI should still be running when the launcher has returned"


# The "hook" of the survival test: it runs the launcher in-process, but the original process never gets to
# exit (Claude Code is cancelling it before it returns), so the tree kill lands while it is still alive.
HOOK_STILL_RUNNING = """
import importlib.util, os, sys, time
spec = importlib.util.spec_from_file_location("launcher", sys.argv[1])
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
hook_pid, real_exit = os.getpid(), os._exit
def exit_unless_hook(code):
    if os.getpid() == hook_pid:
        time.sleep(60)
    real_exit(code)
os._exit = exit_unless_hook
launcher.main(sys.argv[2:])
"""


@posix_only
def test_sync_survives_the_hook_process_tree_being_killed(fake_cli, tmp_path):
    hook = subprocess.Popen(
        [sys.executable, "-c", HOOK_STILL_RUNNING, str(LAUNCHER), "true", str(fake_cli), "sync"],
        stdin=subprocess.DEVNULL,
        env={**os.environ, "FAKE_CLI_SECONDS": "1.5"},
        start_new_session=True,
    )
    try:
        assert _wait_for(tmp_path / "started", 5), "the CLI never started"
        assert not (tmp_path / "done").exists()
        assert hook.poll() is None, "the hook must still be running when it is cancelled"
        # What Claude Code does to a cancelled hook: SIGTERM the process and every descendant.
        # A child started with start_new_session alone is still a descendant, so it dies here.
        for pid in [hook.pid, *_descendants(hook.pid)]:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        hook.wait(timeout=5)
        # The double fork reparented the CLI's launcher to init: it is no longer a descendant, so it finished.
        assert _wait_for(tmp_path / "done", 10), "the sync was killed with the hook's process tree"
    finally:
        if hook.poll() is None:
            hook.kill()
            hook.wait()


@posix_only
def test_launcher_never_fails_the_hook(tmp_path):
    for cli in (str(tmp_path / "missing"), "forgebench-does-not-exist", ""):
        result, elapsed = _run_launcher(cli, env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
        assert result.returncode == 0 and result.stdout == b"" and result.stderr == b"", cli
        assert elapsed < HOOK_BUDGET, cli
    for argv in ([], ["true"]):
        result = subprocess.run([sys.executable, str(LAUNCHER), *argv], capture_output=True, timeout=10)
        assert result.returncode == 0 and result.stdout == b"" and result.stderr == b"", argv


@posix_only
@pytest.mark.parametrize("sync", ["false", "False", "0", "", "${user_config.sync}", "maybe"])
def test_sync_off_never_starts_the_cli(fake_cli, tmp_path, sync):
    """Off, empty or unrecognised (fail closed: no upload without a clear yes)."""
    result, elapsed = _run_launcher(str(fake_cli), sync=sync, payload=b'{"session_id": "abc"}')
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
    assert elapsed < HOOK_BUDGET
    time.sleep(0.5)
    assert not (tmp_path / "argv").exists() and not (tmp_path / "started").exists()


@pytest.mark.parametrize("sync", ["true", "True", "1"])
def test_sync_on_values(sync):
    assert _load_launcher().sync_enabled(sync)


def _load_launcher():
    spec = importlib.util.spec_from_file_location("forgebench_sync_launcher", LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _must_not_run(*_args, **_kwargs):
    raise AssertionError("the launcher went past its early exit")


@pytest.mark.parametrize("missing", ["fork", "setsid"])
def test_without_fork_or_setsid_exits_before_reading_or_forking(monkeypatch, capsys, missing):
    """Windows has neither; checking both before the first fork keeps a missing setsid
    from raising AttributeError (which ``except OSError`` would not catch) in a forked child."""
    launcher = _load_launcher()
    monkeypatch.delattr(launcher.os, missing, raising=False)
    for name in ("fork", "setsid"):
        if name != missing:
            monkeypatch.setattr(launcher.os, name, _must_not_run, raising=False)
    monkeypatch.setattr(launcher, "read_payload", _must_not_run)
    monkeypatch.setattr(launcher.subprocess, "run", _must_not_run)
    assert launcher.main(["true", "forgebench", "sync", "--quiet"]) == 0
    assert capsys.readouterr() == ("", "")


@posix_only
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.test/", "https://x.test"),
        ("https://x.test///", "https://x.test"),
        ("http://127.0.0.1:8000/", "http://127.0.0.1:8000"),
        ("http://localhost:8000", "http://localhost:8000"),
    ],
)
def test_url_is_normalised_before_upload(fake_cli, tmp_path, url, expected):
    result, _ = _run_launcher(fake_cli.as_posix(), url=url)
    assert result.returncode == 0 and result.stderr == b""
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == f"sync --quiet --url {expected}"


@posix_only
@pytest.mark.parametrize("url", ["http://x.test", "http://10.0.0.5:8000", "ftp://x.test", "", "x.test", "https://"])
def test_insecure_or_invalid_url_uploads_nothing(fake_cli, tmp_path, url):
    result, _ = _run_launcher(fake_cli.as_posix(), url=url, payload=b'{"session_id": "abc"}')
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
    time.sleep(0.5)
    assert not (tmp_path / "started").exists()


@posix_only
@pytest.mark.parametrize(
    "args",
    [
        ["sync", "--quiet", "--u", "http://evil.test"],
        ["sync", "--quiet", "--ur", "http://evil.test"],
        ["sync", "--quiet", "--u=http://evil.test"],
        ["sync", "--quiet", "--ur=http://evil.test"],
    ],
)
def test_abbreviated_insecure_url_uploads_nothing(fake_cli, tmp_path, args):
    result, _ = _run_launcher(fake_cli.as_posix(), args=args, payload=b'{"session_id": "abc"}')
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
    time.sleep(0.5)
    assert not (tmp_path / "started").exists()


@posix_only
def test_abbreviated_separate_value_url_is_normalised_before_upload(fake_cli, tmp_path):
    result, _ = _run_launcher(fake_cli.as_posix(), args=["sync", "--quiet", "--ur", "https://x.test/"])
    assert result.returncode == 0 and result.stderr == b""
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == "sync --quiet --ur https://x.test"


@posix_only
def test_abbreviated_equals_form_url_is_normalised_before_upload(fake_cli, tmp_path):
    result, _ = _run_launcher(fake_cli.as_posix(), args=["sync", "--quiet", "--ur=https://x.test/"])
    assert result.returncode == 0 and result.stderr == b""
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == "sync --quiet --ur=https://x.test"


@posix_only
def test_equals_form_insecure_url_uploads_nothing(fake_cli, tmp_path):
    result, _ = _run_launcher(
        fake_cli.as_posix(), args=["sync", "--quiet", "--url=http://x.test"], payload=b'{"session_id": "abc"}'
    )
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
    time.sleep(0.5)
    assert not (tmp_path / "started").exists()


@posix_only
def test_equals_form_url_is_normalised_before_upload(fake_cli, tmp_path):
    result, _ = _run_launcher(fake_cli.as_posix(), args=["sync", "--quiet", "--url=https://x.test/"])
    assert result.returncode == 0 and result.stderr == b""
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == "sync --quiet --url=https://x.test"


@posix_only
def test_last_of_two_url_options_is_validated_too(fake_cli, tmp_path):
    args = ["sync", "--quiet", "--url", "https://x.test", "--url", "http://evil.test"]
    result, _ = _run_launcher(fake_cli.as_posix(), args=args, payload=b'{"session_id": "abc"}')
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""
    time.sleep(0.5)
    assert not (tmp_path / "started").exists()


@posix_only
def test_managed_env_url_is_the_fallback_when_the_option_is_still_production(fake_cli, tmp_path):
    env = {"FORGEBENCH_MCP_URL": "https://staging.forgebench.test/mcp"}
    _run_launcher(fake_cli.as_posix(), url=PROD_URL, env=env)
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == "sync --quiet --url https://staging.forgebench.test"


@posix_only
def test_explicit_url_beats_the_env_fallback(fake_cli, tmp_path):
    env = {"FORGEBENCH_MCP_URL": "https://staging.forgebench.test/mcp"}
    _run_launcher(fake_cli.as_posix(), url="https://own.test", env=env)
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == "sync --quiet --url https://own.test"


@posix_only
def test_production_default_stays_production_without_the_env(fake_cli, tmp_path):
    _run_launcher(fake_cli.as_posix(), url=PROD_URL + "/", env={"FORGEBENCH_MCP_URL": ""})
    assert _wait_for(tmp_path / "started", 5)
    assert (tmp_path / "argv").read_text().strip() == f"sync --quiet --url {PROD_URL}"


def test_missing_fork_is_not_a_traceback_end_to_end(tmp_path):
    """A real subprocess with ``os.fork`` removed: exit 0, nothing printed, nothing run."""
    code = (
        "import os, sys, importlib.util\n"
        "del os.fork\n"
        f"spec = importlib.util.spec_from_file_location('l', {str(LAUNCHER)!r})\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "sys.exit(m.main(['true', 'forgebench', 'sync', '--url', 'https://x.test']))\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=10, cwd=tmp_path)
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b""


def test_sync_off_exits_before_reading_or_forking(monkeypatch):
    launcher = _load_launcher()
    for name in ("fork", "setsid"):
        monkeypatch.setattr(launcher.os, name, _must_not_run, raising=False)
    monkeypatch.setattr(launcher, "read_payload", _must_not_run)
    assert launcher.main(["false", "forgebench", "sync", "--quiet"]) == 0


# --- real Claude Code (opt-in) -------------------------------------------------------------------

real_claude = pytest.mark.skipif(
    os.environ.get("FORGEBENCH_REAL_CLAUDE") != "1",
    reason="set FORGEBENCH_REAL_CLAUDE=1 to install the plugin into a disposable HOME with the real claude CLI",
)


@pytest.fixture
def listener():
    """A loopback HTTP server that records every request it gets."""
    import http.server
    import threading

    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def _record(self):
            hits.append(f"{self.command} {self.path}")
            self.send_response(404)
            self.end_headers()

        do_GET = do_POST = do_DELETE = _record

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", hits
    server.shutdown()


@real_claude
def test_real_claude_mcp_and_sync_options_are_independent(tmp_path, listener):
    """D15 against the installed CLI: unset or empty mcp_url makes no request, a set one reaches only
    that endpoint, and changing either option keeps the other. Only the loopback listener is
    reachable by URL here; "no request to any host" relies on the URL being empty."""
    base, hits = listener
    home = tmp_path / "home"
    redirects = ("ANTHROPIC_", "CLAUDE_CODE_USE_", "CLAUDE_CONFIG_DIR", "FORGEBENCH_")
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith(redirects)},
        "HOME": str(home),
        "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }

    def claude(*args: str, stdin: str | None = None) -> str:
        result = subprocess.run(
            ["claude", *args], input=stdin, capture_output=True, text=True, env=env, timeout=120, check=False
        )
        return result.stdout + result.stderr

    def options() -> dict:
        settings = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
        return settings["pluginConfigs"]["forgebench@forgebench"]["options"]

    def configure(values: dict[str, str]) -> None:
        out = claude("plugin", "configure", "forgebench@forgebench", "--values-stdin", stdin=json.dumps(values))
        assert "saved" in out, out

    def mcp_status() -> str:
        hits.clear()
        return claude("mcp", "get", "plugin:forgebench:forgebench")

    claude("plugin", "marketplace", "add", str(PLUGIN))
    claude("plugin", "install", "forgebench@forgebench", "--config", f"forgebench_url={base}")
    assert "mcp_url" not in options()

    status = mcp_status()
    assert hits == [], "an unset mcp_url must not connect anywhere"
    assert "URL is unset or invalid" in status, status  # the native text, not "Not configured"

    configure({"mcp_url": f"{base}/mcp"})
    mcp_status()
    assert hits and all(hit.split()[1] == "/mcp" for hit in hits), hits

    configure({"sync": "false"})
    assert options() == {"forgebench_url": base, "mcp_url": f"{base}/mcp", "sync": False}

    configure({"mcp_url": ""})
    assert options() == {"forgebench_url": base, "mcp_url": "", "sync": False}
    status = mcp_status()
    assert hits == [] and "URL is unset or invalid" in status, (hits, status)
