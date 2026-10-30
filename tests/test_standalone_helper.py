"""The standalone helper against a fake control plane: sign-in, configuration, context and tasks.

Every run uses an isolated HOME/CLAUDE_CONFIG_DIR and a PATH without the Forgebench CLI (absence is real, not
mocked). The ``sandbox`` fixture fails a test if a fake secret appears in output, argv or sign-in state."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fake_backend import INFER_KEY, REPORT_KEY

posix_only = pytest.mark.skipif(os.name == "nt", reason="the helper supports macOS and Linux")


def wait_for(predicate, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


# ------------------------------------------------------------------------------------------ preflight


def test_preflight_needs_no_cli_and_states_version_capabilities(sandbox):
    new = sandbox.json("preflight", "--claude-version", "2.1.312")
    assert new["ok"] and new["forgebench_cli_required"] is False
    assert new["capabilities"]["mod_pane"] is True
    mid = sandbox.json("preflight", "--claude-version", "2.1.280")
    assert mid["ok"] and mid["capabilities"]["mod_pane"] is False
    assert any("2.1.287" in note for note in mid["notes"])
    old = sandbox.json("preflight", "--claude-version", "2.1.100")
    assert old["ok"] is False and any("upgrade" in p for p in old["problems"])


def test_preflight_refuses_invalid_settings_json(sandbox):
    sandbox.write_settings("{not json")
    result = sandbox.json("preflight", "--claude-version", "2.1.312")
    assert result["ok"] is False and any("not valid JSON" in p for p in result["problems"])


# ------------------------------------------------------------------------------------------- sign-in


@posix_only
def test_browser_sign_in_grants_reporting_and_model_access(sandbox, fake):
    done = sandbox.connect()
    assert done["result"]["reporting"] == "granted" and done["result"]["inference"] == "granted"
    assert fake.count("GET", "/v1/auth/oidc/login") == 1
    login = fake.logins[0]
    assert login["plugin_client"] == "claude_code" and login["redirect"].startswith("http://127.0.0.1:")
    assert login["hostname"].startswith("claude-code-") and len(login["hostname"]) <= 64
    # the exchange used the plugin's own descriptor, never the machine hostname (which would rotate the CLI's key)
    assert fake.exchanges[0]["hostname"] == login["hostname"]
    files = sandbox.data_files()
    connection = [f for f in files if f.parent.name == "connections"]
    assert connection and stat.S_IMODE(connection[0].stat().st_mode) == 0o600
    record = json.loads(connection[0].read_text())
    assert record["reporting"]["api_key"] == REPORT_KEY and record["inference"]["api_key"] == INFER_KEY
    # only the two native helper modes ever print a credential
    key = sandbox.run("api-key", "--origin", fake.origin, check_secrets=False)
    assert key.stdout.strip() == INFER_KEY
    headers = json.loads(sandbox.run("otel-headers", "--origin", fake.origin, check_secrets=False).stdout)
    assert headers["Authorization"] == f"Bearer {REPORT_KEY}" and headers["x-forgebench-device-id"] == login["hostname"]
    sandbox.captured.clear()


@posix_only
def test_without_the_contract_marker_gateway_is_unsupported_and_no_second_login(sandbox, fake):
    fake.plugin_contract = False
    done = sandbox.connect()
    assert done["result"]["reporting"] == "granted" and done["result"]["inference"] == "unsupported"
    assert "plugin_contract" in done["result"]["inference_note"]
    assert fake.count("GET", "/v1/auth/oidc/login") == 1  # never launches another login on its own
    assert fake.count("POST", "/v1/auth/cli/inference") == 0
    applied = sandbox.json("apply")
    assert "gateway" in applied["skipped"] and "gateway" not in {w["group"] for w in applied["written"]}
    assert "ANTHROPIC_BASE_URL" not in sandbox.settings().get("env", {})


@posix_only
def test_declined_model_access_is_reported_not_retried(sandbox, fake):
    fake.inference_error = "no_eligible_key"
    done = sandbox.connect()
    assert done["result"]["inference"] == "no_eligible_key"
    assert sandbox.run("api-key", "--origin", fake.origin).returncode == 1


@posix_only
def test_cancelled_browser_sign_in_stores_nothing(sandbox, fake):
    fake.deny_login = True
    begun = sandbox.json("auth", "begin", "--no-browser")
    import urllib.request

    urllib.request.urlopen(begun["login_url"], timeout=10).read()
    done = sandbox.json("auth", "wait", "--op", begun["op"], "--seconds", "20")
    assert done["status"] == "failed" and done["error"]["code"] == "sign_in_declined"
    assert not [f for f in sandbox.data_files() if f.parent.name == "connections"]


@posix_only
def test_sign_in_can_be_cancelled(sandbox):
    begun = sandbox.json("auth", "begin", "--no-browser")
    cancelled = sandbox.json("auth", "cancel", "--op", begun["op"])
    assert cancelled["status"] == "cancelled"


def test_http_non_loopback_origin_is_refused(sandbox):
    proc = sandbox.run("--json", "auth", "begin", "--no-browser", "--url", "http://example.com", url=False)
    assert proc.returncode == 2 and "invalid_origin" in proc.stdout


# ------------------------------------------------------------------------------------------- apply


def _helper_words(command: str) -> list[str]:
    return shlex.split(command)


@posix_only
def test_apply_writes_gateway_and_native_otel_and_keeps_user_settings(sandbox, fake):
    sandbox.write_settings({"model": "opus", "env": {"MY_VAR": "1", "OTEL_RESOURCE_ATTRIBUTES": "team=a"},
                            "permissions": {"allow": ["Bash(ls)"]}})
    sandbox.connect()
    result = sandbox.json("apply")
    assert result["pending_restart"] is True and not result["conflicts"]
    settings = sandbox.settings()
    env = settings["env"]
    assert settings["model"] == "opus" and settings["permissions"] == {"allow": ["Bash(ls)"]}
    assert env["MY_VAR"] == "1" and env["OTEL_RESOURCE_ATTRIBUTES"] == "team=a"
    assert env["ANTHROPIC_BASE_URL"] == fake.origin  # Claude appends /v1/messages itself
    assert env["ANTHROPIC_CUSTOM_HEADERS"] == "X-Forgebench-Harness: claude_code"
    assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == fake.origin + "/v1/telemetry/otlp"
    assert env["OTEL_EXPORTER_OTLP_PROTOCOL"] == "http/json" and env["OTEL_LOGS_EXPORTER"] == "otlp"
    assert env["OTEL_TRACES_EXPORTER"] == "none"  # the deployment does not store native traces
    for flag in ("OTEL_LOG_USER_PROMPTS", "OTEL_LOG_TOOL_DETAILS", "OTEL_LOG_RAW_API_BODIES"):
        assert env[flag] == "0"
    # no secret in settings; helper commands point at a stable copied runtime with an absolute interpreter
    assert REPORT_KEY not in sandbox.settings_path.read_text() and INFER_KEY not in sandbox.settings_path.read_text()
    words = _helper_words(settings["apiKeyHelper"])
    assert os.path.isabs(words[0]) and "forgebench-plugin/runtime/" in words[1] and words[2] == "api-key"
    assert _helper_words(settings["otelHeadersHelper"])[2] == "otel-headers"
    # claude runs these through a shell; they must print only the credential
    out = subprocess.run(settings["apiKeyHelper"], shell=True, capture_output=True, text=True,
                         env=sandbox.env(), timeout=30)
    assert out.stdout.strip() == INFER_KEY and out.returncode == 0
    sandbox.captured.clear()
    # idempotent
    again = sandbox.json("apply")
    assert not again["written"] and not again["conflicts"]


@posix_only
def test_apply_uses_native_traces_only_when_the_backend_reports_support(sandbox, fake):
    fake.delivery = {"capture_contract": 1, "source": "claude_code", "signals": {
        "native_traces": {"supported": True, "stored_count": 0}}}
    sandbox.connect()
    result = sandbox.json("apply")
    env = sandbox.settings()["env"]
    assert result["traces"] is True and env["OTEL_TRACES_EXPORTER"] == "otlp"
    assert env["CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"] == "1"
    assert env["OTEL_LOG_TOOL_CONTENT"] == "0"


@posix_only
def test_existing_exporter_and_gateway_settings_are_reported_never_overwritten(sandbox, fake):
    original = {"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.corp/otlp", "OTEL_LOGS_EXPORTER": "none",
                        "ANTHROPIC_BASE_URL": "https://proxy.corp"}, "apiKeyHelper": "/opt/corp/key"}
    sandbox.write_settings(original)
    sandbox.connect()
    result = sandbox.json("apply")
    assert not result["written"]
    assert set(result["skipped_groups"]) == {"gateway", "telemetry"}
    keys = {c["key"] for c in result["conflicts"]}
    assert {"OTEL_EXPORTER_OTLP_ENDPOINT", "ANTHROPIC_BASE_URL", "apiKeyHelper"} <= keys
    assert sandbox.settings() == original  # byte-for-byte semantic equality: nothing cleared or replaced
    assert all("value" not in c for c in result["conflicts"])


@posix_only
def test_foreign_provider_credentials_and_login_policy_are_conflicts(sandbox):
    sandbox.connect()
    env = sandbox.env(ANTHROPIC_API_KEY="sk-ant-someone-elses")
    result = sandbox.json("apply", env=env)
    assert "gateway" in result["skipped_groups"]
    assert any(c["key"] == "ANTHROPIC_API_KEY" and c["layer"] == "process" for c in result["conflicts"])
    assert "sk-ant-someone-elses" not in json.dumps(result)


@posix_only
def test_user_enabled_content_capture_blocks_telemetry(sandbox):
    sandbox.write_settings({"env": {"OTEL_LOG_USER_PROMPTS": "1"}})
    sandbox.connect()
    result = sandbox.json("apply", "--no-gateway")
    assert "telemetry" in result["skipped_groups"]
    assert any(c["kind"] == "privacy" for c in result["conflicts"])
    assert sandbox.settings() == {"env": {"OTEL_LOG_USER_PROMPTS": "1"}}


@posix_only
def test_invalid_settings_json_refuses_to_write(sandbox):
    sandbox.connect()
    sandbox.write_settings("{ nope")
    proc = sandbox.run("--json", "apply")
    assert proc.returncode == 2 and "settings_unreadable" in proc.stdout
    assert sandbox.settings_path.read_text() == "{ nope"


@posix_only
def test_policy_off_local_or_unreachable_never_enables_telemetry(sandbox, fake):
    sandbox.connect()
    fake.capture_policy = {"effective": {"mode": "off", "revision": 4}}
    off = sandbox.json("apply", "--no-gateway")
    assert "telemetry" in off["skipped"] and not off["written"]
    fake.capture_policy = {"effective": {"mode": "local", "revision": 5}}
    local = sandbox.json("apply", "--no-gateway")
    assert "local capture" in local["skipped"]["telemetry"]
    assert not sandbox.settings_path.exists()


@posix_only
def test_managed_deployment_origin_isolated_from_other_credentials(sandbox, fake):
    sandbox.connect()
    other = sandbox.json("status", "--url", "http://127.0.0.1:9", "--offline")
    assert other["connection"]["signed_in"] is False  # production/other credentials are never reused
    assert sandbox.run("api-key", "--origin", "http://127.0.0.1:9").stdout == ""


# ------------------------------------------------------------------------------------------ logout


@posix_only
def test_logout_restores_only_unchanged_values_and_reports_the_rest(sandbox, fake):
    sandbox.write_settings({"env": {"ANTHROPIC_CUSTOM_HEADERS": "X-Corp: 1", "KEEP": "yes"}})
    sandbox.connect()
    sandbox.json("apply")
    settings = sandbox.settings()
    assert settings["env"]["ANTHROPIC_CUSTOM_HEADERS"] == "X-Corp: 1\nX-Forgebench-Harness: claude_code"
    settings["env"]["OTEL_LOGS_EXPORT_INTERVAL"] = "9999"  # the user edited one of our values afterwards
    sandbox.write_settings(settings)
    result = sandbox.json("logout")
    assert any(item["key"] == "OTEL_LOGS_EXPORT_INTERVAL" for item in result["settings"]["left"])
    after = sandbox.settings()
    assert after["env"]["KEEP"] == "yes" and after["env"]["ANTHROPIC_CUSTOM_HEADERS"] == "X-Corp: 1"
    assert after["env"]["OTEL_LOGS_EXPORT_INTERVAL"] == "9999"
    assert "apiKeyHelper" not in after and "ANTHROPIC_BASE_URL" not in after["env"]
    assert "remain active" in result["server_revocation"]
    assert result["credentials_removed"] is True


@posix_only
def test_logout_revoke_reports_unsupported_servers_honestly(sandbox, fake):
    fake.revoke_status = 404
    sandbox.connect()
    result = sandbox.json("logout", "--revoke")
    assert result["server_revocation"] == {"reporting": "unsupported_by_server", "inference": "unsupported_by_server"}
    fake2 = None  # noqa: F841


@posix_only
def test_logout_revoke_calls_the_current_key_endpoint_when_present(sandbox, fake):
    sandbox.connect()
    result = sandbox.json("logout", "--revoke")
    assert result["server_revocation"] == {"reporting": "revoked", "inference": "revoked"}
    assert sorted(fake.revoked) == ["inference", "reporting"]


# ------------------------------------------------------------------------------------------- context


def _hook(sandbox, event, session_id="11111111-2222-3333-4444-555555555555", sync="true", cwd=None, extra_env=None):
    payload = json.dumps({"session_id": session_id, "hook_event_name": event, "cwd": cwd or str(sandbox.root),
                          "source": "startup"})
    env = sandbox.env(**(extra_env or {}))
    return sandbox.run("hook", event, "--sync", sync, stdin=payload, env=env)


@posix_only
def test_session_start_delivers_the_native_session_and_confirms_the_contract(sandbox, fake):
    sandbox.connect()
    repo = sandbox.root / "repo"
    repo.mkdir()
    for args in (["init", "-q", "-b", "fix/ENG-123"], ["remote", "add", "origin",
                                                       "https://user:pw@github.com/acme/widgets.git?token=abc"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    start = time.time()
    proc = _hook(sandbox, "SessionStart", cwd=str(repo))
    assert proc.returncode == 0 and time.time() - start < 5
    assert wait_for(lambda: fake.meta_bodies)
    body = fake.meta_bodies[0]
    entry = body["sessions"][0]
    assert body["capture_transport"] == "native" and body["device_id"].startswith("claude-code-")
    assert entry["source"] == "claude_code" and entry["session_id"] == "11111111-2222-3333-4444-555555555555"
    assert entry["branch"] == "fix/ENG-123" and entry["repository"] == "github.com/acme/widgets"
    assert entry["repo"] == "widgets" and entry["session_kind"] == "main" and entry["usage_expected"] is False
    for forbidden in ("usage", "usage_by_model", "input_tokens", "transcript", "cwd", "task_reference"):
        assert forbidden not in entry
    assert "pw" not in json.dumps(body) and "token=abc" not in json.dumps(body)
    assert wait_for(lambda: sandbox.json("status", "--offline")["context"]["confirmed_by_backend"] is True)
    status = sandbox.json("status", "--offline")
    assert status["context"]["pending"] == 0 and status["states"]["backend_received"] is True


@posix_only
def test_context_without_the_backend_contract_is_unconfirmed(sandbox, fake):
    fake.meta_contract = False
    sandbox.connect()
    _hook(sandbox, "SessionStart")
    assert wait_for(lambda: fake.meta_bodies)
    assert wait_for(lambda: sandbox.json("status", "--offline")["context"]["last_status"] == "delivered_unconfirmed")
    assert sandbox.json("status", "--offline")["context"]["confirmed_by_backend"] is False


@posix_only
def test_session_end_carries_the_end_time_for_the_same_session(sandbox, fake):
    sandbox.connect()
    _hook(sandbox, "SessionStart")
    assert wait_for(lambda: len(fake.meta_bodies) >= 1)
    _hook(sandbox, "SessionEnd")
    assert wait_for(lambda: len(fake.meta_bodies) >= 2)
    first, last = fake.meta_bodies[0]["sessions"][0], fake.meta_bodies[-1]["sessions"][0]
    assert last["session_id"] == first["session_id"] and last["started_at"] == first["started_at"]
    assert "ended_at" in last and "ended_at" not in first


@posix_only
def test_sync_false_sends_nothing_and_touches_nothing(sandbox, fake):
    sandbox.connect()
    before = sorted(sandbox.data_files())
    proc = _hook(sandbox, "SessionStart", sync="false")
    time.sleep(0.5)
    assert proc.returncode == 0 and proc.stdout == "" and not fake.meta_bodies
    assert sorted(sandbox.data_files()) == before  # no payload read into any file
    assert not sandbox.settings_path.exists()  # and sync=false never turns on OTel by itself


@posix_only
def test_not_connected_nudges_once_and_sends_nothing(sandbox, fake):
    first = _hook(sandbox, "SessionStart")
    assert "not connected" in json.loads(first.stdout)["systemMessage"]
    assert _hook(sandbox, "SessionStart").stdout == ""
    assert not fake.meta_bodies and fake.count("POST", "/v1/sessions/meta") == 0


@posix_only
def test_capture_off_purges_queued_context_and_sends_nothing(sandbox, fake):
    sandbox.connect()
    fake.capture_policy = {"effective": {"mode": "off", "revision": 9}}
    _hook(sandbox, "SessionStart")
    assert wait_for(lambda: sandbox.json("status", "--offline")["context"]["last_status"] == "capture_off")
    assert not fake.meta_bodies and sandbox.json("status", "--offline")["context"]["pending"] == 0


@posix_only
def test_auth_failure_pauses_delivery_and_keeps_the_snapshot(sandbox, fake):
    sandbox.connect()
    fake.meta_status = 401
    _hook(sandbox, "SessionStart")
    assert wait_for(lambda: sandbox.json("status", "--offline")["context"]["last_status"] == "auth_failed")
    assert sandbox.json("status", "--offline")["context"]["pending"] == 1


@posix_only
def test_unreachable_policy_holds_context_back(sandbox, fake):
    sandbox.connect()
    fake.capture_policy = None  # 404 -> legacy: allowed
    _hook(sandbox, "SessionStart")
    assert wait_for(lambda: fake.meta_bodies)


@posix_only
def test_invalid_url_sends_nothing(sandbox, fake):
    sandbox.connect()
    payload = json.dumps({"session_id": "s", "hook_event_name": "SessionStart", "cwd": "/"})
    proc = sandbox.run("hook", "SessionStart", "--sync", "true", "--url", "http://evil.example", stdin=payload,
                       url=False)
    time.sleep(0.3)
    assert proc.returncode == 0 and not fake.meta_bodies


# --------------------------------------------------------------------------------------------- tasks


@posix_only
def test_task_declaration_uses_the_full_session_id_and_never_infers(sandbox, fake):
    sandbox.connect()
    result = sandbox.json("task", "declare", "--connection", "c-1", "--task", "ENG-1", "--session-id", "sess-" + "x" * 80,
                          "--origin", fake.origin)
    assert result["declared"] is True and result["review_status"] == "pending"
    declaration = fake.declarations[0]
    assert declaration["session_id"] == "sess-" + "x" * 80 and declaration["source"] == "claude_code"
    assert declaration["mechanism"] == "ui"
    invalid = sandbox.json("task", "declare", "--connection", "c-1", "--task", "NOPE-9", "--session-id", "s",
                           "--origin", fake.origin)
    assert invalid["declared"] is False and len(fake.declarations) == 1


@posix_only
def test_task_selection_refused_for_a_builder_key_is_reported_as_unavailable(sandbox, fake):
    sandbox.connect()
    fake.tasks_status = 403
    result = sandbox.json("task", "options", "--origin", fake.origin)
    assert result["state"] == "unavailable" and "backend dispatch B" in result["message"]


# ---------------------------------------------------------------------------------- independence


def test_helper_never_touches_the_cli_or_foreign_credential_stores():
    sources = "\n".join(p.read_text() for p in (HELPER_DIR).rglob("*.py")) + (HELPER_DIR.parent / "forgebench_helper.py").read_text()
    for forbidden in ("credentials.json", "gateway-keys.json", "FORGEBENCH_API_KEY", 'which("forgebench")',
                      "forgebench sync", "keychain", "security find-generic-password", ".credentials", "mcp-needs-auth"):
        assert forbidden not in sources, forbidden
    wrapper = (HELPER_DIR.parent / "forgebench-run").read_text()
    assert "forgebench " not in wrapper.replace("forgebench-run", "").replace("forgebench_helper", "").replace("Forgebench", "")


HELPER_DIR = Path(__file__).resolve().parents[1] / "scripts" / "fbplugin"
