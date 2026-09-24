"""Tests for scripts/forgebench_scan.py — the hosted-MCP repository scanner.

Most tests run the scanner the way Claude Code does — ``python3
forgebench_scan.py ...`` as a subprocess, from the repository root — against
``fixtures/sample_repo`` (a CrewAI crew and a LangGraph agent wired to MCP
servers declared in code and in ``.mcp.json``, plus agents under ``tests/``,
``docs/`` and — created by the ``repo`` fixture, since ``.claude/`` is
gitignored — ``.claude/skills`` that must be skipped). The fixture is copied
to a temporary directory outside any git checkout so the repository identity
is fully determined by ``--origin``, and ``HOME`` points at a scratch home so
the developer's real client configs are never read.

The contract test imports the CONTROL PLANE's own validator
(``apps/control-plane/app/scans/payload.py``, stdlib-only) and checks the
scanner's payload passes it unchanged — scanner and server can never
silently disagree about the wire format.

Run: ``python3 -m pytest packages/forgebench-plugin/tests`` (Python >= 3.10,
pytest; tree-sitter optional).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
SCANNER = PLUGIN / "scripts" / "forgebench_scan.py"
VENDOR = PLUGIN / "scripts" / "_vendor" / "agent_harness_explorer"
FIXTURE = HERE / "fixtures" / "sample_repo"
MONOREPO = PLUGIN.parent.parent
BUNDLE = MONOREPO / "packages/cli-session-reviewer/forgebench_session_reviewer/bundles/agent-harness-explorer/scripts"
CONTROL_PLANE = MONOREPO / "apps" / "control-plane"
ORIGIN = "https://github.com/Acme/Sample-Repo.git"
SECRET_MARK = "must_never_upload"
EXCLUDED_AGENTS = ("TestOnlyAgent", "DocsOnlyAgent", "SkillOnlyAgent")


def _load_scanner():
    spec = importlib.util.spec_from_file_location("forgebench_scan", SCANNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scan = _load_scanner()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    # A PERSONAL server in the home directory: must not be read unless asked.
    (h / ".claude.json").write_text(json.dumps({"mcpServers": {"personal": {"command": "personal-mcp"}}}))
    return h


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    dest = tmp_path / "sample-repo"
    shutil.copytree(FIXTURE, dest)
    # Created here rather than committed: ``.claude/`` is gitignored in this
    # monorepo. A coding-agent skill script that declares an agent — the
    # scanner must skip ``.claude/skills`` by default.
    skill = dest / ".claude" / "skills" / "demo" / "scripts"
    skill.mkdir(parents=True)
    (skill / "helper.py").write_text(
        "from crewai import Agent\n\nskill_agent = Agent(role='SkillOnlyAgent', goal='x', backstory='y', tools=[])\n"
    )
    return dest


def run(repo: Path, home: Path, *args: str, python: str = sys.executable, env: dict | None = None):
    environ = {**os.environ, "HOME": str(home), **(env or {})}
    if not env or "FORGEBENCH_SCAN_TICKET" not in env:
        environ.pop("FORGEBENCH_SCAN_TICKET", None)
    return subprocess.run(
        [python, str(SCANNER), *args], cwd=repo, env=environ, capture_output=True, text=True, timeout=120
    )


def scan_to_file(repo: Path, home: Path, *extra: str) -> tuple[dict, bytes, subprocess.CompletedProcess]:
    out = repo.parent / "payload.json"
    proc = run(repo, home, "--out", str(out), "--origin", ORIGIN, *extra)
    assert proc.returncode == 0, proc.stderr
    raw = out.read_bytes().rstrip(b"\n")
    return json.loads(raw), raw, proc


# =====================================================================================
# the payload
# =====================================================================================
def test_payload_from_the_fixture_repo(repo, home):
    payload, raw, proc = scan_to_file(repo, home)

    assert payload["schema"] == "forgebench.scan/v1"
    assert payload["scanner"]["version"] == scan.SCANNER_VERSION
    assert len(payload["scanner"]["sha256"]) == 64
    assert payload["repo"] == {
        "origin_hash": "sha256:" + hashlib.sha256(b"github.com/acme/sample-repo").hexdigest(),
        "origin_display": "github.com/acme/sample-repo",
        "commit": None,
        "root_basename": "sample-repo",
    }

    servers = {s["name"]: s for s in payload["mcp_servers"]}
    assert sorted(servers) == ["papers", "papers-mcp", "tracker", "weather"]
    assert servers["papers"]["transport"] == "stdio" and servers["papers"]["env_keys"] == ["PAPERS_API_KEY"]
    assert servers["papers"]["source"] == "claude-code (project)"
    # a synthesized npx name loses its version, and so does its fingerprint
    assert servers["papers-mcp"]["command_fingerprint"] == scan.command_fingerprint("npx", ["-y", "@acme/papers-mcp@9.9.9"])
    assert servers["tracker"] == {
        "name": "tracker",
        "transport": "http",
        "source": "claude-code (project)",
        "url_host": "tracker.example.test",
        "env_keys": [],
        "header_keys": ["Authorization"],
        "tools": [],
    }
    assert servers["weather"]["url_host"] == "mcp.weather.example.test"

    agents = {(a["framework"], a["declared_name"], a["path"]) for a in payload["agents"]}
    assert agents == {("crewai", "Researcher", "crew/research_crew.py"), ("langgraph", "planner", "graph/planner.py")}
    assert {(r["agent"], r["server"]) for r in payload["agent_mcp_servers"]} == {
        ("Researcher", "papers-mcp"),
        ("planner", "papers"),
        ("planner", "weather"),
    }
    assert any("SHADOWED" in g for g in payload["gaps"])  # code 'papers' vs .mcp.json 'papers'
    assert any("were not dialed" in g for g in payload["gaps"])

    # What must never leave the laptop.
    for forbidden in (SECRET_MARK, str(repo), str(home), "servers/papers_server.py", "https://", "@1.4.2", "personal"):
        assert forbidden.encode() not in raw, forbidden
    for name in EXCLUDED_AGENTS:
        assert name.encode() not in raw


def test_stdout_is_counts_and_sha256_only(repo, home):
    payload, raw, proc = scan_to_file(repo, home)
    lines = proc.stdout.strip().splitlines()
    assert lines[0].startswith("forgebench scan: 4 MCP server(s) (0 dialed, 0 tool(s) known), 2 agent(s), 3 agent-to-server")
    assert lines[1] == f"payload: {len(raw)} bytes sha256={hashlib.sha256(raw).hexdigest()}"
    for repo_string in ("Researcher", "planner", "papers", "weather", "tracker", str(repo), SECRET_MARK):
        assert repo_string not in proc.stdout
    assert proc.stderr == ""


def test_payload_passes_the_control_plane_validator_unchanged(repo, home):
    if not (CONTROL_PLANE / "app" / "scans" / "payload.py").is_file():
        pytest.skip("control plane sources not available")
    sys.path.insert(0, str(CONTROL_PLANE))
    try:
        from app.scans.payload import validate_part
    finally:
        sys.path.remove(str(CONTROL_PLANE))
    payload, _, _ = scan_to_file(repo, home, "--dial", "papers")
    normalized = validate_part("scanner", payload)
    assert json.dumps(normalized, sort_keys=True) == json.dumps(payload, sort_keys=True)


def test_scanning_is_deterministic(repo, home):
    a, raw_a, _ = scan_to_file(repo, home)
    b, raw_b, _ = scan_to_file(repo, home)
    assert raw_a == raw_b


def test_default_excludes_and_include(repo, home):
    payload, _, _ = scan_to_file(repo, home, "--include", "tests")
    names = {a["declared_name"] for a in payload["agents"]}
    assert "TestOnlyAgent" in names and "DocsOnlyAgent" not in names and "SkillOnlyAgent" not in names
    payload, _, _ = scan_to_file(repo, home, "--include", ".claude/skills")
    assert "SkillOnlyAgent" in {a["declared_name"] for a in payload["agents"]}
    nested = repo / "pkg" / ".claude" / "skills" / "x"
    nested.mkdir(parents=True)
    (nested / "tool.py").write_text("from crewai import Agent\nnested = Agent(role='NestedSkillAgent', tools=[])\n")
    payload, _, _ = scan_to_file(repo, home)
    assert "NestedSkillAgent" not in {a["declared_name"] for a in payload["agents"]}


def test_personal_configs_are_read_only_when_asked(repo, home):
    payload, _, _ = scan_to_file(repo, home)
    assert "personal" not in {s["name"] for s in payload["mcp_servers"]}
    payload, _, _ = scan_to_file(repo, home, "--include-user-configs")
    assert "personal" in {s["name"] for s in payload["mcp_servers"]}


def test_dial_lists_tools_only_for_the_approved_server(repo, home):
    payload, _, proc = scan_to_file(repo, home, "--dial", "papers")
    tools = {s["name"]: [t["name"] for t in s["tools"]] for s in payload["mcp_servers"]}
    assert tools == {"papers": ["delete_paper", "search_papers"], "papers-mcp": [], "tracker": [], "weather": []}
    assert "(1 dialed, 2 tool(s) known)" in proc.stdout


def test_unknown_dial_name_is_refused_before_anything_runs(repo, home):
    proc = run(repo, home, "--out", "x.json", "--dial", "not-a-server")
    assert proc.returncode == 2 and not (repo / "x.json").exists()


def test_list_servers_is_a_consent_listing(repo, home):
    proc = run(repo, home, "--list-servers")
    assert proc.returncode == 0
    assert "Nothing has been launched or contacted" in proc.stdout
    assert "LAUNCHES: python3 servers/papers_server.py" in proc.stdout
    assert "CONTACTS: https://tracker.example.test/mcp?token=[REDACTED]" in proc.stdout
    assert SECRET_MARK not in proc.stdout


def test_nothing_to_do_is_an_error(repo, home):
    proc = run(repo, home)
    assert proc.returncode == 2 and "nothing to do" in proc.stderr


def test_python_version_gate():
    old = next(
        (p for p in ("/usr/bin/python3", "/usr/local/bin/python3.9", "/usr/bin/python3.9") if _is_old_python(p)), None
    )
    if old is None:
        pytest.skip("no Python < 3.10 on this machine")
    proc = subprocess.run([old, str(SCANNER), "--list-servers"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "Python 3.10 or newer is required" in proc.stderr


def _is_old_python(path: str) -> bool:
    if not Path(path).exists():
        return False
    try:
        out = subprocess.run([path, "-c", "import sys; print(sys.version_info[:2] < (3, 10))"], capture_output=True, text=True, timeout=10)
    except OSError:
        return False
    return out.stdout.strip() == "True"


# =====================================================================================
# upload
# =====================================================================================
class _Stub:
    def __init__(self, status: int, body: dict):
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "body": self.rfile.read(length)})
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def url(self, scan_id: str) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1/scans/{scan_id}/parts"


def test_upload_sends_the_exact_bytes_under_the_ticket(repo, home):
    scan_id, ticket = str(uuid.uuid4()), "fbscan_" + "t" * 43
    with _Stub(201, {"part_id": "part-1", "parts_remaining": 7, "bytes_remaining": 123}) as stub:
        proc = run(repo, home, "--upload-url", stub.url(scan_id), "--origin", ORIGIN, env={"FORGEBENCH_SCAN_TICKET": ticket})
    assert proc.returncode == 0, proc.stderr
    [req] = stub.requests
    assert req["path"] == f"/v1/scans/{scan_id}/parts"
    assert req["headers"]["Authorization"] == f"Bearer {ticket}"
    assert req["headers"]["Content-Type"] == "application/json"
    assert f"sha256={hashlib.sha256(req['body']).hexdigest()}" in proc.stdout
    assert "uploaded: part part-1" in proc.stdout
    assert ticket not in proc.stdout and SECRET_MARK.encode() not in req["body"]


def test_upload_failure_reports_the_server_code(repo, home):
    detail = {"detail": {"code": "scan_sealed", "message": "This scan has already been reviewed."}}
    with _Stub(409, detail) as stub:
        proc = run(repo, home, "--upload-url", stub.url(str(uuid.uuid4())), "--ticket", "fbscan_" + "u" * 43)
    assert proc.returncode == 1
    assert "upload failed: HTTP 409 scan_sealed" in proc.stderr


@pytest.mark.parametrize(
    "url, ticket, ok",
    [
        ("https://api.example.com/v1/scans/%s/parts", "fbscan_abc", True),
        ("http://localhost:8000/v1/scans/%s/parts", "fbscan_abc", True),
        ("https://gw.example.com/forgebench/v1/scans/%s/parts", "fbscan_abc", True),  # path prefix
        ("http://api.example.com/v1/scans/%s/parts", "fbscan_abc", False),  # ticket over plain http
        ("https://api.example.com/v1/scans/%s/parts?x=1", "fbscan_abc", False),
        ("https://api.example.com/v1/agents/%s", "fbscan_abc", False),
        ("https://user:pw@api.example.com/v1/scans/%s/parts", "fbscan_abc", False),
        ("https://api.example.com/v1/scans/%s/parts", "sk_live_abc", False),
    ],
)
def test_upload_target_guards(url, ticket, ok):
    problem = scan.check_upload_target(url % uuid.uuid4(), ticket, allow_insecure=False)
    assert (problem is None) is ok, problem


# =====================================================================================
# identity helpers
# =====================================================================================
@pytest.mark.parametrize(
    "remote, expected",
    [
        ("git@github.com:Acme/Agents.git", "github.com/acme/agents"),
        ("https://user:token@github.com/acme/agents", "github.com/acme/agents"),
        ("ssh://git@github.com:22/acme/agents.git", "github.com/acme/agents"),
        ("https://gitlab.example.com/group/sub/repo.git/", "gitlab.example.com/group/sub/repo"),
        ("https://dev.azure.com/org/proj/_git/repo", "dev.azure.com/org/proj/_git/repo"),
        ("/srv/git/repo.git", None),
        ("file:///srv/git/repo.git", None),
        ("", None),
    ],
)
def test_normalize_remote(remote, expected):
    assert scan.normalize_remote(remote) == expected


def _fake_git(top: Path, *, remote: str, packed: bool = False) -> str:
    sha = "c0ffee" + "0" * 34
    git = top / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "config").write_text(f'[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://x.test/a/b\n[remote "origin"]\n\turl = {remote}\n')
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    if packed:
        (git / "packed-refs").write_text(f"# pack-refs with: peeled\n{sha} refs/heads/main\n")
    else:
        (git / "refs" / "heads" / "main").write_text(sha + "\n")
    return sha


@pytest.mark.parametrize("packed", [False, True])
def test_repo_identity_from_git_files(tmp_path, packed):
    top = tmp_path / "checkout-dir"
    (top / "services" / "bots").mkdir(parents=True)
    sha = _fake_git(top, remote="git@github.com:Acme/Thing.git", packed=packed)
    repo, prefix = scan.repo_identity(top / "services" / "bots", None)
    assert repo["origin_display"] == "github.com/acme/thing" and repo["commit"] == sha
    assert repo["root_basename"] == "thing"  # the repo's name, not the checkout directory's
    assert prefix == "services/bots"


def test_repo_identity_in_a_worktree(tmp_path):
    main = tmp_path / "main"
    main.mkdir()
    sha = _fake_git(main, remote="https://github.com/acme/thing")
    wt_gitdir = main / ".git" / "worktrees" / "feature"
    wt_gitdir.mkdir(parents=True)
    (wt_gitdir / "commondir").write_text("../..\n")
    (wt_gitdir / "HEAD").write_text(sha + "\n")
    worktree = tmp_path / "feature-checkout"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {wt_gitdir}\n")
    repo, prefix = scan.repo_identity(worktree, None)
    assert repo["origin_display"] == "github.com/acme/thing" and repo["commit"] == sha and prefix == ""


def test_repo_without_remote_is_local(tmp_path):
    d = tmp_path / "My Project"
    d.mkdir()
    repo, _ = scan.repo_identity(d, None)
    assert repo["origin_display"] == "local/my-project" and repo["commit"] is None


@pytest.mark.parametrize(
    "command, args, identity, pretty",
    [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem@1.2.0", "/Users/me/dir"],
         "npx:@modelcontextprotocol/server-filesystem", "server-filesystem"),
        ("/opt/homebrew/bin/npx", ["-y", "@acme/papers-mcp"], "npx:@acme/papers-mcp", "papers-mcp"),
        ("docker", ["run", "-i", "--rm", "ghcr.io/acme/github-mcp:1.4@sha256:abc"], "docker:ghcr.io/acme/github-mcp", "github-mcp"),
        ("python3.12", ["servers/papers_server.py", "--port", "1"], "python:papers_server.py", "papers_server"),
        ("uv", ["run", "--with", "x", "server.py"], "uv:server.py", "server"),
        ("uvx", ["mcp-server-time==0.6"], "uvx:mcp-server-time", "mcp-server-time"),
        ("python", ["-m", "acme.mcp_server", "--verbose"], "python:acme.mcp_server", "acme.mcp_server"),
        ("docker", ["run", "-e", "TOKEN", "--rm", "-i", "acme/jira-mcp:latest", "stdio"], "docker:acme/jira-mcp", "jira-mcp"),
        ("/usr/local/bin/github-mcp-server", ["stdio"], "github-mcp-server", "github-mcp-server"),
    ],
)
def test_launch_identity_and_pretty_names(command, args, identity, pretty):
    assert scan.launch_identity(command, args) == identity
    assert scan.pretty_server_name(command, args) == pretty


# =====================================================================================
# vendored bundle scanners
# =====================================================================================
def test_vendored_scanners_match_the_bundle():
    if not BUNDLE.is_dir():
        pytest.skip("not running inside the forgebench monorepo")
    for name in scan.VENDORED_FILES:
        assert (VENDOR / name).read_bytes() == (BUNDLE / name).read_bytes(), (
            f"{name} drifted from the bundle — copy it again (see scripts/_vendor/README.md)"
        )


def test_bundle_discover_only_prints_json_to_stdout_without_out(repo, home, monkeypatch, capsys):
    import inspect_mcp_configs
    import inspect_mcp_source

    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    assert inspect_mcp_source._main(["inspect_mcp_source.py", "--discover-only", "--root", str(repo)]) == 0
    out, err = capsys.readouterr()
    doc = json.loads(out)
    assert {a["name"] for a in doc["agents"]} == {"Researcher", "planner"}
    assert "agent declaration" in err  # the human listing moved to stderr

    assert inspect_mcp_configs._main(["inspect_mcp_configs.py", "--discover-only", "--root", str(repo)]) == 0
    out, err = capsys.readouterr()
    assert {s["name"] for s in json.loads(out)["stdio_servers"]} >= {"papers"}
    assert "LAUNCHED" in err

    target = repo.parent / "discovered.json"
    assert inspect_mcp_source._main(["x", "--discover-only", "--root", str(repo), "--out", str(target)]) == 0
    out, _ = capsys.readouterr()
    assert "agent declaration" in out and json.loads(target.read_text())["agents"]


def test_bundle_ts_discover_only_prints_json(repo, monkeypatch, capsys):
    import inspect_ts_mcp_source

    if not inspect_ts_mcp_source.TREE_SITTER_AVAILABLE:
        pytest.skip("tree-sitter not installed")
    (repo / "web").mkdir()
    (repo / "web" / "agent.ts").write_text(
        'import { Agent } from "@mastra/core/agent";\nexport const agent = new Agent({ name: "TsAgent", tools: {} });\n'
    )
    assert inspect_ts_mcp_source._main(["x", "--discover-only", "--root", str(repo)]) == 0
    out, _ = capsys.readouterr()
    assert [a["name"] for a in json.loads(out)["agents"]] == ["TsAgent"]


def test_bundle_file_cap_warning_is_loud(tmp_path):
    import inspect_mcp_source

    for i in range(3):
        (tmp_path / f"m{i}.py").write_text("x = 1\n")
    _, warnings = inspect_mcp_source.iter_python_files(tmp_path, set(inspect_mcp_source._DEFAULT_EXCLUDE_DIRS), 1)
    [warning] = warnings
    assert warning.startswith("INCOMPLETE SCAN") and inspect_mcp_source.TRUNCATION_MARKER in warning


def test_scanner_reports_truncation(repo, home):
    payload, _, proc = scan_to_file(repo, home, "--max-files", "1")
    assert "INCOMPLETE: the file cap was reached" in proc.stdout
    assert any(g.startswith("INCOMPLETE SCAN") for g in payload["gaps"])
