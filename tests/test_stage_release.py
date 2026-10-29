import json
import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_DIR / "scripts/stage_release.py"


def test_production_url_guard_passes_for_plugin_tree(tmp_path):
    staged = tmp_path / "staged"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--source", str(PLUGIN_DIR), "--destination", str(staged)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    plugin = staged / "plugins/forgebench"
    for required in (
        ".claude-plugin/plugin.json",
        ".mcp.json",
        "hooks/hooks.json",
        "scripts/forgebench_sync_launcher.py",
        "scripts/_vendor",
        "skills",
        "LICENSE",
        "README.md",
    ):
        assert (plugin / required).exists(), required

    for excluded in (
        "tests",
        "scripts/stage_release.py",
        ".claude-plugin/marketplace.json",
    ):
        assert not (plugin / excluded).exists(), excluded
    assert not list(plugin.rglob("__pycache__"))
    assert not list(plugin.rglob(".pytest_cache"))
    assert not list(plugin.rglob("*.pyc"))


def test_production_url_guard_rejects_dev_artifact(tmp_path):
    dev_plugin = tmp_path / "plugin"
    shutil.copytree(PLUGIN_DIR, dev_plugin)
    manifest_path = dev_plugin / ".claude-plugin/plugin.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["userConfig"]["forgebench_url"]["default"] = "http://localhost:8000"
    manifest_path.write_text(json.dumps(manifest))

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--source", str(dev_plugin), "--destination", str(tmp_path / "staged")],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "must default to https://api.forgebench.ai" in result.stderr
