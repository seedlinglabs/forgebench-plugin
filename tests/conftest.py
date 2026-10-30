from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_backend import Fake, SECRETS  # noqa: E402

PLUGIN = Path(__file__).resolve().parents[1]
HELPER = PLUGIN / "scripts" / "forgebench_helper.py"


class Sandbox:
    """An isolated HOME / CLAUDE_CONFIG_DIR with a minimal PATH that does not contain the Forgebench CLI."""

    def __init__(self, root: Path, fake: Fake):
        self.root = root
        self.home = root / "home"
        self.config = self.home / ".claude"
        self.config.mkdir(parents=True)
        self.fake = fake
        self.captured: list[str] = []  # every stdout/stderr string, scanned for secrets by the fixture
        self.argvs: list[list[str]] = []

    def env(self, **extra) -> dict:
        env = {"HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(self.config), "PATH": "/usr/bin:/bin",
               "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
        env.update(extra)
        return env

    def run(self, *args: str, stdin: str | None = None, env: dict | None = None, cwd: str | None = None,
            url: bool = True, check_secrets: bool = True):
        cmd = [sys.executable, str(HELPER)]
        full = list(args)
        words = [a for a in full if a != "--json"]
        takes_url = not (words and words[0] == "auth" and len(words) > 1 and words[1] in ("wait", "cancel"))
        if url and takes_url and "--url" not in full and "--origin" not in full:
            full += ["--url", self.fake.origin]
        argv = cmd + full
        self.argvs.append(argv)
        proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=60,
                              env=env or self.env(), cwd=cwd or str(self.root))
        self.captured += [proc.stdout, proc.stderr]
        return proc

    def json(self, *args, **kwargs) -> dict:
        proc = self.run("--json", *args, **kwargs)
        assert proc.stdout.strip(), proc.stderr
        return json.loads(proc.stdout)

    def connect(self) -> dict:
        begun = self.json("auth", "begin", "--no-browser")
        assert begun["status"] == "waiting", begun
        urllib.request.urlopen(begun["login_url"], timeout=10).read()  # the "browser": login -> loopback callback
        done = self.json("auth", "wait", "--op", begun["op"], "--seconds", "20")
        assert done["status"] == "complete", done
        return done

    @property
    def settings_path(self) -> Path:
        return self.config / "settings.json"

    def settings(self) -> dict:
        return json.loads(self.settings_path.read_text())

    def write_settings(self, value) -> None:
        self.settings_path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2))

    def data_files(self) -> list[Path]:
        root = self.config / "forgebench-plugin"
        return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


@pytest.fixture
def fake():
    backend = Fake().start()
    yield backend
    backend.stop()


@pytest.fixture
def sandbox(tmp_path, fake):
    box = Sandbox(tmp_path, fake)
    yield box
    # No fake secret may appear in anything the helper printed, in any argv, or in the sign-in state files.
    for text in box.captured:
        for secret in SECRETS:
            assert secret not in text, "a secret leaked to stdout/stderr"
    for argv in box.argvs:
        for secret in SECRETS:
            assert all(secret not in part for part in argv)
    for path in (box.config / "forgebench-plugin" / "auth").glob("*.json") if (box.config / "forgebench-plugin" / "auth").exists() else []:
        for secret in SECRETS:
            assert secret not in path.read_text()
