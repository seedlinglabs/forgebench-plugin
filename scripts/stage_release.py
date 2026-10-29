#!/usr/bin/env python3
"""Stage and validate the Claude plugin artifact for forgebench-cli."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

PRODUCTION_URL = "https://api.forgebench.ai"


def _ignore_dev_artifacts(source_root: Path):
    """Return a copytree ignore callback preserving runtime scripts."""
    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(source_root)
            if (
                relative == Path("tests")
                or relative == Path("scripts/stage_release.py")
                or relative == Path(".claude-plugin/marketplace.json")
                or name in {"__pycache__", ".pytest_cache"}
                or (path.is_file() and path.suffix == ".pyc")
            ):
                ignored.add(name)
        return ignored

    return ignore


def require_production_url(plugin_dir: Path) -> None:
    """Fail unless the plugin default and its resolved MCP URL are production."""
    try:
        plugin = json.loads((plugin_dir / ".claude-plugin/plugin.json").read_text())
        mcp = json.loads((plugin_dir / ".mcp.json").read_text())
        default = plugin["userConfig"]["forgebench_url"]["default"]
        configured_url = mcp["mcpServers"]["forgebench"]["url"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"invalid plugin URL configuration: {exc}") from exc

    if default != PRODUCTION_URL:
        raise ValueError(
            f"plugin must default to {PRODUCTION_URL} (got {default!r})"
        )

    valid_mcp_urls = ("${user_config.mcp_url}", f"{PRODUCTION_URL}/mcp", "${user_config.forgebench_url}/mcp")
    resolved = configured_url.replace("${user_config.forgebench_url}", default)
    if configured_url not in valid_mcp_urls and resolved != f"{PRODUCTION_URL}/mcp":
        raise ValueError(
            "plugin must resolve its MCP URL to https://api.forgebench.ai/mcp "
            f"or use '${{user_config.mcp_url}}' (got {configured_url!r})"
        )


def stage(source: Path, destination: Path) -> None:
    """Copy the plugin and create the public repository marketplace manifest."""
    source = source.resolve()
    destination = destination.resolve()
    require_production_url(source)
    if destination == source or source in destination.parents:
        raise ValueError("destination must not be the source or inside the source")

    plugin_destination = destination / "plugins/forgebench"
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"destination must be empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, plugin_destination, ignore=_ignore_dev_artifacts(source))
    marketplace_dir = destination / ".claude-plugin"
    marketplace_dir.mkdir()
    (marketplace_dir / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "forgebench",
                "owner": {"name": "forgebench", "url": "https://forgebench.ai"},
                "description": "The forgebench Claude Code plugin marketplace.",
                "plugins": [
                    {
                        "name": "forgebench",
                        "source": "./plugins/forgebench",
                        "description": "The forgebench Claude Code plugin.",
                        "category": "security",
                        "tags": ["mcp", "agents", "governance", "budgets"],
                    }
                ],
            },
            indent=2,
        )
        + "\n"
    )
    require_production_url(plugin_destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    stage(args.source, args.destination)
    print(f"Staged plugin at {args.destination / 'plugins/forgebench'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
