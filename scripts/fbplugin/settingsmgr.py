"""Native Claude Code configuration: gateway binding and OTel exporter, applied only on an explicit user action.

Rules:
* only ``$CLAUDE_CONFIG_DIR/settings.json`` (user scope) is ever written; managed, project, local settings
  and the process environment are read to detect conflicts and are never modified;
* a value is ours only if the ownership receipt says we wrote it and it is unchanged; anything else that
  occupies a key we need is a conflict that is reported (key names and layers only, never values) and that
  group is skipped; nothing foreign is cleared;
* invalid JSON in the settings file refuses the write; the write is locked, atomic, and re-checked against
  the bytes that were planned from;
* the receipt is journaled before the write, so a crash between the two is recoverable;
* unapply restores only values that still equal what we wrote.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .common import (HelperError, atomic_write, config_dir, data_dir, ensure_private_dir, file_lock, iso, read_json,
                     subdir, write_json, truthy)

HARNESS_LINE = "X-Forgebench-Harness: claude_code"
HELPER_TTL = "3600000"
OTLP_SUFFIX = "/v1/telemetry/otlp"
CONTENT_FLAGS = ("OTEL_LOG_USER_PROMPTS", "OTEL_LOG_ASSISTANT_RESPONSES", "OTEL_LOG_TOOL_DETAILS",
                 "OTEL_LOG_TOOL_CONTENT", "OTEL_LOG_RAW_API_BODIES")
GATEWAY_FOREIGN_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
                       "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
GATEWAY_FOREIGN_TOP = ("forceLoginMethod", "forceLoginOrgUUID")
OTEL_FOREIGN_ENV = (
    "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_HEADERS", "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "BETA_TRACING_ENDPOINT", "ENABLE_BETA_TRACING_DETAILED",
    "ENABLE_ENHANCED_TELEMETRY_BETA")


@dataclass
class Layer:
    name: str  # user | managed | project | local | process
    data: dict
    path: str = ""
    error: str = ""

    @property
    def env(self) -> dict:
        value = self.data.get("env") if self.name != "process" else self.data
        return value if isinstance(value, dict) else {}


def settings_path() -> Path:
    return config_dir() / "settings.json"


def managed_path() -> Path:
    system = platform.system()
    if system == "Darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    return Path("/etc/claude-code/managed-settings.json")


def _load(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, ""
    except OSError:
        return {}, "unreadable"
    if not text.strip():
        return {}, ""
    try:
        value = json.loads(text)
    except ValueError:
        return {}, "invalid_json"
    return (value, "") if isinstance(value, dict) else ({}, "not_an_object")


def read_layers(cwd: str | None = None, environ: dict | None = None) -> list[Layer]:
    layers = []
    for name, path in (("user", settings_path()), ("managed", managed_path())):
        data, error = _load(path)
        layers.append(Layer(name, data, str(path), error))
    if cwd:
        for name, rel in (("project", ".claude/settings.json"), ("local", ".claude/settings.local.json")):
            data, error = _load(Path(cwd) / rel)
            layers.append(Layer(name, data, str(Path(cwd) / rel), error))
    layers.append(Layer("process", dict(os.environ if environ is None else environ)))
    return layers


# ------------------------------------------------------------------------------------ runtime copy


def _bundle_files(src: Path) -> list[Path]:
    files = [src / "forgebench_helper.py"]
    files += sorted((src / "fbplugin").glob("*.py"))
    return [f for f in files if f.is_file()]


def bundle_digest(src: Path) -> str:
    digest = hashlib.sha256()
    for file in _bundle_files(src):
        digest.update(file.name.encode())
        digest.update(file.read_bytes())
    return digest.hexdigest()[:12]


def install_runtime(src: Path, keep: set[str] | None = None) -> tuple[Path, str]:
    """Copy the packaged helper to a stable private path (plugin updates move CLAUDE_PLUGIN_ROOT)."""
    digest = bundle_digest(src)
    root = subdir("runtime")
    target = root / digest
    entry = target / "forgebench_helper.py"
    if not entry.exists():
        staging = root / f".{digest}.tmp-{os.getpid()}"
        shutil.rmtree(staging, ignore_errors=True)
        (staging / "fbplugin").mkdir(parents=True)
        for file in _bundle_files(src):
            dest = staging / file.relative_to(src)
            shutil.copy2(file, dest)
            os.chmod(dest, 0o600)
        try:
            os.rename(staging, target)
        except OSError:
            shutil.rmtree(staging, ignore_errors=True)
    keep = (keep or set()) | {digest}
    for old in root.iterdir():
        if old.is_dir() and not old.name.startswith(".") and old.name not in keep:
            shutil.rmtree(old, ignore_errors=True)
    return entry, digest


def helper_command(entry: Path, mode: str, origin: str) -> str:
    """The shell-quoted command Claude runs for ``apiKeyHelper`` / ``otelHeadersHelper`` (through /bin/sh -c)."""
    return shlex.join([sys.executable, str(entry), mode, "--origin", origin])


# ------------------------------------------------------------------------------------ desired values


def desired(origin: str, entry: Path, gateway: bool, telemetry: bool, traces: bool) -> list[dict]:
    items: list[dict] = []
    if gateway:
        items += [
            {"group": "gateway", "scope": "env", "key": "ANTHROPIC_BASE_URL", "value": origin},
            {"group": "gateway", "scope": "env", "key": "CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "value": HELPER_TTL},
            {"group": "gateway", "scope": "header", "key": "ANTHROPIC_CUSTOM_HEADERS", "value": HARNESS_LINE},
            {"group": "gateway", "scope": "top", "key": "apiKeyHelper",
             "value": helper_command(entry, "api-key", origin)},
        ]
    if telemetry:
        env = {
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_METRICS_EXPORTER": "otlp",
            "OTEL_TRACES_EXPORTER": "otlp" if traces else "none",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
            "OTEL_EXPORTER_OTLP_ENDPOINT": origin + OTLP_SUFFIX,
            "OTEL_METRICS_INCLUDE_VERSION": "true",
            "OTEL_LOGS_EXPORT_INTERVAL": "5000",
            **{flag: "0" for flag in CONTENT_FLAGS},
        }
        if traces:
            env["CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"] = "1"
        items += [{"group": "telemetry", "scope": "env", "key": k, "value": v} for k, v in env.items()]
        items.append({"group": "telemetry", "scope": "top", "key": "otelHeadersHelper",
                      "value": helper_command(entry, "otel-headers", origin)})
    return items


# ------------------------------------------------------------------------------------ planning


@dataclass
class Plan:
    writes: list[dict] = field(default_factory=list)  # entries to write (with previous/had_previous)
    unchanged: list[dict] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)
    skipped_groups: set = field(default_factory=set)


def _owned(receipt: dict | None, item: dict) -> dict | None:
    for entry in (receipt or {}).get("entries", []):
        if entry["scope"] == item["scope"] and entry["key"] == item["key"] and entry["group"] == item["group"]:
            return entry
    return None


def _same(key: str, current: object, value: str) -> bool:
    if key in CONTENT_FLAGS:
        return not truthy(current) and str(current).strip().lower() not in ("file",) and not str(current).startswith("file:")
    return str(current) == value


def _conflict(group: str, key: str, layer: str, kind: str, reason: str) -> dict:
    return {"group": group, "key": key, "layer": layer, "kind": kind, "reason": reason}


def _layer_value(layer: Layer, scope: str, key: str):
    if scope == "top":
        return layer.data.get(key) if layer.name != "process" else None
    return layer.env.get(key)


def plan(items: list[dict], layers: list[Layer], receipt: dict | None) -> Plan:
    result = Plan()
    user = next(layer for layer in layers if layer.name == "user")
    if user.error:
        raise HelperError("settings_unreadable",
                          f"{user.path} is not valid JSON ({user.error}); fix it first. Nothing was changed")
    if "env" in user.data and not isinstance(user.data["env"], dict):
        raise HelperError("settings_unreadable", f"{user.path} has a non-object `env`; nothing was changed")
    groups = {item["group"] for item in items}
    owned_values = {(e["scope"], e["key"]): e["value"] for e in (receipt or {}).get("entries", [])}
    for group in sorted(groups):
        group_items = [i for i in items if i["group"] == group]
        conflicts: list[dict] = []
        for layer in layers:
            if layer.error and layer.name in ("managed",):
                conflicts.append(_conflict(group, "settings", layer.name, "unreadable", "managed settings unreadable"))
        # detect-only foreign configuration
        foreign_env = GATEWAY_FOREIGN_ENV if group == "gateway" else OTEL_FOREIGN_ENV
        for layer in layers:
            if layer.name in ("project", "local") and group == "telemetry":
                continue  # Claude ignores exporter variables in repository settings
            for key in foreign_env:
                value = layer.env.get(key)
                if value not in (None, "") and owned_values.get(("env", key)) != value:
                    conflicts.append(_conflict(group, key, layer.name, "foreign",
                                               "already configured elsewhere; left untouched"))
            if group == "gateway":
                for key in GATEWAY_FOREIGN_TOP:
                    if layer.data.get(key) not in (None, "") and layer.name != "process":
                        conflicts.append(_conflict(group, key, layer.name, "login_policy",
                                                   "login policy may prevent a gateway key helper"))
        # per-key checks against every layer
        for item in group_items:
            key, scope, value = item["key"], item["scope"], item["value"]
            for layer in layers:
                if layer.name in ("project", "local") and group == "telemetry":
                    continue
                if layer.name == "process" and scope == "top":
                    continue
                current = _layer_value(layer, scope, key)
                if current in (None, ""):
                    continue
                if scope == "header":
                    continue
                own = owned_values.get((scope, key))
                if layer.name == "user":
                    if own is not None and current == own:
                        continue
                    if _same(key, current, value):
                        continue
                    kind = "privacy" if key in CONTENT_FLAGS else "foreign"
                    conflicts.append(_conflict(group, key, "user", kind,
                                               "content capture is enabled in your settings; not copied to Forgebench"
                                               if kind == "privacy" else "set to a different value; left untouched"))
                else:
                    if own is not None and current == own:
                        continue
                    if _same(key, current, value) or key in CONTENT_FLAGS and not truthy(current):
                        continue
                    kind = "privacy" if key in CONTENT_FLAGS else "overrides"
                    conflicts.append(_conflict(group, key, layer.name, kind,
                                               "set by this layer, which would override or conflict with Forgebench"))
        if conflicts:
            result.skipped_groups.add(group)
            result.conflicts += _dedupe(conflicts)
            continue
        for item in group_items:
            current = _layer_value(user, item["scope"], item["key"])
            own = _owned(receipt, item)
            entry = dict(item)
            if item["scope"] == "header":
                lines = [ln for ln in str(current or "").split("\n") if ln.strip()]
                if item["value"] in lines:
                    if own is not None:
                        result.unchanged.append(own)
                    else:
                        result.unchanged.append({**item, "owned": False})
                    continue
                entry["previous"] = current
                entry["had_previous"] = current is not None
            elif current in (None, ""):
                entry["previous"], entry["had_previous"] = None, False
            elif own is not None and current == own["value"]:
                if current == item["value"]:
                    result.unchanged.append(own)
                    continue
                entry["previous"], entry["had_previous"] = own["previous"], own["had_previous"]
            else:  # identical to what we want but placed by the user: leave theirs, own nothing
                result.unchanged.append({**item, "owned": False})
                continue
            result.writes.append(entry)
    return result


def _dedupe(conflicts: list[dict]) -> list[dict]:
    seen, out = set(), []
    for c in conflicts:
        marker = (c["group"], c["key"], c["layer"])
        if marker not in seen:
            seen.add(marker)
            out.append(c)
    return out


# ------------------------------------------------------------------------------------ receipt


def receipt_path() -> Path:
    return subdir("receipts") / "settings.json"


def load_receipt() -> dict | None:
    value = read_json(receipt_path())
    return value if isinstance(value, dict) and isinstance(value.get("entries"), list) else None


def _entries_merge(receipt: dict | None, plan_: Plan) -> list[dict]:
    entries = {(e["scope"], e["key"], e["group"]): e for e in (receipt or {}).get("entries", [])}
    for entry in plan_.writes:
        entries[(entry["scope"], entry["key"], entry["group"])] = entry
    return list(entries.values())


def apply(items: list[dict], origin: str, runtime_digest: str, cwd: str | None, capture: dict | None = None) -> dict:
    """Plan and write. Returns ``{written, unchanged, conflicts, skipped_groups, pending_restart}``."""
    path = settings_path()
    config_dir().mkdir(parents=True, exist_ok=True)
    with file_lock(path):
        layers = read_layers(cwd)
        receipt = load_receipt()
        plan_ = plan(items, layers, receipt)
        user = next(layer for layer in layers if layer.name == "user")
        if not plan_.writes:
            return _summary(plan_, False, receipt)
        raw_before = path.read_text(encoding="utf-8") if path.exists() else ""
        entries = _entries_merge(receipt, plan_)
        journal = {"version": 1, "origin": origin, "state": "applying", "applied_at": iso(), "runtime": runtime_digest,
                   "entries": entries, "pending_restart": True, "capture": capture or (receipt or {}).get("capture")}
        write_json(receipt_path(), journal)
        settings = json.loads(raw_before) if raw_before.strip() else {}
        env = dict(settings.get("env") or {})
        for entry in plan_.writes:
            key, value = entry["key"], entry["value"]
            if entry["scope"] == "env":
                env[key] = value
            elif entry["scope"] == "header":
                lines = [ln for ln in str(env.get(key) or "").split("\n") if ln.strip()]
                env[key] = "\n".join(lines + [value])
            else:
                settings[key] = value
        if env:
            settings["env"] = env
        current_raw = path.read_text(encoding="utf-8") if path.exists() else ""
        if current_raw != raw_before:
            raise HelperError("settings_changed", "settings.json changed while planning; nothing was written, retry")
        atomic_write(path, json.dumps(settings, indent=2) + "\n", None if path.exists() else 0o600)
        journal["state"] = "applied"
        write_json(receipt_path(), journal)
        return _summary(plan_, True, journal)


def _summary(plan_: Plan, wrote: bool, receipt: dict | None) -> dict:
    return {
        "written": [{"group": e["group"], "key": e["key"]} for e in plan_.writes],
        "unchanged": [{"group": e["group"], "key": e["key"]} for e in plan_.unchanged],
        "conflicts": plan_.conflicts,
        "skipped_groups": sorted(plan_.skipped_groups),
        "pending_restart": bool(wrote or (receipt or {}).get("pending_restart")),
    }


def unapply(groups: set[str] | None = None) -> dict:
    """Restore only unchanged values we wrote. Anything modified since stays and is reported."""
    path = settings_path()
    with file_lock(path):
        receipt = load_receipt()
        if not receipt:
            return {"restored": [], "left": [], "note": "no Forgebench-owned settings were recorded"}
        raw = path.read_text(encoding="utf-8") if path.exists() else ""
        _, error = _load(path)
        if error:
            raise HelperError("settings_unreadable", f"{path} is not valid JSON; nothing was changed")
        settings = json.loads(raw) if raw.strip() else {}
        env = dict(settings.get("env") or {})
        restored, left, kept = [], [], []
        for entry in receipt["entries"]:
            if groups is not None and entry["group"] not in groups:
                kept.append(entry)
                continue
            key, scope = entry["key"], entry["scope"]
            container = settings if scope == "top" else env
            current = container.get(key)
            label = {"group": entry["group"], "key": key}
            if scope == "header":
                lines = [ln for ln in str(current or "").split("\n") if ln.strip()]
                if entry["value"] not in lines:
                    left.append({**label, "reason": "already removed or modified"})
                    continue
                lines.remove(entry["value"])
                if lines:
                    env[key] = "\n".join(lines)
                elif entry.get("had_previous"):
                    env[key] = entry.get("previous") or ""
                else:
                    env.pop(key, None)
                restored.append(label)
            elif current == entry["value"]:
                if entry.get("had_previous"):
                    container[key] = entry["previous"]
                else:
                    container.pop(key, None)
                restored.append(label)
            else:
                left.append({**label, "reason": "changed since Forgebench wrote it"})
        if env:
            settings["env"] = env
        else:
            settings.pop("env", None)
        if restored:
            atomic_write(path, json.dumps(settings, indent=2) + "\n")
        if kept:
            receipt["entries"] = kept
            receipt["pending_restart"] = True
            write_json(receipt_path(), receipt)
        else:
            receipt_path().unlink(missing_ok=True)
        return {"restored": restored, "left": left}


def confirm_active(environ: dict | None = None) -> bool:
    """Clear ``pending_restart`` once this Claude process runs with the values we wrote."""
    receipt = load_receipt()
    if not receipt or not receipt.get("pending_restart"):
        return False
    environ = os.environ if environ is None else environ
    probes = [e for e in receipt["entries"] if e["scope"] == "env" and e["key"] in
              ("ANTHROPIC_BASE_URL", "CLAUDE_CODE_ENABLE_TELEMETRY", "OTEL_EXPORTER_OTLP_ENDPOINT")]
    if probes and all(environ.get(e["key"]) == e["value"] for e in probes):
        receipt["pending_restart"] = False
        write_json(receipt_path(), receipt)
        return True
    return False


def owned_state(receipt: dict | None, layers: list[Layer]) -> dict:
    """Per group: ``applied`` / ``modified`` (a value changed since we wrote it) / ``absent``."""
    out: dict = {}
    if not receipt:
        return out
    user = next(layer for layer in layers if layer.name == "user")
    for entry in receipt["entries"]:
        group = out.setdefault(entry["group"], "applied")
        current = _layer_value(user, entry["scope"], entry["key"])
        if entry["scope"] == "header":
            ok = entry["value"] in [ln for ln in str(current or "").split("\n") if ln.strip()]
        else:
            ok = current == entry["value"]
        if not ok:
            out[entry["group"]] = "modified"
        elif group == "modified":
            out[entry["group"]] = "modified"
    return out
