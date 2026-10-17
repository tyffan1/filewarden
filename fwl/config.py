"""Configuration handling: API key and defaults stored in a small JSON file.

Locations:

* Windows — ``%APPDATA%\\filewarden\\config.json``
* macOS/Linux — ``$XDG_CONFIG_HOME/filewarden/config.json`` or ``~/.config/filewarden/config.json``

The file is created with ``0600`` permissions so the key stays private.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

APP_DIR_NAME = "filewarden"
ENV_KEYS = ("VIRUSTOTAL_API_KEY", "VT_API_KEY")

DEFAULTS: dict[str, Any] = {
    "rpm": 4.0,              # public API allows 4 requests per minute
    "max_upload_mb": 32.0,   # direct upload limit of the public API
    "upload_policy": "ask",  # never | ask | always
}


def config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_DIR_NAME
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_DIR_NAME


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config() -> dict[str, Any]:
    path = config_path()
    data: dict[str, Any] = {}
    try:
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            data = loaded
    except (OSError, ValueError):
        data = {}
    merged = dict(DEFAULTS)
    merged.update(data)
    return merged


def save_config(config: dict[str, Any]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    return path


def save_api_key(api_key: str) -> Path:
    config = load_config()
    config["api_key"] = api_key.strip()
    return save_config(config)


def resolve_api_key(explicit: str | None = None) -> str | None:
    """Key resolution order: CLI argument → environment → config file."""
    if explicit and explicit.strip():
        return explicit.strip()
    for name in ENV_KEYS:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    stored = load_config().get("api_key")
    if isinstance(stored, str) and stored.strip():
        return stored.strip()
    return None


def api_key_source() -> str:
    """Human readable description of where the current key comes from."""
    for name in ENV_KEYS:
        if os.environ.get(name, "").strip():
            return f"environment variable {name}"
    if isinstance(load_config().get("api_key"), str) and load_config()["api_key"].strip():
        return f"file {config_path()}"
    return "not set"
