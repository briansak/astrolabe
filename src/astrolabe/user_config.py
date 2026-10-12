"""Per-user config. The model path lives outside the engagements directory."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def config_path() -> Path:
    """0600 file written by ``astrolabe setup``. macOS uses Application Support; Linux uses XDG."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Astrolabe" / "config.toml"
    configured = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(configured).expanduser() if configured else Path.home() / ".config"
    return base / "astrolabe" / "config.toml"


def saved_model_path() -> Path | None:
    """The path stored by setup. This does not read ANTARES_MODEL_PATH."""
    path = config_path()
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        if key.strip() != "model_path":
            continue
        stored = value.strip()
        if stored.startswith('"'):
            stored = json.loads(stored)
        if stored:
            return Path(str(stored)).expanduser()
    return None


def model_path() -> Path | None:
    """ANTARES_MODEL_PATH wins. Otherwise the path stored by setup. Missing means unset."""
    configured = os.environ.get("ANTARES_MODEL_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return saved_model_path()


def write_model_path(directory: Path) -> Path:
    """Record the weights directory. The file is mode 0600. The directory itself is not created."""
    path = config_path()
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_text(f"model_path = {json.dumps(str(directory))}\n", encoding="utf-8")
    os.chmod(path, 0o600)
    os.chmod(path.parent, 0o700)
    return path
