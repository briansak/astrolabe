"""Pinned Antares-1B weight identity. SHA256 is a file digest, not a secret."""

from __future__ import annotations

import hashlib
from pathlib import Path

WEIGHT_FILENAME = "model.safetensors"
EXPECTED_SHA256 = "6ba4155a50cd0cede3e10285b0d84b460dcc3caa0175a424e14d3bb606fda675"
HF_REPO_ID = "fdtn-ai/antares-1b"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def weight_path(model_dir: Path) -> Path:
    return model_dir / WEIGHT_FILENAME


def verify_weights(model_dir: Path) -> str:
    """Return the SHA256 of model.safetensors or raise if it does not match the pin."""
    path = weight_path(model_dir)
    if not path.is_file():
        raise FileNotFoundError(f"Antares weights missing at {path}")
    if not (model_dir / "config.json").is_file():
        raise FileNotFoundError(f"Invalid model directory {model_dir}: missing config.json")
    actual = sha256_file(path)
    if actual != EXPECTED_SHA256:
        raise ValueError(
            f"Antares weight SHA256 mismatch for {path.name}: expected {EXPECTED_SHA256}, got {actual}"
        )
    return actual
