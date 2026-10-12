"""Per-run bearer tokens for the completions route.

The runner writes one token file per container run. The file is removed when the
run ends. Completions require a matching Authorization bearer. The token is a
random value from the runner, never a secret stored in the tree.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path


def token_directory() -> Path | None:
    """The directory the server and the UI resolved. None when those paths disagree."""
    try:
        from astrolabe.inference_socket import SocketDirectoryError, configured_token_directory
    except ImportError:
        configured = os.environ.get("ANTARES_TOKEN_DIR", "").strip()
        return Path(configured) if configured else None
    try:
        return configured_token_directory()
    except SocketDirectoryError:
        return None


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def token_is_active(token: str) -> bool:
    directory = token_directory()
    if directory is None or not directory.is_dir() or not token:
        return False
    matched = False
    for path in directory.iterdir():
        if not path.is_file() or path.name.startswith("."):
            continue
        try:
            expected = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if expected and hmac.compare_digest(expected, token):
            matched = True
    return matched
