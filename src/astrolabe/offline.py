"""Investigation runs stay offline. Only an operator advisory sync may use the network."""

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_IN_RUN: ContextVar[bool] = ContextVar("astrolabe_investigation_run", default=False)


@contextmanager
def investigation_run():
    token = _IN_RUN.set(True)
    try:
        yield
    finally:
        _IN_RUN.reset(token)


def in_investigation_run() -> bool:
    if _IN_RUN.get():
        return True
    return os.environ.get("ASTROLABE_INVESTIGATION_RUN", "").strip() == "1"


def investigation_lock_present(root: Path | None) -> bool:
    if root is None or not root.is_dir():
        return False
    return any(root.glob("*/antares-data/run.lock"))
