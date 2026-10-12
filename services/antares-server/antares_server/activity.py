"""In-flight token counts for the current completion. No prompt or output text."""

from __future__ import annotations

import threading
from datetime import UTC, datetime


class GenerationActivity:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._in_flight = False
        self._tokens = 0
        self._last: str | None = None

    def begin(self) -> None:
        with self._lock:
            self._in_flight = True
            self._tokens = 0

    def token(self) -> None:
        with self._lock:
            if not self._in_flight:
                return
            self._tokens += 1
            self._last = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def end(self) -> None:
        with self._lock:
            self._in_flight = False

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "in_flight": self._in_flight,
                "tokens_generated": self._tokens if self._in_flight else 0,
                "last_token_at": self._last,
            }


def activity_response(engine: object) -> dict[str, object]:
    """The three count fields. Any other snapshot key is dropped."""
    snapshot = engine.activity_snapshot()  # type: ignore[attr-defined]
    if not isinstance(snapshot, dict):
        snapshot = {}
    count = snapshot.get("tokens_generated", 0)
    last = snapshot.get("last_token_at")
    return {
        "in_flight": snapshot.get("in_flight") is True,
        "tokens_generated": count if isinstance(count, int) and not isinstance(count, bool) else 0,
        "last_token_at": last if isinstance(last, str) else None,
    }
