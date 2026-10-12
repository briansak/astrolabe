#!/usr/bin/env python3
"""Stream one long completion through the container's loopback proxy.

Exit 0 only when the first byte arrives quickly and the stream lasts longer
than five minutes. A buffered response that waits out the generation fails.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

ENDPOINT = os.environ.get("ANTARES_ENDPOINT", "http://127.0.0.1:8000/v1/completions")
MODEL = os.environ.get("ANTARES_MODEL", "fdtn-ai/antares-1b")
MAX_TOKENS = int(os.environ.get("ASTROLABE_LONG_MAX_TOKENS", "8192"))
MIN_SECONDS = float(os.environ.get("ASTROLABE_LONG_MIN_SECONDS", "300"))
MAX_FIRST_BYTE_SECONDS = float(os.environ.get("ASTROLABE_LONG_MAX_FIRST_BYTE", "30"))

PROMPT = (
    "Count upward by ones, one integer per line, starting at 1. "
    "Do not stop until you are told to stop.\n"
)


def main() -> int:
    body = json.dumps(
        {
            "model": MODEL,
            "prompt": PROMPT,
            "max_tokens": MAX_TOKENS,
            "temperature": 0.3,
            "top_p": 1.0,
            "frequency_penalty": 0.3,
            "stream": True,
            "stop": [],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    first_byte: float | None = None
    received = 0
    chunks = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            while True:
                block = response.readline()
                if not block:
                    break
                if first_byte is None:
                    first_byte = time.monotonic()
                received += len(block)
                chunks += 1
                if block.startswith(b"data: [DONE]"):
                    break
                if b'"error"' in block:
                    print(block.decode("utf-8", errors="replace"), file=sys.stderr)
                    return 1
    except Exception as exc:  # noqa: BLE001 — report the failure and exit
        print(f"stream failed after {time.monotonic() - started:.1f}s: {exc}", file=sys.stderr)
        return 1
    total = time.monotonic() - started
    ttfb = (first_byte - started) if first_byte is not None else -1.0
    print(
        json.dumps(
            {
                "ttfb_seconds": round(ttfb, 3),
                "total_seconds": round(total, 3),
                "bytes": received,
                "chunks": chunks,
                "max_tokens": MAX_TOKENS,
            }
        )
    )
    if first_byte is None or ttfb > MAX_FIRST_BYTE_SECONDS or total < MIN_SECONDS:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
