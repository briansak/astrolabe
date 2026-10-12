"""Live investigation activity from the trace file created for this run.

Customer report text is not rewritten here. The live file is deleted when the
run ends. The stored summary has counters and the trace hash, not commands.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from astrolabe.inference_socket import SocketDirectoryError, configured_inference_socket
from astrolabe.redact import redact_text

_LAST_ACTION_LIMIT = 120

_TERMINAL_TOOLS = {"terminal", "bash"}
_SEARCH = {"rg", "grep", "find"}
_READ = {"cat", "head", "tail", "nl", "read_file"}
_POLL_SECONDS = 0.05


def activity_path(directory: Path) -> Path:
    """Host-side file. The container mounts snapshot and antares-data, not this path."""
    return directory / "activity.json"


def stall_seconds() -> float:
    raw = os.environ.get("ASTROLABE_ACTIVITY_STALL_SECONDS", "60").strip()
    try:
        return float(raw)
    except ValueError:
        return 60.0


def split_command(command: str) -> list[str]:
    """Split a terminal command into segments on &&, ;, and |."""
    segments: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(command):
        if command.startswith("&&", index):
            segments.append("".join(current))
            current = []
            index += 2
            continue
        if command[index] in ";|":
            segments.append("".join(current))
            current = []
            index += 1
            continue
        current.append(command[index])
        index += 1
    segments.append("".join(current))
    return [segment.strip() for segment in segments if segment.strip()]


def classify_segment(segment: str) -> str:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    if not tokens:
        return "other"
    name = Path(tokens[0]).name
    if name == "git" and len(tokens) > 1 and tokens[1] == "grep":
        return "search"
    if name in _SEARCH:
        return "search"
    if name in _READ:
        return "read"
    if name == "sed" and len(tokens) > 1 and tokens[1] == "-n":
        return "read"
    return "other"


def command_classes(command: str) -> list[str]:
    return [classify_segment(segment) for segment in split_command(command)]


def blocked_label(reason: str) -> str:
    lowered = reason.lower()
    if "duplicate" in lowered:
        return "duplicate"
    if "budget" in lowered:
        return "budget"
    return "safety"


def stall_view(activity: dict[str, object], now: float | None = None) -> tuple[bool, int]:
    """Stall from the last host receipt, or from container start when no event has arrived."""
    moment = time.time() if now is None else now
    anchor = activity.get("last_event_at")
    if not isinstance(anchor, (int, float)):
        anchor = activity.get("started_at")
    if not isinstance(anchor, (int, float)):
        return False, 0
    elapsed = max(0, int(moment - float(anchor)))
    return elapsed >= stall_seconds(), elapsed


def progress_detail(activity: dict[str, object] | None, now: float | None = None) -> tuple[str, bool]:
    """Return the detail line and whether the heartbeat is fresh enough to pulse."""
    if activity is None:
        return "Starting container.", True
    detail = str(activity.get("detail") or "Starting container.")
    stalled, elapsed = stall_view(activity, now)
    if stalled:
        return f"No activity for {elapsed}s. {detail}", False
    return detail, True


def counter_line(activity: dict[str, object] | None) -> str:
    counters = activity.get("counters") if isinstance(activity, dict) else None
    if not isinstance(counters, dict):
        counters = {}
    loop = activity.get("loop_control") if isinstance(activity, dict) else None
    if not isinstance(loop, dict):
        loop = {}

    def count(source: dict[str, object], key: str) -> int:
        value = source.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return value

    return (
        f"Model turns {count(counters, 'model_turns')}. "
        f"Searches {count(counters, 'searches')}. "
        f"Reads {count(counters, 'reads')}. "
        f"Other {count(counters, 'other')}. "
        f"Submissions {count(counters, 'submissions')}. "
        f"Duplicate {count(loop, 'duplicate')}. "
        f"Safety {count(loop, 'safety')}. "
        f"Budget {count(loop, 'budget')}."
    )


def format_last_action(tool: str, arguments: dict[str, object]) -> str:
    """Tool name plus a redacted command, path, or query. At most 120 characters."""
    operand = ""
    for key in ("command", "path", "query"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            operand = value.strip()
            break
    text = redact_text(f"{tool} {operand}".strip())
    return text[:_LAST_ACTION_LIMIT]


def model_server_line(detail: str, payload: dict[str, object] | None) -> str:
    """Server-wide token count, shown only while this run is waiting for the model."""
    if detail != "Waiting for model":
        return ""
    if not isinstance(payload, dict) or payload.get("in_flight") is not True:
        return ""
    count = payload.get("tokens_generated")
    if isinstance(count, bool) or not isinstance(count, int):
        return ""
    return f"Model server: generating {count} tokens"


def fetch_generation() -> dict[str, object] | None:
    """GET /v1/activity on the inference socket. Missing or slow sockets yield nothing."""
    try:
        path = configured_inference_socket()
    except SocketDirectoryError:
        return None
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect(str(path))
        sock.sendall(b"GET /v1/activity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        raw = bytearray()
        while len(raw) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw.extend(chunk)
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()
    head, separator, body = bytes(raw).partition(b"\r\n\r\n")
    if separator != b"\r\n\r\n" or b" 200 " not in head.split(b"\r\n", 1)[0]:
        return None
    try:
        payload = json.loads(body.decode("utf-8").strip() or "null")
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def load_activity(directory: Path) -> dict[str, object] | None:
    path = activity_path(directory)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ActivityTailer:
    """Tail the investigation trace created after launch. Join it from the run's finally."""

    def __init__(self, directory: Path, container_slot: dict[str, str] | None = None) -> None:
        self.directory = directory
        self.container_slot = container_slot if container_slot is not None else {}
        self.traces = directory / "antares-data" / "traces"
        self._path = activity_path(directory)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._known: set[Path] = set()
        self._trace: Path | None = None
        self._offset = 0
        self._pending = b""
        self.started_at = 0.0
        self.last_event_at: float | None = None
        self.trace_timestamp: float | None = None
        self.phase = "starting container"
        self.detail = "Starting container."
        self.last_action = ""
        self.phase_times: dict[str, str] = {}
        self.counters = {
            "model_turns": 0,
            "submissions": 0,
            "searches": 0,
            "reads": 0,
            "other": 0,
        }
        self.loop_control = {"duplicate": 0, "safety": 0, "budget": 0}
        self.trace_lines = 0

    def start(self) -> None:
        self.started_at = time.time()
        self.phase_times["starting container"] = _utc(self.started_at)
        if self.traces.is_dir():
            self._known = {path.resolve() for path in self.traces.glob("*.investigation.jsonl")}
        self._thread = threading.Thread(target=self._loop, name="astrolabe-activity", daemon=True)
        self._thread.start()

    def finish(self, *, exit_code: int, cancelled: bool) -> dict[str, object]:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        with self._lock:
            if not self._closed:
                self._drain()
            summary = self._summary(exit_code=exit_code, cancelled=cancelled)
            self._closed = True
            self._path.unlink(missing_ok=True)
            self._temp_path().unlink(missing_ok=True)
        if thread is not None and thread.is_alive():
            thread.join(timeout=1)
        return summary

    def drain(self) -> None:
        with self._lock:
            if not self._closed:
                self._drain()

    def _loop(self) -> None:
        while True:
            self.drain()
            if self._stop.is_set():
                return
            self._stop.wait(_POLL_SECONDS)

    def _discover(self) -> Path | None:
        if not self.traces.is_dir():
            return None
        fresh = [
            path
            for path in self.traces.glob("*.investigation.jsonl")
            if path.resolve() not in self._known
        ]
        if not fresh:
            return None
        return min(fresh, key=lambda path: path.stat().st_mtime)

    def _drain(self) -> None:
        if self._trace is None:
            self._trace = self._discover()
            if self._trace is None:
                self._write()
                return
        try:
            with self._trace.open("rb") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
        except OSError:
            self._write()
            return
        if chunk:
            self._offset += len(chunk)
            self._pending += chunk
        while b"\n" in self._pending:
            raw, self._pending = self._pending.split(b"\n", 1)
            self.trace_lines += 1
            self._apply_line(raw.decode("utf-8", "replace"))
        self._write()

    def _apply_line(self, line: str) -> None:
        if not line.strip():
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(event, dict):
            return
        phase = str(event.get("phase") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        self.last_event_at = time.time()
        timestamp = event.get("timestamp")
        if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
            self.trace_timestamp = float(timestamp)
        if phase == "message":
            if payload.get("role") == "assistant":
                self.counters["model_turns"] += 1
            self._advance("investigating")
            return
        if phase == "ingest":
            self.detail = "Waiting for model"
            self._advance("investigating")
            return
        if phase == "tool_result":
            self.detail = "Waiting for model"
            self._advance("investigating")
            return
        if phase == "tool_call":
            tool = str(payload.get("tool_name") or "")
            arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
            command = arguments.get("command") if isinstance(arguments.get("command"), str) else ""
            for label in _tool_classes(tool, command):
                self.counters[{"search": "searches", "read": "reads", "other": "other"}[label]] += 1
            self.detail = f"Running tool: {tool}" if tool else "Running tool"
            self.last_action = format_last_action(tool, arguments)
            self._advance("investigating")
            return
        if phase == "tool_blocked":
            reason = payload.get("reason") if isinstance(payload.get("reason"), str) else ""
            label = blocked_label(reason)
            self.loop_control[label] += 1
            self.detail = f"Blocked: {label}"
            self._advance("investigating")
            return
        if phase == "final_submission":
            self.counters["submissions"] += 1
            self._advance("submitting")
            return
        if phase == "finding":
            self._advance("submitting")

    def _advance(self, phase: str) -> None:
        order = ("starting container", "investigating", "submitting")
        if phase not in order or self.phase not in order:
            return
        if order.index(phase) <= order.index(self.phase):
            return
        self.phase = phase
        self.phase_times.setdefault(phase, _utc(time.time()))

    def _write(self) -> None:
        if self._closed:
            return
        payload = {
            "phase": self.phase,
            "detail": self.detail,
            "started_at": self.started_at,
            "last_event_at": self.last_event_at,
            "trace_timestamp": self.trace_timestamp,
            "counters": dict(self.counters),
            "loop_control": dict(self.loop_control),
            "container_name": self.container_slot.get("name", ""),
            "last_action": self.last_action,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._temp_path()
        temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        temporary.replace(self._path)

    def _temp_path(self) -> Path:
        return self._path.with_name(f".{self._path.name}.{os.getpid()}.tmp")

    def _summary(self, *, exit_code: int, cancelled: bool) -> dict[str, object]:
        if cancelled:
            status = "cancelled"
        elif exit_code == 0:
            status = "completed"
        else:
            status = "failed"
        self.phase_times.setdefault(status, _utc(time.time()))
        trace = {"name": "", "lines": 0, "sha256": ""}
        if self._trace is not None and self._trace.is_file():
            data = self._trace.read_bytes()
            trace = {
                "name": self._trace.name,
                "lines": data.count(b"\n"),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        return {
            "start": _utc(self.started_at) if self.started_at else "",
            "end": _utc(time.time()),
            "phases": dict(self.phase_times),
            "counters": dict(self.counters),
            "loop_control": dict(self.loop_control),
            "exit_status": status,
            "trace": trace,
        }


def _tool_classes(tool: str, command: str) -> list[str]:
    if tool == "read_file":
        return ["read"]
    if tool in _TERMINAL_TOOLS and command:
        return command_classes(command)
    return []
