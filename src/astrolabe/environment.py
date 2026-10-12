"""Local dependency checks for the landing page. No network and no file creation."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

from astrolabe.cwe import CweDataError, load_cwe_relations
from astrolabe.engagement import advisory_cache_dir, durable_audit_path
from astrolabe.user_config import model_path
from astrolabe.inference_socket import (
    SOCKET_VARIABLES,
    TOKEN_VARIABLES,
    SocketDirectoryError,
    configured_inference_socket,
    configured_token_directory,
    require_private_directory,
    resolved_inference_socket,
    socket_override_mismatch,
    token_override_mismatch,
)
from astrolabe.runner import IMAGE

CHECK_TIMEOUT = 2.0
CACHE_SECONDS = 30.0
HEALTH_READ_CAP = 65536

Probe = Callable[[], "Check"]


class Check:
    def __init__(self, name: str, status: str, detail: str, hint: str = "") -> None:
        self.name = name
        self.status = status
        self.detail = detail
        self.hint = hint


class _Flight:
    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.running = False
        self.result: list[Check] | None = None
        self.monotonic = 0.0


_flights: dict[str, _Flight] = {}
_flights_guard = threading.Lock()


def run_checks(root: Path, *, force: bool = False) -> list[Check]:
    """Run every probe once. Concurrent callers share that run, then a 30s cache."""
    key = str(root.resolve())
    with _flights_guard:
        flight = _flights.setdefault(key, _Flight())
    with flight.condition:
        while flight.running:
            flight.condition.wait()
            if flight.result is not None:
                return list(flight.result)
        fresh = flight.result is not None and (time.monotonic() - flight.monotonic) < CACHE_SECONDS
        if fresh and not force:
            return list(flight.result)
        flight.running = True
    try:
        result = execute_checks(default_probes(root))
    except Exception:
        result = [Check("Environment", "missing", "The check failed", "Re-check.")]
    with flight.condition:
        flight.result = result
        flight.monotonic = time.monotonic()
        flight.running = False
        flight.condition.notify_all()
    return list(result)


def cached_checks(root: Path) -> list[Check] | None:
    """The fresh cached result, or None. This never starts a check."""
    key = str(root.resolve())
    with _flights_guard:
        flight = _flights.get(key)
    if flight is None:
        return None
    with flight.condition:
        if flight.result is None:
            return None
        if (time.monotonic() - flight.monotonic) < CACHE_SECONDS:
            return list(flight.result)
    return None


def prime_cache(root: Path, checks: list[Check]) -> None:
    """Store a result for tests. Does not run probes."""
    key = str(root.resolve())
    flight = _Flight()
    flight.result = list(checks)
    flight.monotonic = time.monotonic()
    with _flights_guard:
        _flights[key] = flight


def rollup(checks: list[Check]) -> str:
    """missing if any required check is missing; warn if any check warns; otherwise ok.

    Advisory cache can only contribute warn.
    """
    status, _count = _rollup(checks)
    return status


def status_label(checks: list[Check] | None) -> tuple[str, str]:
    """Pill kind and text. None means the cache has no fresh result."""
    if checks is None:
        return "muted", "Status · checking"
    status, count = _rollup(checks)
    if status == "missing":
        return "danger", f"Status · {count} missing"
    if status == "warn":
        return "warn", f"Status · {count} warn"
    return "healthy", "Status"


def check_location(name: str, root: Path) -> str:
    """A path or local identifier for one check. No environment values."""
    if name == "Docker daemon":
        return shutil.which("docker") or "docker"
    if name == "Sandbox image":
        return IMAGE
    if name == "Inference socket":
        mismatch = socket_override_mismatch()
        if mismatch is not None:
            return f"{mismatch[0]} {mismatch[1]}"
        try:
            return str(resolved_inference_socket())
        except SocketDirectoryError:
            return ""
    if name == "Token directory":
        mismatch = token_override_mismatch()
        if mismatch is not None:
            return f"{mismatch[0]} {mismatch[1]}"
        try:
            return str(configured_token_directory())
        except SocketDirectoryError as exc:
            return str(exc)
    if name == "Antares-1B weights":
        found = weights_dir()
        return str(found) if found is not None else "not configured"
    if name == "CWE data":
        return "astrolabe/data/cwe/cwe-relations.json"
    if name == "PDF rendering":
        return "weasyprint"
    if name == "Engagement paths":
        return f"{root} {durable_audit_path(root)}"
    if name == "git":
        return shutil.which("git") or "git"
    if name == "Advisory cache":
        return str(advisory_cache_dir())
    return ""


def _rollup(checks: list[Check]) -> tuple[str, int]:
    missing = 0
    warn = 0
    for item in checks:
        status = item.status
        if item.name == "Advisory cache" and status != "ok":
            status = "warn"
        if status == "missing":
            missing += 1
        elif status == "warn":
            warn += 1
    if missing:
        return "missing", missing
    if warn:
        return "warn", warn
    return "ok", 0


def execute_checks(probes: list[tuple[str, Probe]]) -> list[Check]:
    """Run probes together. Each one is abandoned after CHECK_TIMEOUT seconds."""
    started = time.monotonic()
    boxes: list[dict[str, Check]] = []
    threads: list[threading.Thread] = []
    for name, probe in probes:
        box: dict[str, Check] = {}
        boxes.append(box)
        thread = threading.Thread(target=_store, args=(box, name, probe), name=f"astrolabe-check-{name}", daemon=True)
        thread.start()
        threads.append(thread)
    results: list[Check] = []
    for (name, _probe), thread, box in zip(probes, threads, boxes, strict=True):
        remaining = CHECK_TIMEOUT - (time.monotonic() - started)
        thread.join(max(0.0, remaining))
        if thread.is_alive() or "check" not in box:
            results.append(Check(name, "missing", "Timed out", "Re-check."))
        else:
            results.append(box["check"])
    return results


def default_probes(root: Path) -> list[tuple[str, Probe]]:
    return [
        ("Docker daemon", check_docker),
        ("Sandbox image", check_sandbox_image),
        ("Inference socket", check_inference),
        ("Token directory", check_token_directory),
        ("Antares-1B weights", check_weights),
        ("CWE data", check_cwe),
        ("PDF rendering", check_pdf),
        ("Engagement paths", lambda: check_paths(root)),
        ("git", check_git),
        ("Advisory cache", check_advisory_cache),
    ]


def inference_socket_path() -> Path:
    """The shared socket a new run and the inference server use."""
    return configured_inference_socket()


def weights_dir() -> Path | None:
    return model_path()


def check_docker() -> Check:
    completed = _command(["docker", "version", "--format", "{{.Server.Version}}"])
    if completed is None:
        return Check("Docker daemon", "missing", "docker was not found", "Install Docker and start the daemon.")
    if completed.timed_out:
        return Check("Docker daemon", "missing", "Timed out", "Start the Docker daemon and re-check.")
    if completed.returncode != 0:
        return Check("Docker daemon", "missing", "The daemon did not respond", "Start the Docker daemon and re-check.")
    version = (completed.stdout or "").strip().splitlines()
    detail = f"Server {version[0]}" if version else "The daemon responded"
    return Check("Docker daemon", "ok", detail)


def check_sandbox_image() -> Check:
    completed = _command(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE])
    if completed is None:
        return Check("Sandbox image", "missing", "docker was not found", "Install Docker and build the CLI image.")
    if completed.timed_out:
        return Check("Sandbox image", "missing", "Timed out", "Start the Docker daemon and re-check.")
    if completed.returncode != 0:
        return Check(
            "Sandbox image",
            "missing",
            f"{IMAGE} is not present locally",
            "Build it with scripts/build-cli-image.sh.",
        )
    return Check("Sandbox image", "ok", f"{IMAGE} is present locally")


def _directory_hint(exc: SocketDirectoryError, fallback: str) -> str:
    text = str(exc)
    if "engagements directory" in text:
        return text
    return fallback


def check_inference() -> Check:
    mismatch = socket_override_mismatch()
    if mismatch is not None:
        server, runner = mismatch
        return Check(
            "Inference socket",
            "missing",
            f"{server} and {runner}",
            "Set ANTARES_SOCKET and ASTROLABE_INFERENCE_SOCKET to the same path.",
        )
    try:
        path = configured_inference_socket()
    except SocketDirectoryError as exc:
        return Check("Inference socket", "missing", str(exc), _directory_hint(exc, "Use one socket path."))
    if path.parent.exists():
        try:
            require_private_directory(path.parent, SOCKET_VARIABLES)
        except SocketDirectoryError as exc:
            return Check(
                "Inference socket",
                "missing",
                str(exc),
                "chmod 700 the socket directory, or unset the socket variable.",
            )
    if not path.exists():
        return Check(
            "Inference socket",
            "missing",
            f"{path} is not present",
            "Start the inference server so it listens on that socket.",
        )
    return _probe_health(path)


def check_token_directory() -> Check:
    """Report the token directory path. Do not read or list its contents."""
    mismatch = token_override_mismatch()
    if mismatch is not None:
        server, runner = mismatch
        return Check(
            "Token directory",
            "missing",
            f"{server} and {runner}",
            "Set ANTARES_TOKEN_DIR and ASTROLABE_TOKEN_DIR to the same path.",
        )
    try:
        directory = configured_token_directory()
    except SocketDirectoryError as exc:
        return Check(
            "Token directory",
            "missing",
            str(exc),
            _directory_hint(exc, "Use one token directory outside the socket directory."),
        )
    if not directory.exists():
        return Check(
            "Token directory",
            "missing",
            f"{directory} is not present",
            "Start Astrolabe so it can create that directory, or chmod 700 it.",
        )
    try:
        require_private_directory(directory, TOKEN_VARIABLES)
    except SocketDirectoryError as exc:
        return Check(
            "Token directory",
            "missing",
            str(exc),
            "chmod 700 the token directory, or unset the token variable.",
        )
    return Check("Token directory", "ok", "present")


def check_weights() -> Check:
    directory = weights_dir()
    if directory is None:
        return Check(
            "Antares-1B weights",
            "missing",
            "Model path is not configured",
            "Run astrolabe setup --model-path DIR, or set ANTARES_MODEL_PATH.",
        )
    weights = directory / "model.safetensors"
    config = directory / "config.json"
    if weights.is_file() and config.is_file():
        return Check("Antares-1B weights", "ok", f"present (not verified) at {directory}")
    missing = [name for name, path in (("model.safetensors", weights), ("config.json", config)) if not path.is_file()]
    return Check(
        "Antares-1B weights",
        "missing",
        f"Missing {', '.join(missing)} in {directory}",
        "Point setup --model-path at the directory that contains the weights.",
    )


def check_cwe() -> Check:
    try:
        payload = load_cwe_relations()
    except CweDataError as exc:
        return Check("CWE data", "missing", str(exc), "Reinstall Astrolabe so the CWE package data is present.")
    return Check("CWE data", "ok", f"{len(payload)} relations")


def check_pdf() -> Check:
    """Warn when assessment PDF rendering cannot run. HTML reports still generate.

    This does not import WeasyPrint. The status probes share a short deadline.
    """
    import importlib.util

    if importlib.util.find_spec("weasyprint") is None:
        return Check(
            "PDF rendering",
            "warn",
            "WeasyPrint is not installed",
            "pip install weasyprint. On macOS, brew install pango.",
        )
    if sys_pango_missing():
        return Check(
            "PDF rendering",
            "warn",
            "Pango was not found",
            "On macOS, brew install pango. Assessment HTML is still written.",
        )
    return Check("PDF rendering", "ok", "WeasyPrint is installed and Pango was found")


def sys_pango_missing() -> bool:
    import ctypes.util

    return ctypes.util.find_library("pango-1.0") is None


def check_paths(root: Path) -> Check:
    """os.access only. Creates nothing. An audit path inside the engagements directory is missing."""
    audit = durable_audit_path(root)
    export_note = "Export path is chosen on the Reports card."
    if _is_inside(audit, root):
        return Check(
            "Engagement paths",
            "missing",
            f"Audit log {audit} is inside the engagements directory. {export_note}",
            "Keep the durable audit log outside the engagements directory.",
        )
    engagements_ok = root.is_dir() and os.access(root, os.W_OK)
    if audit.exists():
        audit_ok = os.access(audit, os.W_OK) if audit.is_file() else os.access(audit, os.W_OK)
    else:
        audit_ok = audit.parent.is_dir() and os.access(audit.parent, os.W_OK)
    if engagements_ok and audit_ok:
        return Check("Engagement paths", "ok", f"Engagements {root}. Audit {audit}. {export_note}")
    problems: list[str] = []
    if not engagements_ok:
        problems.append(f"{root} is not writable")
    if not audit_ok:
        problems.append(f"{audit} is not writable")
    return Check(
        "Engagement paths",
        "missing",
        f"{' '.join(problems)} {export_note}",
        "Make the engagements directory and the audit log parent writable.",
    )


def check_git() -> Check:
    completed = _command(["git", "--version"])
    if completed is None:
        return Check("git", "missing", "git was not found", "Install git.")
    if completed.timed_out:
        return Check("git", "missing", "Timed out", "Install git and re-check.")
    if completed.returncode != 0:
        return Check("git", "missing", "git did not run", "Install git.")
    line = (completed.stdout or "").strip().splitlines()
    return Check("git", "ok", line[0] if line else "git is available")


def check_advisory_cache() -> Check:
    cache = advisory_cache_dir()
    found = sorted(cache.glob("*.json")) if cache.is_dir() else []
    if found:
        return Check("Advisory cache", "ok", f"{len(found)} advisories in {cache}")
    return Check(
        "Advisory cache",
        "warn",
        f"No advisories in {cache}",
        "Import advisories from a local directory. Investigations fail closed when a cache file is missing.",
    )


def health_ok(raw: bytes) -> bool:
    """HTTP 200 and a JSON body whose status is ok. Anything else is not ok."""
    text = raw.decode("utf-8", "replace")
    separator = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n" if "\n\n" in text else ""
    if not separator:
        return False
    head, body = text.split(separator, 1)
    lines = head.splitlines()
    if not lines:
        return False
    parts = lines[0].split()
    if len(parts) < 2 or parts[1] != "200":
        return False
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _decode_chunks(body)
    elif "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError:
            return False
        body = body[:length]
    try:
        payload = json.loads(body.strip())
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and payload.get("status") == "ok"


class _Command:
    def __init__(self, returncode: int, stdout: str, *, timed_out: bool = False) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.timed_out = timed_out


def _command(args: list[str]) -> _Command | None:
    try:
        completed = subprocess.run(
            args,
            timeout=CHECK_TIMEOUT,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return _Command(1, "", timed_out=True)
    except OSError:
        return None
    return _Command(completed.returncode, completed.stdout or "")


def _probe_health(path: Path) -> Check:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(CHECK_TIMEOUT)
    try:
        sock.connect(str(path))
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        raw = bytearray()
        while len(raw) < HEALTH_READ_CAP:
            chunk = sock.recv(min(4096, HEALTH_READ_CAP - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
    except (TimeoutError, OSError):
        return Check(
            "Inference socket",
            "missing",
            f"{path} did not return a healthy response",
            "Start the inference server and re-check.",
        )
    finally:
        sock.close()
    if health_ok(bytes(raw)):
        return Check("Inference socket", "ok", str(path))
    return Check(
        "Inference socket",
        "missing",
        f"{path} did not return a healthy response",
        "Start the inference server and re-check.",
    )


def _store(box: dict[str, Check], name: str, probe: Probe) -> None:
    try:
        box["check"] = probe()
    except Exception:
        box["check"] = Check(name, "missing", "The check failed", "Re-check.")


def _decode_chunks(body: str) -> str:
    parts: list[str] = []
    rest = body
    while rest:
        line, separator, rest = rest.partition("\n")
        size_text = line.split(";", 1)[0].strip()
        if not size_text:
            continue
        try:
            size = int(size_text, 16)
        except ValueError:
            break
        if size == 0:
            break
        if not separator:
            break
        parts.append(rest[:size])
        rest = rest[size:]
        if rest.startswith("\r\n"):
            rest = rest[2:]
        elif rest.startswith("\n"):
            rest = rest[1:]
    return "".join(parts)


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
