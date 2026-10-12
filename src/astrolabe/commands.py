"""setup, doctor, and start. setup's only network use is the local image build."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from importlib.resources import files
from pathlib import Path

from astrolabe.engagement import engagements_root
from astrolabe.environment import check_location, default_probes, execute_checks, health_ok, rollup
from astrolabe.inference_socket import (
    SocketDirectoryError,
    configured_inference_socket,
    ensure_private_socket_dir,
    ensure_private_token_dir,
)
from astrolabe.runner import IMAGE
from astrolabe.user_config import model_path, write_model_path

UV_IMAGE = (
    "ghcr.io/astral-sh/uv:0.9.7"
    "@sha256:ba4857bf2a068e9bc0e64eed8563b065908a4cd6bfb66b531a9c424c8e25e142"
)
IMAGE_BUILD_NOTICE = (
    "The sandbox image build contacts these hosts:\n"
    "- Docker Hub, for python:3.12.11-slim-bookworm\n"
    f"- ghcr.io, for {UV_IMAGE}\n"
    "- Debian, for apt packages in the image\n"
    "- PyPI, for the Antares CLI's Python dependencies\n"
)
_SANDBOX_FILES = ("Dockerfile", "entrypoint.sh", "long_completion.py", "constraints.txt")
_HEALTH_WAIT_SECONDS = 600


def cmd_setup(model_dir: Path) -> int:
    directory = model_dir.expanduser().resolve()
    missing = [
        name
        for name in ("model.safetensors", "config.json", "antares-cli.zip")
        if not (directory / name).is_file()
    ]
    if missing:
        print(f"Missing {', '.join(missing)} in {directory}", file=sys.stderr)
        return 2
    try:
        from antares_server.weights import verify_weights
    except ImportError:
        print("astrolabe-antares-server is not installed.", file=sys.stderr)
        return 2
    try:
        verify_weights(directory)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    write_model_path(directory)
    try:
        ensure_private_socket_dir(configured_inference_socket())
        ensure_private_token_dir()
    except SocketDirectoryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(IMAGE_BUILD_NOTICE, end="")
    return _build_image(directory / "antares-cli.zip")


def cmd_doctor(root: Path | None = None) -> int:
    engagements = engagements_root(root)
    checks = execute_checks(default_probes(engagements))
    for item in checks:
        fix = item.hint if item.status != "ok" else ""
        print(f"{item.name}\t{item.status}\t{check_location(item.name, engagements)}\t{fix}")
    return 1 if rollup(checks) == "missing" else 0


def cmd_start(port: int = 8765) -> int:
    holder = _port_holder(port)
    if holder is not None:
        print(f"Port {port} is in use by {holder}.", file=sys.stderr)
        return 1
    if model_path() is None:
        print("Model path is not configured. Run astrolabe setup --model-path DIR.", file=sys.stderr)
        return 2
    server = subprocess.Popen([sys.executable, "-m", "antares_server"])
    try:
        if not _wait_for_health(server):
            print("The inference server did not become healthy.", file=sys.stderr)
            return 1
        from astrolabe.ui import main as ui_main

        return ui_main(["--port", str(port)])
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


def _build_image(zip_path: Path, *, label: str | None = None) -> int:
    if shutil.which("docker") is None:
        print("docker was not found.", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        packaged = files("astrolabe").joinpath("sandbox")
        for name in _SANDBOX_FILES:
            stage.joinpath(name).write_bytes(packaged.joinpath(name).read_bytes())
        stage.joinpath("antares-cli.zip").write_bytes(zip_path.read_bytes())
        command = ["docker", "build", "-t", IMAGE]
        if label:
            command.extend(["--label", label])
        command.append(str(stage))
        completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        print(f"docker build failed ({completed.returncode}).", file=sys.stderr)
        return completed.returncode
    print(f"built {IMAGE}")
    return 0


def _port_holder(port: int) -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        return _listener_name(port)
    finally:
        probe.close()
    return None


def _listener_name(port: int) -> str:
    if shutil.which("lsof") is None:
        return "an unknown process"
    completed = subprocess.run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
        check=False,
        capture_output=True,
        text=True,
    )
    lines = [line for line in completed.stdout.splitlines()[1:] if line.strip()]
    if not lines:
        return "an unknown process"
    parts = lines[0].split()
    name = parts[0] if parts else "an unknown process"
    pid = parts[1] if len(parts) > 1 else ""
    return f"{name} (pid {pid})" if pid else name


def _wait_for_health(server: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + _HEALTH_WAIT_SECONDS
    while time.monotonic() < deadline:
        if server.poll() is not None:
            return False
        try:
            path = configured_inference_socket()
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
            continue
        if path.exists() and _socket_health(path):
            return True
        time.sleep(0.5)
    return False


def _socket_health(path: Path) -> bool:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(os.fspath(path))
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        raw = bytearray()
        while len(raw) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw.extend(chunk)
    except (TimeoutError, OSError):
        return False
    finally:
        sock.close()
    return health_ok(bytes(raw))
