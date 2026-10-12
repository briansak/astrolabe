"""up, down, status, and logs. setup, doctor, and start keep their own behavior."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from astrolabe.engagement import durable_audit_path, engagements_root, home_root
from astrolabe.user_config import saved_model_path, write_model_path

GATE_URL = "https://huggingface.co/fdtn-ai/antares-1b"
ZIP_LABEL = "ai.astrolabe.cli-zip-sha256"
WEIGHT_FILES = ("model.safetensors", "config.json", "antares-cli.zip")
DOCKER_MESSAGE = "Start Docker Desktop, then rerun ./astrolabe up."
DEFAULT_PORT = 8765
HF_REPO = "fdtn-ai/antares-1b"


def checkout_root() -> Path | None:
    root = Path.cwd()
    if (root / "pyproject.toml").is_file() and (root / "src" / "astrolabe").is_dir():
        return root
    return None


def default_weights_dir(root: Path) -> Path:
    return root / "models" / "1b"


def run_dir() -> Path:
    return home_root() / "var" / "run"


def log_dir() -> Path:
    return home_root() / "var" / "log"


def weights_complete(path: Path) -> bool:
    return all((path / name).is_file() for name in WEIGHT_FILES)


def resolve_weights(explicit: Path | None, root: Path) -> Path | None:
    """First complete directory: --model-path, ANTARES_MODEL_PATH, saved config, ./models/1b."""
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())
    configured = os.environ.get("ANTARES_MODEL_PATH", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    saved = saved_model_path()
    if saved is not None:
        candidates.append(saved)
    candidates.append(default_weights_dir(root))
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if weights_complete(candidate):
            return candidate.resolve()
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def docker_is_running() -> bool:
    if shutil.which("docker") is None:
        return False
    completed = subprocess.run(["docker", "info"], capture_output=True, text=True)
    return completed.returncode == 0


def labeled_image_hash() -> str | None:
    from astrolabe.runner import IMAGE

    completed = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{index .Config.Labels \"" + ZIP_LABEL + "\"}}",
            IMAGE,
        ],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    if not value or value == "<no value>":
        return None
    return value


def build_image(zip_path: Path) -> int:
    from astrolabe.commands import IMAGE_BUILD_NOTICE, _build_image

    digest = sha256_file(zip_path)
    print(IMAGE_BUILD_NOTICE, end="")
    return _build_image(zip_path, label=f"{ZIP_LABEL}={digest}")


def _record_model(directory: Path) -> int:
    """The non-build half of setup: verify, store the path, and create the runtime directories."""
    missing = [name for name in WEIGHT_FILES if not (directory / name).is_file()]
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
        from astrolabe.inference_socket import (
            SocketDirectoryError,
            configured_inference_socket,
            ensure_private_socket_dir,
            ensure_private_token_dir,
        )

        ensure_private_socket_dir(configured_inference_socket())
        ensure_private_token_dir()
    except SocketDirectoryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def setup_if_needed(directory: Path) -> int:
    """Skip the image build when the image label matches this zip."""
    digest = sha256_file(directory / "antares-cli.zip")
    image_ok = labeled_image_hash() == digest
    saved = saved_model_path()
    path_ok = saved is not None and saved.resolve() == directory.resolve()
    if image_ok and path_ok:
        return 0
    code = _record_model(directory)
    if code != 0 or image_ok:
        return code
    return build_image(directory / "antares-cli.zip")


def _huggingface_ready() -> bool:
    """True when the hub library can see a login. The token value is not recorded."""
    try:
        from huggingface_hub import get_token
    except ImportError:
        print(
            "huggingface_hub is not installed. Rerun ./astrolabe up after the checkout install finishes.",
            file=sys.stderr,
        )
        return False
    if not get_token():
        print(
            "Hugging Face login was not found. "
            f"Run `hf auth login`, accept the gate at {GATE_URL}, then rerun ./astrolabe up.",
            file=sys.stderr,
        )
        return False
    return True


def download_weights(dest: Path) -> int:
    """Download into ./models/1b with the existing Hugging Face login. Never print the token."""
    if not _huggingface_ready():
        return 1
    from huggingface_hub import snapshot_download

    dest.mkdir(parents=True, exist_ok=True)
    try:
        snapshot_download(repo_id=HF_REPO, local_dir=str(dest))
    except Exception:
        print(
            "The Hugging Face download was refused. "
            f"Accept the gate at {GATE_URL} and log in with `hf auth login`.",
            file=sys.stderr,
        )
        return 1
    if not weights_complete(dest):
        print(
            f"The download did not produce model.safetensors, config.json, and antares-cli.zip in {dest}.",
            file=sys.stderr,
        )
        return 1
    return 0


def _consent(download: bool) -> bool:
    if download:
        return True
    if not sys.stdin.isatty():
        return False
    answer = input("Download Antares-1B into ./models/1b? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _missing_weights(expected: Path) -> None:
    print(
        "No weights directory has model.safetensors, config.json, and antares-cli.zip.\n"
        f"Accept the Hugging Face gate: {GATE_URL}\n"
        f"Expected directory: {expected}",
        file=sys.stderr,
    )


def _command_line(pid: int) -> str:
    completed = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def _live(pid: int) -> bool:
    completed = subprocess.run(["ps", "-p", str(pid)], capture_output=True)
    return completed.returncode == 0


def _is_astrolabe_process(pid: int, role: str) -> bool:
    command = _command_line(pid)
    if role == "inference":
        return "antares_server" in command
    return "astrolabe" in command and "ui" in command


def _read_pid(path: Path) -> int | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text.isdigit():
        return None
    return int(text)


def _saved_port() -> int:
    path = run_dir() / "port"
    if not path.is_file():
        return DEFAULT_PORT
    text = path.read_text(encoding="utf-8").strip()
    if text.isdigit():
        return int(text)
    return DEFAULT_PORT


def _url(port: int) -> str:
    return f"http://127.0.0.1:{port}/"


def already_running() -> int | None:
    """The port when both recorded processes are still Astrolabe processes."""
    inference = _read_pid(run_dir() / "inference.pid")
    ui = _read_pid(run_dir() / "ui.pid")
    if inference is None or ui is None:
        return None
    if not _live(inference) or not _live(ui):
        return None
    if not _is_astrolabe_process(inference, "inference") or not _is_astrolabe_process(ui, "ui"):
        return None
    return _saved_port()


def _stop_pid(pid: int) -> None:
    if not _live(pid):
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not _live(pid):
            return
        time.sleep(0.2)
    if _live(pid):
        os.kill(pid, signal.SIGKILL)


def _wait_for_ui(port: int, proc: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                data = sock.recv(32)
            if data.startswith(b"HTTP/"):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def start_background(port: int) -> int:
    from astrolabe.commands import _port_holder, _wait_for_health

    holder = _port_holder(port)
    if holder is not None:
        print(f"Port {port} is in use by {holder}.", file=sys.stderr)
        return 1
    run = run_dir()
    logs = log_dir()
    run.mkdir(parents=True, mode=0o700)
    logs.mkdir(parents=True, mode=0o700)
    inference_log = (logs / "inference.log").open("ab")
    try:
        server = subprocess.Popen(
            [sys.executable, "-m", "antares_server"],
            stdout=inference_log,
            stderr=inference_log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    finally:
        inference_log.close()
    (run / "inference.pid").write_text(f"{server.pid}\n", encoding="utf-8")
    if not _wait_for_health(server):
        _stop_pid(server.pid)
        print("The inference server did not become healthy.", file=sys.stderr)
        return 1
    ui_log = (logs / "ui.log").open("ab")
    try:
        ui = subprocess.Popen(
            [sys.executable, "-m", "astrolabe", "ui", "--port", str(port)],
            stdout=ui_log,
            stderr=ui_log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    finally:
        ui_log.close()
    (run / "ui.pid").write_text(f"{ui.pid}\n", encoding="utf-8")
    (run / "port").write_text(f"{port}\n", encoding="utf-8")
    if not _wait_for_ui(port, ui):
        _stop_pid(ui.pid)
        _stop_pid(server.pid)
        print("The UI did not respond.", file=sys.stderr)
        return 1
    print(_url(port))
    return 0


def _ensure_data_dirs() -> None:
    root = engagements_root()
    root.mkdir(parents=True, exist_ok=True)
    durable_audit_path(root).parent.mkdir(parents=True, exist_ok=True)


def run_doctor() -> int:
    """Doctor before start. A socket that is not present yet does not block; start creates it."""
    from astrolabe.environment import default_probes, execute_checks

    from astrolabe.commands import check_location

    _ensure_data_dirs()
    engagements = engagements_root()
    checks = execute_checks(default_probes(engagements))
    blocking: list[str] = []
    for item in checks:
        pending_socket = (
            item.name == "Inference socket" and item.status == "missing" and "is not present" in item.detail
        )
        status = item.status
        if item.name == "Advisory cache" and status != "ok":
            status = "warn"
        fix = item.hint if status != "ok" else ""
        print(f"{item.name}\t{status}\t{check_location(item.name, engagements)}\t{fix}")
        if status == "missing" and not pending_socket:
            blocking.append(item.hint)
    if blocking:
        for hint in blocking:
            print(hint, file=sys.stderr)
        return 1
    return 0


def cmd_up(argv: list[str]) -> int:
    parsed = _parse_up(argv)
    if parsed is None:
        return 2
    port, explicit, download, foreground = parsed
    running = already_running()
    if running is not None:
        print(_url(running))
        return 0
    if not docker_is_running():
        print(DOCKER_MESSAGE, file=sys.stderr)
        return 1
    root = checkout_root() or Path.cwd()
    if checkout_root() is not None:
        from astrolabe.bootstrap import ensure_installed

        ensure_installed(root)
    directory = resolve_weights(Path(explicit) if explicit else None, root)
    expected = default_weights_dir(root)
    if directory is None:
        _missing_weights(expected)
        if not _consent(download):
            return 1
        code = download_weights(expected)
        if code != 0:
            return code
        directory = resolve_weights(Path(explicit) if explicit else None, root)
        if directory is None:
            _missing_weights(expected)
            return 1
    code = setup_if_needed(directory)
    if code != 0:
        return code
    if run_doctor() != 0:
        return 1
    if foreground:
        from astrolabe.commands import cmd_start

        return cmd_start(port)
    return start_background(port)


def cmd_down() -> int:
    refused = False
    for role, name in (("inference", "inference.pid"), ("ui", "ui.pid")):
        path = run_dir() / name
        pid = _read_pid(path)
        if pid is None:
            continue
        if not _live(pid):
            path.unlink(missing_ok=True)
            continue
        if not _is_astrolabe_process(pid, role):
            print(f"PID {pid} is not an Astrolabe process.", file=sys.stderr)
            refused = True
            continue
        _stop_pid(pid)
        path.unlink(missing_ok=True)
    if refused:
        return 1
    print("stopped")
    return 0


def cmd_status() -> int:
    from astrolabe.commands import cmd_doctor

    port = _saved_port()
    running = already_running()
    print("running" if running is not None else "stopped")
    print(_url(port))
    return cmd_doctor()


def cmd_logs(follow: bool) -> int:
    logs = log_dir()
    paths = [logs / "inference.log", logs / "ui.log"]
    if not follow:
        for path in paths:
            print(f"== {path.name} ==")
            if path.is_file():
                sys.stdout.write(path.read_text(encoding="utf-8", errors="replace"))
            else:
                print("(empty)")
        return 0
    offsets = {path: 0 for path in paths}
    try:
        while True:
            for path in paths:
                if not path.is_file():
                    continue
                data = path.read_bytes()
                if len(data) <= offsets[path]:
                    continue
                sys.stdout.buffer.write(data[offsets[path] :])
                sys.stdout.buffer.flush()
                offsets[path] = len(data)
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0


def main(argv: list[str]) -> int:
    command = argv[0]
    rest = argv[1:]
    if command == "up":
        return cmd_up(rest)
    if command == "down":
        return cmd_down()
    if command == "status":
        return cmd_status()
    if command == "logs":
        return cmd_logs("--follow" in rest)
    print(f"unknown command {command}", file=sys.stderr)
    return 2


def _parse_up(argv: list[str]) -> tuple[int, str | None, bool, bool] | None:
    port = DEFAULT_PORT
    explicit: str | None = None
    download = False
    foreground = False
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--model-path":
            if index + 1 >= len(argv):
                print("usage: astrolabe up --model-path DIR", file=sys.stderr)
                return None
            explicit = argv[index + 1]
            index += 2
            continue
        if item == "--port":
            if index + 1 >= len(argv):
                print("usage: astrolabe up --port 8765", file=sys.stderr)
                return None
            port = int(argv[index + 1])
            index += 2
            continue
        if item == "--download-weights":
            download = True
            index += 1
            continue
        if item == "--foreground":
            foreground = True
            index += 1
            continue
        print(f"unknown argument {item}", file=sys.stderr)
        return None
    return port, explicit, download, foreground
