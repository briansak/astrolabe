"""Engagement runner. The CLI runs in a container; inference stays on the host."""

from __future__ import annotations

import contextvars
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from astrolabe.engagement import EngagementError
from astrolabe.inference_socket import (
    SocketDirectoryError,
    configured_inference_socket,
    configured_token_directory,
    ensure_private_socket_dir,
    ensure_private_token_dir,
)
from astrolabe.snapshot import materialize_snapshot

IMAGE = os.environ.get("ASTROLABE_CLI_IMAGE", "astrolabe-antares-cli:1")
SERVED_MODEL_ID = "fdtn-ai/antares-1b"
PROCESS_INSTANCE = str(uuid.uuid4())
_LEGACY_MAX_AGE = timedelta(hours=1)
cancel_event: contextvars.ContextVar[threading.Event | None] = contextvars.ContextVar(
    "astrolabe_cancel_event",
    default=None,
)
container_slot: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "astrolabe_container_slot",
    default=None,
)


def engagement_paths(engagement: Path) -> dict[str, Path]:
    engagement = engagement.resolve()
    return {
        "root": engagement,
        "snapshot": engagement / "snapshot",
        "data": engagement / "antares-data",
        "socket": engagement / "socket",
    }


def prepare_snapshot(repo: Path, engagement: Path, *, include_test_paths: bool) -> Path:
    paths = engagement_paths(engagement)
    snapshot = paths["snapshot"]
    if snapshot.exists():
        raise SystemExit(f"Snapshot already exists at {snapshot}; remove the engagement directory first")
    paths["data"].mkdir(parents=True, exist_ok=True)
    paths["socket"].mkdir(parents=True, exist_ok=True)
    return materialize_snapshot(repo, snapshot, include_test_paths=include_test_paths)


class _SocketBridge:
    """Holds one Colima relay until the CLI container exits."""

    def __init__(self) -> None:
        self.relay_name: str | None = None
        self.volume_name: str | None = None
        self.port: int | None = None
        self._closed = False
        self._stop = threading.Event()
        self._listener: socket.socket | None = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.relay_name:
            subprocess.run(
                ["docker", "rm", "-f", self.relay_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        if self.volume_name:
            subprocess.run(
                ["docker", "volume", "rm", self.volume_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None


def cleanup_orphaned_relays() -> None:
    """Remove dead labeled relays, and unlabeled relays older than one hour."""
    _remove_stale(
        ["docker", "ps", "-a", "--filter", "name=astrolabe-relay-", "--format", "{{.Names}}"],
        "astrolabe-relay-",
        "container",
    )
    _remove_stale(
        ["docker", "volume", "ls", "--filter", "name=astrolabe-sock-", "--format", "{{.Name}}"],
        "astrolabe-sock-",
        "volume",
    )


def _owner_labels() -> list[str]:
    return [
        "--label",
        f"astrolabe.owner={PROCESS_INSTANCE}",
        "--label",
        f"astrolabe.pid={os.getpid()}",
    ]


def _remove_stale(list_args: list[str], prefix: str, kind: str) -> None:
    try:
        listed = subprocess.run(list_args, text=True, capture_output=True, check=False)
    except OSError:
        return
    if listed.returncode != 0:
        return
    for name in listed.stdout.split():
        if not name.startswith(prefix) or not _should_remove(kind, name):
            continue
        command = ["docker", "rm", "-f", name] if kind == "container" else ["docker", "volume", "rm", name]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _should_remove(kind: str, name: str) -> bool:
    inspected = _inspect_resource(kind, name)
    if inspected is None:
        return False
    owner, pid_text, created = inspected
    labeled = bool(owner) or bool(pid_text)
    if labeled:
        return not _pid_running(pid_text)
    return _older_than_one_hour(created)


def _inspect_resource(kind: str, name: str) -> tuple[str, str, str] | None:
    if kind == "container":
        template = '{{index .Config.Labels "astrolabe.owner"}}|{{index .Config.Labels "astrolabe.pid"}}|{{.Created}}'
        command = ["docker", "inspect", "--format", template, name]
    else:
        template = '{{index .Labels "astrolabe.owner"}}|{{index .Labels "astrolabe.pid"}}|{{.CreatedAt}}'
        command = ["docker", "volume", "inspect", "--format", template, name]
    try:
        inspected = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError:
        return None
    if inspected.returncode != 0:
        return None
    owner, pid_text, created = (inspected.stdout.strip().split("|", 2) + ["", ""])[:3]
    return _blank_label(owner), _blank_label(pid_text), created.strip()


def _blank_label(value: str) -> str:
    text = value.strip()
    if text in {"", "<no value>", "<nil>"}:
        return ""
    return text


def _pid_running(pid_text: str) -> bool:
    try:
        pid = int(pid_text)
    except ValueError:
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _older_than_one_hour(created: str) -> bool:
    stamp = _parse_created(created)
    if stamp is None:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return datetime.now(UTC) - stamp > _LEGACY_MAX_AGE


def _parse_created(value: str) -> datetime | None:
    text = value.strip()
    if not text or text in {"<no value>", "<nil>"}:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, tail = text.split(".", 1)
        digits: list[str] = []
        rest = ""
        for index, char in enumerate(tail):
            if char.isdigit() and len(digits) < 6:
                digits.append(char)
            elif char.isdigit():
                continue
            else:
                rest = tail[index:]
                break
        text = head + "." + "".join(digits) + rest
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _use_vm_socket_bridge() -> bool:
    mode = os.environ.get("ASTROLABE_SOCKET_BRIDGE", "auto")
    if mode == "1":
        return True
    if mode == "0":
        return False
    return sys.platform == "darwin"


def _linux_socket_mount(socket_path: Path) -> list[str]:
    """Bind-mount the socket's parent. That directory may contain only the socket."""
    directory = socket_path.parent
    extra = sorted(item.name for item in directory.iterdir() if item.name != socket_path.name)
    if extra:
        raise EngagementError(
            f"Socket directory {directory} must contain only {socket_path.name}. Found {', '.join(extra)}."
        )
    return ["-v", f"{directory}:/run/astrolabe:ro"]


def _socket_mount(bridge: _SocketBridge) -> list[str]:
    if _use_vm_socket_bridge():
        if not bridge.volume_name:
            raise EngagementError("The inference relay has no socket volume")
        return ["-v", f"{bridge.volume_name}:/run/astrolabe:ro"]
    return _linux_socket_mount(configured_inference_socket())


def _issue_run_token() -> Path:
    """Write a one-run bearer token where the server can see it and the container cannot."""
    try:
        directory = ensure_private_token_dir(configured_token_directory())
    except SocketDirectoryError as exc:
        raise EngagementError(str(exc)) from exc
    token = secrets.token_urlsafe(32)
    name = secrets.token_hex(8)
    temporary = directory / f".{name}.tmp"
    target = directory / name
    temporary.write_text(token + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)
    os.chmod(target, 0o600)
    return target


def _prepare_relay(bridge: _SocketBridge) -> None:
    """Bind an ephemeral loopback port and start this run's relay. Bind and start failures are EngagementError."""
    if not _use_vm_socket_bridge():
        return
    unix_path = configured_inference_socket()
    if not unix_path.exists():
        raise SystemExit(f"Inference socket is not listening at {unix_path}")
    run_id = uuid.uuid4().hex[:12]
    bridge.volume_name = f"astrolabe-sock-{run_id}"
    bridge.relay_name = f"astrolabe-relay-{run_id}"
    _listen_loopback(bridge, unix_path)
    _start_relay(bridge)


def _start_relay(bridge: _SocketBridge) -> None:
    if not bridge.relay_name or not bridge.volume_name or bridge.port is None:
        raise EngagementError("The inference relay did not start")
    created = subprocess.run(
        ["docker", "volume", "create", *_owner_labels(), bridge.volume_name],
        text=True,
        capture_output=True,
    )
    if created.returncode != 0:
        detail = created.stderr.strip() or "The inference relay volume did not start"
        raise EngagementError(detail)
    started = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            bridge.relay_name,
            *_owner_labels(),
            "--user",
            "0:0",
            "--entrypoint",
            "socat",
            "--add-host",
            "host.docker.internal:host-gateway",
            "-v",
            f"{bridge.volume_name}:/run/astrolabe",
            IMAGE,
            "UNIX-LISTEN:/run/astrolabe/inference.sock,fork,reuseaddr,unlink-early,mode=666",
            f"TCP:host.docker.internal:{bridge.port}",
        ],
        text=True,
        capture_output=True,
    )
    if started.returncode != 0:
        detail = started.stderr.strip() or "The inference relay did not start"
        raise EngagementError(detail)
    try:
        _wait_for_vm_socket(bridge.relay_name)
    except SystemExit as exc:
        raise EngagementError(str(exc) or "The inference relay did not start") from exc


def _listen_loopback(bridge: _SocketBridge, unix_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 0))
    except OSError as exc:
        listener.close()
        raise EngagementError(f"The inference relay could not bind a loopback port: {exc}") from exc
    bridge.port = int(listener.getsockname()[1])
    listener.listen(16)
    listener.settimeout(0.5)
    bridge._listener = listener

    def serve() -> None:
        while not bridge._stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=_pump_to_unix,
                args=(client, unix_path),
                name="astrolabe-socket-pump",
                daemon=True,
            ).start()

    threading.Thread(target=serve, name="astrolabe-loopback-proxy", daemon=True).start()


def _pump_to_unix(client: socket.socket, unix_path: Path) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(str(unix_path))
    except OSError:
        client.close()
        return

    def pump(source: socket.socket, dest: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                dest.sendall(data)
        except OSError:
            pass
        finally:
            for sock, how in ((source, socket.SHUT_RD), (dest, socket.SHUT_WR)):
                try:
                    sock.shutdown(how)
                except OSError:
                    pass

    reverse = threading.Thread(target=pump, args=(upstream, client), daemon=True)
    reverse.start()
    pump(client, upstream)
    reverse.join(timeout=1)
    client.close()
    upstream.close()


def _wait_for_vm_socket(relay_name: str) -> None:
    for _ in range(50):
        probe = subprocess.run(
            ["docker", "exec", relay_name, "test", "-S", "/run/astrolabe/inference.sock"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.1)
    raise SystemExit("The VM inference socket did not appear")


def _container_name() -> str:
    return f"astrolabe-{uuid.uuid4().hex[:12]}"


def _with_container_name(args: list[str], name: str) -> list[str]:
    try:
        image_at = args.index(IMAGE)
    except ValueError:
        image_at = len(args)
    return [*args[:image_at], "--name", name, *args[image_at:]]


def _run_until_cancelled(
    args: list[str],
    cancel: threading.Event,
    *,
    capture: bool,
) -> subprocess.CompletedProcess[str]:
    if cancel.is_set():
        return subprocess.CompletedProcess(args, 1, "", "cancelled")
    name = args[args.index("--name") + 1] if "--name" in args else ""
    process = subprocess.Popen(
        args,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    while process.poll() is None:
        if cancel.is_set():
            process.kill()
            if name:
                subprocess.run(
                    ["docker", "kill", name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            break
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            continue
    stdout, stderr = process.communicate()
    code = process.returncode if process.returncode is not None else 1
    return subprocess.CompletedProcess(args, code, stdout or "", stderr or "")


def run_container(
    engagement: Path,
    command: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    stream: bool = True,
    needs_inference: bool = True,
) -> subprocess.CompletedProcess[str]:
    paths = engagement_paths(engagement)
    if not paths["snapshot"].is_dir():
        raise SystemExit(f"Missing hardened snapshot at {paths['snapshot']}")
    paths["data"].mkdir(parents=True, exist_ok=True)
    memory = os.environ.get("ASTROLABE_CONTAINER_MEMORY", "1536m")
    cpus = os.environ.get("ASTROLABE_CONTAINER_CPUS", "1")
    env = {
        "ANTARES_DATA_DIR": "/data",
        "ANTARES_ENDPOINT": "http://127.0.0.1:8000/v1/completions",
        "ANTARES_MODEL": SERVED_MODEL_ID,
        "HOME": "/data",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if extra_env:
        env.update(extra_env)
    token_file = _issue_run_token()
    if token_file is not None:
        env["ANTARES_API_KEY"] = token_file.read_text(encoding="utf-8").strip()
    if "ANTARES_DATA_DIR" not in env or not env["ANTARES_DATA_DIR"]:
        raise SystemExit("ANTARES_DATA_DIR must be set inside the container")
    docker_env: list[str] = []
    for key, value in env.items():
        docker_env.extend(["-e", f"{key}={value}"])
    args = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--cpus",
        cpus,
        "--memory",
        memory,
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m",
        "-v",
        f"{paths['snapshot']}:/workspace/repo:ro",
        "-v",
        f"{paths['data']}:/data:rw",
        *docker_env,
        IMAGE,
        *command,
    ]
    bridge = _SocketBridge()
    try:
        if needs_inference:
            try:
                socket_path = configured_inference_socket()
                ensure_private_socket_dir(socket_path)
            except SocketDirectoryError as exc:
                raise EngagementError(str(exc)) from exc
            _prepare_relay(bridge)
            mount_at = args.index("-v")
            args[mount_at:mount_at] = _socket_mount(bridge)
        name = _container_name()
        slot = container_slot.get()
        if slot is not None:
            slot["name"] = name
        named = _with_container_name(args, name)
        cancel = cancel_event.get()
        if cancel is None:
            return subprocess.run(named, text=True, capture_output=not stream)
        return _run_until_cancelled(named, cancel, capture=not stream)
    finally:
        bridge.close()
        if token_file is not None:
            token_file.unlink(missing_ok=True)


def cmd_query(repo: Path, cwe: str, engagement: Path, *, include_test_paths: bool) -> int:
    prepare_snapshot(repo, engagement, include_test_paths=include_test_paths)
    result = run_container(
        engagement,
        ["antares", "query", "/workspace/repo", "--cwe", cwe],
        extra_env={"ANTARES_REMOTE_TIMEOUT_SECONDS": os.environ.get("ANTARES_REMOTE_TIMEOUT_SECONDS", "1200")},
    )
    if result.returncode != 0:
        return result.returncode
    return 0


def cmd_verify_isolation(engagement: Path) -> int:
    paths = engagement_paths(engagement)
    paths["snapshot"].mkdir(parents=True, exist_ok=True)
    paths["data"].mkdir(parents=True, exist_ok=True)
    paths["socket"].mkdir(parents=True, exist_ok=True)
    script = (
        "import os, socket, sys\n"
        "devs = open('/proc/net/dev', encoding='utf-8').read()\n"
        "print(devs)\n"
        "names = []\n"
        "for line in devs.splitlines()[2:]:\n"
        "    names.append(line.split(':', 1)[0].strip())\n"
        "print('interfaces=' + ','.join(names))\n"
        "if names != ['lo']:\n"
        "    sys.exit(1)\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 443), timeout=3).close()\n"
        "except OSError as exc:\n"
        "    print(f'outbound=failed {type(exc).__name__}: {exc}')\n"
        "    sys.exit(0)\n"
        "print('outbound=ok')\n"
        "sys.exit(1)\n"
    )
    result = run_container(engagement, ["python", "-c", script])
    return result.returncode


def cmd_long_generation(engagement: Path, max_tokens: int) -> int:
    paths = engagement_paths(engagement)
    paths["snapshot"].mkdir(parents=True, exist_ok=True)
    paths["data"].mkdir(parents=True, exist_ok=True)
    paths["socket"].mkdir(parents=True, exist_ok=True)
    result = run_container(
        engagement,
        ["python", "/opt/astrolabe/long_completion.py"],
        extra_env={"ASTROLABE_LONG_MAX_TOKENS": str(max_tokens)},
    )
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    cleanup_orphaned_relays()
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"--version", "-V"}:
        from astrolabe import __version__

        print(f"astrolabe {__version__}")
        return 0
    if args and args[0] == "setup":
        from astrolabe.commands import cmd_setup

        if "--model-path" not in args:
            print("usage: astrolabe setup --model-path DIR", file=sys.stderr)
            return 2
        return cmd_setup(Path(args[args.index("--model-path") + 1]))
    if args and args[0] == "doctor":
        from astrolabe.commands import cmd_doctor

        root = None
        if "--engagements-root" in args:
            root = Path(args[args.index("--engagements-root") + 1])
        return cmd_doctor(root)
    if args and args[0] == "start":
        from astrolabe.commands import cmd_start

        port = 8765
        if "--port" in args:
            port = int(args[args.index("--port") + 1])
        return cmd_start(port)
    if args and args[0] in {"up", "down", "status", "logs"}:
        from astrolabe.lifecycle import main as lifecycle_main

        return lifecycle_main(args)
    phase2 = {
        "engagement",
        "attest",
        "intake",
        "investigate",
        "rerun",
        "verdict",
        "coverage",
        "export",
        "purge",
        "advisories",
        "report",
    }
    if args and args[0] == "ui":
        from astrolabe.ui import main as ui_main

        return ui_main(args[1:])
    if args and args[0] in phase2:
        from astrolabe.phase2_cli import main as phase2_main

        return phase2_main(args)
    if not args or args[0] in {"-h", "--help"}:
        print(
            "usage:\n"
            "  python -m astrolabe engagement create --id ID --customer NAME --scope TEXT "
            "--start YYYY-MM-DD --consultant NAME [--reference REF --authorized]\n"
            "  python -m astrolabe attest --engagement ID --actor NAME --reference SOW --scope TEXT\n"
            "  python -m astrolabe intake --engagement ID --path DIR_OR_ARCHIVE\n"
            "  python -m astrolabe investigate --engagement ID --cwe CWE-89 --actor NAME "
            "(--advisory-id ID | --advisory-text TEXT | --exploratory)\n"
            "  python -m astrolabe rerun --engagement ID --investigation INV --actor NAME\n"
            "  python -m astrolabe verdict --engagement ID --path FILE --cwe CWE-89 "
            "--state confirmed --actor NAME --note TEXT [--confirm-advisory]\n"
            "  python -m astrolabe coverage --engagement ID\n"
            "  python -m astrolabe engagement close --id ID --actor NAME\n"
            "  python -m astrolabe export --engagement ID --output FILE.tar.gz --actor NAME "
            "[--allow-draft] [--report-only]\n"
            "  python -m astrolabe purge --engagement ID --actor NAME\n"
            "  python -m astrolabe advisories sync [--engagement ID] --id CVE-... --actor NAME\n"
            "  python -m astrolabe advisories import DIR\n"
            "  python -m astrolabe report assessment --engagement ID --actor NAME\n"
            "  python -m astrolabe report remediation --engagement ID --actor NAME\n"
            "  python -m astrolabe report finalize --engagement ID --actor NAME\n"
            "  python -m astrolabe ui [--port 8765]\n"
            "  python -m astrolabe setup --model-path DIR\n"
            "  python -m astrolabe doctor\n"
            "  python -m astrolabe start [--port 8765]\n"
            "  python -m astrolabe up [--model-path DIR] [--port 8765] [--download-weights] [--foreground]\n"
            "  python -m astrolabe down\n"
            "  python -m astrolabe status\n"
            "  python -m astrolabe logs [--follow]\n"
            "  python -m astrolabe verify-isolation --engagement DIR\n"
            "  python -m astrolabe long-generation --engagement DIR [--max-tokens N]",
            file=sys.stderr,
        )
        return 2
    command = args[0]
    if command == "verify-isolation":
        return cmd_verify_isolation(_require_engagement(args[1:]))
    if command == "long-generation":
        engagement, max_tokens = _parse_long(args[1:])
        return cmd_long_generation(engagement, max_tokens)
    print(f"unknown command {command}", file=sys.stderr)
    return 2


def _require_engagement(args: list[str]) -> Path:
    if "--engagement" not in args:
        raise SystemExit("--engagement is required")
    return Path(args[args.index("--engagement") + 1])


def _parse_long(args: list[str]) -> tuple[Path, int]:
    engagement = _require_engagement(args)
    if "--max-tokens" in args:
        return engagement, int(args[args.index("--max-tokens") + 1])
    return engagement, int(os.environ.get("ASTROLABE_LONG_MAX_TOKENS", "8192"))


if __name__ == "__main__":
    raise SystemExit(main())
