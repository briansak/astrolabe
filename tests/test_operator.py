"""setup, doctor, and start. Docker and the model stay stubbed."""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import tempfile
import types
from pathlib import Path

import pytest

from astrolabe.commands import IMAGE_BUILD_NOTICE, UV_IMAGE, cmd_doctor, cmd_setup, cmd_start
from astrolabe.environment import Check
from astrolabe.runner import main


def _install_weight_stub() -> None:
    package = types.ModuleType("antares_server")
    weights = types.ModuleType("antares_server.weights")

    def verify_weights(directory: Path) -> str:
        assert (directory / "model.safetensors").is_file()
        return "stub"

    weights.verify_weights = verify_weights  # type: ignore[attr-defined]
    package.weights = weights  # type: ignore[attr-defined]
    sys.modules["antares_server"] = package
    sys.modules["antares_server.weights"] = weights


def test_version_and_query_is_not_dispatched(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "astrolabe 0.1.0"
    assert main(["-V"]) == 0
    assert main(["query", "--help"]) == 2
    assert "unknown command query" in capsys.readouterr().err


def test_setup_records_the_model_path_and_names_the_image_hosts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("ANTARES_MODEL_PATH", raising=False)
    socket_dir = Path(tempfile.mkdtemp(prefix="assock", dir="/tmp"))
    token_dir = Path(tempfile.mkdtemp(prefix="astok", dir="/tmp"))
    monkeypatch.setenv("ANTARES_SOCKET", str(socket_dir / "inference.sock"))
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_dir / "inference.sock"))
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(token_dir))
    monkeypatch.setenv("ASTROLABE_TOKEN_DIR", str(token_dir))
    weights = tmp_path / "weights"
    weights.mkdir()
    for name in ("model.safetensors", "config.json", "antares-cli.zip"):
        (weights / name).write_bytes(b"local")
    _install_weight_stub()
    built: dict[str, Path] = {}

    def build(zip_path: Path) -> int:
        built["zip"] = zip_path
        return 0

    monkeypatch.setattr("astrolabe.commands._build_image", build)
    try:
        assert cmd_setup(weights) == 0
    finally:
        shutil.rmtree(socket_dir, ignore_errors=True)
        shutil.rmtree(token_dir, ignore_errors=True)
    assert built["zip"] == weights / "antares-cli.zip"
    printed = capsys.readouterr().out
    assert IMAGE_BUILD_NOTICE in printed
    for host in ("Docker Hub", "ghcr.io", "Debian", "PyPI"):
        assert host in printed
    assert UV_IMAGE in printed
    from astrolabe.user_config import config_path

    config = config_path()
    assert config.is_file()
    assert config.stat().st_mode & 0o777 == 0o600
    assert config.parent.stat().st_mode & 0o777 == 0o700
    assert str(weights.resolve()) in config.read_text(encoding="utf-8")
    assert not (home / "Astrolabe" / "engagements").exists()


def test_setup_refuses_a_weights_directory_without_the_cli_zip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    weights = tmp_path / "weights"
    weights.mkdir()
    (weights / "model.safetensors").write_bytes(b"x")
    (weights / "config.json").write_bytes(b"{}")
    assert cmd_setup(weights) == 2
    assert "antares-cli.zip" in capsys.readouterr().err


def test_doctor_exits_nonzero_only_when_a_required_check_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing(_root: Path) -> list[tuple[str, object]]:
        return [("Docker daemon", lambda: Check("Docker daemon", "missing", "down", "Start Docker."))]

    monkeypatch.setattr("astrolabe.commands.default_probes", missing)
    monkeypatch.setattr("astrolabe.commands.check_location", lambda name, root: "docker")
    assert cmd_doctor(tmp_path) == 1
    assert "Docker daemon\tmissing\tdocker\tStart Docker." in capsys.readouterr().out

    def warned(_root: Path) -> list[tuple[str, object]]:
        return [("PDF rendering", lambda: Check("PDF rendering", "warn", "no pango", "brew install pango"))]

    monkeypatch.setattr("astrolabe.commands.default_probes", warned)
    monkeypatch.setattr("astrolabe.commands.check_location", lambda name, root: "weasyprint")
    assert cmd_doctor(tmp_path) == 0
    assert "PDF rendering\twarn\tweasyprint\tbrew install pango" in capsys.readouterr().out


def test_start_refuses_a_busy_port_and_an_unset_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    port = int(held.getsockname()[1])
    try:
        assert cmd_start(port) == 1
    finally:
        held.close()
    assert f"Port {port} is in use" in capsys.readouterr().err
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ANTARES_MODEL_PATH", raising=False)
    assert cmd_start(0) == 2
    assert "Model path is not configured" in capsys.readouterr().err


def test_start_launches_the_server_then_the_ui(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTARES_MODEL_PATH", str(tmp_path / "weights"))
    seen: dict[str, object] = {}

    class FakeServer:
        def __init__(self, args: list[str]) -> None:
            seen["args"] = args
            self.returncode = None

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            seen["terminated"] = True
            self.returncode = 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            seen["killed"] = True

    monkeypatch.setattr(subprocess, "Popen", lambda args: FakeServer(args))
    monkeypatch.setattr("astrolabe.commands._wait_for_health", lambda server: True)

    def ui_main(argv: list[str]) -> int:
        seen["ui"] = argv
        return 0

    monkeypatch.setattr("astrolabe.ui.main", ui_main)
    assert cmd_start(8799) == 0
    assert seen["args"] == [sys.executable, "-m", "antares_server"]
    assert seen["ui"] == ["--port", "8799"]
    assert seen["terminated"] is True
