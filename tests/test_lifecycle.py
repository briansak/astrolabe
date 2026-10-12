"""up, down, status, and logs. Docker, the model, and Hugging Face stay stubbed."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

import pytest

from astrolabe.lifecycle import (
    DOCKER_MESSAGE,
    GATE_URL,
    WEIGHT_FILES,
    cmd_down,
    cmd_up,
    resolve_weights,
    sha256_file,
)
from astrolabe.user_config import config_path, write_model_path


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


def _fill(path: Path, payload: bytes = b"local-weights") -> None:
    path.mkdir(parents=True, exist_ok=True)
    for name in WEIGHT_FILES:
        (path / name).write_bytes(payload)


def _checkout(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src" / "astrolabe").mkdir(parents=True)
    (root / "src" / "astrolabe" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname = 'astrolabe'\n", encoding="utf-8")
    server = root / "services" / "antares-server"
    (server / "antares_server").mkdir(parents=True)
    (server / "antares_server" / "__init__.py").write_text("", encoding="utf-8")
    (server / "pyproject.toml").write_text("[project]\nname = 'astrolabe-antares-server'\n", encoding="utf-8")
    (root / ".venv").mkdir()
    return root


def _runtime(monkeypatch: pytest.MonkeyPatch, home: Path) -> tuple[Path, Path]:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("ANTARES_MODEL_PATH", raising=False)
    monkeypatch.delenv("ASTROLABE_ENGAGEMENTS_DIR", raising=False)
    socket_dir = Path(tempfile.mkdtemp(prefix="assock", dir="/tmp"))
    token_dir = Path(tempfile.mkdtemp(prefix="astok", dir="/tmp"))
    monkeypatch.setenv("ANTARES_SOCKET", str(socket_dir / "inference.sock"))
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_dir / "inference.sock"))
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(token_dir))
    monkeypatch.setenv("ASTROLABE_TOKEN_DIR", str(token_dir))
    return socket_dir, token_dir


def test_up_second_run_skips_install_and_image_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _checkout(tmp_path)
    _fill(root / "models" / "1b")
    socket_dir, token_dir = _runtime(monkeypatch, tmp_path / "home")
    monkeypatch.chdir(root)
    _install_weight_stub()
    installs: list[Path] = []
    builds: list[Path] = []
    stored: dict[str, str | None] = {"hash": None}

    def install_checkout(path: Path) -> None:
        installs.append(path)

    def build_image(zip_path: Path) -> int:
        builds.append(zip_path)
        stored["hash"] = sha256_file(zip_path)
        return 0

    monkeypatch.setattr("astrolabe.bootstrap.install_checkout", install_checkout)
    monkeypatch.setattr("astrolabe.lifecycle.build_image", build_image)
    monkeypatch.setattr("astrolabe.lifecycle.labeled_image_hash", lambda: stored["hash"])
    monkeypatch.setattr("astrolabe.lifecycle.docker_is_running", lambda: True)
    monkeypatch.setattr("astrolabe.lifecycle.run_doctor", lambda: 0)
    monkeypatch.setattr("astrolabe.lifecycle.start_background", lambda port: (print(f"http://127.0.0.1:{port}/") or 0))
    try:
        assert cmd_up([]) == 0
        assert cmd_up([]) == 0
    finally:
        shutil.rmtree(socket_dir, ignore_errors=True)
        shutil.rmtree(token_dir, ignore_errors=True)
    assert len(installs) == 1
    assert len(builds) == 1
    assert "http://127.0.0.1:8765/" in capsys.readouterr().out


def test_weights_resolution_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _checkout(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ANTARES_MODEL_PATH", raising=False)
    explicit = tmp_path / "explicit"
    env_dir = tmp_path / "from-env"
    saved = tmp_path / "saved"
    checkout = root / "models" / "1b"
    for path in (explicit, env_dir, saved, checkout):
        _fill(path, path.name.encode())
    write_model_path(saved)
    monkeypatch.setenv("ANTARES_MODEL_PATH", str(env_dir))
    assert resolve_weights(explicit, root) == explicit.resolve()
    (explicit / "antares-cli.zip").unlink()
    assert resolve_weights(explicit, root) == env_dir.resolve()
    monkeypatch.delenv("ANTARES_MODEL_PATH", raising=False)
    assert resolve_weights(None, root) == saved.resolve()
    config_path().unlink()
    assert resolve_weights(None, root) == checkout.resolve()


def test_missing_weights_print_the_gate_url_and_do_not_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _checkout(tmp_path)
    socket_dir, token_dir = _runtime(monkeypatch, tmp_path / "home")
    monkeypatch.chdir(root)
    downloads: list[Path] = []
    monkeypatch.setattr("astrolabe.lifecycle.docker_is_running", lambda: True)
    monkeypatch.setattr("astrolabe.lifecycle.download_weights", lambda dest: downloads.append(dest) or 0)
    monkeypatch.setattr("astrolabe.bootstrap.install_checkout", lambda root: None)
    try:
        assert cmd_up([]) == 1
    finally:
        shutil.rmtree(socket_dir, ignore_errors=True)
        shutil.rmtree(token_dir, ignore_errors=True)
    captured = capsys.readouterr()
    assert GATE_URL in captured.err
    assert "models/1b" in captured.err
    assert downloads == []


def test_docker_not_running_exits_with_the_desktop_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr("astrolabe.lifecycle.docker_is_running", lambda: False)
    assert cmd_up([]) == 1
    assert capsys.readouterr().err.strip() == DOCKER_MESSAGE


def test_down_refuses_a_pid_that_is_not_an_astrolabe_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    run = tmp_path / "home" / "Astrolabe" / "var" / "run"
    run.mkdir(parents=True)
    pid = os.getpid()
    (run / "inference.pid").write_text(f"{pid}\n", encoding="utf-8")

    def refuse_signal(*_args: object) -> None:
        raise AssertionError("down signaled a process")

    monkeypatch.setattr(os, "kill", refuse_signal)
    assert cmd_down() == 1
    assert f"PID {pid} is not an Astrolabe process." in capsys.readouterr().err
    assert os.getpid() == pid


def test_already_running_up_exits_0_with_the_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    run = tmp_path / "home" / "Astrolabe" / "var" / "run"
    run.mkdir(parents=True)
    pid = os.getpid()
    (run / "inference.pid").write_text(f"{pid}\n", encoding="utf-8")
    (run / "ui.pid").write_text(f"{pid}\n", encoding="utf-8")
    (run / "port").write_text("8765\n", encoding="utf-8")
    monkeypatch.setattr(
        "astrolabe.lifecycle._command_line",
        lambda _pid: "python -m antares_server astrolabe ui --port 8765",
    )
    started: list[int] = []
    monkeypatch.setattr("astrolabe.lifecycle.start_background", lambda port: started.append(port) or 0)
    monkeypatch.setattr("astrolabe.lifecycle.docker_is_running", lambda: False)
    assert cmd_up([]) == 0
    assert capsys.readouterr().out.strip() == "http://127.0.0.1:8765/"
    assert started == []


def test_token_is_never_written_to_config_logs_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "hf_test_token_should_not_leak"
    root = _checkout(tmp_path)
    socket_dir, token_dir = _runtime(monkeypatch, tmp_path / "home")
    monkeypatch.chdir(root)
    _install_weight_stub()
    calls: list[dict[str, object]] = []

    def snapshot_download(**kwargs: object) -> str:
        calls.append(kwargs)
        dest = Path(str(kwargs["local_dir"]))
        _fill(dest)
        return str(dest)

    hub = types.ModuleType("huggingface_hub")
    hub.get_token = lambda: sentinel  # type: ignore[attr-defined]
    hub.snapshot_download = snapshot_download  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "huggingface_hub", hub)
    monkeypatch.setattr("astrolabe.lifecycle.docker_is_running", lambda: True)

    def current_hash() -> str | None:
        path = root / "models" / "1b" / "antares-cli.zip"
        if not path.is_file():
            return None
        return sha256_file(path)

    monkeypatch.setattr("astrolabe.lifecycle.labeled_image_hash", current_hash)
    monkeypatch.setattr("astrolabe.lifecycle.run_doctor", lambda: 0)
    monkeypatch.setattr("astrolabe.lifecycle.start_background", lambda port: 0)
    monkeypatch.setattr("astrolabe.bootstrap.install_checkout", lambda _root: None)
    log = tmp_path / "home" / "Astrolabe" / "var" / "log" / "inference.log"
    log.parent.mkdir(parents=True)
    log.write_text("server log\n", encoding="utf-8")
    try:
        assert cmd_up(["--download-weights"]) == 0
    finally:
        shutil.rmtree(socket_dir, ignore_errors=True)
        shutil.rmtree(token_dir, ignore_errors=True)
    captured = capsys.readouterr()
    assert calls and "token" not in calls[0]
    blob = captured.out + captured.err + config_path().read_text(encoding="utf-8") + log.read_text(encoding="utf-8")
    assert sentinel not in blob
