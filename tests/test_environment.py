"""Landing-page dependency checks stay local and bounded."""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from astrolabe.engagement import EngagementError
from astrolabe.environment import (
    CHECK_TIMEOUT,
    Check,
    check_advisory_cache,
    check_inference,
    check_location,
    check_paths,
    check_token_directory,
    execute_checks,
    health_ok,
    rollup,
    run_checks,
    status_label,
)
from astrolabe.inference_socket import (
    SocketDirectoryError,
    configured_inference_socket,
    configured_token_directory,
    default_socket_directory,
    default_token_directory,
    ensure_private_socket_dir,
    ensure_private_token_dir,
    replace_existing_socket,
    sun_path_limit,
)
from astrolabe.runner import _SocketBridge, _socket_mount, run_container


def test_rollup_is_missing_over_warn_and_advisory_cache_only_warns(tmp_path: Path, monkeypatch) -> None:
    names = (
        "Docker daemon",
        "Sandbox image",
        "Inference socket",
        "Antares-1B weights",
        "CWE data",
        "Engagement paths",
        "git",
        "Advisory cache",
    )
    ok = [Check(name, "ok", "") for name in names]
    assert rollup(ok) == "ok"
    assert status_label(ok) == ("healthy", "Status")
    warned = [Check(name, "warn" if name == "Inference socket" else "ok", "") for name in names]
    assert rollup(warned) == "warn"
    assert status_label(warned) == ("warn", "Status · 1 warn")
    two = [Check(name, "warn" if name in {"Inference socket", "git"} else "ok", "") for name in names]
    assert status_label(two) == ("warn", "Status · 2 warn")
    missing = [Check(name, "missing" if name == "Docker daemon" else "ok", "") for name in names]
    assert rollup(missing) == "missing"
    assert status_label(missing) == ("danger", "Status · 1 missing")
    advisory = [Check(name, "missing" if name == "Advisory cache" else "ok", "") for name in names]
    assert rollup(advisory) == "warn"
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "empty-cache"))
    cached = check_advisory_cache()
    assert cached.status == "warn"
    present = [Check(name, "ok", "") for name in names if name != "Advisory cache"]
    assert rollup([*present, cached]) == "warn"
    assert status_label(None) == ("muted", "Status · checking")


def test_default_socket_path_resolves_without_an_engagement(monkeypatch) -> None:
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    monkeypatch.delenv("ASTROLABE_INFERENCE_SOCKET", raising=False)
    path = configured_inference_socket()
    assert path.name == "inference.sock"
    if sys.platform == "darwin":
        expected = Path.home() / "Library" / "Application Support" / "Astrolabe" / "run" / "inference.sock"
    else:
        runtime = os.environ.get("XDG_RUNTIME_DIR", "").strip() or f"/run/user/{os.getuid()}"
        expected = Path(runtime) / "astrolabe" / "inference.sock"
    assert path == expected
    monkeypatch.setenv("ANTARES_SOCKET", "/tmp/astrolabe/shared.sock")
    assert configured_inference_socket() == Path("/tmp/astrolabe/shared.sock")
    monkeypatch.delenv("ANTARES_SOCKET")
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", "/tmp/astrolabe/shared.sock")
    assert configured_inference_socket() == Path("/tmp/astrolabe/shared.sock")


def test_group_writable_socket_dir_is_refused(monkeypatch) -> None:
    directory = Path(tempfile.mkdtemp(prefix="asg", dir="/tmp"))
    os.chmod(directory, 0o770)
    monkeypatch.setenv("ANTARES_SOCKET", str(directory / "inference.sock"))
    monkeypatch.delenv("ASTROLABE_INFERENCE_SOCKET", raising=False)
    with pytest.raises(SocketDirectoryError, match="group or world") as caught:
        ensure_private_socket_dir(configured_inference_socket())
    message = str(caught.value)
    assert str(directory) in message
    assert "chmod 700" in message
    assert "unset ANTARES_SOCKET" in message
    assert directory.stat().st_mode & 0o777 == 0o770
    shutil.rmtree(directory, ignore_errors=True)


def test_mismatched_socket_overrides_are_missing(monkeypatch) -> None:
    monkeypatch.setenv("ANTARES_SOCKET", "/tmp/astrolabe/server.sock")
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", "/tmp/astrolabe/runner.sock")
    result = check_inference()
    assert result.status == "missing"
    assert "/tmp/astrolabe/server.sock" in result.detail
    assert "/tmp/astrolabe/runner.sock" in result.detail


def test_linux_mount_uses_the_configured_socket_parent(monkeypatch) -> None:
    monkeypatch.setattr("astrolabe.runner.sys.platform", "linux")
    monkeypatch.delenv("ASTROLABE_SOCKET_BRIDGE", raising=False)
    directory = Path(tempfile.mkdtemp(prefix="asm", dir="/tmp"))
    os.chmod(directory, 0o700)
    socket_path = directory / "inference.sock"
    socket_path.write_bytes(b"")
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_path))
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    mount = _socket_mount(_SocketBridge())
    assert mount == ["-v", f"{directory}:/run/astrolabe:ro"]
    (directory / "other").write_text("nope", encoding="utf-8")
    try:
        with pytest.raises(EngagementError, match="must contain only inference.sock"):
            _socket_mount(_SocketBridge())
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_check_inference_reports_ok_when_the_socket_is_healthy(monkeypatch) -> None:
    directory = Path(tempfile.mkdtemp(prefix="astrolabe-sock-", dir="/tmp"))
    os.chmod(directory, 0o700)
    path = directory / "inference.sock"
    ready = threading.Event()

    def serve() -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(path))
            sock.listen(1)
            ready.set()
            sock.settimeout(2)
            connection, _ = sock.accept()
            try:
                connection.settimeout(2)
                connection.recv(4096)
                body = b'{"status":"ok"}'
                header = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                connection.sendall(header + body)
            finally:
                connection.close()
        finally:
            sock.close()

    thread = threading.Thread(target=serve)
    thread.start()
    assert ready.wait(2)
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(path))
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    try:
        result = check_inference()
        thread.join(2)
    finally:
        path.unlink(missing_ok=True)
        directory.rmdir()
    assert result.status == "ok"


def test_token_directory_in_the_socket_parent_blocks_the_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("astrolabe.runner.sys.platform", "linux")
    monkeypatch.delenv("ASTROLABE_SOCKET_BRIDGE", raising=False)
    socket_dir = Path(tempfile.mkdtemp(prefix="asb", dir="/tmp"))
    os.chmod(socket_dir, 0o700)
    (socket_dir / "inference.sock").write_bytes(b"")
    (socket_dir / "tokens").mkdir()
    token_dir = Path(tempfile.mkdtemp(prefix="atb", dir="/tmp"))
    os.chmod(token_dir, 0o700)
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_dir / "inference.sock"))
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(token_dir))
    monkeypatch.delenv("ASTROLABE_TOKEN_DIR", raising=False)
    engagement = tmp_path / "engagement"
    (engagement / "snapshot").mkdir(parents=True)
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    try:
        with pytest.raises(EngagementError, match="tokens"):
            run_container(engagement, ["true"])
    finally:
        shutil.rmtree(socket_dir, ignore_errors=True)
        shutil.rmtree(token_dir, ignore_errors=True)
    assert not any(args[:2] == ["docker", "run"] for args in calls)


def test_token_directory_agrees_and_stays_outside_the_socket(tmp_path: Path, monkeypatch) -> None:
    directory = tmp_path / "tokens"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    marker = directory / "marker-file"
    marker.write_text("marker-value\n", encoding="utf-8")
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(directory))
    monkeypatch.delenv("ASTROLABE_TOKEN_DIR", raising=False)
    assert configured_token_directory() == directory
    monkeypatch.delenv("ANTARES_TOKEN_DIR")
    monkeypatch.setenv("ASTROLABE_TOKEN_DIR", str(directory))
    assert configured_token_directory() == directory
    result = check_token_directory()
    assert result.status == "ok"
    assert result.detail == "present"
    assert "marker-file" not in result.detail
    assert "marker-value" not in result.detail
    assert check_location("Token directory", tmp_path) == str(directory)
    loose = tmp_path / "loose-tokens"
    loose.mkdir()
    os.chmod(loose, 0o770)
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(loose))
    monkeypatch.setenv("ASTROLABE_TOKEN_DIR", str(loose))
    refused = check_token_directory()
    assert refused.status == "missing"
    assert str(loose) in refused.detail
    assert "chmod 700" in refused.detail
    assert "unset ANTARES_TOKEN_DIR" in refused.detail
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(directory))
    monkeypatch.setenv("ASTROLABE_TOKEN_DIR", str(tmp_path / "other-tokens"))
    mismatched = check_token_directory()
    assert mismatched.status == "missing"
    assert str(directory) in mismatched.detail
    assert str(tmp_path / "other-tokens") in mismatched.detail


def test_unset_xdg_runtime_dir_does_not_create_run_user(monkeypatch) -> None:
    monkeypatch.setattr("astrolabe.inference_socket.sys.platform", "linux")
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    for name in (
        "ANTARES_SOCKET",
        "ASTROLABE_INFERENCE_SOCKET",
        "ANTARES_TOKEN_DIR",
        "ASTROLABE_TOKEN_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    base = Path(f"/run/user/{os.getuid()}")
    real_is_dir = Path.is_dir
    real_exists = Path.exists
    real_mkdir = Path.mkdir
    created: list[Path] = []

    def is_dir(self: Path) -> bool:
        if self == base:
            return False
        return real_is_dir(self)

    def exists(self: Path) -> bool:
        if self == base or base in self.parents:
            return False
        return real_exists(self)

    def mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == base or base in self.parents:
            created.append(self)
            raise AssertionError(f"tried to create {self}")
        real_mkdir(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_dir", is_dir)
    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    with pytest.raises(SocketDirectoryError) as caught:
        ensure_private_socket_dir(default_socket_directory() / "inference.sock")
    message = str(caught.value)
    assert str(base) in message
    assert "XDG_RUNTIME_DIR" in message
    assert "ANTARES_SOCKET" in message
    assert "ASTROLABE_INFERENCE_SOCKET" in message
    assert "ANTARES_TOKEN_DIR" in message
    assert "ASTROLABE_TOKEN_DIR" in message
    with pytest.raises(SocketDirectoryError, match="XDG_RUNTIME_DIR"):
        ensure_private_token_dir()
    assert created == []


def test_linux_runtime_dir_is_per_user_when_xdg_is_unset(monkeypatch) -> None:
    monkeypatch.setattr("astrolabe.inference_socket.sys.platform", "linux")
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    socket_dir = default_socket_directory()
    token_dir = default_token_directory()
    assert socket_dir == Path(f"/run/user/{os.getuid()}") / "astrolabe"
    assert token_dir == Path(f"/run/user/{os.getuid()}") / "astrolabe-tokens"
    assert not str(socket_dir).startswith("/tmp")
    assert not str(token_dir).startswith("/tmp")
    assert socket_dir not in token_dir.parents
    assert token_dir not in socket_dir.parents


def test_server_replaces_only_an_owned_socket() -> None:
    directory = Path(tempfile.mkdtemp(prefix="astrolabe-own-", dir="/tmp"))
    os.chmod(directory, 0o700)
    path = directory / "inference.sock"
    try:
        path.write_text("not-a-socket", encoding="utf-8")
        with pytest.raises(SocketDirectoryError, match="not a socket owned"):
            replace_existing_socket(path)
        assert path.read_text(encoding="utf-8") == "not-a-socket"
        path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        sock.close()
        replace_existing_socket(path)
        assert not path.exists()
    finally:
        if path.exists():
            path.unlink()
        directory.rmdir()


def test_long_socket_path_exceeds_the_sun_path_limit(monkeypatch) -> None:
    limit = sun_path_limit()
    long_path = "/" + ("a" * limit)
    monkeypatch.setenv("ANTARES_SOCKET", long_path)
    monkeypatch.delenv("ASTROLABE_INFERENCE_SOCKET", raising=False)
    with pytest.raises(SocketDirectoryError, match="sun_path limit") as caught:
        configured_inference_socket()
    message = str(caught.value)
    assert long_path in message
    assert str(limit) in message


def test_token_and_socket_inside_engagements_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.ui import _environment_page

    engagements = tmp_path / "engagements"
    engagements.mkdir()
    monkeypatch.setenv("ASTROLABE_ENGAGEMENTS_DIR", str(engagements))
    token_dir = engagements / "cli-vs-harness" / "tokens"
    token_dir.mkdir(parents=True)
    os.chmod(token_dir, 0o700)
    alias = tmp_path / "token-alias"
    alias.symlink_to(token_dir)
    socket_dir = engagements / "cli-vs-harness" / "socket"
    socket_dir.mkdir()
    monkeypatch.delenv("ASTROLABE_TOKEN_DIR", raising=False)
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(alias))
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_dir / "inference.sock"))
    token_default = default_token_directory()
    socket_default = default_socket_directory() / "inference.sock"
    with pytest.raises(SocketDirectoryError) as token_error:
        configured_token_directory()
    token_message = str(token_error.value)
    assert str(token_dir.resolve()) in token_message
    assert str(engagements.resolve()) in token_message
    assert str(token_default) in token_message
    with pytest.raises(SocketDirectoryError) as socket_error:
        configured_inference_socket()
    socket_message = str(socket_error.value)
    assert str(socket_dir.resolve()) in socket_message
    assert str(engagements.resolve()) in socket_message
    assert str(socket_default) in socket_message
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(engagements))
    with pytest.raises(SocketDirectoryError, match="engagements directory"):
        configured_inference_socket()
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_dir / "inference.sock"))
    token_check = check_token_directory()
    socket_check = check_inference()
    assert token_check.status == "missing"
    assert socket_check.status == "missing"
    assert str(token_default) in token_check.detail
    assert str(socket_default) in socket_check.detail
    page = _environment_page(engagements, [token_check, socket_check])
    assert page.count(">missing</span>") == 2
    assert "Token directory" in page
    assert "Inference socket" in page
    outside = tmp_path / "tokens"
    outside.mkdir()
    os.chmod(outside, 0o700)
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(outside))
    assert configured_token_directory() == outside
    assert check_token_directory().status == "ok"
    escaped = engagements / "nested" / ".." / ".." / "outside-tokens"
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(escaped))
    assert configured_token_directory() == escaped


def test_a_slow_check_is_non_ok_within_the_timeout() -> None:
    def slow() -> Check:
        time.sleep(CHECK_TIMEOUT + 3)
        return Check("Docker daemon", "ok", "late")

    started = time.perf_counter()
    result = execute_checks([("Docker daemon", slow)])
    elapsed = time.perf_counter() - started
    assert elapsed < CHECK_TIMEOUT + 1
    assert result[0].status != "ok"


def test_checks_do_not_open_a_non_loopback_connection(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    monkeypatch.delenv("ASTROLABE_INFERENCE_SOCKET", raising=False)
    original = socket.socket.connect

    def connect(self, address):  # type: ignore[no-untyped-def]
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0]
            if host not in {"127.0.0.1", "::1"}:
                raise AssertionError(address)
        return original(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    run_checks(tmp_path / "engagements", force=True)


def test_health_is_ok_only_for_http_200_and_status_ok() -> None:
    ok = b'{"status":"ok"}'
    down = b'{"status":"down"}'
    assert health_ok(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(ok)).encode() + b"\r\n\r\n" + ok)
    assert not health_ok(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(down)).encode() + b"\r\n\r\n" + down)
    assert not health_ok(b"HTTP/1.1 503 Unavailable\r\nContent-Length: " + str(len(ok)).encode() + b"\r\n\r\n" + ok)


def test_path_check_uses_access_and_refuses_an_audit_inside_engagements(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    monkeypatch.setenv("ASTROLABE_AUDIT_LOG", str(root / "audit.jsonl"))
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    result = check_paths(root)
    after = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert result.status == "missing"
    assert "inside the engagements directory" in result.detail
    assert before == after
