"""The Darwin socket relay is one port, container, and volume per run."""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

from astrolabe.engagement import EngagementError
from astrolabe.runner import cancel_event, cleanup_orphaned_relays, run_container

_SHORT_DIRS: list[Path] = []


@pytest.fixture(autouse=True)
def _remove_short_dirs():
    yield
    for directory in _SHORT_DIRS:
        shutil.rmtree(directory, ignore_errors=True)
    _SHORT_DIRS.clear()


def test_per_run_relay_and_volume_are_removed_after_cancel(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ASTROLABE_SOCKET_BRIDGE", "1")
    _private_socket(monkeypatch, tmp_path)
    engagement = tmp_path / "engagement"
    (engagement / "snapshot").mkdir(parents=True)
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    event = threading.Event()
    event.set()
    token = cancel_event.set(event)
    try:
        run_container(engagement, ["true"])
        run_container(engagement, ["true"])
    finally:
        cancel_event.reset(token)

    removed = [args[-1] for args in calls if args[:3] == ["docker", "rm", "-f"]]
    volumes = [args[-1] for args in calls if args[:3] == ["docker", "volume", "rm"]]
    started = [
        args[args.index("--name") + 1]
        for args in calls
        if len(args) > 3 and args[:3] == ["docker", "run", "-d"]
    ]
    assert len(started) == 2
    assert started[0] != started[1]
    assert set(removed) == set(started)
    assert {name.removeprefix("astrolabe-relay-") for name in started} == {
        name.removeprefix("astrolabe-sock-") for name in volumes
    }
    targets = [args[-1] for args in calls if args[:3] == ["docker", "run", "-d"]]
    assert all(target.startswith("TCP:host.docker.internal:") for target in targets)


def test_startup_cleans_dead_and_old_unlabeled_relays(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            return _completed("astrolabe-relay-dead\nastrolabe-relay-old\n")
        if args[:3] == ["docker", "volume", "ls"]:
            return _completed("astrolabe-sock-dead\n")
        if args[1:3] == ["inspect", "--format"] or args[1:4] == ["volume", "inspect", "--format"]:
            name = args[-1]
            if name.endswith("dead"):
                return _completed("owner|2000000001|2026-10-10T00:00:00.000000000Z")
            return _completed("<no value>|<no value>|2020-01-01T00:00:00.000000000Z")
        return _completed("")

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    cleanup_orphaned_relays()
    assert ["docker", "rm", "-f", "astrolabe-relay-dead"] in calls
    assert ["docker", "rm", "-f", "astrolabe-relay-old"] in calls
    assert ["docker", "volume", "rm", "astrolabe-sock-dead"] in calls


def test_startup_orphan_cleanup_does_not_match_a_run_container(monkeypatch) -> None:
    run_name = "astrolabe-" + "0123456789ab"
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            filters = [args[index + 1] for index, arg in enumerate(args) if arg == "--filter"]
            assert "name=astrolabe-relay-" in filters
            assert "name=astrolabe-" not in filters
            return _completed(f"astrolabe-relay-dead\n{run_name}\n")
        if args[:3] == ["docker", "volume", "ls"]:
            return _completed("")
        if args[1:3] == ["inspect", "--format"]:
            return _completed("<no value>|<no value>|2020-01-01T00:00:00.000000000Z")
        return _completed("")

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    cleanup_orphaned_relays()
    removed = [args[-1] for args in calls if args[:3] == ["docker", "rm", "-f"]]
    assert "astrolabe-relay-dead" in removed
    assert run_name not in removed


def test_another_owners_live_relay_survives_a_second_startup(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            return _completed("astrolabe-relay-live\n")
        if args[:3] == ["docker", "volume", "ls"]:
            return _completed("astrolabe-sock-live\n")
        if args[1:3] == ["inspect", "--format"] or args[1:4] == ["volume", "inspect", "--format"]:
            return _completed(f"other-owner|{os.getpid()}|2020-01-01T00:00:00.000000000Z")
        return _completed("")

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    cleanup_orphaned_relays()
    assert ["docker", "rm", "-f", "astrolabe-relay-live"] not in calls
    assert ["docker", "volume", "rm", "astrolabe-sock-live"] not in calls


def test_socket_mount_failure_removes_the_relay_and_volume(monkeypatch, tmp_path: Path) -> None:
    calls = _bridge(monkeypatch, tmp_path)

    def boom(_bridge):  # type: ignore[no-untyped-def]
        raise EngagementError("mount failed")

    monkeypatch.setattr("astrolabe.runner._socket_mount", boom)
    engagement = tmp_path / "engagement"
    with pytest.raises(EngagementError, match="mount failed"):
        run_container(engagement, ["true"])
    started = [
        args[args.index("--name") + 1]
        for args in calls
        if len(args) > 3 and args[:3] == ["docker", "run", "-d"]
    ]
    removed = [args[-1] for args in calls if args[:3] == ["docker", "rm", "-f"]]
    volumes = [args[-1] for args in calls if args[:3] == ["docker", "volume", "rm"]]
    created = [args[-1] for args in calls if args[:3] == ["docker", "volume", "create"]]
    assert started
    assert set(removed) == set(started)
    assert set(volumes) == set(created)


def test_plan_starts_no_relay(monkeypatch, tmp_path: Path) -> None:
    calls = _bridge(monkeypatch, tmp_path)
    engagement = tmp_path / "engagement"
    run_container(
        engagement,
        ["antares", "plan", "/workspace/repo", "--format", "json"],
        needs_inference=False,
    )
    assert not any(args[:3] == ["docker", "run", "-d"] for args in calls)
    assert not any(args[:3] == ["docker", "volume", "create"] for args in calls)
    cli = [args for args in calls if args[:2] == ["docker", "run"]]
    assert cli
    assert not any("inference.sock" in arg or arg.startswith("astrolabe-sock-") for arg in cli[0])


def test_plan_leaves_the_running_checks_relay(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    lock = threading.Lock()
    release = threading.Event()
    started = threading.Event()
    cli_runs = {"count": 0}
    _bridge(monkeypatch, tmp_path, calls=calls, lock=lock)

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        with lock:
            calls.append(list(args))
        if args[:2] == ["docker", "run"] and (len(args) < 3 or args[2] != "-d"):
            cli_runs["count"] += 1
            if cli_runs["count"] == 1:
                started.set()
                assert release.wait(timeout=5)
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    engagement = tmp_path / "engagement"

    def check() -> None:
        run_container(engagement, ["antares", "query", "/workspace/repo", "--cwe", "CWE-89"])

    thread = threading.Thread(target=check)
    thread.start()
    assert started.wait(timeout=5)
    run_container(
        engagement,
        ["antares", "plan", "/workspace/repo", "--format", "json"],
        needs_inference=False,
    )
    with lock:
        snapshot = list(calls)
    assert not any(args[:3] == ["docker", "rm", "-f"] for args in snapshot)
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()


def _bridge(
    monkeypatch,
    tmp_path: Path,
    *,
    calls: list[list[str]] | None = None,
    lock: threading.Lock | None = None,
) -> list[list[str]]:
    monkeypatch.setenv("ASTROLABE_SOCKET_BRIDGE", "1")
    _private_socket(monkeypatch, tmp_path)
    engagement = tmp_path / "engagement"
    (engagement / "snapshot").mkdir(parents=True, exist_ok=True)
    recorded = calls if calls is not None else []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        if lock is None:
            recorded.append(list(args))
        else:
            with lock:
                recorded.append(list(args))
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    return recorded


def _private_socket(monkeypatch, tmp_path: Path) -> Path:
    socket_dir = Path(tempfile.mkdtemp(prefix="asl", dir="/tmp"))
    os.chmod(socket_dir, 0o700)
    _SHORT_DIRS.append(socket_dir)
    socket_path = socket_dir / "inference.sock"
    socket_path.write_bytes(b"")
    token_dir = Path(tempfile.mkdtemp(prefix="atk", dir="/tmp"))
    os.chmod(token_dir, 0o700)
    _SHORT_DIRS.append(token_dir)
    monkeypatch.setenv("ASTROLABE_INFERENCE_SOCKET", str(socket_path))
    monkeypatch.delenv("ANTARES_SOCKET", raising=False)
    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(token_dir))
    monkeypatch.delenv("ASTROLABE_TOKEN_DIR", raising=False)
    return socket_path


def _completed(stdout: str):  # type: ignore[no-untyped-def]
    return type("Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()
