"""Live trace tailing, command classes, and the inference activity counts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tarfile
import threading
import time
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.activity import (
    ActivityTailer,
    activity_path,
    command_classes,
    format_last_action,
    model_server_line,
    progress_detail,
)
from astrolabe.engagement import attest, create_engagement
from astrolabe.intake import intake_local
from astrolabe.investigate import start_investigation
from astrolabe.purge import close_engagement, export_engagement
from astrolabe.runner import cancel_event, run_container
from astrolabe.ui import App, _write_queue
from tests.secret_fixtures import aws_example_key

_SERVER = Path(__file__).resolve().parents[1] / "services" / "antares-server"
_SPEC = importlib.util.spec_from_file_location(
    "antares_generation_activity",
    _SERVER / "antares_server" / "activity.py",
)
assert _SPEC is not None and _SPEC.loader is not None
_GENERATION = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GENERATION)
GenerationActivity = _GENERATION.GenerationActivity
activity_response = _GENERATION.activity_response


def test_command_segments_classify_searches_reads_and_other() -> None:
    assert command_classes("cd /tmp && rg foo | head") == ["other", "search", "read"]
    assert command_classes("cat file | nl") == ["read", "read"]
    assert command_classes("git grep token") == ["search"]
    assert command_classes("find . -name app.py") == ["search"]
    assert command_classes("grep -n pay app.py") == ["search"]
    assert command_classes("sed -n 1p file") == ["read"]
    assert command_classes("sed 1p file") == ["other"]
    assert command_classes("ls") == ["other"]
    assert command_classes("pwd") == ["other"]
    assert command_classes("ls && pwd") == ["other", "other"]
    assert "read" not in command_classes("ls && pwd")


def test_ls_and_pwd_are_not_counted_as_reads(tmp_path: Path) -> None:
    directory = tmp_path / "engagement"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    tailer = ActivityTailer(directory)
    _write_trace(
        traces / "run.investigation.jsonl",
        [
            _tool("ls"),
            _tool("pwd"),
            _tool("ls && pwd"),
        ],
    )
    tailer.drain()
    assert tailer.counters["reads"] == 0
    assert tailer.counters["other"] == 4
    assert tailer.counters["searches"] == 0


def test_older_trace_in_the_directory_is_ignored(tmp_path: Path) -> None:
    directory = tmp_path / "engagement"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    _write_trace(traces / "old.investigation.jsonl", [_tool("rg old-query")])
    tailer = ActivityTailer(directory)
    tailer.start()
    try:
        _write_trace(traces / "new.investigation.jsonl", [_tool("cat app.py")])
        _wait(lambda: tailer.counters["reads"] == 1)
        assert tailer.counters["searches"] == 0
        assert tailer.phase == "investigating"
    finally:
        tailer.finish(exit_code=0, cancelled=False)


def test_partial_final_line_is_not_counted_until_complete(tmp_path: Path) -> None:
    directory = tmp_path / "engagement"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    path = traces / "run.investigation.jsonl"
    event = _tool("rg pending")
    path.write_bytes(json.dumps(event).encode("utf-8"))
    tailer = ActivityTailer(directory)
    tailer.drain()
    assert tailer.counters["searches"] == 0
    with path.open("ab") as handle:
        handle.write(b"\n")
    tailer.drain()
    assert tailer.counters["searches"] == 1


def test_tailer_thread_stops_on_cancel(tmp_path: Path) -> None:
    root = _engagement(tmp_path)
    directory = root / "acme-2026"
    event = threading.Event()
    token = cancel_event.set(event)

    def runner(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        assert any(thread.name == "astrolabe-activity" and thread.is_alive() for thread in threading.enumerate())
        event.set()
        return CompletedProcess(command, 1, "", "cancelled")

    try:
        investigation = start_investigation(
            root,
            "acme-2026",
            cwe="CWE-89",
            actor="Ada",
            exploratory=True,
            runner=runner,
        )
    finally:
        cancel_event.reset(token)
    activity = investigation["runs"][-1]["activity"]
    assert isinstance(activity, dict)
    assert activity["exit_status"] == "cancelled"
    assert not activity_path(directory).exists()
    assert not any(thread.name == "astrolabe-activity" and thread.is_alive() for thread in threading.enumerate())


def test_summary_has_trace_sha256_and_no_command_text(tmp_path: Path) -> None:
    root = _engagement(tmp_path)
    marker = "fixture-command-marker"
    result_body = "fixture-result-marker"

    def runner(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        traces = engagement / "antares-data" / "traces"
        traces.mkdir(parents=True, exist_ok=True)
        path = traces / "run.investigation.jsonl"
        _write_trace(
            path,
            [
                _tool(f"cd /tmp && rg {marker} | head"),
                {
                    "phase": "tool_blocked",
                    "timestamp": 15,
                    "payload": {"tool_name": "terminal", "reason": "Skipped duplicate tool call: terminal"},
                },
                {
                    "phase": "tool_result",
                    "timestamp": 20,
                    "payload": {"tool_name": "terminal", "result_summary": result_body},
                },
                {
                    "phase": "message",
                    "timestamp": 30,
                    "payload": {"role": "assistant", "content": "model-said-" + marker},
                },
                {"phase": "final_submission", "timestamp": 40, "payload": {"tool_name": "submit_vulnerable_files"}},
            ],
        )
        time.sleep(0.3)
        return CompletedProcess(command, 0)

    investigation = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=runner,
    )
    directory = root / "acme-2026"
    activity = investigation["runs"][-1]["activity"]
    assert isinstance(activity, dict)
    trace_path = directory / "antares-data" / "traces" / "run.investigation.jsonl"
    digest = hashlib.sha256(trace_path.read_bytes()).hexdigest()
    assert activity["trace"]["sha256"] == digest
    assert activity["trace"]["name"] == "run.investigation.jsonl"
    assert activity["trace"]["lines"] == 5
    assert activity["loop_control"]["duplicate"] == 1
    assert activity["counters"]["searches"] == 1
    assert activity["counters"]["reads"] == 1
    assert activity["counters"]["other"] == 1
    assert activity["counters"]["model_turns"] == 1
    assert activity["counters"]["submissions"] == 1
    assert activity["exit_status"] == "completed"
    stored = json.dumps(activity)
    assert marker not in stored
    assert result_body not in stored
    assert "model-said" not in stored
    assert "Skipped duplicate" not in stored
    assert not activity_path(directory).exists()
    assert "antares-data" not in activity_path(directory).parts
    assert "snapshot" not in activity_path(directory).parts


def test_progress_contains_no_tool_result_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prompt = "hidden-prompt-text"
    output = "hidden-output-text"
    monkeypatch.setattr(
        "astrolabe.ui.fetch_generation",
        lambda: {"in_flight": True, "tokens_generated": 4, "prompt": prompt, "output": output},
    )
    root = _engagement(tmp_path)
    directory = root / "acme-2026"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    result_body = "fixture-tool-result-body"
    message_body = "fixture-message-body"
    tailer = ActivityTailer(directory)
    tailer.start()
    try:
        _write_trace(
            traces / "run.investigation.jsonl",
            [
                {
                    "phase": "tool_result",
                    "payload": {"tool_name": "read_file", "result_summary": result_body},
                },
                {"phase": "message", "payload": {"role": "assistant", "content": message_body}},
                {"phase": "message", "payload": {"role": "user", "content": "assistant mentioned only in the body"}},
            ],
        )
        _wait(lambda: tailer.trace_lines >= 3)
        assert tailer.counters["model_turns"] == 1
        live = json.dumps(json.loads(activity_path(directory).read_text(encoding="utf-8")))
        assert result_body not in live
        assert message_body not in live
        _write_queue(
            directory,
            [{"id": "q1", "mode": "exploratory", "cwe": "CWE-89", "source": "search", "status": "running"}],
        )
        app = App(root)
        app._running.add("acme-2026")
        page = app.engagement_page("acme-2026")
        progress = page.split('id="progress"', 1)[1].split("</div>", 1)[0]
        assert result_body not in progress
        assert message_body not in progress
        assert prompt not in progress
        assert output not in progress
        assert "Model server: generating 4 tokens" in progress
        assert "Waiting for model" in progress
        assert "Model turns 1." in progress
    finally:
        tailer.finish(exit_code=0, cancelled=False)


def test_stall_message_includes_the_current_detail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASTROLABE_ACTIVITY_STALL_SECONDS", "10")
    root = _engagement(tmp_path)
    directory = root / "acme-2026"
    now = time.time()
    activity_path(directory).write_text(
        json.dumps(
            {
                "phase": "investigating",
                "detail": "Waiting for model",
                "started_at": now - 100,
                "last_event_at": now - 30,
                "trace_timestamp": 111.0,
                "counters": {},
                "loop_control": {},
            }
        ),
        encoding="utf-8",
    )
    detail, fresh = progress_detail(json.loads(activity_path(directory).read_text(encoding="utf-8")), now)
    assert fresh is False
    assert detail.startswith("No activity for ")
    assert detail.endswith("Waiting for model")
    _write_queue(
        directory,
        [{"id": "q1", "mode": "exploratory", "cwe": "CWE-89", "source": "search", "status": "running"}],
    )
    app = App(root)
    app._running.add("acme-2026")
    page = app.engagement_page("acme-2026")
    progress = page.split('id="progress"', 1)[1].split("</div>", 1)[0]
    assert "No activity for" in progress
    assert "Waiting for model" in progress
    assert "run-mark" not in progress


def test_every_run_container_is_named(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> CompletedProcess[str]:
        calls.append(list(args))
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setenv("ANTARES_TOKEN_DIR", str(tmp_path / "tokens"))
    monkeypatch.setenv("ASTROLABE_TOKEN_DIR", str(tmp_path / "tokens"))
    monkeypatch.setattr("astrolabe.runner.subprocess.run", fake_run)
    engagement = tmp_path / "engagement"
    (engagement / "snapshot").mkdir(parents=True)
    run_container(engagement, ["antares", "query", "/workspace/repo"], needs_inference=False)
    docker = [args for args in calls if args[:2] == ["docker", "run"]]
    assert docker
    name = docker[0][docker[0].index("--name") + 1]
    assert len(name) == len("astrolabe-") + 12
    assert name.startswith("astrolabe-")
    assert name.removeprefix("astrolabe-").isalnum()


def test_activity_route_returns_counts_only() -> None:
    prompt = "hidden-prompt-text"
    output = "hidden-output-text"
    meter = GenerationActivity()
    meter.begin()
    meter.token()
    meter.token()
    current = meter.snapshot()
    assert current["in_flight"] is True
    assert current["tokens_generated"] == 2
    assert isinstance(current["last_token_at"], str)
    assert prompt not in json.dumps(current)
    meter.end()
    idle = meter.snapshot()
    assert idle["in_flight"] is False
    assert idle["tokens_generated"] == 0
    assert idle["last_token_at"] == current["last_token_at"]

    class Stub:
        def activity_snapshot(self) -> dict[str, object]:
            return {**current, "prompt": prompt, "output": output}

    view = activity_response(Stub())
    assert set(view) == {"in_flight", "tokens_generated", "last_token_at"}
    encoded = json.dumps(view)
    assert prompt not in encoded
    assert output not in encoded
    assert model_server_line("Waiting for model", view) == "Model server: generating 2 tokens"
    assert model_server_line("Running tool: terminal", view) == ""
    assert prompt not in model_server_line(
        "Waiting for model",
        {"in_flight": True, "tokens_generated": 2, "prompt": prompt},
    )
    source = (_SERVER / "antares_server" / "main.py").read_text(encoding="utf-8")
    route = source.split("def activity", 1)[1].split("def _require_run_token", 1)[0]
    assert "_require_run_token" not in route
    assert "prompt" not in route


def test_progress_last_action_is_truncated_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = aws_example_key()
    result_body = "fixture-tool-result-body"
    message_body = "fixture-message-body"
    command = f"rg {key} " + ("word " * 40) + "ENDMARKER"
    root = _engagement(tmp_path)
    directory = root / "acme-2026"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    tailer = ActivityTailer(directory)
    tailer.start()
    try:
        _write_trace(
            traces / "run.investigation.jsonl",
            [
                _tool(command),
                {
                    "phase": "tool_result",
                    "payload": {"tool_name": "terminal", "result_summary": result_body},
                },
                {"phase": "message", "payload": {"role": "assistant", "content": message_body}},
            ],
        )
        _wait(lambda: tailer.detail == "Waiting for model" and bool(tailer.last_action))
        action = tailer.last_action
        assert action.startswith("terminal rg ")
        assert "<redacted>" in action
        assert len(action) == 120
        assert key not in action
        assert "ENDMARKER" not in action
        assert result_body not in action
        assert message_body not in action
        live = activity_path(directory).read_text(encoding="utf-8")
        assert result_body not in live
        assert message_body not in live
        assert key not in live
        monkeypatch.setattr(
            "astrolabe.ui.fetch_generation",
            lambda: {"in_flight": True, "tokens_generated": 9, "prompt": key, "output": result_body},
        )
        _write_queue(
            directory,
            [{"id": "q1", "mode": "exploratory", "cwe": "CWE-89", "source": "search", "status": "running"}],
        )
        app = App(root)
        app._running.add("acme-2026")
        page = app.engagement_page("acme-2026")
        progress = page.split('id="progress"', 1)[1].split("</div>", 1)[0]
        assert "ENDMARKER" not in progress
        assert result_body not in progress
        assert message_body not in progress
        assert key not in progress
        assert "redacted" in progress
        assert "terminal rg" in progress
        assert "Model server: generating 9 tokens" in progress
    finally:
        tailer.finish(exit_code=0, cancelled=False)


def test_counters_and_last_action_follow_a_fixture_stream(tmp_path: Path) -> None:
    directory = tmp_path / "engagement"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    result_body = "fixture-tool-result-body"
    message_body = "fixture-message-body"
    tailer = ActivityTailer(directory)
    _write_trace(
        traces / "run.investigation.jsonl",
        [
            _tool("rg payment"),
            {
                "phase": "tool_result",
                "payload": {"tool_name": "terminal", "result_summary": result_body},
            },
            {
                "phase": "tool_call",
                "timestamp": 2,
                "payload": {"tool_name": "read_file", "arguments": {"path": "app.py"}},
            },
            {
                "phase": "tool_call",
                "timestamp": 3,
                "payload": {"tool_name": "terminal", "arguments": {"query": "token lookup"}},
            },
            {
                "phase": "tool_blocked",
                "payload": {"reason": "Skipped duplicate tool call: terminal"},
            },
            {
                "phase": "tool_blocked",
                "payload": {"reason": "blocked sensitive file"},
            },
            {
                "phase": "tool_blocked",
                "payload": {"reason": "Terminal call budget exhausted (15/15)"},
            },
            {"phase": "message", "payload": {"role": "assistant", "content": message_body}},
            {"phase": "final_submission", "payload": {"tool_name": "submit_vulnerable_files"}},
        ],
    )
    tailer.drain()
    assert tailer.counters == {
        "model_turns": 1,
        "submissions": 1,
        "searches": 1,
        "reads": 1,
        "other": 0,
    }
    assert tailer.loop_control == {"duplicate": 1, "safety": 1, "budget": 1}
    assert tailer.last_action == "terminal token lookup"
    assert format_last_action("read_file", {"path": "app.py"}) == "read_file app.py"
    assert result_body not in tailer.last_action
    assert message_body not in json.dumps(
        {
            "last_action": tailer.last_action,
            "detail": tailer.detail,
            "counters": tailer.counters,
        }
    )
    assert tailer.phase == "submitting"
    assert tailer.detail == "Blocked: budget"


def test_stalled_fixture_shows_the_stall_message_and_does_not_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ACTIVITY_STALL_SECONDS", "10")
    root = _engagement(tmp_path)
    directory = root / "acme-2026"
    now = time.time()
    activity_path(directory).write_text(
        json.dumps(
            {
                "phase": "investigating",
                "detail": "Waiting for model",
                "started_at": now - 5,
                "last_event_at": now - 30,
                "counters": {},
                "loop_control": {},
                "last_action": "terminal rg app.py",
            }
        ),
        encoding="utf-8",
    )
    _write_queue(
        directory,
        [{"id": "q1", "mode": "exploratory", "cwe": "CWE-89", "source": "search", "status": "running"}],
    )
    app = App(root)
    app._running.add("acme-2026")
    page = app.engagement_page("acme-2026")
    progress = page.split('id="progress"', 1)[1].split("</div>", 1)[0]
    assert "No activity for" in progress
    assert "Waiting for model" in progress
    row = next(part for part in page.split("<tr") if "CWE-89" in part and "running" in part)
    assert "Cancel" in row
    assert "cancelled" not in row
    assert _read_status(directory) == "running"


def test_summary_is_written_on_completion_failure_and_cancel(tmp_path: Path) -> None:
    root = _engagement(tmp_path)
    completed = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=_trace_runner(0),
    )
    failed = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-22",
        actor="Ada",
        exploratory=True,
        runner=_trace_runner(1),
    )
    event = threading.Event()
    event.set()
    token = cancel_event.set(event)
    try:
        cancelled = start_investigation(
            root,
            "acme-2026",
            cwe="CWE-79",
            actor="Ada",
            exploratory=True,
            runner=_trace_runner(1),
        )
    finally:
        cancel_event.reset(token)
    by_status = {
        "completed": completed["runs"][-1]["activity"],
        "failed": failed["runs"][-1]["activity"],
        "cancelled": cancelled["runs"][-1]["activity"],
    }
    for status, activity in by_status.items():
        assert isinstance(activity, dict)
        _assert_summary_fields(activity)
        assert activity["exit_status"] == status
        assert activity["phases"][status]
        assert activity["trace"]["sha256"]
        assert "last_action" not in activity
    app = App(root)
    page = app.engagement_page("acme-2026")
    assert page.count('<details class="activity-summary">') == 3
    assert 'activity-summary" open' not in page
    for status in ("completed", "failed", "cancelled"):
        assert f"Exit status: {status}" in page
    assert "SHA-256" in page
    assert "Model turns" in page
    assert "Duplicate" in page
    assert "Safety" in page
    assert "Budget" in page
    assert "Phases:" in page
    assert "Start " in page
    assert "End " in page


def test_summary_is_in_the_full_package_and_absent_from_report_only(tmp_path: Path) -> None:
    key = aws_example_key()
    root = _engagement(tmp_path)
    directory = root / "acme-2026"

    def runner(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        traces = engagement / "antares-data" / "traces"
        traces.mkdir(parents=True, exist_ok=True)
        _write_trace(traces / "run.investigation.jsonl", [_tool(f"rg {key}")])
        time.sleep(0.2)
        return CompletedProcess(command, 0)

    investigation = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=runner,
    )
    activity = investigation["runs"][-1]["activity"]
    assert isinstance(activity, dict)
    reports = directory / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "assessment.html").write_text("<p>Consultant report.</p>\n", encoding="utf-8")
    close_engagement(root, "acme-2026", actor="Ada")
    full = export_engagement(
        root,
        "acme-2026",
        tmp_path / "full.tar.gz",
        actor="Ada",
        allow_draft=True,
    )
    report = export_engagement(
        root,
        "acme-2026",
        tmp_path / "report.tar.gz",
        actor="Ada",
        allow_draft=True,
        report_only=True,
    )
    with tarfile.open(full) as bundle:
        names = set(bundle.getnames())
        assert "investigations.json" in names
        extracted = bundle.extractfile("investigations.json")
        assert extracted is not None
        stored = extracted.read().decode("utf-8")
    assert activity["trace"]["sha256"] in stored
    assert "exit_status" in stored
    assert key not in stored
    with tarfile.open(full) as bundle:
        raw = b"".join(
            member.read()
            for member in (bundle.extractfile(name) for name in bundle.getnames())
            if member is not None
        )
    assert key.encode() not in raw
    with tarfile.open(report) as bundle:
        assert "investigations.json" not in bundle.getnames()


def test_pulse_only_while_the_last_event_is_inside_the_stall_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ACTIVITY_STALL_SECONDS", "10")
    root = _engagement(tmp_path)
    directory = root / "acme-2026"
    _write_queue(
        directory,
        [{"id": "q1", "mode": "exploratory", "cwe": "CWE-89", "source": "search", "status": "running"}],
    )
    app = App(root)
    app._running.add("acme-2026")
    now = time.time()
    activity_path(directory).write_text(
        json.dumps(
            {
                "detail": "Running tool: terminal",
                "started_at": now - 100,
                "last_event_at": now,
                "counters": {},
                "loop_control": {},
            }
        ),
        encoding="utf-8",
    )
    fresh = app.engagement_page("acme-2026")
    fresh_progress = fresh.split('id="progress"', 1)[1].split("</div>", 1)[0]
    fresh_row = next(part for part in fresh.split("<tr") if "CWE-89" in part)
    assert "run-mark" in fresh_progress
    assert "run-mark" in fresh_row
    assert "No activity for" not in fresh_progress
    activity_path(directory).write_text(
        json.dumps(
            {
                "detail": "Running tool: terminal",
                "started_at": now,
                "last_event_at": now - 30,
                "counters": {},
                "loop_control": {},
            }
        ),
        encoding="utf-8",
    )
    stale = app.engagement_page("acme-2026")
    stale_progress = stale.split('id="progress"', 1)[1].split("</div>", 1)[0]
    stale_row = next(part for part in stale.split("<tr") if "CWE-89" in part)
    assert "run-mark" not in stale_progress
    assert "run-mark" not in stale_row
    assert "No activity for" in stale_progress
    assert "Model server: generating" not in stale_progress


def _engagement(tmp_path: Path) -> Path:
    root = tmp_path / "engagements"
    root.mkdir()
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    attest(root, "acme-2026", actor="Ada", reference="SOW-14", scope="Billing service")
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    intake_local(root, "acme-2026", source)
    return root


def _tool(command: str) -> dict[str, object]:
    return {
        "phase": "tool_call",
        "timestamp": 1,
        "payload": {"tool_name": "terminal", "arguments": {"command": command}},
    }


def _write_trace(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def _trace_runner(code: int):
    def runner(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        traces = engagement / "antares-data" / "traces"
        traces.mkdir(parents=True, exist_ok=True)
        name = f"run-{code}-{command[-1]}.investigation.jsonl"
        _write_trace(traces / name, [{"phase": "ingest", "timestamp": 1, "payload": {}}])
        return CompletedProcess(command, code)

    return runner


def _assert_summary_fields(activity: dict[str, object]) -> None:
    assert activity["start"]
    assert activity["end"]
    phases = activity["phases"]
    assert isinstance(phases, dict) and phases
    counters = activity["counters"]
    assert isinstance(counters, dict)
    for key in ("model_turns", "submissions", "searches", "reads", "other"):
        assert key in counters
    loop = activity["loop_control"]
    assert isinstance(loop, dict)
    for key in ("duplicate", "safety", "budget"):
        assert key in loop
    trace = activity["trace"]
    assert isinstance(trace, dict)
    for key in ("name", "lines", "sha256"):
        assert key in trace


def _read_status(directory: Path) -> str:
    rows = json.loads((directory / "launch-queue.json").read_text(encoding="utf-8"))
    return str(rows[0]["status"])


def _wait(ready) -> None:
    for _ in range(50):
        if ready():
            return
        time.sleep(0.05)
    raise AssertionError("activity tailer did not observe the new trace")
