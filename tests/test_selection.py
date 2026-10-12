"""Investigation selection stays a list of single-CWE runs."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.advisories import NETWORK_NOTICE
from astrolabe.cwe import base_variant_children
from astrolabe.engagement import create_engagement, load_engagement, save_engagement
from astrolabe.reports import write_assessment
from astrolabe.selection import (
    EXCLUDED_EVIDENCE,
    EXPLORATORY_NOTE,
    INTAKE_BUSY,
    INTAKE_REQUIRED,
    OWASP_GROUP,
    PLAN_EMPTY,
    PLAN_STALE,
    status_estimate_text,
    plan_rows,
    plan_snapshot,
)
from astrolabe.ui import SCAN_GATE, SINGLE_FILE_NOTE, App, _SCRIPT

PLAN = {
    "selected_checks": [
        {
            "cwe_ids": ["CWE-89"],
            "reasons": ["sql query in app.py"],
            "evidence": ["app.py"],
            "repository_evidence_score": 40,
            "worker_group": "A03 Injection",
        },
        {
            "cwe_ids": ["CWE-22"],
            "reasons": ["Member of the current MITRE CWE Top 25"],
            "evidence": [],
            "repository_evidence_score": 0,
            "worker_group": "A01 Broken Access Control",
        },
    ]
}


class Client:
    def __init__(self, server) -> None:
        host, port = server.server_address[:2]
        self.base = f"http://{host}:{port}"

    def open(self, method: str, path: str, fields: dict[str, str] | None = None, pairs=None) -> tuple[int, str]:
        payload = None
        headers: dict[str, str] = {}
        if pairs is not None:
            payload = urllib.parse.urlencode(pairs).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif fields is not None:
            payload = urllib.parse.urlencode(fields).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if method == "POST":
            headers["Origin"] = self.base
        request = urllib.request.Request(self.base + path, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_once(client: Client, method: str, path: str, fields: dict[str, str] | None = None):
    payload = None
    headers: dict[str, str] = {}
    if fields is not None:
        payload = urllib.parse.urlencode(fields).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if method == "POST":
        headers["Origin"] = client.base
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(client.base + path, data=payload, headers=headers, method=method)
    try:
        with opener.open(request) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), exc.headers


def _serve(root: Path, runner):
    app = App(root, runner=runner)
    server = app.serve(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return Client(server), app, server


def _prepare(client: Client, tmp_path: Path, engagement_id: str = "acme-2026") -> None:
    status, _page = client.open(
        "POST",
        "/",
        {
            "id": engagement_id,
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    assert status == 200
    status, _page = client.open(
        "POST",
        f"/e/{engagement_id}/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service"},
    )
    assert status == 200
    source = tmp_path / engagement_id
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    status, _page = client.open("POST", f"/e/{engagement_id}/intake/preview", {"path": str(source)})
    assert status == 200
    status, _page = client.open("POST", f"/e/{engagement_id}/intake/confirm", {})
    assert status == 200


def _cache(tmp_path: Path, advisory_id: str, summary: str, details: str, cwes: list[str]) -> None:
    cache = tmp_path / "advisories"
    cache.mkdir(exist_ok=True)
    (cache / f"{advisory_id}.json").write_text(
        json.dumps({"id": advisory_id, "summary": summary, "details": details, "cwe_ids": cwes}),
        encoding="utf-8",
    )


def _runner(calls: list[list[str]], files: dict[str, str] | None = None):
    files = files or {}

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        calls.append(list(command))
        if len(command) > 1 and command[1] == "plan":
            return CompletedProcess(command, 0, stdout=json.dumps(PLAN))
        cwe = command[command.index("--cwe") + 1]
        report_dir = engagement / "antares-data" / "reports" / f"run-{len(calls)}"
        report_dir.mkdir(parents=True)
        file_path = files.get(cwe, "app.py")
        report = {"findings": [{"file_path": file_path, "submission_rank": 1, "cwe_ids": [cwe]}]}
        (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        return CompletedProcess(command, 0, stdout="")

    return runner


def test_plan_runs_in_the_offline_container_without_a_model_call(monkeypatch, tmp_path: Path) -> None:
    seen: list[tuple[list[str], bool, bool]] = []

    def fake(
        engagement: Path,
        command: list[str],
        stream: bool = True,
        needs_inference: bool = True,
    ) -> CompletedProcess[str]:
        seen.append((list(command), stream, needs_inference))
        return CompletedProcess(command, 0, stdout='{"selected_checks": []}')

    monkeypatch.setattr("astrolabe.investigate.run_container", fake)
    (tmp_path / "snapshot").mkdir()
    plan_snapshot(tmp_path)
    command, stream, needs_inference = seen[0]
    assert command[:4] == ["antares", "plan", "/workspace/repo", "--format"]
    assert command[1] == "plan"
    assert "query" not in command
    assert "completions" not in " ".join(command)
    assert stream is False
    assert needs_inference is False
    plan_snapshot(tmp_path, "owasp")
    preset, _stream, preset_inference = seen[1]
    assert preset_inference is False
    assert preset[1] == "plan"
    assert "owasp" in preset
    assert "query" not in preset


def test_advisory_preselects_listed_cwes_and_requires_a_choice_when_none_are_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "advisories"))
    _cache(tmp_path, "CVE-2024-9001", "Summary line", "Detail line", ["CWE-89", "CWE-79"])
    _cache(tmp_path, "CVE-2024-9002", "Empty advisory", "No weakness id", [])
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/advisory", {"ids": "CVE-2024-9001"})
        assert status == 200
        assert "Summary line\n\nDetail line" in page
        assert 'value="CVE-2024-9001|CWE-89" checked' in page
        assert 'value="CVE-2024-9001|CWE-79" checked' in page
        status, page = client.open("POST", "/e/acme-2026/select/advisory", {"ids": "CVE-2024-9002"})
        assert status == 200
        assert "This advisory lists no CWE. Choose one from the catalog." in page
        assert " checked>" not in page
        status, page = client.open("POST", "/e/acme-2026/review", {"actor": "Ada"})
        assert status == 400
        assert "Choose at least one CWE" in page
        assert calls == []
    finally:
        server.shutdown()


def test_cached_advisory_preselects_cwe_327(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "advisories"))
    _cache(tmp_path, "CVE-2022-29217", "Fixture summary", "Fixture details", ["CWE-327"])
    client, _app, server = _serve(tmp_path / "engagements", _runner([]))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/advisory", {"ids": "CVE-2022-29217"})
        assert status == 200
        assert 'value="CVE-2022-29217|CWE-327" checked' in page
        children = base_variant_children("CWE-327")
        assert children
        for child in children:
            assert f'value="CVE-2022-29217|{child}"' in page
            assert f'value="CVE-2022-29217|{child}" checked' not in page
    finally:
        server.shutdown()


def test_class_cwe_shows_the_note_and_does_not_replace_itself_with_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "advisories"))
    _cache(tmp_path, "CVE-2024-9003", "Broad class", "Input validation", ["CWE-20"])
    client, _app, server = _serve(tmp_path / "engagements", _runner([]))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/advisory", {"ids": "CVE-2024-9003"})
        assert status == 200
        assert "Broad weakness classes give the model less to search for." in page
        assert 'value="CVE-2024-9003|CWE-20" checked' in page
        child = base_variant_children("CWE-20")[0]
        assert f'value="CVE-2024-9003|{child}"' in page
        assert f'value="CVE-2024-9003|{child}" checked' not in page
    finally:
        server.shutdown()


def test_missing_advisory_offers_sync_and_does_not_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "advisories"))
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/advisory", {"ids": "CVE-2024-9004"})
        assert status == 200
        assert "CVE-2024-9004 is not in the local cache" in page
        assert NETWORK_NOTICE in page
        assert "Review launch" not in page
        assert 'name="actor"' not in page
        assert "<label>Actor" not in page
        assert calls == []
    finally:
        server.shutdown()


def test_preset_expands_to_concrete_cwes_and_leaves_evidence_free_cwes_unchecked(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert calls[0] == ["antares", "plan", "/workspace/repo", "--format", "json"]
        assert 'value="recommended|CWE-89" checked' in page
        assert 'value="recommended|CWE-22" checked' not in page
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "top25"})
        assert status == 200
        assert calls[1][1] == "plan"
        assert "--scope" in calls[1] and "top25" in calls[1]
        assert "query" not in calls[1]
        assert "completions" not in " ".join(calls[1])
        assert 'value="top25|CWE-89" checked' in page
        assert 'value="top25|CWE-22"' in page
        assert 'value="top25|CWE-22" checked' not in page
        assert "sql query in app.py" in page
        assert "Member of the current MITRE CWE Top 25" in page
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "owasp"})
        assert f"<h2>{OWASP_GROUP}</h2>" in page
        assert "<h2>A03 Injection</h2>" not in page
        assert "<h2>A01 Broken Access Control</h2>" not in page
        assert "<h2>Software Development</h2>" not in page
        assert "<h2>Research Concepts</h2>" not in page
        assert 'value="owasp|CWE-89" checked' not in page
        assert 'value="owasp|CWE-22" checked' not in page
        status, page = client.open(
            "POST",
            "/e/acme-2026/review",
            {"choice": "top25|CWE-89", "actor": "Ada"},
        )
        assert status == 200
        assert "CWE-89" in page
        assert "top25" in page
        snapshot = str(load_engagement(tmp_path / "engagements", "acme-2026")["snapshot_sha256"])
        assert snapshot[:12] in page
        assert "Each investigation returns candidate files for you to review." in page
        assert len([call for call in calls if call[1] == "query"]) == 0
    finally:
        server.shutdown()


def test_more_than_ten_selections_require_confirmation(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        choices = [("choice", f"search|CWE-{index}") for index in range(1, 12)]
        status, page = client.open("POST", "/e/acme-2026/review", pairs=[*choices, ("actor", "Ada")])
        assert status == 200
        assert "11 investigations need confirmation" in page
        assert "Approximate total time" in page
        items = [
            ("item", json.dumps({"source": "search", "cwe": f"CWE-{index}", "advisory_text": "", "title": ""}))
            for index in range(1, 12)
        ]
        status, page = client.open("POST", "/e/acme-2026/launch", pairs=[*items, ("actor", "Ada")])
        assert status == 400
        assert "11 investigations need confirmation" in page
        assert '<p class="callout"' in page
        assert 'value="search|CWE-1" checked' in page
        assert 'value="search|CWE-11" checked' in page
        assert calls == []
        status, _page = client.open(
            "POST",
            "/e/acme-2026/launch",
            pairs=[*items, ("actor", "Ada"), ("confirm_over_cap", "on")],
        )
        assert status == 200
        queries = [call for call in calls if call[1] == "query"]
        assert len(queries) == 11
        assert all(call.count("--cwe") == 1 for call in queries)
    finally:
        server.shutdown()


def test_each_cwe_is_its_own_investigation_and_results_stay_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "advisories"))
    _cache(tmp_path, "CVE-2024-9001", "Summary line", "Detail line", ["CWE-89", "CWE-79"])
    calls: list[list[str]] = []
    client, _app, server = _serve(
        tmp_path / "engagements",
        _runner(calls, {"CWE-89": "db.py", "CWE-79": "view.py"}),
    )
    try:
        _prepare(client, tmp_path)
        items = [
            ("item", json.dumps({"source": "CVE-2024-9001", "cwe": "CWE-89", "advisory_text": "", "title": ""})),
            ("item", json.dumps({"source": "CVE-2024-9001", "cwe": "CWE-79", "advisory_text": "", "title": ""})),
        ]
        status, page = client.open("POST", "/e/acme-2026/launch", pairs=[*items, ("actor", "Ada")])
        assert status == 200, page
        queries = [call for call in calls if len(call) > 1 and call[1] == "query"]
        assert len(queries) == 2
        assert [call[call.index("--cwe") + 1] for call in queries] == ["CWE-89", "CWE-79"]
        assert all(call.count("--cwe") == 1 for call in queries)
        directory = tmp_path / "engagements" / "acme-2026"
        investigations = json.loads((directory / "investigations.json").read_text(encoding="utf-8"))
        assert len(investigations) == 2
        snapshot = str(load_engagement(tmp_path / "engagements", "acme-2026")["snapshot_sha256"])
        assert {item["cwe"] for item in investigations} == {"CWE-89", "CWE-79"}
        assert {item["selection_source"] for item in investigations} == {"CVE-2024-9001"}
        assert {item["snapshot_sha256"] for item in investigations} == {snapshot}
        coverage = json.loads((directory / "coverage.json").read_text(encoding="utf-8"))
        assert {item["selection_source"] for item in coverage["cwes"]} == {"CVE-2024-9001"}
        assert {item["snapshot_sha256"] for item in coverage["cwes"]} == {snapshot}
        status, page = client.open("GET", "/e/acme-2026")
        review = page.split('id="review"', 1)[1].split('id="reports"', 1)[0]
        assert review.count('class="investigation-results"') == 2
        first, second = review.split('class="investigation-results"', 1)[1].split('class="investigation-results"', 1)
        assert "db.py" in first
        assert "view.py" not in first
        assert "view.py" in second
        assert "finding" not in review.lower()
        assert "pending review" in review
        assert 'id="coverage"' in review
        assert "<h3>Advisory</h3>" in review
        assert "<h3>Exploratory</h3>" in review
        assessment = write_assessment(tmp_path / "engagements", "acme-2026", actor="Ada")
        report = assessment["html"].read_text(encoding="utf-8")
        assert "CVE-2024-9001" in report
        assert snapshot in report
        assert "Selection source" in report
    finally:
        server.shutdown()


def test_launch_is_refused_during_clone_or_reintake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    release = threading.Event()
    client, app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        app._intake_busy.add("acme-2026")
        status, page = client.open(
            "POST",
            "/e/acme-2026/launch",
            {"item": json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""}), "actor": "Ada"},
        )
        assert status == 400
        assert INTAKE_BUSY in page
        assert '<p class="callout"' in page
        assert 'value="search|CWE-89" checked' in page
        assert calls == []
        app._intake_busy.discard("acme-2026")
        started = threading.Event()

        def slow_reintake(*_args, **_kwargs):
            started.set()
            assert release.wait(timeout=5)
            return load_engagement(tmp_path / "engagements", "acme-2026")

        monkeypatch.setattr("astrolabe.ui.reintake", slow_reintake)
        worker = threading.Thread(
            target=lambda: client.open("POST", "/e/acme-2026/intake/again", {"actor": "Ada"}),
            daemon=True,
        )
        worker.start()
        assert started.wait(timeout=5)
        status, page = client.open(
            "POST",
            "/e/acme-2026/launch",
            {"item": json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""}), "actor": "Ada"},
        )
        assert status == 400
        assert INTAKE_BUSY in page
        assert calls == []
        release.set()
        worker.join(timeout=5)
    finally:
        release.set()
        server.shutdown()


def test_second_launch_is_refused_while_one_is_queuing(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    calls: list[list[str]] = []

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        calls.append(list(command))
        entered.set()
        assert release.wait(timeout=5)
        return CompletedProcess(command, 0, stdout="")

    client, _app, server = _serve(tmp_path / "engagements", runner)
    try:
        _prepare(client, tmp_path)
        item = json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})
        status, page = client.open("POST", "/e/acme-2026/launch", {"item": item, "actor": "Ada"})
        assert status == 200
        assert entered.wait(timeout=5)
        status, page = client.open("POST", "/e/acme-2026/launch", {"item": item, "actor": "Ada"})
        assert status == 400
        assert "Another launch is still queuing for this engagement." in page
        assert '<p class="callout"' in page
        assert 'value="search|CWE-89" checked' in page
        assert len(calls) == 1
    finally:
        release.set()
        server.shutdown()


def test_queued_investigation_can_be_cancelled_before_it_runs(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    calls: list[list[str]] = []

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        calls.append(list(command))
        if len(calls) == 1:
            entered.set()
            assert release.wait(timeout=5)
        return CompletedProcess(command, 0, stdout="")

    client, _app, server = _serve(tmp_path / "engagements", runner)
    try:
        _prepare(client, tmp_path)
        items = [
            ("item", json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})),
            ("item", json.dumps({"source": "search", "cwe": "CWE-22", "advisory_text": "", "title": ""})),
        ]
        status, _page = client.open("POST", "/e/acme-2026/launch", pairs=[*items, ("actor", "Ada")])
        assert status == 200
        assert entered.wait(timeout=5)
        queue = json.loads((tmp_path / "engagements" / "acme-2026" / "launch-queue.json").read_text(encoding="utf-8"))
        waiting = next(item for item in queue if item["status"] == "queued")
        status, page = client.open("POST", "/e/acme-2026/cancel", {"queue_id": waiting["id"]})
        assert status == 200
        assert "Investigation cancelled." in page
        release.set()
        for _ in range(40):
            queue = json.loads(
                (tmp_path / "engagements" / "acme-2026" / "launch-queue.json").read_text(encoding="utf-8")
            )
            if all(item["status"] != "running" for item in queue):
                break
            threading.Event().wait(0.05)
        assert [call[call.index("--cwe") + 1] for call in calls if "--cwe" in call] == ["CWE-89"]
        assert next(item["status"] for item in queue if item["cwe"] == "CWE-22") == "cancelled"
    finally:
        release.set()
        server.shutdown()


def test_status_estimate_uses_recorded_runs_then_the_per_check_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert status_estimate_text([]) == "about 120 seconds"
    monkeypatch.setenv("ASTROLABE_ESTIMATE_PER_CHECK", "90")
    assert status_estimate_text([]) == "about 90 seconds"
    investigations = [{"runs": [{"elapsed_seconds": 40}, {"elapsed_seconds": 20}]}]
    assert status_estimate_text(investigations) == "about 30 seconds"


def test_cancelling_the_running_check_offers_restart_and_start(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    calls: list[list[str]] = []

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        calls.append(list(command))
        if len(calls) == 1:
            entered.set()
            assert release.wait(timeout=5)
        return CompletedProcess(command, 0, stdout="")

    client, _app, server = _serve(tmp_path / "engagements", runner)
    try:
        _prepare(client, tmp_path)
        items = [
            ("item", json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})),
            ("item", json.dumps({"source": "search", "cwe": "CWE-22", "advisory_text": "", "title": ""})),
        ]
        status, _page = client.open("POST", "/e/acme-2026/launch", pairs=[*items, ("actor", "Ada")])
        assert status == 200
        assert entered.wait(timeout=5)
        queue_path = tmp_path / "engagements" / "acme-2026" / "launch-queue.json"
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        running = next(item for item in queue if item["status"] == "running")
        waiting = next(item for item in queue if item["status"] == "queued")
        status, page = client.open("POST", "/e/acme-2026/cancel", {"queue_id": running["id"]})
        assert status == 200
        release.set()
        page = ""
        for _ in range(40):
            status, page = client.open("GET", "/e/acme-2026")
            if ">Restart</button>" in page and ">Start</button>" in page:
                break
            threading.Event().wait(0.05)
        assert ">Restart</button>" in page
        assert ">Start</button>" in page
        restarted = page.split(">Restart</button>", 1)[0]
        assert "CWE-89" in restarted
        started = page.split(">Start</button>", 1)[0]
        assert "CWE-22" in started
        assert [call[call.index("--cwe") + 1] for call in calls if "--cwe" in call] == ["CWE-89"]
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
        assert next(item["status"] for item in queue if item["id"] == waiting["id"]) == "queued"
        status, _page = client.open("POST", "/e/acme-2026/start", {"queue_id": waiting["id"]})
        assert status == 200
        for _ in range(40):
            seen = [call[call.index("--cwe") + 1] for call in calls if "--cwe" in call]
            if seen == ["CWE-89", "CWE-22"]:
                break
            threading.Event().wait(0.05)
        assert [call[call.index("--cwe") + 1] for call in calls if "--cwe" in call] == ["CWE-89", "CWE-22"]
    finally:
        release.set()
        server.shutdown()


def test_single_file_exploratory_path_keeps_both_notes(tmp_path: Path) -> None:
    client, _app, server = _serve(tmp_path / "engagements", _runner([]))
    try:
        status, _page = client.open(
            "POST",
            "/",
            {
                "id": "script",
                "customer": "Acme",
                "scope": "One file",
                "start": "2026-10-09",
                "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
            },
        )
        assert status == 200
        client.open(
            "POST",
            "/e/script/attest",
            {"actor": "Ada", "reference": "SOW-14", "scope": "One file"},
        )
        client.open(
            "POST",
            "/e/script/intake/preview",
            {"filename": "pay.py", "script": "print(1)\n"},
        )
        client.open("POST", "/e/script/intake/confirm", {})
        status, page = client.open("POST", "/e/script/select/explore", {})
        assert status == 200
        assert EXPLORATORY_NOTE in page
        assert SINGLE_FILE_NOTE in page
        assert "Exploratory" in page
    finally:
        server.shutdown()


def test_recommended_preselects_at_most_n_and_owasp_is_one_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASTROLABE_PRESELECT_LIMIT", "5")
    checks = []
    for index, score in enumerate((9, 8, 7, 6, 5, 4, 0)):
        checks.append(
            {
                "cwe_ids": [f"CWE-{200 + index}"],
                "reasons": [f"signal in app{index}.py"],
                "evidence": [f"app{index}.py"],
                "repository_evidence_score": score,
                "repository_specific_evidence_score": 1,
                "worker_group": "Software Development",
            }
        )
    rows = plan_rows({"selected_checks": checks})
    selected = [row["cwe"] for row in rows if row["preselect"]]
    assert selected == ["CWE-200", "CWE-201", "CWE-202", "CWE-203", "CWE-204"]
    assert rows[0]["score"] == 9
    top = plan_rows({"selected_checks": checks}, scope="top25")
    assert [row["cwe"] for row in top if row["preselect"]] == selected
    owasp = plan_rows({"selected_checks": checks}, scope="owasp")
    assert all(row["preselect"] is False for row in owasp)
    assert {row["group"] for row in owasp} == {OWASP_GROUP}


def test_preselect_ties_keep_cli_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASTROLABE_PRESELECT_LIMIT", "1")
    rows = plan_rows(
        {
            "selected_checks": [
                {
                    "cwe_ids": ["CWE-22"],
                    "reasons": ["path in first.py"],
                    "evidence": ["first.py"],
                    "repository_evidence_score": 3,
                },
                {
                    "cwe_ids": ["CWE-89"],
                    "reasons": ["query in second.py"],
                    "evidence": ["second.py"],
                    "repository_evidence_score": 3,
                    "repository_category_evidence_score": 3,
                },
            ]
        }
    )
    assert [row["preselect"] for row in rows] == [True, False]


def test_docs_only_evidence_is_not_preselected_or_shown() -> None:
    rows = plan_rows(
        {
            "selected_checks": [
                {
                    "cwe_ids": ["CWE-22"],
                    "reasons": ["config in docs/conf.py"],
                    "evidence": ["docs/conf.py"],
                    "repository_evidence_score": 40,
                }
            ]
        }
    )
    assert rows[0]["preselect"] is False
    assert rows[0]["score"] == 40
    assert rows[0]["evidence"] == EXCLUDED_EVIDENCE
    assert rows[0]["reasons"] == []
    assert rows[0]["evidence_paths"] == []
    assert "docs/conf.py" not in rows[0]["evidence"]


def test_parent_and_child_with_the_same_evidence_collapse_to_the_child() -> None:
    shared = {
        "reasons": ["signature check in jwt/api_jws.py"],
        "evidence": ["jwt/api_jws.py"],
        "repository_evidence_score": 12,
    }
    rows = plan_rows(
        {
            "selected_checks": [
                {"cwe_ids": ["CWE-345"], **shared},
                {"cwe_ids": ["CWE-347"], **shared},
            ]
        }
    )
    assert [row["cwe"] for row in rows] == ["CWE-347"]
    assert rows[0]["related"] == ["CWE-345"]
    assert rows[0]["preselect"] is True


def test_plan_while_a_check_is_running(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        if len(command) > 1 and command[1] == "plan":
            assert started.wait(timeout=5)
            return CompletedProcess(command, 0, stdout=json.dumps(PLAN))
        started.set()
        assert release.wait(timeout=5)
        report_dir = engagement / "antares-data" / "reports" / "run-overlap"
        report_dir.mkdir(parents=True)
        report = {"findings": [{"file_path": "app.py", "submission_rank": 1, "cwe_ids": ["CWE-89"]}]}
        (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        return CompletedProcess(command, 0, stdout="")

    client, _app, server = _serve(tmp_path / "engagements", runner)
    try:
        _prepare(client, tmp_path)
        item = json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})

        def launch() -> None:
            client.open("POST", "/e/acme-2026/launch", {"actor": "Ada", "item": item})

        thread = threading.Thread(target=launch)
        thread.start()
        assert started.wait(timeout=5)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert "CWE-89" in page
        assert "Something went wrong" not in page
        release.set()
        thread.join(timeout=5)
    finally:
        release.set()
        server.shutdown()


def test_progress_poll_schedules_the_next_fetch_after_this_one_settles() -> None:
    start = _SCRIPT.index('getAttribute("data-poll") === "progress"')
    poll = _SCRIPT[start : _SCRIPT.index("const statusPill")]
    assert "setInterval" not in poll
    assert poll.count("fetch(") == 1
    positions: list[int] = []
    cursor = 0
    while True:
        found = poll.find("setTimeout(tick", cursor)
        if found < 0:
            break
        positions.append(found)
        cursor = found + 1
    fetch_at = poll.index("fetch(")
    then_at = poll.index(".then((response)")
    catch_at = poll.index(".catch(")
    assert len(positions) == 3
    assert fetch_at < then_at < positions[0] < catch_at < positions[1] < positions[2]


def test_progress_is_present_while_the_queue_is_non_empty(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        started.set()
        assert release.wait(timeout=5)
        report_dir = engagement / "antares-data" / "reports" / "run-queue"
        report_dir.mkdir(parents=True, exist_ok=True)
        report = {"findings": [{"file_path": "app.py", "submission_rank": 1, "cwe_ids": ["CWE-89"]}]}
        (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        return CompletedProcess(command, 0, stdout="")

    client, _app, server = _serve(tmp_path / "engagements", runner)
    try:
        _prepare(client, tmp_path)
        items = [
            ("item", json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})),
            ("item", json.dumps({"source": "search", "cwe": "CWE-22", "advisory_text": "", "title": ""})),
            ("actor", "Ada"),
        ]

        def launch() -> None:
            client.open("POST", "/e/acme-2026/launch", pairs=items)

        thread = threading.Thread(target=launch)
        thread.start()
        assert started.wait(timeout=5)
        status, page = client.open("GET", "/e/acme-2026")
        assert status == 200
        assert 'id="progress"' in page
        assert 'id="run-status"' in page
        assert "<summary>Status</summary>" in page
        assert page.index('class="is-running"') < page.index('id="run-status"')
        assert page.index('id="run-status"') < page.index('id="progress"')
        assert "CWE-22" in page
        running_rows = [row for row in page.split("<tr")[1:] if row.startswith(' class="is-running"')]
        assert len(running_rows) == 1
        assert "CWE-89" in running_rows[0]
        assert "CWE-22" not in running_rows[0]
        assert 'class="run-mark"' in running_rows[0]
        assert "running" in running_rows[0]
        assert "about 120 seconds" in running_rows[0]
        assert "Start" not in running_rows[0]
        queued = next(row for row in page.split("<tr") if "CWE-22" in row)
        assert "Cancel" in queued
        assert ">Start</button>" not in queued
        status, script = client.open("GET", "/astrolabe.js")
        assert status == 200
        assert "Lost connection to Astrolabe. Reload to resume." in script
        assert "30000" in script
        release.set()
        thread.join(timeout=5)
    finally:
        release.set()
        server.shutdown()


def _checks(scores: list[int], start: int = 200) -> list[dict[str, object]]:
    checks = []
    for index, score in enumerate(scores):
        checks.append(
            {
                "cwe_ids": [f"CWE-{start + index}"],
                "reasons": [f"signal in app{index}.py"],
                "evidence": [f"app{index}.py"],
                "repository_evidence_score": score,
            }
        )
    return checks


def _payload_runner(calls: list[list[str]], payload: dict[str, object]):
    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        calls.append(list(command))
        if len(command) > 1 and command[1] == "plan":
            return CompletedProcess(command, 0, stdout=json.dumps(payload))
        return CompletedProcess(command, 0, stdout="")

    return runner


def test_plan_rows_keep_filtered_reason_and_evidence_arrays() -> None:
    rows = plan_rows(
        {
            "selected_checks": [
                {
                    "cwe_ids": ["CWE-89"],
                    "reasons": ["sql query in app.py", "Member of the current MITRE CWE Top 25"],
                    "evidence": ["app.py", "docs/conf.py"],
                    "repository_evidence_score": 4,
                }
            ]
        }
    )
    assert rows[0]["evidence"] == "sql query in app.py; Member of the current MITRE CWE Top 25; app.py"
    assert rows[0]["reasons"] == ["sql query in app.py", "Member of the current MITRE CWE Top 25"]
    assert rows[0]["evidence_paths"] == ["app.py"]


def test_plan_post_redirects_and_get_does_not_run_the_cli(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, _page, headers = _open_once(
            client, "POST", "/e/acme-2026/select/explore", {"picker": "recommended"}
        )
        assert status == 303
        assert headers.get("Location") == "/e/acme-2026/plan/recommended"
        assert len(calls) == 1
        assert calls[0][1] == "plan"
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert status == 200
        assert len(calls) == 1
        assert 'value="recommended|CWE-89" checked' in page
    finally:
        server.shutdown()


def test_intake_makes_the_stored_plan_out_of_date(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        directory = tmp_path / "engagements" / "acme-2026"
        stored = json.loads((directory / "plans.json").read_text(encoding="utf-8"))
        stored["recommended"]["snapshot_sha256"] = "a" * 64
        (directory / "plans.json").write_text(json.dumps(stored), encoding="utf-8")
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert status == 200
        assert PLAN_STALE in page
        assert "Run plan" in page
        assert len(calls) == 1
        source = tmp_path / "acme-2026"
        (source / "app.py").write_text("print(2)\n", encoding="utf-8")
        status, _page = client.open(
            "POST",
            "/e/acme-2026/intake/preview",
            {"path": str(source), "replace": "on"},
        )
        assert status == 200
        status, _page = client.open("POST", "/e/acme-2026/intake/confirm", {})
        assert status == 200
        assert not (directory / "plans.json").is_file()
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert PLAN_EMPTY in page
        assert "Run plan" in page
        assert PLAN_STALE not in page
        assert len(calls) == 1
    finally:
        server.shutdown()


def test_missing_plan_says_no_plan_yet_and_a_changed_snapshot_is_out_of_date(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert status == 200
        assert PLAN_EMPTY in page
        assert "Run plan" in page
        assert PLAN_STALE not in page
        assert len(calls) == 0
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        directory = tmp_path / "engagements" / "acme-2026"
        stored = json.loads((directory / "plans.json").read_text(encoding="utf-8"))
        stored["recommended"]["snapshot_sha256"] = "a" * 64
        (directory / "plans.json").write_text(json.dumps(stored), encoding="utf-8")
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert status == 200
        assert PLAN_STALE in page
        assert "Run plan" in page
        assert PLAN_EMPTY not in page
    finally:
        server.shutdown()


def test_plan_tabs_mark_the_active_picker(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {})
        assert status == 200
        assert 'aria-current="page"' not in page
        for label in ("Advisory", "Recommended", "Top 25", "OWASP", "Search"):
            assert label in page
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert page.count('aria-current="page"') == 1
        assert 'aria-current="page">Recommended</button>' in page
        assert 'href="/e/acme-2026/plan/advisory"' in page
        assert 'href="/e/acme-2026/plan/search"' in page
        assert 'name="picker" value="top25"' in page
        assert 'name="picker" value="owasp"' in page
        status, page = client.open("GET", "/e/acme-2026/plan/advisory")
        assert status == 200
        assert "Paste advisory text" in page
        assert "Look up advisories" in page
        assert 'aria-current="page">Advisory</a>' in page
        status, page = client.open("GET", "/e/acme-2026/plan/search")
        assert "Enter an id, name, or description to search." in page
        assert 'aria-current="page">Search</a>' in page
        assert len(calls) == 1
    finally:
        server.shutdown()


def test_unready_plan_shows_needs_and_does_not_run(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        create_engagement(
            tmp_path / "engagements",
            engagement_id="acme-2026",
            customer="Acme",
            scope="Billing service",
            start_date="2026-10-09",
            consultants=["Ada"],
        )
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 400
        assert 'class="needs"' in page
        assert "Authorize" in page
        assert SCAN_GATE in page
        assert calls == []
        status, _page = client.open(
            "POST",
            "/e/acme-2026/attest",
            {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service", "authorized": "on"},
        )
        assert status == 200
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert status == 400
        assert "Add code" in page
        assert INTAKE_REQUIRED in page
        assert calls == []
    finally:
        server.shutdown()


def test_sel_drops_unknown_ids_and_none_and_top_are_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    payload = {"selected_checks": _checks([9, 8, 1])}
    client, _app, server = _serve(tmp_path / "engagements", _payload_runner(calls, payload))
    try:
        _prepare(client, tmp_path)
        monkeypatch.setenv("ASTROLABE_PRESELECT_LIMIT", "5")
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        page = client.open("GET", "/e/acme-2026/plan/recommended")[1]
        assert '<a href="/e/acme-2026/plan/recommended?sel=none">Select none</a>' in page
        assert '<a href="/e/acme-2026/plan/recommended?sel=top">Select top 5</a>' in page
        page = client.open("GET", "/e/acme-2026/plan/recommended?sel=CWE-200,CWE-999")[1]
        assert 'value="recommended|CWE-200" checked' in page
        assert "CWE-999" not in page
        assert 'value="recommended|CWE-201" checked' not in page
        page = client.open("GET", "/e/acme-2026/plan/recommended?sel=none")[1]
        assert 'value="recommended|CWE-200" checked' not in page
        assert 'value="recommended|CWE-201" checked' not in page
        monkeypatch.setenv("ASTROLABE_PRESELECT_LIMIT", "1")
        page = client.open("GET", "/e/acme-2026/plan/recommended?sel=top")[1]
        assert 'value="recommended|CWE-200" checked' in page
        assert 'value="recommended|CWE-201" checked' not in page
        assert 'value="recommended|CWE-202" checked' not in page
        assert len(calls) == 1
    finally:
        server.shutdown()


def test_structured_evidence_shows_paths_reasons_and_mixed_prose(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    payload = {
        "selected_checks": [
            {
                "cwe_ids": ["CWE-89"],
                "reasons": [
                    "sql query in app.py",
                    "second in b.py",
                    "third in c.py",
                    "fourth in d.py",
                ],
                "evidence": ["app.py", "app.py", "note about app.py"],
                "repository_evidence_score": 5,
            }
        ]
    }
    client, _app, server = _serve(tmp_path / "engagements", _payload_runner(calls, payload))
    try:
        _prepare(client, tmp_path)
        _status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert page.count('<li class="mono">app.py</li>') == 1
        visible, _details = page.split("<details>", 1)
        assert "sql query in app.py" in visible
        assert "note about app.py" in visible
        assert "fourth in d.py" not in visible
        assert "<summary>+1 more</summary>" in page
        assert "fourth in d.py" in page
        assert "<summary>Raw evidence</summary>" in page
        raw = "sql query in app.py; second in b.py; third in c.py; fourth in d.py; app.py; app.py; note about app.py"
        assert raw in page
    finally:
        server.shutdown()


def test_excluded_only_rows_stay_unchecked(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    payload = {
        "selected_checks": [
            {
                "cwe_ids": ["CWE-22"],
                "reasons": ["config in docs/conf.py"],
                "evidence": ["docs/conf.py"],
                "repository_evidence_score": 40,
            },
            {
                "cwe_ids": ["CWE-89"],
                "reasons": ["sql query in app.py"],
                "evidence": ["app.py"],
                "repository_evidence_score": 10,
            },
        ]
    }
    client, _app, server = _serve(tmp_path / "engagements", _payload_runner(calls, payload))
    try:
        _prepare(client, tmp_path)
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        _status, page = client.open("GET", "/e/acme-2026/plan/recommended?sel=CWE-22,CWE-89")
        assert 'value="recommended|CWE-89" checked' in page
        assert 'value="recommended|CWE-22" checked' not in page
        assert EXCLUDED_EVIDENCE in page
    finally:
        server.shutdown()


def test_snapshot_mismatch_refuses_launch(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        record = load_engagement(tmp_path / "engagements", "acme-2026")
        digest = str(record["snapshot_sha256"])
        status, page = client.open(
            "POST",
            "/e/acme-2026/review",
            {"choice": "recommended|CWE-89", "actor": "Ada"},
        )
        assert status == 200
        assert f'name="snapshot_sha256" value="{digest}"' in page
        record["snapshot_sha256"] = "b" * 64
        save_engagement(tmp_path / "engagements", record)
        item = json.dumps({"source": "recommended", "cwe": "CWE-89", "advisory_text": "", "title": ""})
        status, page = client.open(
            "POST",
            "/e/acme-2026/launch",
            {"item": item, "actor": "Ada", "snapshot_sha256": digest},
        )
        assert status == 400
        assert PLAN_STALE in page
        assert "Run plan" in page
        assert 'value="recommended|CWE-89" checked' in page
        assert not any(len(call) > 1 and call[1] == "query" for call in calls)
    finally:
        server.shutdown()


def test_back_to_plan_preserves_the_selection(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        status, page = client.open(
            "POST",
            "/e/acme-2026/review",
            {"choice": "recommended|CWE-22", "actor": "Ada"},
        )
        assert status == 200
        assert 'href="/e/acme-2026/plan/recommended?sel=CWE-22"' in page
        status, page = client.open("GET", "/e/acme-2026/plan/recommended?sel=CWE-22")
        assert status == 200
        assert 'value="recommended|CWE-22" checked' in page
        assert 'value="recommended|CWE-89" checked' not in page
    finally:
        server.shutdown()


def test_launch_redirects_to_the_investigate_step(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        digest = str(load_engagement(tmp_path / "engagements", "acme-2026")["snapshot_sha256"])
        item = json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})
        status, _page, headers = _open_once(
            client,
            "POST",
            "/e/acme-2026/launch",
            {"item": item, "actor": "Ada", "snapshot_sha256": digest},
        )
        assert status == 303
        assert headers.get("Location") == "/e/acme-2026?step=investigate#progress"
    finally:
        server.shutdown()


def test_top25_preselects_at_most_n_and_search_preselects_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASTROLABE_PRESELECT_LIMIT", "2")
    calls: list[list[str]] = []
    payload = {"selected_checks": _checks([1, 9, 8, 7, 6, 5], start=300)}
    client, _app, server = _serve(tmp_path / "engagements", _payload_runner(calls, payload))
    try:
        _prepare(client, tmp_path)
        _status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "top25"})
        assert 'value="top25|CWE-301" checked' in page
        assert 'value="top25|CWE-302" checked' in page
        assert 'value="top25|CWE-300" checked' not in page
        assert 'value="top25|CWE-303" checked' not in page
        _status, page = client.open(
            "POST",
            "/e/acme-2026/select/explore",
            {"picker": "search", "q": "CWE-89"},
        )
        assert 'value="search|CWE-89"' in page
        assert 'value="search|CWE-89" checked' not in page
        assert len([call for call in calls if len(call) > 1 and call[1] == "plan"]) == 1
    finally:
        server.shutdown()


def test_plans_json_is_absent_from_both_exports(tmp_path: Path) -> None:
    import tarfile

    from astrolabe.purge import _add_assessment, _add_full_bundle

    directory = tmp_path / "eng"
    (directory / "reports").mkdir(parents=True)
    (directory / "plans.json").write_text('{"marker": "plan-not-exported"}\n', encoding="utf-8")
    (directory / "pasted-advisory.json").write_text(
        '{"text": "pasted-body-not-exported"}\n',
        encoding="utf-8",
    )
    (directory / "engagement.json").write_text("{}\n", encoding="utf-8")
    (directory / "reports" / "assessment.html").write_text("<p>Report</p>", encoding="utf-8")
    full = tmp_path / "full.tar.gz"
    report = tmp_path / "report.tar.gz"
    with tarfile.open(full, "w:gz") as bundle:
        _add_full_bundle(bundle, directory)
    with tarfile.open(report, "w:gz") as bundle:
        _add_assessment(bundle, directory)
    for path in (full, report):
        with tarfile.open(path) as bundle:
            names = bundle.getnames()
            assert "plans.json" not in names
            assert "pasted-advisory.json" not in names
        raw = path.read_bytes()
        assert b"plan-not-exported" not in raw
        assert b"pasted-body-not-exported" not in raw


def test_plans_are_written_under_the_engagement_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import contextmanager

    from astrolabe.engagement import _engagement_lock, _write_json

    order: list[str] = []

    @contextmanager
    def spy_lock(directory: Path):
        order.append("enter")
        with _engagement_lock(directory):
            order.append("held")
            yield
        order.append("exit")

    def spy_write(path: Path, payload: object) -> None:
        assert order[-1] == "held"
        assert path.name == "plans.json"
        order.append("write")
        _write_json(path, payload)

    monkeypatch.setattr("astrolabe.plan_store._engagement_lock", spy_lock)
    monkeypatch.setattr("astrolabe.plan_store._write_json", spy_write)
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, _page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert "write" in order
        assert order.index("write") > order.index("held")
        stored = json.loads((tmp_path / "engagements" / "acme-2026" / "plans.json").read_text(encoding="utf-8"))
        assert stored["recommended"]["rows"]
    finally:
        server.shutdown()


_PLAN_ROW_FIELDS = {
    "cwe",
    "evidence",
    "reasons",
    "evidence_paths",
    "score",
    "excluded_only",
    "preselect",
    "group",
    "related",
}


def _assert_shell(page: str, engagement_id: str, picker_label: str) -> None:
    assert 'class="engagement-header"' in page
    assert f'<span class="mono">{engagement_id}</span>' in page
    assert "Acting as Ada" in page
    assert 'id="status-pill"' in page
    assert 'aria-label="Breadcrumb"' in page
    assert "Investigate" in page
    assert picker_label in page


def test_plans_json_fields_for_each_picker(tmp_path: Path) -> None:
    import hashlib

    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        directory = tmp_path / "engagements" / "acme-2026"
        for picker in ("recommended", "top25", "owasp"):
            status, _page = client.open("POST", "/e/acme-2026/select/explore", {"picker": picker})
            assert status == 200
            stored = json.loads((directory / "plans.json").read_text(encoding="utf-8"))
            plan = stored[picker]
            assert set(plan) == {"snapshot_sha256", "rows"}
            assert set(plan["rows"][0]) == _PLAN_ROW_FIELDS
        status, _page = client.open(
            "POST",
            "/e/acme-2026/select/explore",
            {"picker": "search", "q": "CWE-89"},
        )
        assert status == 200
        stored = json.loads((directory / "plans.json").read_text(encoding="utf-8"))
        assert set(stored["search"]) == {"snapshot_sha256", "query"}
        assert stored["search"]["query"] == "CWE-89"
        status, _page = client.open(
            "POST",
            "/e/acme-2026/select/advisory",
            {"ids": "CVE-2024-9001"},
        )
        assert status == 200
        stored = json.loads((directory / "plans.json").read_text(encoding="utf-8"))
        assert set(stored["advisory"]) == {"snapshot_sha256", "ids", "title", "query"}
        assert stored["advisory"]["ids"] == ["CVE-2024-9001"]
        assert not (directory / "pasted-advisory.json").exists()
        body = "Billing module uses string concatenation in the query."
        status, page = client.open(
            "POST",
            "/e/acme-2026/select/advisory",
            {"advisory_text": body, "title": "Billing note"},
        )
        assert status == 200
        stored = json.loads((directory / "plans.json").read_text(encoding="utf-8"))
        advisory = stored["advisory"]
        assert set(advisory) == {"snapshot_sha256", "ids", "advisory_sha256", "title", "query"}
        assert advisory["ids"] == []
        assert advisory["title"] == "Billing note"
        assert advisory["advisory_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()
        assert body not in (directory / "plans.json").read_text(encoding="utf-8")
        pasted = json.loads((directory / "pasted-advisory.json").read_text(encoding="utf-8"))
        assert pasted == {"text": body}
        assert f'<textarea name="advisory_text" readonly class="query-text">{body}</textarea>' in page
    finally:
        server.shutdown()


def test_plan_and_review_pages_render_the_engagement_shell(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        _assert_shell(page, "acme-2026", "Recommended")
        status, page = client.open(
            "POST",
            "/e/acme-2026/review",
            {"choice": "recommended|CWE-89", "actor": "Ada"},
        )
        assert status == 200
        assert "<h1>Launch review</h1>" in page
        _assert_shell(page, "acme-2026", "Recommended")
    finally:
        server.shutdown()


def test_selected_count_is_server_rendered_with_aria_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from astrolabe.selection import estimate_seconds, format_estimate

    monkeypatch.delenv("ASTROLABE_ESTIMATE_PER_CHECK", raising=False)

    calls: list[list[str]] = []
    client, _app, server = _serve(tmp_path / "engagements", _runner(calls))
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert '<p aria-live="polite"><span data-selected-count>1</span> selected</p>' in page
        assert format_estimate(estimate_seconds([], 1), 1) in page
        assert "Approximate total time is 120 seconds, using 120 seconds per check, for 1 investigations." in page
        status, page = client.open(
            "POST",
            "/e/acme-2026/select/explore",
            {"picker": "search", "q": "CWE-89"},
        )
        assert status == 200
        assert '<p aria-live="polite"><span data-selected-count>0</span> selected</p>' in page
        assert format_estimate(None, 0) in page
        assert 'value="search|CWE-89" checked' not in page
    finally:
        server.shutdown()
