"""Review cards show snapshot lines and keep trace text off the card."""

from __future__ import annotations

import hashlib
import html
import io
import json
from pathlib import Path

from astrolabe.cwe import base_variant_children, cwe_abstraction, cwe_name, displayed_mitigations
from astrolabe.engagement import create_engagement, save_engagement
from astrolabe.candidates import observe_candidates
from astrolabe.redact import MITRE_LIKELIHOOD_LABEL
from astrolabe.search_hits import line_hits, read_snapshot_lines
from astrolabe.selection import CLASS_NOTE
from astrolabe.ui import App
from tests.secret_fixtures import aws_example_key

_SNAPSHOT = "a" * 64
_OTHER = "b" * 64
_TRACE_SHA = "c" * 64


def test_line_hit_for_myapp_does_not_match_app() -> None:
    events = [
        {
            "phase": "tool_call",
            "payload": {"tool_name": "terminal", "arguments": {"command": "nl app.py"}},
        },
        {"phase": "tool_result", "payload": {"result_summary": "app.py:4:from nl"}},
        {
            "phase": "tool_call",
            "payload": {"tool_name": "terminal", "arguments": {"command": "rg -n load"}},
        },
        {
            "phase": "tool_result",
            "payload": {
                "result_summary": "\n".join(
                    [
                        "myapp.py:63:config = yaml.load(stream)",
                        "./app.py:9:kept",
                        "App.py:8:different case",
                        "dir/app.py:7:different path",
                    ]
                )
            },
        },
    ]
    assert line_hits(events, "app.py") == [9]
    assert 63 not in line_hits(events, "app.py")
    assert line_hits(events, "myapp.py") == [63]
    prefixed = [
        {
            "phase": "tool_call",
            "payload": {"tool_name": "terminal", "arguments": {"command": "grep -n token"}},
        },
        {"phase": "tool_result", "payload": {"result_summary": "./pkg/app.py:3:yes"}},
    ]
    assert line_hits(prefixed, "app.py", "pkg") == [3]
    many = "\n".join(f"app.py:{number}:x" for number in range(1, 8))
    capped = [
        {"phase": "tool_call", "payload": {"arguments": {"command": "rg pattern"}}},
        {"phase": "tool_result", "payload": {"result_summary": many}},
    ]
    assert line_hits(capped, "app.py") == [1, 2, 3, 4, 5]


def test_snapshot_read_stays_inside_skips_large_or_binary_and_replaces_bytes(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("OUTSIDE\n", encoding="utf-8")
    assert read_snapshot_lines(snapshot, "../secret.txt", [1]) is None
    assert read_snapshot_lines(snapshot, "nested/../../secret.txt", [1]) is None
    link = snapshot / "link.txt"
    link.symlink_to(outside)
    assert read_snapshot_lines(snapshot, "link.txt", [1]) is None
    (snapshot / "big.txt").write_bytes(b"a" * (1024 * 1024 + 1))
    assert read_snapshot_lines(snapshot, "big.txt", [1]) is None
    (snapshot / "bin.txt").write_bytes(b"hello\0world\n")
    assert read_snapshot_lines(snapshot, "bin.txt", [1]) is None
    (snapshot / "app.py").write_bytes(b"before\n\xffafter\nlater-marker\n")
    assert read_snapshot_lines(snapshot, "app.py", [2]) == {2: "\ufffdafter"}


def test_review_renders_snapshot_lines_and_not_trace_text(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    snapshot_line = "stream = open(path)  # " + ("padding " * 25)
    assert len(snapshot_line) > 160
    _write_snapshot(directory, "app.py", ["filler", snapshot_line])
    _write_trace(
        directory,
        "named.investigation.jsonl",
        _search("app.py:2:TRACE-ONLY-MARKER")
        + [_finding("app.py", "Z" * 20)],
    )
    _write_trace(
        directory,
        "other.investigation.jsonl",
        _search("app.py:1:UNNAMED-TRACE-MARKER"),
    )
    _store(
        directory,
        _investigation(
            "inv-1",
            paths=["app.py"],
            trace_name="named.investigation.jsonl",
            snapshot=_SNAPSHOT,
        ),
    )
    _report(directory, "run-1", [("app.py", 1)])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="inv-1", run=1)
    review = _review(App(root), "cards")
    assert "TRACE-ONLY-MARKER" not in review
    assert "UNNAMED-TRACE-MARKER" not in review
    assert 'class="trace"' not in review
    assert "Where the searches matched this file" in review
    assert f"line 2: <span class=\"mono\">{snapshot_line[:160]}</span>" in review
    assert snapshot_line[:161] not in review
    assert "Look through app.py for " in review
    assert "Open app.py:2 and check " in review
    assert "1 candidate file" in review
    assert "Outcome: completed" in review
    assert "Duration: 12.5 seconds" in review


def test_review_hides_lines_from_an_earlier_snapshot(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    _write_snapshot(directory, "app.py", ["filler", "CURRENT-SNAPSHOT-TEXT"])
    _write_trace(directory, "named.investigation.jsonl", _search("./app.py:2:EARLIER-TRACE-TEXT"))
    _store(
        directory,
        _investigation(
            "inv-1",
            paths=["app.py"],
            trace_name="named.investigation.jsonl",
            snapshot=_OTHER,
        ),
    )
    _report(directory, "run-1", [("app.py", 1)])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="inv-1", run=1)
    review = _review(App(root), "cards")
    assert "Search matches are from an earlier snapshot. Re-run to refresh." in review
    assert "CURRENT-SNAPSHOT-TEXT" not in review
    assert "EARLIER-TRACE-TEXT" not in review
    assert "line 2:" not in review


def test_review_hides_secret_looking_snapshot_lines(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    key = aws_example_key()
    _write_snapshot(directory, "app.py", [f"token = {key}"])
    _write_trace(directory, "named.investigation.jsonl", _search(f"app.py:1:{key}"))
    _store(
        directory,
        _investigation("inv-1", paths=["app.py"], trace_name="named.investigation.jsonl", snapshot=_SNAPSHOT),
    )
    _report(directory, "run-1", [("app.py", 1)])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="inv-1", run=1)
    review = _review(App(root), "cards")
    assert "line 1 (hidden: looks like a secret)" in review
    assert key not in review


def test_review_ignores_unnamed_traces(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    _write_snapshot(directory, "app.py", ["UNNAMED-SNAPSHOT-LINE"])
    _write_trace(directory, "other.investigation.jsonl", _search("app.py:1:UNNAMED-TRACE-MARKER"))
    _store(directory, _investigation("inv-1", paths=["app.py"], trace_name="", snapshot=_SNAPSHOT))
    _report(directory, "run-1", [("app.py", 1)])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="inv-1", run=1)
    review = _review(App(root), "cards")
    assert "UNNAMED-SNAPSHOT-LINE" not in review
    assert "UNNAMED-TRACE-MARKER" not in review
    assert "Where the searches matched this file" not in review
    name = cwe_name("CWE-89")
    assert f"Open app.py and check {html.escape(name)}" in review


def test_candidate_card_shows_next_step_look_for_and_mitigations(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    name = cwe_name("CWE-89")
    mitigations = displayed_mitigations("CWE-89")
    assert len(mitigations) > 1
    _write_snapshot(directory, "app.py", ["filler", "matched line"])
    _write_snapshot(directory, "view.py", ["advisory line"])
    _write_trace(directory, "explore.investigation.jsonl", _search("app.py:2:trace-text"))
    _write_trace(directory, "guided.investigation.jsonl", _search("view.py:1:trace-text"))
    _store(
        directory,
        _investigation(
            "explore",
            paths=["app.py"],
            trace_name="explore.investigation.jsonl",
            snapshot=_SNAPSHOT,
            report="run-explore",
        ),
        _investigation(
            "guided",
            paths=["view.py"],
            trace_name="guided.investigation.jsonl",
            snapshot=_SNAPSHOT,
            report="run-guided",
            cwe="CWE-89",
            exploratory=False,
        ),
    )
    _report(directory, "run-explore", [("app.py", 1)])
    _report(directory, "run-guided", [("view.py", 1)])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="explore", run=1)
    observe_candidates(root, "cards", file_paths=["view.py"], cwe="CWE-89", investigation_id="guided", run=1)
    review = _review(App(root), "cards")
    explore = review.split('data-investigation="explore"', 1)[1].split("data-investigation=", 1)[0]
    guided = review.split('data-investigation="guided"', 1)[1]
    look = f"Look through app.py for {name}. Confirm the weakness before changing code."
    assert html.escape(look) in explore
    before, details = explore.split("<details><summary>More mitigations</summary>", 1)
    assert html.escape(mitigations[0]) in before
    assert html.escape(mitigations[1]) in details.split("</details>", 1)[0]
    assert "<details open" not in explore
    assert f"Open app.py:2 and check {html.escape(name)}" in explore
    assert "Open view.py and check it against the advisory" in guided
    assert "Open view.py:" not in guided


def test_early_end_sentence_for_failed_cancelled_and_budget(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    _store(
        directory,
        _investigation("failed-run", paths=[], trace_name="", snapshot=_SNAPSHOT, report=None, exit_status="failed"),
        _investigation(
            "cancelled-run",
            paths=[],
            trace_name="",
            snapshot=_SNAPSHOT,
            report=None,
            cwe="CWE-22",
            exit_status="cancelled",
        ),
        _investigation(
            "budget-run",
            paths=[],
            trace_name="",
            snapshot=_SNAPSHOT,
            report=None,
            cwe="CWE-79",
            budget=3,
        ),
    )
    review = _review(App(root), "cards")
    assert "No candidate files. No candidate is not evidence of no weakness." in review
    assert "The run ended early (failed); the search was incomplete." in review
    assert "The run ended early (cancelled); the search was incomplete." in review
    assert "The run ended early (budget); the search was incomplete." in review


def test_rank_stays_in_run_details_until_a_run_submits_two_files(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    _store(
        directory,
        _investigation("single", paths=["app.py"], trace_name="", snapshot=_SNAPSHOT, report="run-single"),
        _investigation(
            "pair",
            paths=["left.py", "right.py"],
            trace_name="",
            snapshot=_SNAPSHOT,
            report="run-pair",
            cwe="CWE-22",
        ),
    )
    _report(directory, "run-single", [("app.py", 1, "High")])
    _report(directory, "run-pair", [("left.py", 1, "Medium"), ("right.py", 2, "Low")])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="single", run=1)
    observe_candidates(
        root, "cards", file_paths=["left.py", "right.py"], cwe="CWE-22", investigation_id="pair", run=1
    )
    review = _review(App(root), "cards")
    single = review.split('data-investigation="single"', 1)[1].split("data-investigation=", 1)[0]
    pair = review.split('data-investigation="pair"', 1)[1]
    single_card = single.split('<article class="candidate">', 1)[1]
    pair_before, pair_cards = pair.split('<article class="candidate">', 1)
    assert "Rank:" not in single_card
    assert "Rank:" in single.split('<article class="candidate">', 1)[0]
    assert MITRE_LIKELIHOOD_LABEL in single.split('<article class="candidate">', 1)[0]
    assert "Rank:" not in pair_before
    assert pair_cards.count("Rank:") == 2
    assert MITRE_LIKELIHOOD_LABEL in pair_cards
    assert "finding" not in review.lower()


def test_candidate_cards_follow_best_rank_then_path(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    first = _investigation(
        "inv-1",
        paths=["mid.py", "zebra.py", "alpha.py"],
        trace_name="",
        snapshot=_SNAPSHOT,
        report="run-1",
    )
    second = _investigation(
        "inv-1",
        paths=["alpha.py", "zebra.py"],
        trace_name="",
        snapshot=_SNAPSHOT,
        report="run-2",
        run=2,
    )
    _store(directory, _merged(first, second))
    _report(directory, "run-1", [("mid.py", 1), ("zebra.py", 2), ("alpha.py", 3)])
    _report(directory, "run-2", [("alpha.py", 1), ("zebra.py", 9)])
    observe_candidates(
        root,
        "cards",
        file_paths=["mid.py", "zebra.py", "alpha.py"],
        cwe="CWE-89",
        investigation_id="inv-1",
        run=1,
    )
    review = _review(App(root), "cards")
    headings = [
        part.split("</h3>", 1)[0].rsplit(">", 1)[-1]
        for part in review.split('<article class="candidate">')[1:]
    ]
    assert headings == ["alpha.py", "mid.py", "zebra.py"]


def test_model_label_is_unverified_redacted_and_limited(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    key = aws_example_key()
    title = key + ("Z" * 200)
    _write_trace(
        directory,
        "named.investigation.jsonl",
        _search("app.py:1:trace") + [_finding("app.py", title)],
    )
    _write_snapshot(directory, "app.py", ["plain line"])
    _store(
        directory,
        _investigation("inv-1", paths=["app.py"], trace_name="named.investigation.jsonl", snapshot=_SNAPSHOT),
    )
    _report(directory, "run-1", [("app.py", 1)])
    observe_candidates(root, "cards", file_paths=["app.py"], cwe="CWE-89", investigation_id="inv-1", run=1)
    review = _review(App(root), "cards")
    assert "Model's label (unverified): " in review
    assert key not in review
    assert "&lt;redacted&gt;" in review
    assert "Z" * 121 not in review
    assert "finding" not in review.lower()


def test_no_candidate_suggestions_link_without_launching(tmp_path: Path, monkeypatch) -> None:
    cache = tmp_path / "advisories"
    cache.mkdir()
    (cache / "CVE-2024-0001.json").write_text(
        json.dumps({"id": "CVE-2024-0001", "summary": "Example", "details": "Example"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(cache))
    root = tmp_path / "engagements"
    record = create_engagement(
        root,
        engagement_id="suggest",
        customer="Acme",
        scope="Billing",
        start_date="2026-10-11",
        consultants=["Ada"],
        reference="SOW-14",
        authorized=True,
    )
    record["snapshot_sha256"] = _SNAPSHOT
    save_engagement(root, record)
    directory = root / "suggest"
    children = [
        child
        for child in base_variant_children("CWE-20")
        if cwe_abstraction(child) in {"Base", "Variant"}
    ]
    assert children
    _store(
        directory,
        _investigation(
            "broad",
            paths=[],
            trace_name="",
            snapshot=_SNAPSHOT,
            cwe="CWE-20",
            budget=2,
            report=None,
        ),
    )
    before = (directory / "investigations.json").read_bytes()
    app = App(root)
    review = _review(app, "suggest")
    search_href = f'/e/suggest/plan/search?q={children[0]}'
    advisory_href = "/e/suggest/plan/advisory?id=CVE-2024-0001"
    assert "No candidate files. No candidate is not evidence of no weakness." in review
    assert CLASS_NOTE in review
    assert f'href="{search_href}"' in review
    assert f'href="{advisory_href}"' in review
    assert "The run ended early (budget); the search was incomplete." in review
    status, page, _kind, _extra = _dispatch(app, "GET", search_href)
    assert status == 200
    assert f'value="{children[0]}"' in page
    assert 'class="plan-rows"' not in page
    status, page, _kind, _extra = _dispatch(app, "GET", advisory_href)
    assert status == 200
    assert "<textarea name=\"ids\">CVE-2024-0001</textarea>" in page
    assert "Investigation running" not in page
    assert (directory / "investigations.json").read_bytes() == before


def test_search_page_prefills_q_without_searching(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    record = create_engagement(
        root,
        engagement_id="lookup",
        customer="Acme",
        scope="Billing",
        start_date="2026-10-11",
        consultants=["Ada"],
        reference="SOW-14",
        authorized=True,
    )
    record["snapshot_sha256"] = _SNAPSHOT
    save_engagement(root, record)
    status, page, _kind, _extra = _dispatch(App(root), "GET", "/e/lookup/plan/search?q=CWE-89")
    assert status == 200
    assert 'value="CWE-89"' in page
    assert 'class="plan-rows"' not in page


def test_trace_page_paginates_and_collapses_messages(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    key = aws_example_key()
    events: list[dict[str, object]] = [
        {
            "phase": "tool_call",
            "payload": {"tool_name": "terminal", "arguments": {"command": f"echo {key}"}},
        },
        {"phase": "tool_result", "payload": {"tool_name": "terminal", "result_summary": key}},
    ]
    events.extend(
        {"phase": "message", "payload": {"role": "assistant", "content": f"body-{index:03d}"}}
        for index in range(200)
    )
    _write_trace(directory, "named.investigation.jsonl", events)
    _store(
        directory,
        _investigation("inv-1", paths=[], trace_name="named.investigation.jsonl", snapshot=_SNAPSHOT, report=None),
    )
    app = App(root)
    status, page, kind, _extra = _dispatch(app, "GET", "/e/cards/runs/inv-1/1/trace")
    assert status == 200
    assert kind.startswith("text/html")
    assert 'class="engagement-header"' in page
    assert "cards" in page
    assert '<details class="trace-message" open' not in page
    assert '<details class="trace-message">' in page
    first = page.split('<details class="trace-message">', 1)[1].split("</details>", 1)[0]
    assert "body-000" in first
    assert "body-197" in page
    assert "body-198" not in page
    assert key not in page
    assert "terminal" in page
    status, second, _kind, _extra = _dispatch(app, "GET", "/e/cards/runs/inv-1/1/trace?page=2")
    assert status == 200
    assert "body-198" in second
    assert "body-199" in second
    assert "body-000" not in second


def test_trace_download_is_a_redacted_export(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    key = aws_example_key()
    _write_trace(
        directory,
        "named.investigation.jsonl",
        [{"phase": "tool_result", "payload": {"result_summary": key}}],
    )
    _store(
        directory,
        _investigation(
            "inv-1",
            paths=[],
            trace_name="named.investigation.jsonl",
            snapshot=_SNAPSHOT,
            report=None,
            trace_sha=_TRACE_SHA,
            trace_lines=7,
        ),
    )
    status, body, kind, extra = _dispatch(App(root), "GET", "/e/cards/runs/inv-1/1/trace.jsonl")
    assert status == 200
    assert kind == "application/x-ndjson"
    assert extra["Cache-Control"] == "no-store"
    assert extra["Content-Disposition"] == 'attachment; filename="cards-inv-1-1.trace.jsonl"'
    header, _newline, rest = body.partition("\n")
    payload = json.loads(header)
    assert payload["astrolabe_trace_export"] == 1
    assert payload["source_sha256"] == _TRACE_SHA
    assert payload["source_lines"] == 7
    assert payload["redacted"] is True
    assert payload["body_sha256"] == hashlib.sha256(rest.encode("utf-8")).hexdigest()
    assert key not in body
    assert "<redacted>" in rest


def test_trace_route_rejects_a_missing_run_and_a_traversal(tmp_path: Path) -> None:
    root, directory = _plant(tmp_path)
    outside = directory / "outside.jsonl"
    outside.write_text('{"phase":"message","payload":{"content":"TRAVERSAL-MARKER"}}\n', encoding="utf-8")
    _store(
        directory,
        _investigation(
            "inv-1",
            paths=[],
            trace_name="../../outside.jsonl",
            snapshot=_SNAPSHOT,
            report=None,
        ),
    )
    app = App(root)
    status, page, _kind, _extra = _dispatch(app, "GET", "/e/cards/runs/inv-1/1/trace")
    assert status == 404
    assert "TRAVERSAL-MARKER" not in page
    status, page, _kind, _extra = _dispatch(app, "GET", "/e/cards/runs/inv-1/1/trace.jsonl")
    assert status == 404
    assert "TRAVERSAL-MARKER" not in page
    status, _page, _kind, _extra = _dispatch(app, "GET", "/e/cards/runs/missing/1/trace")
    assert status == 404
    status, _page, _kind, _extra = _dispatch(app, "GET", "/e/cards/runs/inv-1/9/trace")
    assert status == 404


def _plant(tmp_path: Path, engagement_id: str = "cards") -> tuple[Path, Path]:
    root = tmp_path / "engagements"
    directory = root / engagement_id
    (directory / "antares-data" / "traces").mkdir(parents=True)
    (directory / "antares-data" / "reports").mkdir(parents=True)
    (directory / "snapshot").mkdir()
    record = {
        "id": engagement_id,
        "instance_id": f"instance-{engagement_id}",
        "attestation_migrated": True,
        "customer": "Acme",
        "scope": "Billing",
        "start_date": "2026-10-11",
        "end_date": None,
        "consultants": ["Ada"],
        "state": "open",
        "snapshot_sha256": _SNAPSHOT,
        "intake": None,
    }
    (directory / "engagement.json").write_text(json.dumps(record), encoding="utf-8")
    (directory / "audit.jsonl").write_text("", encoding="utf-8")
    return root, directory


def _investigation(
    investigation_id: str,
    *,
    paths: list[str],
    trace_name: str,
    snapshot: str,
    report: str | None = "run-1",
    cwe: str = "CWE-89",
    run: int = 1,
    budget: int = 0,
    exploratory: bool = True,
    exit_status: str = "completed",
    trace_sha: str = _TRACE_SHA,
    trace_lines: int = 1,
) -> dict[str, object]:
    return {
        "id": investigation_id,
        "cwe": cwe,
        "exploratory": exploratory,
        "selection_source": "search",
        "runs": [
            {
                "run": run,
                "actor": "Ada",
                "exit_code": 0,
                "error": "",
                "report": None if report is None else f"antares-data/reports/{report}/report.json",
                "candidate_paths": paths,
                "snapshot_sha256": snapshot,
                "elapsed_seconds": 12.5,
                "finished_at": "2026-10-11T00:00:01Z",
                "activity": {
                    "start": "2026-10-11T00:00:00Z",
                    "end": "2026-10-11T00:00:01Z",
                    "exit_status": exit_status,
                    "phases": {exit_status: "2026-10-11T00:00:01Z"},
                    "counters": {
                        "model_turns": 1,
                        "submissions": 0,
                        "searches": 1,
                        "reads": 0,
                        "other": 0,
                    },
                    "loop_control": {"duplicate": 0, "safety": 0, "budget": budget},
                    "trace": {"name": trace_name, "lines": trace_lines, "sha256": trace_sha},
                },
            }
        ],
    }


def _merged(first: dict[str, object], second: dict[str, object]) -> dict[str, object]:
    runs = list(first["runs"]) + list(second["runs"])
    return {**first, "runs": runs}


def _store(directory: Path, *investigations: dict[str, object]) -> None:
    (directory / "investigations.json").write_text(json.dumps(list(investigations)), encoding="utf-8")


def _report(directory: Path, name: str, rows: list[tuple[str, int] | tuple[str, int, str]]) -> None:
    findings = []
    for row in rows:
        path, rank = row[0], row[1]
        item: dict[str, object] = {
            "file_path": path,
            "submission_rank": rank,
            "cwe_ids": ["CWE-22" if path in {"left.py", "right.py"} else "CWE-89"],
        }
        if len(row) == 3:
            item["likelihood_of_exploit"] = row[2]
        findings.append(item)
    report_dir = directory / "antares-data" / "reports" / name
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "report.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")


def _write_snapshot(directory: Path, relative: str, lines: list[str]) -> None:
    path = directory / "snapshot" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_trace(directory: Path, name: str, events: list[dict[str, object]]) -> None:
    path = directory / "antares-data" / "traces" / name
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def _search(summary: str) -> list[dict[str, object]]:
    return [
        {
            "phase": "tool_call",
            "payload": {"tool_name": "terminal", "arguments": {"command": "rg -n pattern"}},
        },
        {"phase": "tool_result", "payload": {"tool_name": "terminal", "result_summary": summary}},
    ]


def _finding(path: str, title: str) -> dict[str, object]:
    return {"phase": "finding", "payload": {"file_path": path, "title": title, "submission_rank": 1}}


def _review(app: App, engagement_id: str) -> str:
    page = app.engagement_page(engagement_id)
    return page.split('id="review"', 1)[1].split('id="reports"', 1)[0]


def _dispatch(app: App, method: str, url: str) -> tuple[int, str, str, dict[str, str]]:
    result = app.dispatch(method, url, {}, io.BytesIO(b""))
    extra: dict[str, str] = {}
    if len(result) == 4:
        status, body, content_type, extra = result
    else:
        status, body, content_type = result
    text = body.decode("utf-8") if isinstance(body, bytes) else body
    return status, text, content_type, extra
