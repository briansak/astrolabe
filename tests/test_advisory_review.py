"""Advisory dismissal guardrail and finalize blockers. Matching stays on local text."""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.advisory_review import match_advisory_text
from astrolabe.candidates import VerdictError, list_candidates, set_verdict
from astrolabe.engagement import (
    EngagementError,
    attest,
    create_engagement,
    load_engagement,
    read_durable_audit,
)
from astrolabe.intake import intake_local
from astrolabe.investigate import rerun_investigation, start_investigation
from astrolabe.phase2_cli import main
from astrolabe.reports import finalize_assessment, finalize_block_message, write_assessment

CANDIDATE = "jwt/algorithms.py"
SUMMARY = "Key confusion through non-blocklisted public key formats"
LONG_NOTE = "The HMAC check in this file is not the code the advisory describes."


def test_advisory_path_matches_components_and_ignores_lookalikes() -> None:
    exact = match_advisory_text(
        CANDIDATE,
        "",
        "See jwt/algorithms.py.",
        stripped_prefix="pyjwt-2.3.0",
        source="advisory text",
    )
    prefixed = match_advisory_text(
        CANDIDATE,
        "",
        "See pyjwt/jwt/algorithms.py.",
        stripped_prefix="pyjwt-2.3.0",
        source="advisory text",
    )
    blob = match_advisory_text(
        CANDIDATE,
        "",
        "See https://github.com/jpadilla/pyjwt/blob/2.3.0/jwt/algorithms.py for the change.",
        stripped_prefix=None,
        source="advisory text",
    )
    dropped = match_advisory_text(
        "pyjwt-2.3.0/jwt/algorithms.py",
        "",
        "jwt\\algorithms.py",
        stripped_prefix="pyjwt-2.3.0",
        source="advisory text",
    )
    lookalike = match_advisory_text(
        CANDIDATE,
        "",
        "See myjwt/algorithms.pyc.",
        stripped_prefix=None,
        source="advisory text",
    )
    basename = match_advisory_text(
        CANDIDATE,
        "",
        "The file algorithms.py is involved.",
        stripped_prefix=None,
        source="pasted advisory",
    )
    wrong_case = match_advisory_text(
        CANDIDATE,
        "",
        "See JWT/algorithms.py.",
        stripped_prefix=None,
        source="advisory text",
    )
    assert exact.kind == "path" and exact.source == "advisory text"
    assert "jwt/algorithms.py" in exact.excerpt
    assert prefixed.kind == "path"
    assert blob.kind == "path"
    assert dropped.kind == "path"
    assert lookalike.kind == ""
    assert basename.kind == "filename" and basename.source == "pasted advisory"
    assert wrong_case.kind == ""


def test_sensitive_excerpt_is_omitted() -> None:
    pem = "-" * 5 + "BEGIN " + "PUBLIC KEY" + "-" * 5
    ssh_type = "ssh-" + "ed25519"
    begun = match_advisory_text(
        CANDIDATE,
        SUMMARY,
        "The check is in jwt/algorithms.py " + pem + " and continues.",
        stripped_prefix=None,
        source="advisory text",
    )
    ssh = match_advisory_text(
        CANDIDATE,
        SUMMARY,
        "The check is in jwt/algorithms.py with an " + ssh_type + " token.",
        stripped_prefix=None,
        source="advisory text",
    )
    assert begun.kind == "path" and begun.excerpt == ""
    assert ssh.kind == "path" and ssh.excerpt == ""
    assert ("-" * 5 + "BEGIN") not in begun.excerpt
    for marker in (
        "ecdsa-" + "sha2-" + "nistp256",
        "sk-" + "ssh-",
        "sk-" + "ecdsa-" + "token",
        "A" * 40,
    ):
        matched = match_advisory_text(
            CANDIDATE,
            SUMMARY,
            f"The check is in jwt/algorithms.py using {marker}.",
            stripped_prefix=None,
            source="advisory text",
        )
        assert matched.kind == "path" and matched.excerpt == ""
        assert marker not in matched.excerpt
    short_run = match_advisory_text(
        CANDIDATE,
        SUMMARY,
        "The check is in jwt/algorithms.py using " + ("A" * 39) + ".",
        stripped_prefix=None,
        source="advisory text",
    )
    assert "jwt/algorithms.py" in short_run.excerpt


def test_finalize_block_message_uses_singular_and_plural() -> None:
    assert finalize_block_message(1, 1, 0) == (
        "1 candidate is pending review; 1 needs more information."
    )
    assert finalize_block_message(2, 0, 0) == "2 candidates are pending review."
    assert finalize_block_message(0, 1, 0) == "1 candidate needs more information."
    assert finalize_block_message(0, 2, 0) == "2 candidates need more information."
    assert finalize_block_message(0, 0, 1) == "1 candidate needs re-review on the current snapshot."
    assert finalize_block_message(1, 1, 2) == (
        "1 candidate is pending review; 1 needs more information; "
        "2 need re-review on the current snapshot."
    )


def test_finalize_requires_confirmed_or_not_actionable(tmp_path: Path) -> None:
    root, source = _ready(tmp_path, "finalize-me")
    _investigate(root, "finalize-me", ["pending.py", "held.py", "ok.py", "dismissed.py"], cwe="CWE-89")
    set_verdict(
        root,
        "finalize-me",
        file_path="held.py",
        cwe="CWE-89",
        state="needs_more_info",
        actor="Ada",
        note="Need the caller.",
    )
    set_verdict(
        root,
        "finalize-me",
        file_path="ok.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    set_verdict(
        root,
        "finalize-me",
        file_path="dismissed.py",
        cwe="CWE-89",
        state="not_actionable",
        actor="Ada",
        note="Not this file.",
    )
    write_assessment(root, "finalize-me", actor="Ada")
    with pytest.raises(EngagementError, match="1 candidate is pending review; 1 needs more information.") as raised:
        finalize_assessment(root, "finalize-me", actor="Ada")
    assert "re-review" not in str(raised.value)
    set_verdict(
        root,
        "finalize-me",
        file_path="pending.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    set_verdict(
        root,
        "finalize-me",
        file_path="held.py",
        cwe="CWE-89",
        state="not_actionable",
        actor="Ada",
        note="Not this file.",
    )
    finalized = finalize_assessment(root, "finalize-me", actor="Ada")
    assert finalized["finalized_at"]
    assert source.is_dir()


def test_stale_candidate_blocks_finalize_only_when_the_current_snapshot_observed_it(
    tmp_path: Path,
) -> None:
    quiet = _ready(tmp_path, "stale-quiet")
    _investigate(quiet[0], "stale-quiet", ["app.py"])
    set_verdict(
        quiet[0],
        "stale-quiet",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    (quiet[1] / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(quiet[0], "stale-quiet", quiet[1], replace=True)
    write_assessment(quiet[0], "stale-quiet", actor="Ada")
    assert finalize_assessment(quiet[0], "stale-quiet", actor="Ada")["finalized_at"]

    again = _ready(tmp_path, "stale-again")
    runner = _investigate(again[0], "stale-again", ["app.py"])
    set_verdict(
        again[0],
        "stale-again",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    (again[1] / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(again[0], "stale-again", again[1], replace=True)
    _investigate(again[0], "stale-again", ["app.py"], runner=runner)
    write_assessment(again[0], "stale-again", actor="Ada")
    with pytest.raises(EngagementError, match="1 candidate needs re-review on the current snapshot."):
        finalize_assessment(again[0], "stale-again", actor="Ada")

    unknown = _ready(tmp_path, "stale-rerun")
    _investigate(unknown[0], "stale-rerun", ["app.py"])
    set_verdict(
        unknown[0],
        "stale-rerun",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    (unknown[1] / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(unknown[0], "stale-rerun", unknown[1], replace=True)
    investigation_id = json.loads(
        (unknown[0] / "stale-rerun" / "investigations.json").read_text(encoding="utf-8")
    )[0]["id"]
    rerun_investigation(
        unknown[0],
        "stale-rerun",
        investigation_id,
        actor="Ada",
        runner=_counting_runner(["app.py"], start=2),
    )
    write_assessment(unknown[0], "stale-rerun", actor="Ada")
    with pytest.raises(EngagementError, match="1 candidate needs re-review on the current snapshot."):
        finalize_assessment(unknown[0], "stale-rerun", actor="Ada")


def test_rerun_on_the_old_snapshot_does_not_block_after_a_new_intake(tmp_path: Path) -> None:
    root, source = _ready(tmp_path, "old-rerun")
    _investigate(root, "old-rerun", ["app.py"])
    set_verdict(
        root,
        "old-rerun",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    path = root / "old-rerun" / "investigations.json"
    investigation_id = json.loads(path.read_text(encoding="utf-8"))[0]["id"]
    original = str(load_engagement(root, "old-rerun")["snapshot_sha256"])
    rerun_investigation(
        root,
        "old-rerun",
        investigation_id,
        actor="Ada",
        runner=_counting_runner(["app.py"], start=2),
    )
    runs = json.loads(path.read_text(encoding="utf-8"))[0]["runs"]
    assert [run["snapshot_sha256"] for run in runs] == [original, original]
    (source / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(root, "old-rerun", source, replace=True)
    assert load_engagement(root, "old-rerun")["snapshot_sha256"] != original
    recorded = path.read_text(encoding="utf-8")
    planted = json.loads(recorded)
    del planted[0]["runs"][1]["snapshot_sha256"]
    path.write_text(json.dumps(planted), encoding="utf-8")
    write_assessment(root, "old-rerun", actor="Ada")
    with pytest.raises(EngagementError, match="1 candidate needs re-review on the current snapshot."):
        finalize_assessment(root, "old-rerun", actor="Ada")
    path.write_text(recorded, encoding="utf-8")
    assert finalize_assessment(root, "old-rerun", actor="Ada")["finalized_at"]


def test_verdict_on_a_stale_candidate_binds_the_current_snapshot(tmp_path: Path) -> None:
    root, source = _ready(tmp_path, "rebind")
    runner = _investigate(root, "rebind", ["app.py"])
    set_verdict(
        root,
        "rebind",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    (source / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(root, "rebind", source, replace=True)
    _investigate(root, "rebind", ["app.py"], runner=runner)
    write_assessment(root, "rebind", actor="Ada")
    with pytest.raises(EngagementError, match="1 candidate needs re-review on the current snapshot."):
        finalize_assessment(root, "rebind", actor="Ada")
    set_verdict(
        root,
        "rebind",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed on the current snapshot.",
    )
    stored = json.loads((root / "rebind" / "candidates.json").read_text(encoding="utf-8"))
    record = next(iter(stored.values()))
    current = str(load_engagement(root, "rebind")["snapshot_sha256"])
    assert record["snapshot_sha256"] == current
    assert record["stale"] is False
    assert set(record) == {
        "fingerprint",
        "engagement_id",
        "file_path",
        "cwe",
        "state",
        "actor",
        "note",
        "updated_at",
        "runs",
        "snapshot_sha256",
        "stale",
    }
    listed = list_candidates(root, "rebind")
    assert listed[0]["stale"] is False
    assert listed[0]["presentation_state"] == "confirmed"
    assert finalize_assessment(root, "rebind", actor="Ada")["finalized_at"]


def test_advisory_dismissal_records_confirmed_on_the_audit_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _source = _ready(tmp_path, "dismiss-me")
    _cache(tmp_path, monkeypatch, "The failure is in jwt/algorithms.py.")
    _investigate(
        root,
        "dismiss-me",
        [CANDIDATE],
        cwe="CWE-327",
        advisory_id="CVE-2022-29217",
    )
    with pytest.raises(VerdictError) as missing:
        set_verdict(
            root,
            "dismiss-me",
            file_path=CANDIDATE,
            cwe="CWE-327",
            state="not_actionable",
            actor="Ada",
            note="Too short to explain the comparison.",
        )
    assert "confirmed" in missing.value.errors
    stored = json.loads((root / "dismiss-me" / "candidates.json").read_text(encoding="utf-8"))
    record = next(iter(stored.values()))
    assert record["state"] == "candidate"
    assert "confirmed" not in record
    with pytest.raises(VerdictError) as short:
        set_verdict(
            root,
            "dismiss-me",
            file_path=CANDIDATE,
            cwe="CWE-327",
            state="not_actionable",
            actor="Ada",
            note="Too short to explain the comparison.",
            confirmed=True,
        )
    assert "note" in short.value.errors
    assert record["state"] == "candidate"
    set_verdict(
        root,
        "dismiss-me",
        file_path=CANDIDATE,
        cwe="CWE-327",
        state="confirmed",
        actor="Ada",
        note="Holding it for now.",
    )
    with pytest.raises(VerdictError):
        set_verdict(
            root,
            "dismiss-me",
            file_path=CANDIDATE,
            cwe="CWE-327",
            state="not_actionable",
            actor="Ada",
            note=LONG_NOTE,
        )
    kept = json.loads((root / "dismiss-me" / "candidates.json").read_text(encoding="utf-8"))
    assert next(iter(kept.values()))["state"] == "confirmed"
    set_verdict(
        root,
        "dismiss-me",
        file_path=CANDIDATE,
        cwe="CWE-327",
        state="not_actionable",
        actor="Ada",
        note=LONG_NOTE,
        confirmed=True,
    )
    saved = json.loads((root / "dismiss-me" / "candidates.json").read_text(encoding="utf-8"))
    candidate = next(iter(saved.values()))
    assert candidate["state"] == "not_actionable"
    assert "confirmed" not in candidate
    verdicts = [row for row in read_durable_audit(root, "dismiss-me") if row["action"] == "verdict"]
    assert verdicts[-1]["to_state"] == "not_actionable"
    assert verdicts[-1]["confirmed"] is True
    write_assessment(root, "dismiss-me", actor="Ada")
    assert finalize_assessment(root, "dismiss-me", actor="Ada")["finalized_at"]


def test_basename_mention_does_not_require_the_long_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _source = _ready(tmp_path, "basename-me")
    _cache(tmp_path, monkeypatch, "The file algorithms.py is involved.")
    _investigate(root, "basename-me", [CANDIDATE], cwe="CWE-327", advisory_id="CVE-2022-29217")
    with pytest.raises(VerdictError) as missing:
        set_verdict(
            root,
            "basename-me",
            file_path=CANDIDATE,
            cwe="CWE-327",
            state="not_actionable",
            actor="Ada",
            note="Short note.",
        )
    assert "confirmed" in missing.value.errors
    assert "note" not in missing.value.errors
    set_verdict(
        root,
        "basename-me",
        file_path=CANDIDATE,
        cwe="CWE-327",
        state="not_actionable",
        actor="Ada",
        note="Short note.",
        confirmed=True,
    )
    verdicts = [row for row in read_durable_audit(root, "basename-me") if row["action"] == "verdict"]
    assert verdicts[-1]["confirmed"] is True


def test_exploratory_not_actionable_needs_no_checkbox(tmp_path: Path) -> None:
    root, _source = _ready(tmp_path, "explore-me")
    _investigate(root, "explore-me", ["app.py"])
    set_verdict(
        root,
        "explore-me",
        file_path="app.py",
        cwe="CWE-89",
        state="not_actionable",
        actor="Ada",
        note="Not this file.",
    )
    verdicts = [row for row in read_durable_audit(root, "explore-me") if row["action"] == "verdict"]
    assert verdicts[-1]["to_state"] == "not_actionable"
    assert "confirmed" not in verdicts[-1]


def test_cli_confirm_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    root, _source = _ready(tmp_path, "cli-dismiss")
    _cache(tmp_path, monkeypatch, "The failure is in jwt/algorithms.py.")
    _investigate(root, "cli-dismiss", [CANDIDATE], cwe="CWE-327", advisory_id="CVE-2022-29217")
    refused = main(
        [
            "verdict",
            "--engagement",
            "cli-dismiss",
            "--path",
            CANDIDATE,
            "--cwe",
            "CWE-327",
            "--state",
            "not_actionable",
            "--actor",
            "Ada",
            "--note",
            LONG_NOTE,
            "--engagements-root",
            str(root),
        ]
    )
    assert refused == 2
    assert "compared" in capsys.readouterr().err
    accepted = main(
        [
            "verdict",
            "--engagement",
            "cli-dismiss",
            "--path",
            CANDIDATE,
            "--cwe",
            "CWE-327",
            "--state",
            "not_actionable",
            "--actor",
            "Ada",
            "--note",
            LONG_NOTE,
            "--confirm-advisory",
            "--engagements-root",
            str(root),
        ]
    )
    assert accepted == 0
    verdicts = [row for row in read_durable_audit(root, "cli-dismiss") if row["action"] == "verdict"]
    assert verdicts[-1]["confirmed"] is True


def test_advisory_matching_makes_no_network_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network")

    monkeypatch.setattr("urllib.request.urlopen", explode)
    monkeypatch.setattr("astrolabe.advisories.fetch_json", explode)
    root, _source = _ready(tmp_path, "offline-match")
    _cache(tmp_path, monkeypatch, "The failure is in jwt/algorithms.py.")
    _investigate(root, "offline-match", [CANDIDATE], cwe="CWE-327", advisory_id="CVE-2022-29217")
    from astrolabe.advisory_review import advisory_contexts

    contexts = advisory_contexts(root, "offline-match", {"file_path": CANDIDATE, "cwe": "CWE-327"})
    assert contexts[0].label == "CVE-2022-29217"
    assert contexts[0].names_file is True
    assert contexts[0].match.source == "advisory text"


def _ready(tmp_path: Path, engagement_id: str) -> tuple[Path, Path]:
    root = tmp_path / "engagements"
    root.mkdir(exist_ok=True)
    create_engagement(
        root,
        engagement_id=engagement_id,
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    source = tmp_path / engagement_id
    (source / "jwt").mkdir(parents=True)
    (source / "jwt" / "algorithms.py").write_text("def decode():\n    return None\n", encoding="utf-8")
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    (source / "pending.py").write_text("pending\n", encoding="utf-8")
    (source / "held.py").write_text("held\n", encoding="utf-8")
    (source / "ok.py").write_text("ok\n", encoding="utf-8")
    (source / "dismissed.py").write_text("dismissed\n", encoding="utf-8")
    intake_local(root, engagement_id, source)
    attest(
        root,
        engagement_id,
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    return root, source


def _cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, details: str) -> None:
    cache = tmp_path / "advisories"
    cache.mkdir(exist_ok=True)
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(cache))
    (cache / "CVE-2022-29217.json").write_text(
        json.dumps(
            {
                "id": "CVE-2022-29217",
                "summary": SUMMARY,
                "details": details,
                "aliases": ["GHSA-ffqj-6fqr-9h24"],
                "cwe_ids": ["CWE-327"],
                "source_urls": ["https://osv.dev/vulnerability/CVE-2022-29217"],
                "fetched_at": "2026-10-10T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )


def _investigate(
    root: Path,
    engagement_id: str,
    paths: list[str],
    *,
    cwe: str = "CWE-89",
    advisory_id: str | None = None,
    runner=None,
):
    chosen = runner or _counting_runner(paths)
    kwargs: dict[str, object] = {"cwe": cwe, "actor": "Ada", "runner": chosen}
    if advisory_id:
        kwargs["advisory_id"] = advisory_id
    else:
        kwargs["exploratory"] = True
    start_investigation(root, engagement_id, **kwargs)  # type: ignore[arg-type]
    return chosen


def _counting_runner(paths: list[str], *, start: int = 1):
    names = iter([f"run-{index}" for index in range(start, start + 8)])

    def run(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        report_dir = engagement / "antares-data" / "reports" / next(names)
        report_dir.mkdir(parents=True)
        findings = [
            {
                "file_path": path,
                "submission_rank": index + 1,
                "cwe_ids": ["CWE-89"],
                "likelihood_of_exploit": "High",
            }
            for index, path in enumerate(paths)
        ]
        (report_dir / "report.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")
        return CompletedProcess(command, 0)

    return run
