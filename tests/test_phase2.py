import hashlib
import io
import json
import re
import tarfile
import threading
import zipfile
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.engagement import (
    EngagementError,
    append_durable_audit,
    attest,
    create_engagement,
    durable_audit_path,
    has_attestation,
    load_engagement,
    read_attestation,
    read_durable_audit,
    read_instance_attestation,
)
from astrolabe.intake import intake_local, snapshot_content_hash
from astrolabe.investigate import consultant_line, rerun_investigation, start_investigation
from astrolabe.candidates import confirmed_for_report, set_verdict
from astrolabe.coverage import rebuild_coverage
from astrolabe.purge import _add_full_bundle, close_engagement, export_engagement, purge_engagement
from astrolabe.redact import REDACTED, read_report, read_trace
from astrolabe.runner import main
from tests.secret_fixtures import (
    aws_example_key,
    bearer_secret,
    bearer_token,
    certificate_body,
    certificate_pem,
    connection_password,
    commit_sha,
    connection_url,
    ecdsa_prefix,
    ecdsa_sha2_token,
    ed25519_prefix,
    high_entropy_token,
    pem_marker,
    private_key_body,
    private_key_pem,
    public_key_body,
    public_key_pem,
    sk_ecdsa_token,
    sk_ssh_token,
    ssh_ed25519_token,
    unsigned_jwt,
)


def _root(tmp_path: Path) -> Path:
    path = tmp_path / "engagements"
    path.mkdir()
    return path


def _create(root: Path, engagement_id: str = "acme-2026") -> None:
    create_engagement(
        root,
        engagement_id=engagement_id,
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("def pay():\n    return 1\n", encoding="utf-8")
    (source / "tests").mkdir()
    (source / "tests" / "test_app.py").write_text("def test_pay():\n    pass\n", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("git\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (source / "escape").symlink_to(outside)
    return source


def _attest(root: Path, engagement_id: str = "acme-2026") -> None:
    attest(
        root,
        engagement_id,
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )


def _runner(paths: list[str], *, report_name: str):
    def run(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        report_dir = engagement / "antares-data" / "reports" / report_name
        report_dir.mkdir(parents=True)
        findings = [{"file_path": path, "submission_rank": index + 1, "cwe_ids": ["CWE-89"]} for index, path in enumerate(paths)]
        report = {
            "findings": findings,
            "summary": {"tool_call_count": 2},
            "metadata": {"api_key": "fixture-api-key", "endpoint": "http://127.0.0.1/v1/completions"},
        }
        (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        trace = engagement / "antares-data" / "traces"
        trace.mkdir(parents=True, exist_ok=True)
        event = {"phase": "message", "payload": {"role": "user", "content": "fixture-advisory-body"}}
        (trace / "run.investigation.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
        return CompletedProcess(command, 0)

    return run


def test_scan_refuses_without_attestation(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    intake_local(root, "acme-2026", _source(tmp_path))
    with pytest.raises(EngagementError, match="attestation"):
        start_investigation(
            root,
            "acme-2026",
            cwe="CWE-89",
            actor="Ada",
            exploratory=True,
            runner=_runner(["app.py"], report_name="run-1"),
        )


def test_intake_hashes_snapshot_and_drops_git_tests_and_symlinks(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    record = intake_local(root, "acme-2026", _source(tmp_path))
    directory = root / "acme-2026"
    assert (directory / "src" / "app.py").is_file()
    assert (directory / "snapshot" / "app.py").is_file()
    assert not (directory / "src" / ".git").exists()
    assert not (directory / "src" / "tests").exists()
    assert not (directory / "src" / "escape").exists()
    digest = record["snapshot_sha256"]
    assert digest == snapshot_content_hash(directory / "snapshot")
    assert len(digest) == 64
    (directory / "snapshot" / "app.py").write_text("changed\n", encoding="utf-8")
    assert snapshot_content_hash(directory / "snapshot") != digest


def test_intake_rejects_git_host(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    with pytest.raises(EngagementError, match="git host"):
        intake_local(root, "acme-2026", Path("https://github.com/example/repo"))


def test_archive_intake(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    archive = tmp_path / "src.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("pkg/app.py", "x = 1\n")
        bundle.writestr("README", "hi\n")
    record = intake_local(root, "acme-2026", archive)
    assert (root / "acme-2026" / "src" / "pkg" / "app.py").read_text(encoding="utf-8") == "x = 1\n"
    assert (root / "acme-2026" / "intake" / "src.zip").is_file()
    assert record["intake"]["stripped_prefix"] is None


def _tar_with_root(path: Path, root_name: str, files: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as bundle:
        for relative, text in files.items():
            payload = text.encode("utf-8")
            info = tarfile.TarInfo(f"{root_name}/{relative}")
            info.size = len(payload)
            bundle.addfile(info, io.BytesIO(payload))


def test_archive_root_is_stripped_and_a_repack_keeps_the_verdict(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    body = "def prepare_key():\n    return None\n"
    first = tmp_path / "pyjwt-2.3.0.tar.gz"
    second = tmp_path / "pyjwt-2.3.1.tar.gz"
    _tar_with_root(first, "pyjwt-2.3.0", {"jwt/algorithms.py": body})
    _tar_with_root(second, "pyjwt-2.3.1", {"jwt/algorithms.py": body})
    record = intake_local(root, "acme-2026", first)
    assert record["intake"]["stripped_prefix"] == "pyjwt-2.3.0"
    assert (root / "acme-2026" / "snapshot" / "jwt" / "algorithms.py").read_text(encoding="utf-8") == body
    assert not (root / "acme-2026" / "snapshot" / "pyjwt-2.3.0").exists()
    _attest(root)
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-327",
        actor="Ada",
        exploratory=True,
        runner=_runner(["jwt/algorithms.py"], report_name="run-1"),
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="jwt/algorithms.py",
        cwe="CWE-327",
        state="confirmed",
        actor="Ada",
        note="The key check lives in this file.",
    )
    replaced = intake_local(root, "acme-2026", second, replace=True)
    assert replaced["intake"]["stripped_prefix"] == "pyjwt-2.3.1"
    assert replaced["snapshot_sha256"] == record["snapshot_sha256"]
    coverage = rebuild_coverage(root, "acme-2026")
    assert len(coverage["candidates"]) == 1
    carried = coverage["candidates"][0]
    assert carried["file_path"] == "jwt/algorithms.py"
    assert carried["state"] == "confirmed"
    assert carried["stale"] is False
    assert carried["confirmed_for_report"] is True


def test_consultant_line_names_candidates_pending_review() -> None:
    line = consultant_line(
        {
            "id": "inv-1",
            "exploratory": True,
            "cwe": "CWE-22",
            "runs": [{"candidate_paths": ["jwt/utils.py"]}],
        }
    )
    assert line == "inv-1 mode=exploratory cwe=CWE-22 candidates=1 pending consultant review"
    assert "finding" not in line.lower()
    assert "likelihood" not in line.lower()


def test_advisory_text_is_stored_and_exploratory_is_labeled(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    intake_local(root, "acme-2026", _source(tmp_path))
    _attest(root)
    calls: list[list[str]] = []

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        calls.append(command)
        return _runner(["app.py"], report_name="run-1")(engagement, command)

    advisory = "Use parameterized queries in the billing module."
    investigation = start_investigation(
        root,
        "acme-2026",
        cwe="89",
        actor="Ada",
        advisory_text=advisory,
        runner=runner,
    )
    assert investigation["query_text"] == advisory
    assert investigation["exploratory"] is False
    assert calls[0][calls[0].index("--query") + 1] == advisory
    coverage = rebuild_coverage(root, "acme-2026")
    assert coverage["cwes"][0]["mode"] == "advisory"
    assert coverage["cwes"][0]["exploratory"] is False

    exploratory = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-22",
        actor="Ada",
        exploratory=True,
        runner=runner,
    )
    assert exploratory["query_text"] is None
    assert exploratory["exploratory"] is True
    assert "--query" not in calls[1]
    coverage = rebuild_coverage(root, "acme-2026")
    modes = {item["cwe"]: item["mode"] for item in coverage["cwes"]}
    assert modes["CWE-22"] == "exploratory"


def test_cached_advisory_and_missing_id_fails_closed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    cache = tmp_path / "advisories"
    cache.mkdir()
    (cache / "CVE-2024-0001.json").write_text(
        json.dumps({"id": "CVE-2024-0001", "summary": "Summary line", "details": "Detail line"}),
        encoding="utf-8",
    )
    _create(root)
    intake_local(root, "acme-2026", _source(tmp_path))
    _attest(root)
    seen: list[str] = []

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        seen.append(command[command.index("--query") + 1])
        return _runner(["app.py"], report_name="run-1")(engagement, command)

    investigation = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_id="CVE-2024-0001",
        cache=cache,
        runner=runner,
    )
    assert investigation["query_text"] == "Summary line\n\nDetail line"
    assert seen == ["Summary line\n\nDetail line"]
    with pytest.raises(EngagementError, match="not in the local cache"):
        start_investigation(
            root,
            "acme-2026",
            cwe="CWE-89",
            actor="Ada",
            advisory_id="CVE-1999-0001",
            cache=cache,
            runner=runner,
        )


def test_verdict_carries_across_rerun_and_rerun_does_not_add_coverage(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    intake_local(root, "acme-2026", _source(tmp_path))
    _attest(root)
    batches = [["app.py"], ["app.py", "other.py"]]
    names = ["run-1", "run-2"]

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        return _runner(batches.pop(0), report_name=names.pop(0))(engagement, command)

    investigation = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=runner,
    )
    confirmed = set_verdict(
        root,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed the query construction.",
    )
    rerun_investigation(root, "acme-2026", str(investigation["id"]), actor="Ada", runner=runner)
    coverage = rebuild_coverage(root, "acme-2026")
    assert coverage["cwe_coverage_count"] == 1
    assert coverage["cwes"][0]["coverage_count"] == 1
    assert coverage["cwes"][0]["runs"] == 2
    assert [run["increases_coverage"] for run in coverage["runs"]] == [True, False]
    states = {item["file_path"]: item["state"] for item in coverage["candidates"]}
    assert states["app.py"] == "confirmed"
    assert states["other.py"] == "candidate"
    assert confirmed["fingerprint"]
    assert confirmed["snapshot_sha256"]
    audit = read_durable_audit(root, "acme-2026")
    verdict = next(row for row in audit if row["action"] == "verdict")
    assert verdict["snapshot_sha256"] == confirmed["snapshot_sha256"]
    assert verdict["actor"] == "Ada"
    assert verdict["note"] == "Reviewed the query construction."
    assert verdict["from_state"] == "candidate"
    assert verdict["to_state"] == "confirmed"


def test_report_and_trace_reads_are_redacted(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "findings": [{"file_path": "app.py", "submission_rank": 1}],
                "metadata": {"api_key": "fixture-api-key", "endpoint": "http://127.0.0.1/v1"},
            }
        ),
        encoding="utf-8",
    )
    loaded = read_report(report_path)
    assert loaded["findings"][0]["file_path"] == "app.py"
    assert loaded["metadata"]["api_key"] == REDACTED
    assert loaded["metadata"]["endpoint"] != "http://127.0.0.1/v1"
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_text(
        json.dumps({"phase": "message", "payload": {"role": "user", "content": "fixture-advisory-body"}})
        + "\n",
        encoding="utf-8",
    )
    events = read_trace(trace_path)
    assert events[0]["payload"]["content"] == "fixture-advisory-body"


def test_purge_removes_the_engagement_and_leaves_only_the_purge_record(tmp_path: Path) -> None:
    root = _root(tmp_path)
    engagement_id = "acme-2026"
    _create(root, engagement_id)
    intake_local(root, engagement_id, _source(tmp_path))
    _attest(root, engagement_id)
    (root / engagement_id / "src" / "marker.txt").write_text(engagement_id + "\n", encoding="utf-8")
    (root / engagement_id / "plans.json").write_text('{"recommended": {}}\n', encoding="utf-8")
    assert (root / engagement_id / "plans.json").is_file()
    with pytest.raises(EngagementError, match="Close"):
        purge_engagement(root, engagement_id, actor="Ada")
    close_engagement(root, engagement_id, actor="Ada")
    exported = export_engagement(root, engagement_id, tmp_path / "export.tar.gz", actor="Ada")
    assert exported.is_file()
    entry = purge_engagement(root, engagement_id, actor="Ada", confirm_exports_handled=True)
    assert exported.is_file()
    assert not (root / engagement_id).exists()
    assert not (root / engagement_id / "plans.json").exists()
    for name in ("src", "snapshot", "antares-data", "socket", "reports"):
        assert not (root / engagement_id / name).exists()
    haystack = []
    for path in root.rglob("*"):
        haystack.append(str(path))
        if path.is_file():
            haystack.append(path.read_text(encoding="utf-8", errors="replace"))
    assert engagement_id not in "\n".join(haystack)
    log = next(row for row in read_durable_audit(root, engagement_id) if row["action"] == "purge")
    assert log["engagement_id"] == engagement_id
    assert log["actor"] == "Ada"
    assert log["timestamp"].endswith("Z")
    assert log["files_removed"] == entry["files_removed"]
    assert log["files_removed"] > 0


def test_cli_create_and_attest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _root(tmp_path)
    assert (
        main(
            [
                "engagement",
                "create",
                "--id",
                "acme-2026",
                "--customer",
                "Acme",
                "--scope",
                "Billing service",
                "--start",
                "2026-10-09",
                "--consultant",
                "Ada",
                "--engagements-root",
                str(root),
            ]
        )
        == 0
    )
    assert "Attestation required: run astrolabe attest." in capsys.readouterr().out
    assert has_attestation(root, "acme-2026") is False
    assert (
        main(
            [
                "attest",
                "--engagement",
                "acme-2026",
                "--actor",
                "Ada",
                "--reference",
                "SOW-14",
                "--scope",
                "Billing service",
                "--engagements-root",
                str(root),
            ]
        )
        == 0
    )
    assert has_attestation(root, "acme-2026") is True
    refused = main(
        [
            "investigate",
            "--engagement",
            "acme-2026",
            "--cwe",
            "CWE-89",
            "--actor",
            "Ada",
            "--exploratory",
            "--engagements-root",
            str(root),
        ]
    )
    assert refused == 2
    assert (
        main(
            [
                "engagement",
                "create",
                "--id",
                "acme-attested",
                "--customer",
                "Acme",
                "--scope",
                "Billing service",
                "--start",
                "2026-10-09",
                "--consultant",
                "Ada",
                "--reference",
                "SOW-14",
                "--authorized",
                "--engagements-root",
                str(root),
            ]
        )
        == 0
    )
    captured = capsys.readouterr().out
    assert "Attestation required: run astrolabe attest." not in captured
    assert has_attestation(root, "acme-attested") is True


def test_cli_rejects_an_actor_who_is_not_a_consultant(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    _create(root)
    commands = [
        ["engagement", "close", "--id", "acme-2026", "--actor", "Grace"],
        ["attest", "--engagement", "acme-2026", "--actor", "Grace", "--reference", "SOW-14", "--scope", "Billing service"],
        ["investigate", "--engagement", "acme-2026", "--cwe", "CWE-89", "--actor", "Grace", "--exploratory"],
        ["rerun", "--engagement", "acme-2026", "--investigation", "inv-1", "--actor", "Grace"],
        ["verdict", "--engagement", "acme-2026", "--path", "app.py", "--cwe", "CWE-89", "--state", "confirmed", "--actor", "Grace", "--note", "n"],
        ["export", "--engagement", "acme-2026", "--output", str(tmp_path / "out.tar.gz"), "--actor", "Grace"],
        ["purge", "--engagement", "acme-2026", "--actor", "Grace"],
        ["advisories", "sync", "--engagement", "acme-2026", "--id", "CVE-2024-0001", "--actor", "Grace"],
        ["report", "assessment", "--engagement", "acme-2026", "--actor", "Grace"],
        ["report", "remediation", "--engagement", "acme-2026", "--actor", "Grace"],
        ["report", "finalize", "--engagement", "acme-2026", "--actor", "Grace"],
    ]
    for argv in commands:
        assert main([*argv, "--engagements-root", str(root)]) == 2
        assert capsys.readouterr().err.strip() == "Actor Grace is not a consultant on acme-2026."
    assert load_engagement(root, "acme-2026")["state"] == "open"


def _advisory_record(advisory_id: str, *, opener: object = None) -> dict[str, object]:
    return {
        "id": advisory_id,
        "summary": "stub",
        "details": "stub",
        "aliases": [advisory_id],
        "cwe_ids": [],
        "source_urls": [f"https://osv.dev/vulnerability/{advisory_id}"],
        "source": "osv",
        "fetched_at": "2026-10-11T00:00:00Z",
    }


def _audit_lines(root: Path) -> list[dict[str, object]]:
    path = durable_audit_path(root)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_advisories_sync_engagement_is_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _root(tmp_path)
    _create(root)
    cache = tmp_path / "cache"
    monkeypatch.setattr("astrolabe.advisories.fetch_advisory_record", _advisory_record)
    assert (
        main(
            [
                "advisories",
                "sync",
                "--engagement",
                "acme-2026",
                "--id",
                "CVE-2024-0001",
                "--actor",
                "Grace",
                "--cache",
                str(cache),
                "--engagements-root",
                str(root),
            ]
        )
        == 2
    )
    assert capsys.readouterr().err.strip() == "Actor Grace is not a consultant on acme-2026."
    assert main(
        [
            "advisories",
            "sync",
            "--engagement",
            "acme-2026",
            "--id",
            "CVE-2024-0001",
            "--actor",
            "Ada",
            "--cache",
            str(cache),
            "--engagements-root",
            str(root),
        ]
    ) == 0
    capsys.readouterr()
    recorded = [line for line in _audit_lines(root) if line.get("action") == "advisories_sync"]
    assert recorded[-1]["engagement_id"] == "acme-2026"
    assert recorded[-1]["actor"] == "Ada"
    assert (
        main(
            [
                "advisories",
                "sync",
                "--id",
                "CVE-2024-0002",
                "--actor",
                "Pat",
                "--cache",
                str(cache),
                "--engagements-root",
                str(root),
            ]
        )
        == 0
    )
    capsys.readouterr()
    cache_level = [line for line in _audit_lines(root) if line.get("scope") == "advisory_cache"]
    assert len(cache_level) == 1
    assert "engagement_id" not in cache_level[0]
    assert cache_level[0]["actor"] == "Pat"
    assert (
        main(
            [
                "advisories",
                "sync",
                "--engagement",
                "missing-2026",
                "--id",
                "CVE-2024-0003",
                "--actor",
                "Ada",
                "--cache",
                str(cache),
                "--engagements-root",
                str(root),
            ]
        )
        == 2
    )
    assert capsys.readouterr().err.strip() == "Engagement missing-2026 not found."
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "GHSA-1234-abcd-5678.json").write_text(
        json.dumps({"id": "GHSA-1234-abcd-5678", "summary": "Prepared", "details": "Local"}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "advisories",
                "import",
                str(prepared),
                "--cache",
                str(cache),
            ]
        )
        == 0
    )
    assert "GHSA-1234-abcd-5678" in capsys.readouterr().out


def test_attestation_is_readable_after_purge(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    _attest(root)
    intake_local(root, "acme-2026", _source(tmp_path))
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=_runner(["app.py"], report_name="run-1"),
    )
    close_engagement(root, "acme-2026", actor="Ada")
    purge_engagement(root, "acme-2026", actor="Ada")
    assert not (root / "acme-2026").exists()
    attestation = read_attestation(root, "acme-2026")
    assert attestation is not None
    assert attestation["actor"] == "Ada"
    assert attestation["reference"] == "SOW-14"
    assert attestation["scope"] == "Billing service"
    assert attestation["attested_at"] == "2026-10-09T15:00:00Z"


def test_purge_reports_exports_and_leaves_them_on_disk(tmp_path: Path) -> None:
    root = _root(tmp_path)
    engagement_id = "acme-2026"
    _create(root, engagement_id)
    intake_local(root, engagement_id, _source(tmp_path))
    _attest(root, engagement_id)
    close_engagement(root, engagement_id, actor="Ada")
    destination = tmp_path / "kept.tar.gz"
    export_engagement(root, engagement_id, destination, actor="Ada")
    with pytest.raises(EngagementError, match="kept.tar.gz"):
        purge_engagement(root, engagement_id, actor="Ada")
    assert (root / engagement_id).is_dir()
    assert destination.is_file()
    entry = purge_engagement(root, engagement_id, actor="Ada", confirm_exports_handled=True)
    assert destination.is_file()
    assert not (root / engagement_id).exists()
    recorded = next(row for row in read_durable_audit(root, engagement_id) if row["action"] == "export")
    assert recorded["actor"] == "Ada"
    assert recorded["path"] == str(destination.resolve())
    assert recorded["size"] == destination.stat().st_size
    assert recorded["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert str(destination.resolve()) in entry["exports_still_present"]


def test_reintake_marks_a_carried_verdict_stale(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    source = _source(tmp_path)
    intake_local(root, "acme-2026", source)
    _attest(root)
    first_hash = snapshot_content_hash(root / "acme-2026" / "snapshot")

    names = iter(("run-1", "run-2"))

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        return _runner(["app.py"], report_name=next(names))(engagement, command)

    investigation = start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=runner,
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed the query construction.",
    )
    (source / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(root, "acme-2026", source, replace=True)
    second_hash = snapshot_content_hash(root / "acme-2026" / "snapshot")
    assert second_hash != first_hash
    coverage = rebuild_coverage(root, "acme-2026")
    carried = coverage["candidates"][0]
    assert carried["state"] == "confirmed"
    assert carried["stale"] is True
    assert carried["presentation_state"] == "stale"
    assert carried["confirmed_for_report"] is False
    assert coverage["verdicts"]["confirmed"] == 0
    assert coverage["verdicts"]["stale"] == 1
    rerun_investigation(root, "acme-2026", str(investigation["id"]), actor="Ada", runner=runner)
    coverage = rebuild_coverage(root, "acme-2026")
    returned = coverage["candidates"][0]
    assert returned["state"] == "confirmed"
    assert returned["snapshot_sha256"] == first_hash
    assert confirmed_for_report(returned) is False
    set_verdict(
        root,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Re-confirmed against the new snapshot.",
    )
    coverage = rebuild_coverage(root, "acme-2026")
    fresh = coverage["candidates"][0]
    assert fresh["stale"] is False
    assert fresh["presentation_state"] == "confirmed"
    assert fresh["confirmed_for_report"] is True
    assert fresh["snapshot_sha256"] == second_hash
    assert coverage["verdicts"]["confirmed"] == 1


def test_trace_source_excerpts_redact_each_secret_pattern(tmp_path: Path) -> None:
    aws_key = aws_example_key()
    private_key = private_key_pem()
    connection = connection_url()
    bearer = bearer_token()
    jwt = unsigned_jwt()
    high_entropy = high_entropy_token()
    excerpt = "\n".join(
        [
            "def load_user():",
            f"    key = {aws_key!r}",
            f"    pem = {private_key!r}",
            f"    url = {connection!r}",
            f"    header = {bearer!r}",
            f"    token = {jwt!r}",
            f"    blob = {high_entropy!r}",
            '    return open("app.py")',
        ]
    )
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_text(
        json.dumps(
            {
                "phase": "tool_result",
                "payload": {
                    "tool_name": "read_file",
                    "result_summary": excerpt,
                    "password": "short",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    events = read_trace(trace_path)
    rendered = json.dumps(events)
    payload = events[0]["payload"]
    assert "def load_user" in payload["result_summary"]
    assert "app.py" in payload["result_summary"]
    assert payload["password"] == REDACTED
    for secret in (aws_key, private_key_body(), connection_password(), bearer_secret(), jwt, high_entropy):
        assert secret not in rendered
    assert pem_marker("PRIVATE KEY") not in rendered


def test_full_export_redacts_pem_tokens_and_base64_in_query_text_and_traces(tmp_path: Path) -> None:
    aws_key = aws_example_key()
    private_key = private_key_pem()
    certificate = certificate_pem()
    public_key = public_key_pem()
    bearer = bearer_token()
    jwt = unsigned_jwt()
    high_entropy = high_entropy_token()
    long_base64 = "A" * 48
    snapshot = "ab" * 32
    query = "\n".join(
        [private_key, certificate, public_key, aws_key, bearer, jwt, high_entropy, long_base64]
    )
    directory = tmp_path / "eng"
    traces = directory / "antares-data" / "traces"
    traces.mkdir(parents=True)
    (directory / "investigations.json").write_text(
        json.dumps([{"id": "inv-1", "query_text": query, "snapshot_sha256": snapshot}]) + "\n",
        encoding="utf-8",
    )
    (directory / "engagement.json").write_text(
        json.dumps({"id": "eng", "snapshot_sha256": snapshot}) + "\n",
        encoding="utf-8",
    )
    (traces / "run.jsonl").write_text(
        json.dumps(
            {
                "phase": "message",
                "query_text": query,
                "payload": {"role": "user", "content": query},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    bundle_path = tmp_path / "full.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as bundle:
        _add_full_bundle(bundle, directory)
    with tarfile.open(bundle_path) as bundle:
        exported = b"".join(
            member.read() for member in (bundle.extractfile(name) for name in bundle.getnames()) if member is not None
        )
    for secret in (
        pem_marker("PRIVATE KEY"),
        pem_marker("CERTIFICATE"),
        pem_marker("PUBLIC KEY"),
        private_key_body(),
        certificate_body(),
        public_key_body(),
        aws_key,
        bearer_secret(),
        jwt,
        high_entropy,
        long_base64,
    ):
        assert secret.encode() not in exported
    assert snapshot.encode() in exported
    assert b"query_text" in exported


def test_pasted_advisory_export_redacts_pem_key_tokens_and_base64(tmp_path: Path) -> None:
    pem = private_key_pem()
    base64_run = "Ab+/" * 12
    commit = commit_sha()
    ssh_ed = ssh_ed25519_token()
    ecdsa = ecdsa_sha2_token()
    sk_ssh = sk_ssh_token()
    sk_ecdsa = sk_ecdsa_token()
    ssh_tokens = (ssh_ed, ecdsa, sk_ssh, sk_ecdsa)
    advisory = "\n".join(["Pasted advisory for the fixture.", pem, base64_run, commit, *ssh_tokens])

    def runner(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        query = command[command.index("--query") + 1]
        traces = engagement / "antares-data" / "traces"
        traces.mkdir(parents=True, exist_ok=True)
        event = {
            "phase": "message",
            "query_text": query,
            "payload": {"role": "user", "content": query},
        }
        (traces / "pasted.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
        report_dir = engagement / "antares-data" / "reports" / "run-1"
        report_dir.mkdir(parents=True)
        (report_dir / "report.json").write_text(
            json.dumps({"findings": [], "summary": {}}),
            encoding="utf-8",
        )
        return CompletedProcess(command, 0)

    root = _root(tmp_path)
    _create(root)
    intake_local(root, "acme-2026", _source(tmp_path))
    _attest(root)
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_text=advisory,
        runner=runner,
    )
    close_engagement(root, "acme-2026", actor="Ada")
    bundle_path = export_engagement(root, "acme-2026", tmp_path / "full.tar.gz", actor="Ada")
    with tarfile.open(bundle_path) as bundle:
        exported = b"".join(
            member.read()
            for member in (bundle.extractfile(name) for name in bundle.getnames())
            if member is not None
        )
    for secret in (
        pem_marker("PRIVATE KEY"),
        private_key_body(),
        base64_run,
        "ssh-" + "ed25519",
        ed25519_prefix(),
        ecdsa_prefix(),
        "ecdsa-" + "sha2-" + "nistp256",
        "sk-" + "ssh-",
        "sk-" + "ecdsa-",
    ):
        assert secret.encode() not in exported
    assert commit.encode() in exported
    assert b"Pasted advisory for the fixture." in exported
    assert b"query_text" in exported


def test_redaction_fixtures_have_no_literal_key_token_or_jwt() -> None:
    root = Path(__file__).resolve().parent
    sources = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in root.rglob("*.py")
    }
    assembled = (
        aws_example_key(),
        private_key_pem(),
        certificate_pem(),
        public_key_pem(),
        bearer_token(),
        unsigned_jwt(),
        high_entropy_token(),
        connection_url(),
        ssh_ed25519_token(),
        ecdsa_sha2_token(),
        sk_ssh_token(),
        sk_ecdsa_token(),
        ed25519_prefix(),
        ecdsa_prefix(),
        commit_sha(),
    )
    aws = re.compile(
        r"\b(?:"
        + "AK"
        + "IA|"
        + "AG"
        + "PA|"
        + "AI"
        + "DA|"
        + "AR"
        + "OA|"
        + "AI"
        + "PA|"
        + "AN"
        + "PA|"
        + "AN"
        + "VA|"
        + "AS"
        + "IA"
        + r")[A-Z0-9]{16}\b"
    )
    jwt = re.compile("ey" + r"J[A-Za-z0-9_-]{8,}\." + "ey" + r"J[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    pem = re.compile("-" * 5 + "BEGIN ")
    bearer = re.compile("Bea" + r"rer\s+[A-Za-z0-9._~+/-]{8,}")
    ssh = re.compile("ssh-" + "ed25519|" + "ecdsa-" + "sha2-|" + "sk-" + "ssh-|" + "sk-" + "ecdsa-")
    long_literal = re.compile(r"""['\"][A-Za-z0-9+/=]{40,}['\"]""")
    for name, text in sources.items():
        for secret in assembled:
            assert secret not in text, name
        assert aws.search(text) is None, name
        assert jwt.search(text) is None, name
        assert pem.search(text) is None, name
        assert bearer.search(text) is None, name
        assert ssh.search(text) is None, name
        assert long_literal.search(text) is None, name


def _strip_instance(root: Path, engagement_id: str) -> None:
    path = root / engagement_id / "engagement.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.pop("instance_id", None)
    payload.pop("attestation_migrated", None)
    path.write_text(json.dumps(payload), encoding="utf-8")
    audit_path = root / engagement_id / "audit.jsonl"
    rows = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("action") == "create":
            row["timestamp"] = "2020-01-01T00:00:00Z"
        rows.append(json.dumps(row, sort_keys=True))
    audit_path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_purge_then_same_id_is_refused_and_a_new_id_attests_itself(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root, "pyjwt-230")
    _attest(root, "pyjwt-230")
    close_engagement(root, "pyjwt-230", actor="Ada")
    purge_engagement(root, "pyjwt-230", actor="Ada")
    assert not (root / "pyjwt-230").exists()
    with pytest.raises(EngagementError, match="pyjwt-230b"):
        _create(root, "pyjwt-230")
    assert not (root / "pyjwt-230").exists()
    read_durable_audit(root, "pyjwt-230")
    assert not (root / "pyjwt-230").exists()
    previous = [
        row["instance_id"]
        for row in read_durable_audit(root, "pyjwt-230")
        if row.get("action") == "attest"
    ]
    create_engagement(
        root,
        engagement_id="pyjwt-230b",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
        reference="SOW-14",
        authorized=True,
    )
    assert (root / "pyjwt-230b").is_dir()
    record = load_engagement(root, "pyjwt-230b")
    line = read_instance_attestation(root, record)
    assert line is not None
    assert line["instance_id"] == record["instance_id"]
    assert record["instance_id"] not in previous
    assert has_attestation(root, "pyjwt-230b") is True


def test_migration_does_not_carry_an_attestation_across_a_purge(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    _strip_instance(root, "acme-2026")
    append_durable_audit(root, "acme-2026", {"action": "purge", "actor": "Ada"})
    append_durable_audit(
        root,
        "acme-2026",
        {
            "action": "attest",
            "actor": "Ada",
            "reference": "SOW-14",
            "scope": "Billing service",
            "attested_at": "2026-10-09T15:00:00Z",
        },
    )
    record = load_engagement(root, "acme-2026")
    assert record.get("instance_id")
    assert has_attestation(root, "acme-2026") is False
    carried = [
        row
        for row in read_durable_audit(root, "acme-2026")
        if row.get("action") == "attest" and row.get("instance_id")
    ]
    assert carried == []
    again = load_engagement(root, "acme-2026")
    assert again["instance_id"] == record["instance_id"]
    assert has_attestation(root, "acme-2026") is False


def test_migration_does_not_carry_an_attest_from_before_a_purge_and_later_create(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root, "pyjwt-230")
    directory = root / "pyjwt-230"
    record = json.loads((directory / "engagement.json").read_text(encoding="utf-8"))
    record.pop("instance_id", None)
    record.pop("attestation_migrated", None)
    (directory / "engagement.json").write_text(json.dumps(record), encoding="utf-8")
    (directory / "audit.jsonl").write_text(
        json.dumps(
            {"action": "create", "actor": "consultant", "timestamp": "2026-10-10T19:23:27Z"},
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    log = durable_audit_path(root)
    log.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        {
            "action": "attest",
            "actor": "consultant",
            "attested_at": "2026-10-10T19:19:59Z",
            "engagement_id": "pyjwt-230",
            "reference": "Customer authorization for a point-in-time review of jpadilla/pyjwt at tag 2.3.0",
            "scope": "jpadilla/pyjwt tag 2.3.0, advisory CVE-2022-29217 and exploratory checks",
            "timestamp": "2026-10-10T19:19:59Z",
        },
        {
            "action": "purge",
            "actor": "consultant",
            "engagement_id": "pyjwt-230",
            "timestamp": "2026-10-10T19:20:20Z",
        },
    ]
    original = "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines)
    log.write_text(original, encoding="utf-8")
    loaded = load_engagement(root, "pyjwt-230")
    assert log.read_text(encoding="utf-8") == original
    assert loaded["instance_id"]
    assert has_attestation(root, "pyjwt-230") is False
    carried = [
        row
        for row in read_durable_audit(root, "pyjwt-230")
        if row.get("action") == "attest" and row.get("instance_id")
    ]
    assert carried == []


def test_migration_carries_a_legacy_attest_once(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    _strip_instance(root, "acme-2026")
    append_durable_audit(
        root,
        "acme-2026",
        {
            "action": "attest",
            "actor": "Ada",
            "reference": "SOW-14",
            "scope": "Billing service",
            "attested_at": "2026-10-09T15:00:00Z",
        },
    )
    record = load_engagement(root, "acme-2026")
    assert has_attestation(root, "acme-2026") is True
    load_engagement(root, "acme-2026")
    carried = [
        row
        for row in read_durable_audit(root, "acme-2026")
        if row.get("action") == "attest" and row.get("instance_id") == record["instance_id"]
    ]
    assert len(carried) == 1
    assert carried[0]["reference"] == "SOW-14"


def test_concurrent_loads_assign_one_instance_id_and_one_carried_attest(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root)
    _strip_instance(root, "acme-2026")
    append_durable_audit(
        root,
        "acme-2026",
        {
            "action": "attest",
            "actor": "Ada",
            "reference": "SOW-14",
            "scope": "Billing service",
            "attested_at": "2026-10-09T15:00:00Z",
        },
    )
    barrier = threading.Barrier(2)
    found: list[str] = []

    def load() -> None:
        barrier.wait(timeout=5)
        found.append(str(load_engagement(root, "acme-2026")["instance_id"]))

    threads = [threading.Thread(target=load) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert len(found) == 2
    assert found[0] == found[1]
    carried = [
        row
        for row in read_durable_audit(root, "acme-2026")
        if row.get("action") == "attest" and row.get("instance_id") == found[0]
    ]
    assert len(carried) == 1


def test_purged_id_is_refused_regardless_of_case(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root, "acme")
    _attest(root, "acme")
    close_engagement(root, "acme", actor="Ada")
    purge_engagement(root, "acme", actor="Ada")
    with pytest.raises(EngagementError, match="was purged"):
        _create(root, "Acme")
    assert not (root / "acme").exists()
    assert not (root / "Acme").exists()


def test_live_id_is_refused_regardless_of_case(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _create(root, "acme")
    with pytest.raises(EngagementError, match="already exists"):
        _create(root, "Acme")
    names = [path.name.casefold() for path in root.iterdir() if (path / "engagement.json").is_file()]
    assert names == ["acme"]
