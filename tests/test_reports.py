import json
import socket
import tarfile
import threading
import urllib.request
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.advisories import import_advisories, import_advisory_path, sync_advisories
from astrolabe.candidates import set_verdict
from astrolabe.engagement import EngagementError, attest, create_engagement, read_durable_audit
from astrolabe.intake import intake_local
from astrolabe.investigate import start_investigation
from astrolabe.cwe import NO_MITIGATION, cwes_without_mitigations, displayed_mitigations
from astrolabe.purge import close_engagement, export_engagement
from astrolabe.redact import find_secret_matches
from astrolabe.reports import (
    BENCHMARK,
    SCHEMA_PATH,
    TEMPLATE_VERSION,
    UNREVIEWED_REFUSAL,
    _coverage_html,
    _finding_blocks,
    _render_pdf,
    _strip_ref_markers,
    _summary_paragraph,
    finalize_assessment,
    write_assessment,
    write_remediation,
)
from astrolabe.schema_check import SchemaError, load_schema, validate_schema
from tests.secret_fixtures import aws_example_key

SECRET = aws_example_key()
_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_FINALIZED_AT = "2026-10-10T00:00:00Z"


def _root(tmp_path: Path) -> Path:
    path = tmp_path / "engagements"
    path.mkdir()
    return path


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    return source


def _runner(paths: list[str], *, report_name: str):
    def run(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        report_dir = engagement / "antares-data" / "reports" / report_name
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
        (report_dir / "report.json").write_text(
            json.dumps({"findings": findings, "summary": {}}),
            encoding="utf-8",
        )
        return CompletedProcess(command, 0)

    return run


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> bool:
        return False


def _opener(request: object, timeout: int = 60) -> _Response:
    url = str(getattr(request, "full_url", ""))
    if "api.osv.dev" in url:
        return _Response(
            {
                "summary": "OSV summary",
                "details": "OSV details",
                "aliases": ["GHSA-1234-abcd-5678"],
                "database_specific": {"cwe_ids": ["CWE-89"]},
            }
        )
    if "api.github.com/advisories/" in url:
        return _Response(
            {
                "ghsa_id": "GHSA-1234-abcd-5678",
                "summary": "GHSA summary",
                "description": "GHSA details",
                "aliases": ["CVE-2024-0001"],
                "html_url": "https://github.com/advisories/GHSA-1234-abcd-5678",
                "cwes": [{"cwe_id": "CWE-89"}],
            }
        )
    raise AssertionError(url)


def test_sync_writes_cache_and_audit_and_import_stays_offline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _root(tmp_path)
    cache = tmp_path / "cache"
    records = sync_advisories(
        root,
        actor="Ada",
        ids=["CVE-2024-0001"],
        cache=cache,
        opener=_opener,
    )
    notice = capsys.readouterr().out
    assert "api.osv.dev" in notice
    assert "api.github.com" in notice
    assert "0 cached, 1 fetched" in notice
    stored = json.loads((cache / "CVE-2024-0001.json").read_text(encoding="utf-8"))
    assert stored["summary"] == "GHSA summary"
    assert stored["details"] == "GHSA details"
    assert "GHSA-1234-abcd-5678" in stored["aliases"]
    assert stored["cwe_ids"] == ["CWE-89"]
    assert "https://osv.dev/vulnerability/CVE-2024-0001" in stored["source_urls"]
    assert stored["source_urls"][-1].startswith("https://github.com/advisories/")
    assert stored["fetched_at"].endswith("Z")
    assert records[0]["id"] == "CVE-2024-0001"
    audit = read_durable_audit(root, "advisory-cache")
    synced = audit[-1]
    assert synced["action"] == "advisories_sync"
    assert synced["actor"] == "Ada"
    assert synced["ids"] == ["CVE-2024-0001"]
    assert synced["source"] == "osv+github-advisory"
    assert synced["timestamp"].endswith("Z")
    sync_advisories(root, actor="Ada", ids=["CVE-2024-0001"], cache=cache, opener=_opener)
    cached_notice = capsys.readouterr().out
    assert cached_notice.strip() == "1 cached, 0 fetched"
    assert "api.osv.dev" not in cached_notice

    other = tmp_path / "prepared"
    other.mkdir()
    (other / "GHSA-1234-abcd-5678.json").write_text(
        json.dumps({"id": "GHSA-1234-abcd-5678", "summary": "Prepared offline", "details": "No network"}),
        encoding="utf-8",
    )
    imported = import_advisories(other, cache=cache)
    assert imported == ["GHSA-1234-abcd-5678"]
    assert json.loads((cache / "GHSA-1234-abcd-5678.json").read_text(encoding="utf-8"))["summary"] == "Prepared offline"
    single = tmp_path / "CVE-2099-0001.json"
    single.write_text(
        json.dumps({"id": "CVE-2099-0001", "summary": "One file", "details": "Local file"}),
        encoding="utf-8",
    )
    assert import_advisory_path(single, cache=cache) == ["CVE-2099-0001"]
    assert json.loads((cache / "CVE-2099-0001.json").read_text(encoding="utf-8"))["summary"] == "One file"


def test_sync_is_refused_during_an_investigation(tmp_path: Path) -> None:
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    intake_local(root, "acme-2026", _source(tmp_path))
    attest(
        root,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    called = {"fetch": False}

    def opener(request: object, timeout: int = 60) -> _Response:
        called["fetch"] = True
        raise AssertionError("sync must not fetch during an investigation")

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        with pytest.raises(EngagementError, match="refused during an investigation"):
            sync_advisories(root, actor="Ada", ids=["CVE-2024-0001"], cache=tmp_path / "cache", opener=opener)
        return _runner(["app.py"], report_name="run-1")(engagement, command)

    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        exploratory=True,
        runner=runner,
    )
    assert called["fetch"] is False


def _finalized_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    """One confirmed finding, no secrets, and a frozen approval time."""
    monkeypatch.setattr("astrolabe.reports.utc_now", lambda: _FINALIZED_AT)
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    intake_local(root, "acme-2026", _source(tmp_path))
    attest(
        root,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_text="Use parameterized queries.",
        runner=_runner(["app.py"], report_name="run-1"),
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed the query and confirmed the weakness in this file.",
    )
    write_assessment(root, "acme-2026", actor="Ada")
    write_remediation(root, "acme-2026", actor="Ada")
    finalize_assessment(root, "acme-2026", actor="Ada")
    reports = root / "acme-2026" / "reports"
    return root, reports / "assessment.html", reports / "remediation.md"


def test_finalized_assessment_exports_byte_identical_without_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, html_path, markdown_path = _finalized_fixture(tmp_path, monkeypatch)
    reports = html_path.parent
    stored = {
        "reports/assessment.html": html_path.read_bytes(),
        "reports/assessment-status.json": (reports / "assessment-status.json").read_bytes(),
        "reports/assessment.pdf": (reports / "assessment.pdf").read_bytes(),
        "reports/remediation.md": markdown_path.read_bytes(),
        "reports/remediation.json": (reports / "remediation.json").read_bytes(),
    }
    assert b"Consultant-confirmed candidate files." in stored["reports/assessment.html"]
    close_engagement(root, "acme-2026", actor="Ada")
    report_bundle = export_engagement(
        root,
        "acme-2026",
        tmp_path / "report.tar.gz",
        actor="Ada",
        report_only=True,
    )
    full_bundle = export_engagement(
        root,
        "acme-2026",
        tmp_path / "full.tar.gz",
        actor="Ada",
    )
    report_names = {
        "reports/assessment.html",
        "reports/assessment-status.json",
        "reports/assessment.pdf",
    }
    for bundle, names in ((report_bundle, report_names), (full_bundle, set(stored))):
        with tarfile.open(bundle) as archive:
            for name in names:
                exported = archive.extractfile(name)
                assert exported is not None
                assert exported.read() == stored[name]


def test_report_with_a_fake_key_refuses_export_without_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, html_path, _markdown = _finalized_fixture(tmp_path, monkeypatch)
    key = aws_example_key()
    html_path.write_text(html_path.read_text(encoding="utf-8") + key + "\n", encoding="utf-8")
    line = html_path.read_text(encoding="utf-8").count("\n")
    close_engagement(root, "acme-2026", actor="Ada")
    for report_only, name in ((True, "report.tar.gz"), (False, "full.tar.gz")):
        destination = tmp_path / name
        with pytest.raises(EngagementError) as caught:
            export_engagement(
                root,
                "acme-2026",
                destination,
                actor="Ada",
                report_only=report_only,
            )
        message = str(caught.value)
        assert key not in message
        assert f"assessment.html:{line} aws_key" in message
        assert "Fix the source report and re-finalize." in message
        assert not destination.is_file()


def test_assessment_and_remediation_match_committed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _root_path, html_path, markdown_path = _finalized_fixture(tmp_path, monkeypatch)
    assert html_path.read_bytes() == (_FIXTURES / "assessment.html").read_bytes()
    assert markdown_path.read_bytes() == (_FIXTURES / "remediation.md").read_bytes()


def test_reports_omit_stale_and_unreviewed_and_redact_notes(tmp_path: Path) -> None:
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    source = _source(tmp_path)
    intake_local(root, "acme-2026", source)
    attest(
        root,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_text="Use parameterized queries.",
        runner=_runner(["confirmed.py", "stale.py", "unreviewed.py"], report_name="run-1"),
    )
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-22",
        actor="Ada",
        exploratory=True,
        runner=_runner(["exploratory.py"], report_name="run-2"),
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="confirmed.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note=f"Reviewed the query. Token {SECRET}.",
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="stale.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Confirmed on the first snapshot.",
    )
    (source / "app.py").write_text("changed\n", encoding="utf-8")
    intake_local(root, "acme-2026", source, replace=True)
    set_verdict(
        root,
        "acme-2026",
        file_path="confirmed.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note=f"Re-confirmed. Token {SECRET}.",
    )
    saved = json.loads(
        (root / "acme-2026" / "antares-data" / "reports" / "run-1" / "report.json").read_text(encoding="utf-8")
    )
    labeled = saved["findings"][0]
    assert "likelihood_of_exploit" not in labeled
    assert labeled["mitre_likelihood"]["value"] == "High"
    assert (
        labeled["mitre_likelihood"]["label"]
        == "MITRE likelihood for this weakness class (not model confidence)"
    )
    assessment = write_assessment(root, "acme-2026", actor="Ada")
    remediation = write_remediation(root, "acme-2026", actor="Ada")
    page = assessment["html"].read_text(encoding="utf-8")
    pdf = assessment["pdf"].read_bytes().decode("latin-1", "replace")
    markdown = remediation["markdown"].read_text(encoding="utf-8")
    payload_text = remediation["json"].read_text(encoding="utf-8")
    findings = page.split("<h2>Findings</h2>", 1)[1].split("<h2>What was checked</h2>", 1)[0]
    assert "confirmed.py" in findings
    assert "stale.py" not in findings
    assert "unreviewed.py" not in findings
    assert "exploratory.py" not in page
    assert "stale.py" not in page
    before, after = page.split("<h3>Exploratory</h3>", 1)
    assert "CWE-22" not in before
    assert "CWE-89" in before
    assert "CWE-22" in after
    assert "Advisory-guided and exploratory investigations are listed separately" in page
    assert "No finding" in page or "no weakness" in page
    assert BENCHMARK in page
    assert "File F1" not in page
    assert "0.576" not in page
    assert "74 of 102" not in page
    assert 'id="draft-marker"' in page
    assert "DRAFT" in page
    status = json.loads((root / "acme-2026" / "reports" / "assessment-status.json").read_text(encoding="utf-8"))
    assert status["status"] == "draft"
    for body in (page, pdf, markdown, payload_text):
        assert SECRET not in body
    assert "redacted" in findings
    payload = json.loads(payload_text)
    schema = load_schema(SCHEMA_PATH)
    validate_schema(payload, schema)
    assert payload["verification_required"] is True
    assert set(payload["candidates"][0]) == {"file", "cwe", "status", "mode", "mitigations", "what_to_look_for"}
    broken = dict(payload)
    broken["verification_required"] = False
    with pytest.raises(SchemaError):
        validate_schema(broken, schema)
    recorded = [row for row in read_durable_audit(root, "acme-2026") if row["action"] == "report"]
    assessment_audit = next(row for row in recorded if row["kind"] == "assessment")
    assert assessment_audit["confirmed"] == 1
    assert assessment_audit["stale"] == 1
    assert assessment_audit["unreviewed"] == 2
    assert assessment_audit["actor"] == "Ada"


def test_cwe_dictionary_mitigation_gaps() -> None:
    assert cwes_without_mitigations() == []
    assert displayed_mitigations("CWE-999999") == [NO_MITIGATION]


def test_finalize_clears_draft_and_export_refuses_a_draft(tmp_path: Path) -> None:
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    intake_local(root, "acme-2026", _source(tmp_path))
    attest(
        root,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_text="Use parameterized queries.",
        runner=_runner(["confirmed.py"], report_name="run-1"),
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="confirmed.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed.",
    )
    assessment = write_assessment(root, "acme-2026", actor="Ada")
    with pytest.raises(EngagementError, match="closed"):
        export_engagement(
            root,
            "acme-2026",
            tmp_path / "open-full.tar.gz",
            actor="Ada",
            allow_draft=True,
        )
    with pytest.raises(EngagementError, match="draft"):
        export_engagement(
            root,
            "acme-2026",
            tmp_path / "open-draft.tar.gz",
            actor="Ada",
            report_only=True,
        )
    allowed = export_engagement(
        root,
        "acme-2026",
        tmp_path / "allowed.tar.gz",
        actor="Ada",
        allow_draft=True,
        report_only=True,
    )
    assert b"DRAFT" in tarfile.open(allowed).extractfile("reports/assessment.html").read()
    finalized = finalize_assessment(root, "acme-2026", actor="Ada")
    report_only = export_engagement(
        root,
        "acme-2026",
        tmp_path / "open-report.tar.gz",
        actor="Ada",
        report_only=True,
    )
    with tarfile.open(report_only) as bundle:
        names = set(bundle.getnames())
    assert names == {"reports/assessment.html", "reports/assessment.pdf", "reports/assessment-status.json"}
    with pytest.raises(EngagementError, match="closed"):
        export_engagement(root, "acme-2026", tmp_path / "still-open.tar.gz", actor="Ada")
    close_engagement(root, "acme-2026", actor="Ada")
    page = Path(finalized["html"]).read_text(encoding="utf-8")
    assert "DRAFT" not in page
    assert 'id="sign-off"' in page
    assert "Approved by Ada" in page
    assert BENCHMARK in page
    pdf = assessment["pdf"].read_bytes()
    assert pdf.startswith(b"%PDF")
    exported = export_engagement(root, "acme-2026", tmp_path / "final.tar.gz", actor="Ada")
    assert exported.is_file()
    report_only = export_engagement(
        root,
        "acme-2026",
        tmp_path / "report-only.tar.gz",
        actor="Ada",
        report_only=True,
    )
    with tarfile.open(report_only) as bundle:
        names = set(bundle.getnames())
    assert "reports/assessment.html" in names
    assert "reports/assessment.pdf" in names
    assert "candidates.json" not in names
    assert "engagement.json" not in names
    recorded = [row for row in read_durable_audit(root, "acme-2026") if row["action"] == "report_finalize"]
    assert recorded[-1]["actor"] == "Ada"
    assert recorded[-1]["finalized_at"].endswith("Z")


def test_sync_reports_github_rate_limit_and_resumes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    token = "local-" + "test-" + "token-" + "not-a-" + "secret"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    root = _root(tmp_path)
    cache = tmp_path / "cache"
    state = {"github": 0}

    def opener(request: object, timeout: int = 60) -> _Response:
        url = str(getattr(request, "full_url", ""))
        headers = {str(key).lower(): value for key, value in dict(getattr(request, "headers", {})).items()}
        if "api.osv.dev" in url and "CVE-2024-0001" in url:
            return _Response(
                {
                    "summary": "First",
                    "details": "First details",
                    "aliases": ["GHSA-1111-aaaa-1111"],
                    "database_specific": {"cwe_ids": ["CWE-89"]},
                }
            )
        if "api.osv.dev" in url and "CVE-2024-0002" in url:
            return _Response(
                {
                    "summary": "Second",
                    "details": "Second details",
                    "aliases": ["GHSA-2222-bbbb-2222"],
                    "database_specific": {"cwe_ids": ["CWE-22"]},
                }
            )
        if "api.github.com" in url:
            assert headers.get("authorization") == "Bea" + "rer " + token
            state["github"] += 1
            if "GHSA-2222-bbbb-2222" in url and state["github"] == 2:
                import email.message
                import io
                import urllib.error

                hdrs = email.message.EmailMessage()
                hdrs["X-RateLimit-Remaining"] = "0"
                raise urllib.error.HTTPError(
                    url,
                    403,
                    "rate limit exceeded",
                    hdrs,
                    io.BytesIO(b'{"message":"API rate limit exceeded"}'),
                )
            ghsa = "GHSA-1111-aaaa-1111" if "1111" in url else "GHSA-2222-bbbb-2222"
            return _Response(
                {
                    "ghsa_id": ghsa,
                    "summary": ghsa,
                    "description": "details",
                    "aliases": [],
                    "html_url": f"https://github.com/advisories/{ghsa}",
                    "cwes": [{"cwe_id": "CWE-89"}],
                }
            )
        raise AssertionError(url)

    with pytest.raises(EngagementError, match="Remaining 1: CVE-2024-0002") as caught:
        sync_advisories(
            root,
            actor="Ada",
            ids=["CVE-2024-0001", "CVE-2024-0002"],
            cache=cache,
            opener=opener,
        )
    assert "Fetched 1: CVE-2024-0001" in str(caught.value)
    assert (cache / "CVE-2024-0001.json").is_file()
    assert not (cache / "CVE-2024-0002.json").is_file()
    audit_text = (root.parent / "var" / "audit.jsonl").read_text(encoding="utf-8")
    assert "local-test-token-not-a-secret" not in audit_text
    partial = read_durable_audit(root, "advisory-cache")[-1]
    assert partial["ids"] == ["CVE-2024-0001"]
    assert partial["remaining"] == ["CVE-2024-0002"]

    resumed = sync_advisories(
        root,
        actor="Ada",
        ids=["CVE-2024-0001", "CVE-2024-0002"],
        cache=cache,
        opener=opener,
    )
    assert [item["id"] for item in resumed] == ["CVE-2024-0002"]
    assert (cache / "CVE-2024-0002.json").is_file()


def test_generate_after_finalize_refuses_and_leaves_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, html_path, _markdown = _finalized_fixture(tmp_path, monkeypatch)
    reports = html_path.parent
    html_bytes = html_path.read_bytes()
    status_bytes = (reports / "assessment-status.json").read_bytes()
    pdf_bytes = (reports / "assessment.pdf").read_bytes()
    with pytest.raises(EngagementError, match="finalized by Ada at 2026-10-10T00:00:00Z"):
        write_assessment(root, "acme-2026", actor="Ada")
    assert html_path.read_bytes() == html_bytes
    assert (reports / "assessment-status.json").read_bytes() == status_bytes
    assert (reports / "assessment.pdf").read_bytes() == pdf_bytes
    with pytest.raises(EngagementError, match="can't be regenerated or re-finalized"):
        finalize_assessment(root, "acme-2026", actor="Ada")
    status = json.loads((reports / "assessment-status.json").read_text(encoding="utf-8"))
    assert status["finalized_at"] == _FINALIZED_AT
    assert status["template_version"] == TEMPLATE_VERSION
    assert html_path.read_bytes() == html_bytes
    with pytest.raises(EngagementError, match="Verdicts can't be changed"):
        set_verdict(
            root,
            "acme-2026",
            file_path="app.py",
            cwe="CWE-89",
            state="not_actionable",
            actor="Ada",
            note="Trying to change a finalized verdict.",
        )
    assert html_path.read_bytes() == html_bytes


def test_template_version_zero_is_not_rerendered(tmp_path: Path) -> None:
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    reports = root / "acme-2026" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    html_path = reports / "assessment.html"
    html_path.write_text("<p>Older draft</p>\n", encoding="utf-8")
    status_path = reports / "assessment-status.json"
    status_path.write_text(json.dumps({"status": "draft", "actor": "", "finalized_at": ""}) + "\n", encoding="utf-8")
    html_bytes = html_path.read_bytes()
    status_bytes = status_path.read_bytes()
    with pytest.raises(EngagementError, match="report template 0"):
        write_assessment(root, "acme-2026", actor="Ada")
    with pytest.raises(EngagementError, match="report template 0"):
        finalize_assessment(root, "acme-2026", actor="Ada")
    assert html_path.read_bytes() == html_bytes
    assert status_path.read_bytes() == status_bytes


def test_include_unreviewed_is_refused(tmp_path: Path) -> None:
    with pytest.raises(EngagementError, match=UNREVIEWED_REFUSAL):
        write_assessment(tmp_path, "acme-2026", actor="Ada", include_unreviewed=True)


def test_assessment_sections_notes_and_offline_markup(tmp_path: Path) -> None:
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    source = _source(tmp_path)
    intake_local(root, "acme-2026", source)
    attest(
        root,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    cache = tmp_path / "advisories"
    cache.mkdir()
    (cache / "CVE-2024-0001.json").write_text(
        json.dumps({"id": "CVE-2024-0001", "summary": "Use parameterized queries.", "details": "No file names."}),
        encoding="utf-8",
    )
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_id="CVE-2024-0001",
        cache=cache,
        runner=_runner(["confirmed.py", "skip.py", "later.py"], report_name="run-1"),
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="confirmed.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed the query and confirmed the weakness in this file.",
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="skip.py",
        cwe="CWE-89",
        state="not_actionable",
        actor="Ada",
        note="NOTE-NOT-ACTIONABLE stays out of the report.",
        confirmed=True,
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="later.py",
        cwe="CWE-89",
        state="needs_more_info",
        actor="Ada",
        note="NOTE-NEEDS-INFO stays out of the report.",
    )
    assessment = write_assessment(root, "acme-2026", actor="Ada")
    page = assessment["html"].read_text(encoding="utf-8")
    headings = [
        "Header",
        "Summary",
        "Findings",
        "What was checked",
        "Method and limitations",
        "Appendix",
    ]
    positions = [page.index(f"<h2>{heading}</h2>") for heading in headings]
    assert positions == sorted(positions)
    assert "Approving consultant" in page
    assert "Not yet approved" in page
    assert 'id="draft-marker"' in page
    assert "DRAFT" in page
    assert "#draft-marker {" in page
    assert "transform: rotate(-24deg);" in page
    assert "Found by: advisory-guided check (CVE-2024-0001)" in page
    assert "Improper Neutralization of Special Elements used in an SQL Command" in page
    assert "Consultant explanation: Reviewed the query and confirmed the weakness in this file." in page
    assert "What to look for: Look through confirmed.py for" in page
    assert "1 more mitigation listed in the remediation handoff." in page
    assert "Advisories checked: CVE-2024-0001." in page
    assert "Advisory IDs checked" not in page
    assert "register_globals" not in page
    assert "NOTE-NOT-ACTIONABLE" not in page
    assert "NOTE-NEEDS-INFO" not in page
    assert "skip.py" not in page
    assert "later.py" not in page
    assert 'href="http' not in page
    assert "href='http" not in page
    assert 'src="http' not in page
    assert "/cwe/" not in page
    assert 'href="/e/' not in page
    assert "Report template" in page
    assert f"<td>{TEMPLATE_VERSION}</td>" in page
    assert find_secret_matches(page) == []
    status = json.loads((root / "acme-2026" / "reports" / "assessment-status.json").read_text(encoding="utf-8"))
    assert status["template_version"] == TEMPLATE_VERSION
    assert status["status"] == "draft"
    set_verdict(
        root,
        "acme-2026",
        file_path="later.py",
        cwe="CWE-89",
        state="not_actionable",
        actor="Ada",
        note="Cleared so the draft can be finalized.",
        confirmed=True,
    )
    finalized = finalize_assessment(root, "acme-2026", actor="Ada")
    final_page = Path(finalized["html"]).read_text(encoding="utf-8")
    assert "DRAFT" not in final_page
    assert "draft-marker" not in final_page
    assert "rotate(-24deg)" not in final_page
    assert "Not yet approved" not in final_page
    assert "Approved by Ada" in final_page


def test_pdf_render_refuses_external_urls_without_a_network_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(urllib.request, "urlopen", fail)
    page = (
        "<html><head><style>body { background: url(https://example.test/pixel.png); "
        "font-family: Georgia, serif; }</style></head><body><p>Draft</p></body></html>"
    )
    with pytest.raises(EngagementError, match="does not load external URLs"):
        _render_pdf(page, tmp_path / "blocked.pdf")
    assert not (tmp_path / "blocked.pdf").exists()


def test_unavailable_weasyprint_still_writes_html_and_the_report_page_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins

    from astrolabe.ui import App, _pdf_notice

    real_import = builtins.__import__

    def blocked(name: str, globals: object = None, locals: object = None, fromlist: tuple[str, ...] = (), level: int = 0) -> object:
        if name == "weasyprint" or name.startswith("weasyprint."):
            raise ImportError("weasyprint unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked)
    root = _root(tmp_path)
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    intake_local(root, "acme-2026", _source(tmp_path))
    attest(
        root,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    start_investigation(
        root,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_text="Use parameterized queries.",
        runner=_runner(["app.py"], report_name="run-1"),
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed the query and confirmed the weakness in this file.",
    )
    written = write_assessment(root, "acme-2026", actor="Ada")
    html_path = Path(written["html"])
    pdf_path = Path(written["pdf"])
    page = html_path.read_text(encoding="utf-8")
    assert "<h2>Findings</h2>" in page
    assert not pdf_path.exists()
    directory = html_path.parent.parent
    assert "The PDF was not produced." in _pdf_notice(directory)
    app = App(root)
    server = app.serve(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/e/acme-2026/report") as response:
            report = response.read().decode("utf-8")
    finally:
        server.shutdown()
    assert 'id="pdf-missing"' in report
    assert "The PDF was not produced." in report


def test_assessment_section_headings_appear_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _root, html_path, _markdown = _finalized_fixture(tmp_path, monkeypatch)
    page = html_path.read_text(encoding="utf-8")
    for heading in (
        "Header",
        "Summary",
        "Findings",
        "What was checked",
        "Method and limitations",
        "Appendix",
    ):
        assert page.count(f"<h2>{heading}</h2>") == 1
    for heading in ("Engagement", "Coverage", "Methodology and limitations"):
        assert f"<h2>{heading}</h2>" not in page
    assert page.count("<body") == 1
    assert page.count("body {") == 1
    assert "<th>Consultants</th>" not in page
    assert page.count("Authorization:") == 1
    assert "Authorization: SOW-14" in page
    findings = page.split("<h2>Findings</h2>", 1)[1].split("<h2>What was checked</h2>", 1)[0]
    assert findings.count("<article") == findings.count('<article class="finding">') == 1
    assert "Mode:" not in findings
    assert "Consultant note:" not in findings
    header = page.split("<h2>Header</h2>", 1)[1].split("<h2>Summary</h2>", 1)[0]
    checked = page.split("<h2>What was checked</h2>", 1)[1].split("<h2>Method and limitations</h2>", 1)[0]
    appendix = page.split("<h2>Appendix</h2>", 1)[1]
    full = appendix.split('class="mono">', 1)[1].split("<", 1)[0]
    assert len(full) == 64
    assert page.count(full) == 1
    assert full in appendix
    assert full not in header
    assert full not in checked
    assert checked.count("<th>Snapshot</th>") == 2
    assert "Snapshot SHA-256" not in checked
    assert "<th>Snapshot SHA-256</th>" in appendix
    assert f'<td class="mono">{full[:12]}</td>' in header
    assert f'<td class="mono">{full[:12]}</td>' in checked
    assert "<th>End</th><td>Not set</td>" in header
    assert "<td>Pasted advisory text</td>" in checked
    assert "<td>pasted</td>" not in page
    assert "Verdicts in this mode: none." in page
    assert "Verdicts in this mode: ." not in page
    assert "defense in depth." in findings
    assert "[REF-" not in page
    markdown = _markdown.read_text(encoding="utf-8")
    assert "defense in depth." in markdown
    assert "[REF-" not in markdown
    assert "Advisories checked: pasted advisory text." in page


def test_summary_clause_names_pasted_text_or_ids_and_extra_mitigations_pluralize() -> None:
    pasted = _summary_paragraph(
        {
            "counts": {"confirmed": 1},
            "advisory_ids": [],
            "coverage": {"cwes": [{"mode": "advisory", "selection_source": "pasted", "investigations": 1}]},
        }
    )
    assert pasted.endswith("Advisories checked: pasted advisory text.")
    identified = _summary_paragraph(
        {
            "counts": {"confirmed": 1},
            "advisory_ids": ["CVE-2024-0001"],
            "coverage": {"cwes": [{"mode": "advisory", "selection_source": "CVE-2024-0001", "investigations": 1}]},
        }
    )
    assert "Advisories checked: CVE-2024-0001." in identified
    assert "pasted advisory text" not in identified
    exploratory = _summary_paragraph(
        {
            "counts": {"confirmed": 0},
            "advisory_ids": [],
            "coverage": {"cwes": [{"mode": "exploratory", "selection_source": "search", "investigations": 1}]},
        }
    )
    assert exploratory == "0 confirmed findings. 0 advisory checks and 1 exploratory check."
    assert "Advisories checked" not in exploratory
    row = {
        "file": "app.py",
        "cwe": "CWE-89",
        "name": "Name",
        "mode": "exploratory",
        "advisory_id": "",
        "note": "",
        "what_to_look_for": "",
    }
    plural = _finding_blocks([{**row, "mitigations": ["one", "two", "three", "four", "five"]}])
    assert "2 more mitigations listed in the remediation handoff." in plural
    single = _finding_blocks([{**row, "mitigations": ["one", "two", "three", "four"]}])
    assert "1 more mitigation listed in the remediation handoff." in single


def test_ref_markers_and_coverage_labels() -> None:
    truncated = (
        "Use an application firewall that can detect attacks against this weakness, "
        "or to provide defense in depth [REF-1481."
    )
    assert _strip_ref_markers(truncated).endswith("defense in depth.")
    assert "[REF-" not in _strip_ref_markers(truncated)
    assert _strip_ref_markers("easier to avoid [REF-1482].") == "easier to avoid."
    assert (
        _strip_ref_markers("See the [REF-1492] for a good discussion of best practices.")
        == "See the for a good discussion of best practices."
    )
    digest = "ab" * 32
    coverage = {
        "cwes": [
            {
                "mode": "advisory",
                "cwe": "CWE-89",
                "selection_source": "CVE-2024-0001",
                "snapshot_sha256": digest,
                "investigations": 1,
                "runs": 1,
            },
            {
                "mode": "exploratory",
                "cwe": "CWE-22",
                "selection_source": "search",
                "snapshot_sha256": digest,
                "investigations": 1,
                "runs": 1,
            },
        ],
        "candidates": [{"cwe": "CWE-89", "presentation_state": "confirmed"}],
    }
    advisory = _coverage_html(coverage, "advisory", "Advisory-guided")
    exploratory = _coverage_html(coverage, "exploratory", "Exploratory")
    assert "<td>CVE-2024-0001</td>" in advisory
    assert "Pasted advisory text" not in advisory
    assert f'<td class="mono">{digest[:12]}</td>' in advisory
    assert digest not in advisory
    assert "Verdicts in this mode: confirmed 1." in advisory
    assert "<td>search</td>" in exploratory
    assert "Verdicts in this mode: none." in exploratory
