"""Offline CWE dictionary pages and hover links."""

from __future__ import annotations

import html
import io
import json
import re
import socket
import tarfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe import cwe_catalog
from astrolabe.engagement import create_engagement, engagement_dir, load_engagement
from astrolabe.purge import close_engagement, export_engagement
from astrolabe.reports import _assessment_html, _remediation_json, _remediation_markdown
from astrolabe.selection import CLASS_NOTE, OWASP_GROUP
from astrolabe.ui import PLAN_INTRO, App, Form, _SCRIPT, _cwe_index, cwe_ref

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

    def open(self, method: str, path: str, fields: dict[str, str] | None = None) -> tuple[int, str]:
        payload = None
        headers: dict[str, str] = {}
        if fields is not None:
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


class _Headers:
    def get(self, name: str, default: str = "") -> str:
        return default


def _open_once(client: Client, method: str, path: str) -> tuple[int, str, object]:
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(client.base + path, method=method)
    try:
        with opener.open(request) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), exc.headers


def _serve(root: Path):
    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        if len(command) > 1 and command[1] == "plan":
            return CompletedProcess(command, 0, stdout=json.dumps(PLAN))
        return CompletedProcess(command, 0, stdout="")

    app = App(root, runner=runner)
    server = app.serve(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return Client(server), server


def _prepare(client: Client, tmp_path: Path) -> None:
    status, _page = client.open(
        "POST",
        "/",
        {
            "id": "acme-2026",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    assert status == 200
    client.open(
        "POST",
        "/e/acme-2026/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service"},
    )
    source = tmp_path / "acme-2026"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    client.open("POST", "/e/acme-2026/intake/preview", {"path": str(source)})
    client.open("POST", "/e/acme-2026/intake/confirm", {})


def _title(page: str, cwe_id: str) -> str:
    match = re.search(rf'href="/cwe/{cwe_id}"[^>]*title="([^"]*)"', page)
    assert match is not None
    return html.unescape(match.group(1))


def test_cwe_dictionary_lists_entries(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        status, page = client.open("GET", "/cwe")
        assert status == 200
        assert "<table" in page
        assert "<th>ID</th>" in page
        assert "969 matched" in page
        assert "Page 1 of 10" in page
        assert 'class="cwe-ref"' in page
        assert 'target="_blank"' not in page
        assert "CWE™ content © The MITRE Corporation. Used under the CWE Terms of Use." in page
        assert "MITRE CWE 4.20, released 2026-04-30." in page
        assert '<form method="get" action="/cwe">' in page
        assert 'name="q"' in page
        assert "Narrow this page" not in page
        assert 'id="cwe-live-filter"' not in page
        assert 'class="engagement-header"' not in page
        assert "Acting as" not in page
    finally:
        server.shutdown()


def test_cwe_search_finds_327_by_id_and_name(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        for query in ("327", "CWE-327", "cryptographic"):
            status, page = client.open("GET", f"/cwe?q={query}")
            assert status == 200
            assert 'href="/cwe/CWE-327"' in page
            assert "Use of a Broken or Risky Cryptographic Algorithm" in page
    finally:
        server.shutdown()


def test_cwe_search_for_sql_injection_finds_cwe_89(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        status, page = client.open("GET", "/cwe?q=sql%20injection")
        assert status == 200
        assert 'href="/cwe/CWE-89"' in page
        assert '<form method="get" action="/cwe">' in page
        assert 'name="q"' in page
        assert 'value="sql injection"' in page
        status, script = client.open("GET", "/astrolabe.js")
        assert status == 200
        assert script == _SCRIPT
        assert 'form[action="/cwe"] input[name="q"]' in script
        assert 'location.assign(query ? "/cwe?" + query : "/cwe")' in script
        assert "data-cwe-row" not in script
    finally:
        server.shutdown()


def test_cwe_abstraction_and_view_filters_narrow_results(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        status, narrowed = client.open("GET", "/cwe?abstraction=Class&q=327")
        assert status == 200
        assert 'href="/cwe/CWE-327"' in narrowed
        status, other = client.open("GET", "/cwe?abstraction=Base&q=327")
        assert status == 200
        assert "0 matched" in other
        assert 'href="/cwe/CWE-327"' not in other
        status, top = client.open("GET", "/cwe?view=top25")
        assert status == 200
        assert "25 matched" in top
        assert 'href="/cwe/CWE-89"' in top
        status, owasp = client.open("GET", "/cwe?view=owasp")
        assert status == 200
        assert "246 matched" in owasp
        assert "969 matched" not in owasp
    finally:
        server.shutdown()


def test_invalid_cwe_filters_are_ignored(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        status, page = client.open("GET", "/cwe?abstraction=Nope&view=sideways&page=abc")
        assert status == 200
        assert "969 matched" in page
        assert "Page 1 of 10" in page
        status, capped = client.open("GET", "/cwe?q=" + ("x" * 150))
        assert status == 200
        assert 'value="' + ("x" * 100) + '"' in capped
        assert "x" * 101 not in capped
        status, last = client.open("GET", "/cwe?page=9999")
        assert status == 200
        assert "Page 10 of 10" in last
        status, zero = client.open("GET", "/cwe?page=0")
        assert status == 200
        assert "Page 1 of 10" in zero
    finally:
        server.shutdown()


def test_cwe_numeric_id_redirects_to_canonical_entry(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        status, _page, headers = _open_once(client, "GET", "/cwe/327")
        assert status == 303
        assert headers.get("Location") == "/cwe/CWE-327"
        status, page = client.open("GET", "/cwe/CWE-327")
        assert status == 200
        assert "Use of a Broken or Risky Cryptographic Algorithm" in page
        assert "Class" in page
        assert "Parents (Research Concepts, CWE-1000)" in page
        assert 'href="/cwe/CWE-693"' in page
        assert 'href="/cwe/CWE-328"' in page
        assert 'href="/cwe/CWE-780"' in page
        assert 'href="/cwe/CWE-1240"' in page
        assert CLASS_NOTE in page
        assert "OWASP Top Ten 2025 RC1 (CWE-1450)" in page
        assert "https://cwe.mitre.org/data/definitions/327.html" in page
        assert 'href="https://cwe.mitre.org' not in page
        assert "prefetch" not in page
        assert 'target="_blank"' not in page
    finally:
        server.shutdown()


def test_unknown_cwe_is_not_in_the_local_catalog(tmp_path: Path) -> None:
    client, server = _serve(tmp_path)
    try:
        status, page = client.open("GET", "/cwe/CWE-99999")
        assert status == 404
        assert "Not in the local CWE catalog." in page
    finally:
        server.shutdown()


def test_cwe_dotdot_is_refused(tmp_path: Path) -> None:
    app = App(tmp_path)
    status, body, _content_type = app.route("GET", ["cwe", "..", "x"], Form())
    assert status == 404
    assert "Not in the local CWE catalog." not in body
    status, body, _content_type = app.dispatch("GET", "/cwe/../x", _Headers(), io.BytesIO())
    assert status == 404
    status, body = app.route("GET", ["cwe", "nope"], Form())[:2]
    assert status == 404


def test_missing_catalog_renders_a_message_and_plain_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cwe_catalog, "load_cwe_catalog", lambda: None)
    client, server = _serve(tmp_path / "engagements")
    try:
        status, page = client.open("GET", "/cwe")
        assert status == 200
        assert cwe_catalog.CATALOG_MISSING in page
        _prepare(client, tmp_path)
        client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        status, page = client.open("GET", "/e/acme-2026/plan/recommended")
        assert status == 200
        assert "<code>CWE-89</code>" in page
        assert "cwe-ref" not in page
    finally:
        server.shutdown()


def test_plan_cwe_link_is_outside_the_checkbox_label(tmp_path: Path) -> None:
    client, server = _serve(tmp_path / "engagements")
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert 'value="recommended|CWE-89" checked' in page
        for label in re.findall(r"<label\b[^>]*>.*?</label>", page, flags=re.DOTALL):
            assert "cwe-ref" not in label
        title = _title(page, "CWE-89")
        entry = cwe_catalog.catalog_entry("CWE-89")
        assert entry is not None
        prefix = f"CWE-89 · {entry['name']} ({entry['abstraction']}). "
        assert title.startswith(prefix)
        description = title[len(prefix) :]
        assert description == cwe_catalog.truncate_description(str(entry["description"]))
        assert len(description[:-1]) <= 160
        assert "&#x27;" in page
    finally:
        server.shutdown()


def test_owasp_heading_and_intro_stay_unchanged(tmp_path: Path) -> None:
    client, server = _serve(tmp_path / "engagements")
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/explore", {"picker": "owasp"})
        assert status == 200
        assert f"<h2>{OWASP_GROUP}</h2>" in page
        assert f"<p>{PLAN_INTRO['owasp']}</p>" in page
        assert 'href="/cwe/CWE-1450"' not in page
    finally:
        server.shutdown()


def test_plan_and_review_cwe_links_open_in_a_new_tab(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    client, server = _serve(root)
    try:
        _prepare(client, tmp_path)
        status, plan = client.open("POST", "/e/acme-2026/select/explore", {"picker": "recommended"})
        assert status == 200
        assert 'href="/cwe/CWE-89" target="_blank" rel="noopener"' in plan
        status, review = client.open("POST", "/e/acme-2026/review", {"choice": "recommended|CWE-89"})
        assert status == 200
        assert "Launch review" in review
        assert 'href="/cwe/CWE-89" target="_blank" rel="noopener"' in review
        record = load_engagement(root, "acme-2026")
        sha = str(record["snapshot_sha256"])
        directory = engagement_dir(root, "acme-2026")
        (directory / "investigations.json").write_text(
            json.dumps(
                [
                    {
                        "id": "inv-1",
                        "cwe": "CWE-89",
                        "exploratory": True,
                        "selection_source": "search",
                        "snapshot_sha256": sha,
                        "runs": [{"run": 1, "candidate_paths": ["app.py"], "increases_coverage": True}],
                    }
                ]
            ),
            encoding="utf-8",
        )
        (directory / "candidates.json").write_text(
            json.dumps(
                {
                    "app.py|CWE-89": {
                        "file_path": "app.py",
                        "cwe": "CWE-89",
                        "state": "candidate",
                        "snapshot_sha256": sha,
                        "fingerprint": "abc",
                    }
                }
            ),
            encoding="utf-8",
        )
        (directory / "coverage.json").write_text(
            json.dumps(
                {
                    "cwes": [
                        {
                            "cwe": "CWE-89",
                            "mode": "exploratory",
                            "selection_source": "search",
                            "snapshot_sha256": sha,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        status, page = client.open("GET", "/e/acme-2026?step=review")
        assert status == 200
        assert 'href="/cwe/CWE-89" target="_blank" rel="noopener"' in page
        assert ">CWE: " in page
        assert 'id="coverage"' in page
        title = _title(page, "CWE-89")
        entry = cwe_catalog.catalog_entry("CWE-89")
        assert entry is not None
        assert title.endswith(cwe_catalog.truncate_description(str(entry["description"])))
    finally:
        server.shutdown()


def test_advisory_plan_uses_cwe_ref_outside_the_label(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(tmp_path / "advisories"))
    cache = tmp_path / "advisories"
    cache.mkdir()
    (cache / "CVE-2024-9001.json").write_text(
        json.dumps(
            {
                "id": "CVE-2024-9001",
                "summary": "Summary line",
                "details": "Detail line",
                "cwe_ids": ["CWE-89"],
            }
        ),
        encoding="utf-8",
    )
    client, server = _serve(tmp_path / "engagements")
    try:
        _prepare(client, tmp_path)
        status, page = client.open("POST", "/e/acme-2026/select/advisory", {"ids": "CVE-2024-9001"})
        assert status == 200
        assert 'value="CVE-2024-9001|CWE-89" checked' in page
        assert 'href="/cwe/CWE-89" target="_blank" rel="noopener"' in page
        for label in re.findall(r"<label\b[^>]*>.*?</label>", page, flags=re.DOTALL):
            assert "cwe-ref" not in label
    finally:
        server.shutdown()


def test_cwe_tooltip_handlers_are_on_document() -> None:
    assert 'document.addEventListener("mouseover"' in _SCRIPT
    assert 'document.addEventListener("mouseout"' in _SCRIPT
    assert 'document.addEventListener("focusin"' in _SCRIPT
    assert 'document.addEventListener("focusout"' in _SCRIPT
    assert 'document.addEventListener("keydown"' in _SCRIPT
    assert "isConnected" in _SCRIPT
    assert _SCRIPT.index("const statusPill") < _SCRIPT.index('document.addEventListener("mouseover"')


def test_topbar_links_to_the_cwe_dictionary(tmp_path: Path) -> None:
    client, server = _serve(tmp_path / "engagements")
    try:
        for path in ("/", "/about", "/new", "/environment", "/cwe"):
            status, page = client.open("GET", path)
            assert status == 200
            assert 'href="/cwe">CWE dictionary</a>' in page
        _prepare(client, tmp_path)
        status, page = client.open("GET", "/e/acme-2026")
        assert status == 200
        assert 'href="/cwe">CWE dictionary</a>' in page
    finally:
        server.shutdown()


def test_dictionary_pages_do_not_open_a_network_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(urllib.request, "urlopen", fail)
    cwe_catalog.load_cwe_catalog.cache_clear()
    page = _cwe_index()
    assert "CWE dictionary" in page
    rendered = cwe_ref("CWE-327")
    assert "cwe-ref" in rendered
    assert "https://cwe.mitre.org" not in rendered


def test_assessment_and_export_keep_plain_cwe_ids(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    create_engagement(
        root,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )
    document = {
        "engagement": {
            "customer": "Acme",
            "scope": "Billing service",
            "start_date": "2026-10-09",
            "end_date": "2026-10-10",
            "consultants": ["Ada"],
            "snapshot_sha256": "abc",
        },
        "authorization_reference": "SOW-14",
        "confirmed": [
            {
                "file": "app.py",
                "cwe": "CWE-89",
                "status": "confirmed",
                "mode": "advisory",
                "note": "Checked the query.",
                "mitigations": ["Use a parameterized query."],
                "what_to_look_for": "Look through app.py for SQL injection. Confirm the weakness before changing code.",
            }
        ],
        "include_unreviewed": True,
        "unreviewed": [{"file": "other.py", "cwe": "CWE-22"}],
        "coverage": {
            "cwes": [
                {
                    "cwe": "CWE-89",
                    "mode": "advisory",
                    "selection_source": "recommended",
                    "snapshot_sha256": "abc",
                    "investigations": 1,
                    "runs": 1,
                }
            ]
        },
    }
    page = _assessment_html(document, final=True, approver="Ada", finalized_at="2026-10-10T00:00:00Z")
    markdown = _remediation_markdown(document)
    payload = _remediation_json(document)
    assert "CWE-89" in page
    assert "(CWE-22)" not in page
    assert "Unreviewed candidates" not in page
    assert "<td>CWE-89</td>" in page
    assert "cwe-ref" not in page
    assert 'href="/cwe/' not in page
    assert "- CWE: CWE-89" in markdown
    assert "cwe-ref" not in markdown
    assert payload["candidates"][0]["cwe"] == "CWE-89"
    directory = engagement_dir(root, "acme-2026")
    reports = directory / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "assessment.html").write_text(page, encoding="utf-8")
    (reports / "assessment-status.json").write_text(json.dumps({"status": "final"}) + "\n", encoding="utf-8")
    (reports / "remediation.md").write_text(markdown, encoding="utf-8")
    (reports / "remediation.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
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
        report_only=False,
    )
    exported_html = page.encode("utf-8")
    exported_markdown = markdown.encode("utf-8")
    exported_json = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    assert b"<li>CWE: CWE-89</li>" not in exported_html
    assert b"CWE-89" in exported_html
    assert b"(CWE-22)" not in exported_html
    assert b"cwe-ref" not in exported_html
    assert b"- CWE: CWE-89" in exported_markdown
    with tarfile.open(report_bundle, "r:gz") as archive:
        stored = archive.extractfile("reports/assessment.html")
        assert stored is not None
        assert stored.read() == exported_html
    with tarfile.open(full_bundle, "r:gz") as archive:
        stored = archive.extractfile("reports/assessment.html")
        assert stored is not None
        assert stored.read() == exported_html
        stored = archive.extractfile("reports/remediation.md")
        assert stored is not None
        assert stored.read() == exported_markdown
        stored = archive.extractfile("reports/remediation.json")
        assert stored is not None
        assert stored.read() == exported_json
