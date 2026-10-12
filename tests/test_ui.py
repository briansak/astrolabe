"""The loopback UI uses the engagement commands and does not add rules."""

from __future__ import annotations

import getpass
import html
import io
import json
import threading
from datetime import date
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.engagement import EngagementError
from astrolabe.ui import LOOPBACK, App
from tests.secret_fixtures import aws_example_key

SECRET = aws_example_key()


class Client:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        host, port = server.server_address[:2]
        self.base = f"http://{host}:{port}"

    def exchange(
        self,
        method: str,
        path: str,
        fields: dict[str, str] | None = None,
        *,
        origin: str | None = "self",
        referer: str | None = None,
        host: str | None = None,
        data: bytes | None = None,
        content_type: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> tuple[int, str, object]:
        payload = data
        headers: dict[str, str] = {}
        if fields is not None:
            payload = urllib.parse.urlencode(fields).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif content_type:
            headers["Content-Type"] = content_type
        if method == "POST":
            if origin == "self":
                headers["Origin"] = self.base
            elif origin:
                headers["Origin"] = origin
            if referer:
                headers["Referer"] = referer
        if host:
            headers["Host"] = host
        if extra:
            headers.update(extra)
        request = urllib.request.Request(self.base + path, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, response.read().decode("utf-8"), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8"), exc.headers

    def request(self, method: str, path: str, fields: dict[str, str] | None = None) -> tuple[int, str]:
        status, body, _headers = self.exchange(method, path, fields)
        return status, body

    def post_file(self, path: str, fields: dict[str, str], filename: str, payload: bytes) -> tuple[int, str]:
        boundary = "----astrolabe-test"
        chunks: list[bytes] = []
        for key, value in fields.items():
            chunks.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode()
            )
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"archive\"; filename=\"{filename}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n".encode()
            + payload
            + b"\r\n"
        )
        chunks.append(f"--{boundary}--\r\n".encode())
        body = b"".join(chunks)
        request = urllib.request.Request(
            self.base + path,
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Origin": self.base,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def post_parts(self, path: str, parts: list[tuple[str, str, bytes]]) -> tuple[int, str]:
        boundary = "----astrolabe-parts"
        chunks: list[bytes] = []
        for field, filename, payload in parts:
            chunks.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n".encode()
                + payload
                + b"\r\n"
            )
        chunks.append(f"--{boundary}--\r\n".encode())
        request = urllib.request.Request(
            self.base + path,
            data=b"".join(chunks),
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Origin": self.base,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def open(
        self,
        method: str,
        path: str,
        fields: dict[str, str] | None = None,
        **kwargs: object,
    ) -> tuple[int, str]:
        status, body, _headers = self.exchange(method, path, fields, **kwargs)  # type: ignore[arg-type]
        return status, body


@pytest.fixture
def ui(tmp_path: Path):
    entered = threading.Event()
    release = threading.Event()

    def runner(engagement: Path, command: list[str], **_extra: object) -> CompletedProcess[str]:
        report_dir = engagement / "antares-data" / "reports" / "run-1"
        report_dir.mkdir(parents=True, exist_ok=True)
        report = {
            "findings": [
                {
                    "file_path": "app.py",
                    "submission_rank": 1,
                    "cwe_ids": ["CWE-89"],
                    "likelihood_of_exploit": "High",
                }
            ]
        }
        (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
        trace = engagement / "antares-data" / "traces"
        trace.mkdir(parents=True, exist_ok=True)
        event = {
            "phase": "tool_call",
            "payload": {"tool_name": "terminal", "arguments": {"command": f"echo {SECRET}"}},
        }
        (trace / "run.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
        entered.set()
        assert release.wait(timeout=5)
        return CompletedProcess(command, 0)

    app = App(tmp_path / "engagements", runner=runner)
    server = app.serve(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(server), app, entered, release, tmp_path
    finally:
        release.set()
        server.shutdown()


def test_ui_listens_on_loopback_only(tmp_path: Path) -> None:
    with pytest.raises(EngagementError, match="127.0.0.1"):
        App(tmp_path / "engagements").serve(0, host="0.0.0.0")
    server = App(tmp_path / "engagements").serve(0)
    assert server.server_address[0] == LOOPBACK
    server.server_close()


def test_engagement_lifecycle_pages(ui) -> None:
    client, _app, entered, release, tmp_path = ui
    status, page = client.open(
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
    assert "acme-2026" in page
    assert 'id="scan-gate"' not in page
    status, listed = client.open("GET", "/")
    row_at = listed.index('href="/e/acme-2026"')
    row = listed[row_at : listed.index("</tr>", row_at)]
    assert "acme-2026" in row
    assert "recorded" in row
    assert "finding" not in page.lower()
    assert "File F1" not in page
    assert "precision" not in page.lower()

    status, page = client.open(
        "POST",
        "/e/acme-2026/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service"},
    )
    assert status == 200
    assert "Attestation recorded." in page
    assert 'id="scan-gate"' not in page
    assert "Intake is required before an investigation." in page
    assert 'class="primary" disabled' in page
    assert page.index("Check an advisory") < page.index("Explore without an advisory")
    assert (
        "Exploratory checks identify the affected file far less often than advisory checks "
        "and often return files that are not affected."
    ) in page

    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    status, page = client.open("POST", "/e/acme-2026/intake/preview", {"path": str(source)})
    assert status == 200
    assert 'id="intake-preview"' in page
    assert "10 MB guidance" in page
    assert "app.py" in page
    status, page = client.open("POST", "/e/acme-2026/intake/confirm", {})
    assert status == 200
    assert "Snapshot SHA-256" in page
    assert "Stripped prefix" in page
    assert ">none<" in page

    status, page = client.open(
        "POST",
        "/e/acme-2026/review",
        {"choice": "search|CWE-89", "actor": "Ada"},
    )
    assert status == 200
    assert "Launch review" in page
    assert 'name="actor"' not in page
    assert "<label>Actor" not in page
    assert not entered.is_set()
    status, page = client.open(
        "POST",
        "/e/acme-2026/launch",
        {
            "actor": "Ada",
            "item": json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""}),
        },
    )
    assert status == 200
    assert "Investigation running." in page
    assert entered.wait(timeout=5)
    status, page = client.open("GET", "/e/acme-2026")
    assert "Investigation running." in page or 'id="progress"' in page
    assert SECRET not in page
    progress = page.split('id="progress"', 1)[1].split("</div>", 1)[0]
    assert SECRET not in progress
    assert "echo" not in progress
    release.set()
    for _ in range(40):
        status, page = client.open("GET", "/e/acme-2026")
        if "pending review" in page and 'id="progress"' not in page:
            break
        time.sleep(0.05)
    else:
        raise AssertionError(page)
    review = page.split('id="review"', 1)[1].split('id="reports"', 1)[0]
    assert "pending review" in review
    assert "finding" not in review.lower()
    assert "app.py" in review
    assert "CWE-89" in review
    assert "exploratory" in review
    assert "Rank" in review
    assert "likelihood_of_exploit" not in page
    assert "MITRE likelihood for this weakness class (not model confidence)" in page
    assert SECRET not in page

    status, page = client.open(
        "POST",
        "/e/acme-2026/verdict",
        {"path": "app.py", "cwe": "CWE-89", "state": "confirmed", "actor": "Ada", "note": ""},
    )
    assert status == 400
    assert "note" in page.lower()

    status, page = client.open(
        "POST",
        "/e/acme-2026/verdict",
        {
            "path": "app.py",
            "cwe": "CWE-89",
            "state": "confirmed",
            "actor": "Ada",
            "note": "Reviewed the query construction.",
        },
    )
    assert status == 200
    assert "Verdict recorded." in page

    (source / "app.py").write_text("changed\n", encoding="utf-8")
    status, page = client.open("POST", "/e/acme-2026/intake/again", {})
    assert status == 200
    assert "Stale verdict" in page
    assert "Re-confirm against the current snapshot." in page


def test_archive_upload_shows_the_stripped_prefix(ui) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    client.open(
        "POST",
        "/",
        {
            "id": "pyjwt",
            "customer": "Dry run",
            "scope": "tag archive",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as bundle:
        bundle.writestr("pyjwt-2.3.0/jwt/algorithms.py", "def prepare_key():\n    return None\n")
    status, page = client.post_file("/e/pyjwt/intake/preview", {}, "pyjwt-2.3.0.zip", payload.getvalue())
    assert status == 200
    assert "pyjwt-2.3.0" in page
    assert "Stripped prefix" in page
    status, page = client.open("POST", "/e/pyjwt/intake/confirm", {})
    assert status == 200
    assert "Snapshot SHA-256" in page


def test_purge_requires_confirmation_while_an_export_remains(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    client.open(
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
    client.open(
        "POST",
        "/e/acme-2026/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service"},
    )
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    client.open("POST", "/e/acme-2026/intake", {"path": str(source)})
    client.open("POST", "/e/acme-2026/close", {"actor": "Ada"})
    destination = tmp_path / "export.tar.gz"
    status, page = client.open(
        "POST",
        "/e/acme-2026/export",
        {"actor": "Ada", "output": str(destination)},
    )
    assert status == 200
    assert destination.is_file()
    assert str(destination) in page or str(destination.resolve()) in page
    status, page = client.open("POST", "/e/acme-2026/purge", {"actor": "Ada"})
    assert status == 400
    assert "confirm" in page.lower()
    assert (tmp_path / "engagements" / "acme-2026").is_dir()
    status, page = client.open(
        "POST",
        "/e/acme-2026/purge",
        {"actor": "Ada", "confirm_exports_handled": "on"},
    )
    assert status == 200
    assert "Purged" in page
    assert destination.is_file()
    assert not (tmp_path / "engagements" / "acme-2026").exists()


def test_browser_checks_refuse_foreign_host_origin_and_oversized_archives(ui) -> None:
    import socket
    from urllib.parse import urlparse

    from astrolabe.snapshot import DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES

    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, _body, headers = client.exchange("GET", "/")
    assert status == 200
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    policy = headers["Content-Security-Policy"]
    assert "script-src 'self'" in policy
    assert "style-src 'self'" in policy

    status, body = client.open("GET", "/", host="evil.example")
    assert status == 403
    assert body.strip() == "Refused"

    status, _body = client.open(
        "POST",
        "/",
        {
            "id": "no-origin",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
        origin=None,
    )
    assert status == 403
    assert not (tmp_path / "engagements" / "no-origin").exists()

    status, _body = client.open(
        "POST",
        "/",
        {
            "id": "null-origin",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
        origin="null",
    )
    assert status == 403
    assert not (tmp_path / "engagements" / "null-origin").exists()

    status, _body = client.open(
        "POST",
        "/",
        {
            "id": "chrome-same-origin",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
        origin="null",
        extra={"Sec-Fetch-Site": "same-origin"},
    )
    assert status == 200
    assert (tmp_path / "engagements" / "chrome-same-origin").is_dir()

    status, _body = client.open(
        "POST",
        "/",
        {
            "id": "null-cross-site",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
        origin="null",
        extra={"Sec-Fetch-Site": "cross-site"},
    )
    assert status == 403
    assert not (tmp_path / "engagements" / "null-cross-site").exists()

    status, _body = client.open(
        "POST",
        "/",
        {
            "id": "via-referer",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
        origin=None,
        referer=client.base + "/",
    )
    assert status == 200
    assert (tmp_path / "engagements" / "via-referer").is_dir()

    client.open(
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
    client.open("POST", "/e/acme-2026/close", {"actor": "Ada"})
    status, body = client.open(
        "POST",
        "/e/acme-2026/purge",
        {"actor": "Ada"},
        origin="http://evil.example",
    )
    assert status == 403
    assert "Refused" in body
    assert (tmp_path / "engagements" / "acme-2026").is_dir()

    parsed = urlparse(client.base)
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout=2)
    sock.sendall(
        (
            f"POST / HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\n"
            f"Origin: {client.base}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {DEFAULT_MAX_BYTES + 1}\r\nConnection: close\r\n\r\n"
        ).encode()
    )
    chunks = b""
    while True:
        piece = sock.recv(4096)
        if not piece:
            break
        chunks += piece
    sock.close()
    assert b"413" in chunks
    assert b"Upload exceeds the size cap" in chunks

    client.open(
        "POST",
        "/",
        {
            "id": "caps",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    status, page = client.post_file("/e/caps/intake/preview", {}, "bomb.zip", _claimed_zip(DEFAULT_MAX_BYTES + 1))
    assert status == 400
    assert "before extraction" in page
    engagement = tmp_path / "engagements" / "caps"
    assert not (engagement / "src").exists()
    assert not (engagement / "intake" / "extract").exists()
    assert not (engagement / "intake" / "pending").exists()

    status, page = client.post_file(
        "/e/caps/intake/preview",
        {},
        "wide.zip",
        _counted_zip(DEFAULT_MAX_FILES + 1),
    )
    assert status == 400
    assert "before extraction" in page
    assert not (engagement / "src").exists()
    assert not (engagement / "intake" / "pending" / "extract").exists()


def test_folder_and_single_file_intake_and_clone_notice(ui) -> None:
    from astrolabe.ui import CLONE_NOTICE, SINGLE_FILE_NOTE

    client, app, _entered, release, tmp_path = ui
    release.set()
    client.open(
        "POST",
        "/",
        {
            "id": "folder",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    status, page = client.open("GET", "/e/folder")
    assert CLONE_NOTICE in page
    status, page = client.post_parts(
        "/e/folder/intake/preview",
        [("files", "app.py", b"print(1)\n"), ("files", "tests/test_app.py", b"pass\n")],
    )
    assert status == 200
    assert "Excluded tests: 1" in page
    assert "app.py" in page
    status, page = client.open("POST", "/e/folder/intake/confirm", {})
    assert status == 200
    assert (tmp_path / "engagements" / "folder" / "snapshot" / "app.py").is_file()
    assert not (tmp_path / "engagements" / "folder" / "snapshot" / "tests").exists()

    client.open(
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
    status, page = client.open(
        "POST",
        "/e/script/intake/preview",
        {"filename": "pay.py", "script": "print(1)\n"},
    )
    assert status == 200
    assert "pay.py" in page
    status, page = client.open("POST", "/e/script/intake/confirm", {})
    assert status == 200
    assert "single-file" in page
    assert SINGLE_FILE_NOTE in page
    assert (tmp_path / "engagements" / "script" / "snapshot" / "pay.py").is_file()

    status, page = client.open(
        "POST",
        "/e/script/intake/preview",
        {"url": "https://user:not-a-secret@github.com/example/widgets.git", "ref": "main", "actor": "Ada", "replace": "on"},
    )
    assert status == 400
    assert "credentials" in page.lower()
    blob = (tmp_path / "engagements" / "script" / "engagement.json").read_text(encoding="utf-8")
    assert "not-a-secret" not in blob

    app._running.add("script")
    status, page = client.open(
        "POST",
        "/e/script/intake/preview",
        {"url": "https://github.com/example/widgets.git", "ref": "main", "actor": "Ada", "replace": "on"},
    )
    assert status == 400
    assert "investigation is running" in page


def test_chunked_upload_is_counted_without_content_length(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    from urllib.parse import urlparse

    client, _app, _entered, release, tmp_path = ui
    release.set()
    parsed = urlparse(client.base)
    fields = urllib.parse.urlencode(
        {
            "id": "chunked",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        }
    ).encode()
    body = _chunked(fields, 7)
    status, page = _raw_post(
        parsed.hostname,
        parsed.port,
        client.base,
        body,
        extra="Transfer-Encoding: chunked\r\n",
    )
    assert status == 303
    assert "/e/chunked" in page
    assert (tmp_path / "engagements" / "chunked").is_dir()

    monkeypatch.setattr("astrolabe.ui.UPLOAD_MAX_BYTES", 20)
    status, page = _raw_post(
        parsed.hostname,
        parsed.port,
        client.base,
        b"8\r\nabcdefgh\r\n14\r\n",
        extra="Transfer-Encoding: chunked\r\n",
    )
    assert status == 413
    assert "Upload exceeds the size cap" in page
    assert not (tmp_path / "engagements" / "abcdefgh").exists()


def _chunked(payload: bytes, size: int) -> bytes:
    parts: list[bytes] = []
    for offset in range(0, len(payload), size):
        block = payload[offset : offset + size]
        parts.append(f"{len(block):x}\r\n".encode() + block + b"\r\n")
    parts.append(b"0\r\n\r\n")
    return b"".join(parts)


def _raw_post(host: str | None, port: int, origin: str, body: bytes, *, extra: str) -> tuple[int, str]:
    import socket

    sock = socket.create_connection((host, port), timeout=2)
    sock.settimeout(2)
    request = (
        f"POST / HTTP/1.1\r\nHost: {host}:{port}\r\nOrigin: {origin}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"{extra}Connection: close\r\n\r\n"
    ).encode() + body
    sock.sendall(request)
    chunks = b""
    while True:
        try:
            piece = sock.recv(4096)
        except TimeoutError:
            break
        if not piece:
            break
        chunks += piece
    sock.close()
    head, _, page = chunks.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    return status, page.decode("utf-8", "replace")


def _claimed_zip(claimed: int) -> bytes:
    import binascii
    import struct

    name = b"a.txt"
    data = b"x"
    crc = binascii.crc32(data) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(data),
        claimed,
        len(name),
        0,
    ) + name + data
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(data),
        claimed,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    ) + name
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


def _counted_zip(count: int) -> bytes:
    import binascii
    import struct

    name = b"a.txt"
    data = b"x"
    crc = binascii.crc32(data) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(data),
        len(data),
        len(name),
        0,
    ) + name + data
    parts = []
    for index in range(count):
        member = f"f{index}.txt".encode()
        parts.append(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(member),
                0,
                0,
                0,
                0,
                0,
                0,
            )
            + member
        )
    central = b"".join(parts)
    recorded = min(count, 0xFFFF)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, recorded, recorded, len(central), len(local), 0)
    return local + central + eocd


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def test_create_redirects_303_to_the_engagement(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    opener = urllib.request.build_opener(_NoRedirect)
    payload = urllib.parse.urlencode(
        {
            "id": "acme-2026",
            "customer": "Acme",
            "scope": "Billing service",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        }
    ).encode()
    request = urllib.request.Request(
        client.base + "/",
        data=payload,
        headers={"Origin": client.base, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as caught:
        opener.open(request)
    assert caught.value.code == 303
    assert caught.value.headers.get("Location") == "/e/acme-2026"
    assert (tmp_path / "engagements" / "acme-2026" / "engagement.json").is_file()


def test_purged_id_is_refused_and_a_new_id_is_attested_on_its_own(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    fields = {
        "customer": "Acme",
        "scope": "Billing service",
        "start": "2026-10-09",
        "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
    }
    client.open("POST", "/", {"id": "pyjwt-230", **fields})
    client.open(
        "POST",
        "/e/pyjwt-230/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service"},
    )
    client.open("POST", "/e/pyjwt-230/close", {"actor": "Ada"})
    status, page = client.open(
        "POST",
        "/e/pyjwt-230/purge",
        {"actor": "Ada", "confirm_exports_handled": "on"},
    )
    assert status == 200
    assert not (tmp_path / "engagements" / "pyjwt-230").exists()
    status, page = client.open("POST", "/", {"id": "pyjwt-230", **fields})
    assert status == 400
    assert "pyjwt-230b" in page
    assert not (tmp_path / "engagements" / "pyjwt-230").exists()
    status, page = client.open("POST", "/", {"id": "pyjwt-230b", **fields})
    assert status == 200
    assert "Record authorization" not in page
    assert "Recorded by" not in page
    assert "Authorized:" in page
    from astrolabe.engagement import has_attestation, load_engagement, read_durable_audit, read_instance_attestation

    root = tmp_path / "engagements"
    record = load_engagement(root, "pyjwt-230b")
    line = read_instance_attestation(root, record)
    assert line is not None
    assert line["instance_id"] == record["instance_id"]
    assert has_attestation(root, "pyjwt-230b") is True
    previous = [
        row["instance_id"]
        for row in read_durable_audit(root, "pyjwt-230")
        if row.get("action") == "attest"
    ]
    assert previous
    assert record["instance_id"] not in previous


def test_index_sections_are_about_environment_then_engagements(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()

    def fail(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("index started a check")

    monkeypatch.setattr("astrolabe.ui.run_checks", fail)
    status, page = client.open("GET", "/")
    assert status == 200
    assert 'id="about"' not in page
    assert 'href="/about"' in page
    assert page.index('href="/about"') < page.index('id="engagements"')
    engagements = page.index('id="engagements"')
    assert engagements
    assert 'id="environment"' not in page
    assert 'id="status-pill"' in page
    assert 'href="/environment"' in page
    assert 'aria-haspopup="dialog"' in page
    assert "Status · checking" in page
    assert "status-pill--muted" in page
    status, about = client.open("GET", "/about")
    assert status == 200
    assert 'href="/about"' in about
    assert (
        "Astrolabe is a local, consultant-led code triage tool. "
        "It checks a customer repository snapshot against a published advisory or selected CWEs, "
        "using the Antares-1B model in a sandboxed container. "
        "Model output is a candidate for consultant review, not a finding."
    ) in about
    assert "<dt>Astrolabe</dt><dd>0.1.0</dd>" in about
    assert "<dt>Antares</dt><dd>1.0.0</dd>" in about


def test_failing_dependency_renders_missing(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.environment import Check

    client, _app, _entered, release, _tmp_path = ui
    release.set()
    monkeypatch.setattr(
        "astrolabe.ui.run_checks",
        lambda root, force=False: [Check("Docker daemon", "missing", "The daemon did not respond", "Start Docker.")],
    )
    status, page = client.open("GET", "/environment")
    assert status == 200
    assert "missing" in page
    assert "Status · 1 missing" in page
    assert "status-pill--danger" in page
    assert 'id="environment-checks"' in page


def test_index_does_not_modify_engagement_or_audit(ui) -> None:
    from astrolabe.engagement import append_durable_audit, durable_audit_path

    client, _app, _entered, release, tmp_path = ui
    release.set()
    root = tmp_path / "engagements"
    directory = root / "legacy-1"
    directory.mkdir()
    record = {
        "id": "legacy-1",
        "customer": "Acme",
        "scope": "Billing",
        "start_date": "2026-01-01",
        "end_date": None,
        "consultants": ["Ada"],
        "state": "open",
        "snapshot_sha256": None,
        "intake": None,
    }
    (directory / "engagement.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (directory / "audit.jsonl").write_text(
        json.dumps({"action": "create", "actor": "Ada", "timestamp": "2020-01-01T00:00:00Z"}) + "\n",
        encoding="utf-8",
    )
    append_durable_audit(
        root,
        "legacy-1",
        {
            "action": "attest",
            "actor": "Ada",
            "reference": "SOW",
            "scope": "Billing",
            "attested_at": "2020-01-02T00:00:00Z",
        },
    )
    engagement_before = (directory / "engagement.json").read_bytes()
    audit_path = durable_audit_path(root)
    audit_before = audit_path.read_bytes()
    status, page = client.open("GET", "/")
    assert status == 200
    assert (directory / "engagement.json").read_bytes() == engagement_before
    assert audit_path.read_bytes() == audit_before
    row_at = page.index('href="/e/legacy-1"')
    row = page[row_at : page.index("</tr>", row_at)]
    assert "recorded" in row


def test_index_lists_live_engagements_newest_activity_first(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    monkeypatch.setattr("astrolabe.ui.run_checks", lambda root, force=False: [])
    root = tmp_path / "engagements"
    sha = "a" * 64
    _plant(root, "older-eng", "2026-01-01T00:00:00Z", "open", sha)
    _plant(root, "newer-eng", "2026-06-01T00:00:00Z", "open", None)
    _plant(root, "purged-eng", "2026-08-01T00:00:00Z", "purged", None)
    status, page = client.open("GET", "/")
    assert status == 200
    assert "purged-eng" not in page
    assert page.index('href="/e/newer-eng"') < page.index('href="/e/older-eng"')
    newer_at = page.index('href="/e/newer-eng"')
    newer = page[newer_at : page.index("</tr>", newer_at)]
    assert "required" in newer
    assert f'title="{sha}"' in page
    assert "a" * 12 in page
    assert "No engagements yet." not in page


def test_new_page_keeps_the_create_form_and_validation_returns_values(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.environment import Check, prime_cache

    client, _app, _entered, release, tmp_path = ui
    release.set()
    calls: list[object] = []

    def record(*args: object, **kwargs: object) -> list[Check]:
        calls.append(args)
        return []

    monkeypatch.setattr("astrolabe.ui.run_checks", record)
    prime_cache(tmp_path / "engagements", [Check("Docker daemon", "missing", "down", "Start Docker.")])
    status, page = client.open("GET", "/new")
    assert status == 200
    for name in ("id", "customer", "scope", "start", "end", "consultants"):
        assert f'name="{name}"' in page
    assert 'action="/"' in page
    assert "Not ready: Docker daemon" in page
    assert '<button class="primary" type="submit">Create engagement</button>' in page
    assert calls == []
    status, page = client.open(
        "POST",
        "/",
        {
            "id": "not a valid id",
            "customer": "A&B <tag>",
            "scope": "Billing",
            "start": "2026-10-09",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    assert status == 400
    assert 'name="customer"' in page
    assert 'value="A&amp;B &lt;tag&gt;"' in page
    assert 'id="engagements"' not in page
    assert not (tmp_path / "engagements" / "not a valid id").exists()


def _new_fields(**overrides: str) -> dict[str, str]:
    fields = {
        "id": "acme-2026",
        "customer": "Acme",
        "scope": "Billing service",
        "start": "2026-10-09",
        "end": "",
        "consultants": "Ada",
        "reference": "SOW-14",
        "authorized": "on",
    }
    fields.update(overrides)
    return fields


def test_new_page_fields_defaults_and_does_not_run_checks(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    calls: list[object] = []

    def record(*args: object, **_kwargs: object) -> list[object]:
        calls.append(args)
        return []

    monkeypatch.setattr("astrolabe.ui.run_checks", record)
    status, page = client.open("GET", "/new")
    assert status == 200
    assert "New engagement" in page
    assert "Creates a local workspace. Authorization is recorded on this form. Checks stay off until it is stored." in page
    assert 'class="card form-card"' in page
    assert 'class="env-hint">* Required' in page
    assert page.index('name="customer"') < page.index('name="id"')
    assert page.index('name="id"') < page.index('name="scope"')
    assert page.index('name="scope"') < page.index('name="reference"')
    assert page.index('name="reference"') < page.index('name="authorized"')
    assert page.index('name="authorized"') < page.index('name="start"')
    assert page.index('name="start"') < page.index('name="end"')
    assert page.index('name="end"') < page.index('name="consultants"')
    assert page.index('class="form-row"') < page.index('name="start"')
    assert '<label for="customer">Customer *</label>' in page
    assert '<label for="id">Engagement ID *</label>' in page
    assert '<label for="scope">Scope *</label>' in page
    assert '<label for="reference">Authorization reference *</label>' in page
    assert "The customer's written authorization covers this scope." in page
    assert "A SOW, contract, ticket, or email that a reviewer could locate later." in page
    assert '<label for="start">Start *</label>' in page
    assert '<label for="end">End (optional)</label>' in page
    assert '<label for="consultants">Consultants *</label>' in page
    assert 'maxlength="200"' in page
    assert 'maxlength="2000"' in page
    assert 'rows="3"' in page
    assert 'pattern="^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$"' in page
    assert 'type="date"' in page
    assert f'value="{date.today().isoformat()}"' in page
    assert f'value="{html.escape(getpass.getuser())}"' in page
    assert html.escape("Lowercase letters, digits, hyphens. Can't be changed or reused after purge.") in page
    assert "What the customer authorized. Confirmed at attestation." in page
    assert "Comma-separated. The first name is recorded as the creator." in page
    assert 'aria-describedby="id-hint"' in page
    assert 'href="/">Cancel</a>' in page
    assert '<button class="primary" type="submit">Create engagement</button>' in page
    assert "disabled" not in page.split("<form", 1)[1].split("</form>", 1)[0]
    assert 'id="form-errors"' not in page
    assert calls == []
    _status, script = client.open("GET", "/astrolabe.js")
    assert "idEdited" in script
    assert "createButton.disabled = true" in script
    assert "createButton.disabled = false" in script
    assert "formErrors.focus" in script


def test_invalid_engagement_ids_return_400_under_id(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    for engagement_id in ("ACME", "-acme", "ab", "a" * 65):
        status, page = client.open("POST", "/", _new_fields(id=engagement_id, customer="A&B"))
        assert status == 400
        assert f'value="{html.escape(engagement_id, quote=True)}"' in page
        assert 'value="A&amp;B"' in page
        assert 'id="id-error"' in page
        assert 'aria-invalid="true"' in page
        assert 'aria-describedby="id-hint id-error"' in page
        assert 'href="#id"' in page
        assert 'role="alert"' in page
        assert 'tabindex="-1"' in page
        assert not (tmp_path / "engagements" / engagement_id).exists()


def test_mixed_case_id_suggests_the_lowercase_form(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, page = client.open("POST", "/", _new_fields(id="Acme-2026"))
    assert status == 400
    assert 'value="Acme-2026"' in page
    assert 'id="id-error"' in page
    error = page.split('id="id-error"', 1)[1].split("</p>", 1)[0]
    assert "acme-2026" in error
    assert "differs only by case or whitespace" in error
    assert 'href="#id"' in page
    assert not (tmp_path / "engagements" / "acme-2026").exists()
    assert not (tmp_path / "engagements" / "Acme-2026").exists()


def test_end_before_start_returns_400_under_end(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, page = client.open("POST", "/", _new_fields(start="2026-10-10", end="2026-10-01"))
    assert status == 400
    assert 'id="end-error"' in page
    assert "on or after start" in page.split('id="end-error"', 1)[1].split("</p>", 1)[0]
    assert 'aria-invalid="true"' in page.split('id="end"', 1)[1].split(">", 1)[0]
    assert 'value="2026-10-10"' in page
    assert 'value="2026-10-01"' in page
    assert 'min="2026-10-10"' in page
    assert not (tmp_path / "engagements" / "acme-2026").exists()


def test_missing_customer_scope_or_consultants_returns_400(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, page = client.open(
        "POST",
        "/",
        _new_fields(customer="  ", scope="", consultants=","),
    )
    assert status == 400
    for name in ("customer", "scope", "consultants"):
        assert f'id="{name}-error"' in page
        assert f'href="#{name}"' in page
        assert "required" in page.split(f'id="{name}-error"', 1)[1].split("</p>", 1)[0].lower()
    assert not (tmp_path / "engagements" / "acme-2026").exists()
    status, page = client.open("POST", "/", _new_fields(customer="A" * 201))
    assert status == 400
    assert 'id="customer-error"' in page
    assert "200" in page.split('id="customer-error"', 1)[1].split("</p>", 1)[0]
    status, page = client.open("POST", "/", _new_fields(consultants="A" * 101))
    assert status == 400
    assert 'id="consultants-error"' in page
    assert "100" in page.split('id="consultants-error"', 1)[1].split("</p>", 1)[0]


def test_live_and_purged_ids_are_refused_under_id(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, _page = client.open("POST", "/", _new_fields())
    assert status == 200
    status, page = client.open("POST", "/", _new_fields(id="ACME-2026"))
    assert status == 400
    error = page.split('id="id-error"', 1)[1].split("</p>", 1)[0]
    assert "already exists" in error
    assert 'href="#id"' in page
    client.open(
        "POST",
        "/e/acme-2026/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "Billing service"},
    )
    client.open("POST", "/e/acme-2026/close", {"actor": "Ada"})
    client.open("POST", "/e/acme-2026/purge", {"actor": "Ada", "confirm_exports_handled": "on"})
    assert not (tmp_path / "engagements" / "acme-2026").exists()
    status, page = client.open("POST", "/", _new_fields(id="Acme-2026"))
    assert status == 400
    error = page.split('id="id-error"', 1)[1].split("</p>", 1)[0]
    assert "was purged" in error
    assert "Acme-2026b" in error
    assert not (tmp_path / "engagements" / "Acme-2026").exists()


def test_create_audit_actor_is_the_first_consultant(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, _page = client.open("POST", "/", _new_fields(consultants=" Ada , Bob "))
    assert status == 200
    entry = json.loads((tmp_path / "engagements" / "acme-2026" / "audit.jsonl").read_text().splitlines()[0])
    assert entry["action"] == "create"
    assert entry["actor"] == "Ada"
    record = json.loads((tmp_path / "engagements" / "acme-2026" / "engagement.json").read_text())
    assert record["consultants"] == ["Ada", "Bob"]


def test_new_engagement_escapes_values_on_rerender(ui) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    payload = "<script>alert(1)</script>"
    status, page = client.open(
        "POST",
        "/",
        _new_fields(id="-bad", customer=payload, scope=payload, consultants=payload),
    )
    assert status == 400
    assert "<script>alert" not in page
    assert page.count("&lt;script&gt;alert(1)&lt;/script&gt;") >= 3
    assert 'value="-bad"' in page


def test_existing_engagement_ids_still_load(ui) -> None:
    from astrolabe.engagement import load_engagement

    client, _app, _entered, release, tmp_path = ui
    release.set()
    root = tmp_path / "engagements"
    _plant(root, "Ab_1", "2026-01-01T00:00:00Z", "open", None)
    assert load_engagement(root, "Ab_1")["id"] == "Ab_1"
    status, page = client.open("GET", "/e/Ab_1")
    assert status == 200
    assert "Ab_1" in page
    status, _page = client.open("POST", "/", _new_fields(id="ab"))
    assert status == 400
    assert (root / "Ab_1" / "engagement.json").is_file()
    assert not (root / "ab").exists()


def test_recheck_uses_origin_checks_and_redirects_home(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    monkeypatch.setattr("astrolabe.ui.run_checks", lambda root, force=False: [])
    status, _body = client.open("POST", "/environment/recheck", {}, origin=None)
    assert status == 403
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        client.base + "/environment/recheck",
        data=b"",
        headers={"Origin": client.base, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as caught:
        opener.open(request)
    assert caught.value.code == 303
    assert caught.value.headers.get("Location") == "/"
    assert _recheck_location(client, {"next": "/environment"}) == "/environment"
    assert _recheck_location(client, {"next": "//evil.example"}) == "/"
    assert _recheck_location(client, {"next": "https://evil.example"}) == "/"
    assert _recheck_location(client, {"next": "/\\evil"}) == "/"


def test_pages_read_the_cache_and_do_not_run_checks(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    calls: list[object] = []

    def record(*args: object, **_kwargs: object) -> list[object]:
        calls.append(args)
        return []

    monkeypatch.setattr("astrolabe.ui.run_checks", record)
    status, engagement = client.open(
        "POST",
        "/",
        {
            "id": "status-eng",
            "customer": "Acme",
            "scope": "Billing",
            "start": "2026-01-01",
            "consultants": "Ada",
            "reference": "SOW-14",
            "authorized": "on",
        },
    )
    assert status == 200
    status, home = client.open("GET", "/")
    status, fresh = client.open("GET", "/new")
    status, again = client.open("GET", "/e/status-eng")
    assert calls == []
    for page in (engagement, home, fresh, again):
        assert "Status · checking" in page
        assert "status-pill--muted" in page
        assert page.count("<script") == 1
        assert 'src="/astrolabe.js"' in page
    status, script = client.open("GET", "/astrolabe.js")
    assert status == 200
    assert "preventDefault" in script
    assert "DOMParser" in script
    assert "showModal" in script
    assert 'location.assign("/environment")' in script
    assert "statusPill.focus" in script


def test_environment_page_lists_every_check_with_a_location(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.environment import check_location, default_probes

    secret = "astrolabe-status-secret-value"
    monkeypatch.setenv("ASTROLABE_STATUS_SECRET", secret)
    client, app, _entered, release, _tmp_path = ui
    release.set()
    status, page = client.open("GET", "/environment")
    assert status == 200
    for name, _probe in default_probes(app.root):
        assert name in page
        assert _esc_path(check_location(name, app.root)) in page
    assert secret not in page
    for column in ("Check", "Health", "Location", "Detail", "Fix"):
        assert f"<th>{column}</th>" in page
    assert 'name="next"' in page
    assert 'value="/environment"' in page
    assert 'action="/environment/recheck"' in page


def test_readiness_warning_ignores_advisory_cache() -> None:
    from astrolabe.environment import Check
    from astrolabe.ui import _readiness_warning

    assert _readiness_warning(None) == ""
    assert _readiness_warning([Check("Advisory cache", "warn", "none")]) == ""
    assert _readiness_warning([Check("Advisory cache", "missing", "none")]) == ""
    assert _readiness_warning([Check("PDF rendering", "warn", "Pango was not found")]) == ""
    assert "Not ready: Inference socket" in _readiness_warning([Check("Inference socket", "warn", "later")])


def _recheck_location(client: Client, fields: dict[str, str]) -> str | None:
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        client.base + "/environment/recheck",
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        headers={"Origin": client.base, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as caught:
        opener.open(request)
    assert caught.value.code == 303
    return caught.value.headers.get("Location")


def _esc_path(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plant(root: Path, engagement_id: str, stamp: str, state: str, sha: str | None) -> None:
    directory = root / engagement_id
    directory.mkdir()
    record = {
        "id": engagement_id,
        "instance_id": f"instance-{engagement_id}",
        "attestation_migrated": True,
        "customer": "Acme",
        "scope": "Billing",
        "start_date": "2026-01-01",
        "end_date": None,
        "consultants": ["Ada"],
        "state": state,
        "snapshot_sha256": sha,
        "intake": None,
    }
    (directory / "engagement.json").write_text(json.dumps(record), encoding="utf-8")
    (directory / "audit.jsonl").write_text(
        json.dumps({"action": "create", "actor": "Ada", "timestamp": stamp}) + "\n",
        encoding="utf-8",
    )


def _no_redirect(client: Client, path: str, fields: dict[str, str], extra: dict[str, str] | None = None):
    opener = urllib.request.build_opener(_NoRedirect)
    headers = {"Origin": client.base, "Content-Type": "application/x-www-form-urlencoded"}
    if extra:
        headers.update(extra)
    request = urllib.request.Request(
        client.base + path,
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with opener.open(request) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), exc.headers


def test_acting_as_cookie_is_a_preference_and_bad_cookies_fall_back(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    fields = _new_fields(id="cookie-a", consultants="Ada, Bob")
    client.open("POST", "/", fields)
    status, _page, _headers = client.exchange(
        "POST",
        "/e/cookie-a/acting-as",
        {"consultant": "Bob"},
        origin=None,
    )
    assert status == 403
    status, _page, _headers = client.exchange(
        "POST",
        "/e/cookie-a/acting-as",
        {"consultant": "Bob"},
        origin=None,
        extra={"Origin": "null", "Sec-Fetch-Site": "cross-site"},
    )
    assert status == 403
    status, _page, headers = _no_redirect(client, "/e/cookie-a/acting-as", {"consultant": "Bob"})
    assert status == 303
    cookie = headers.get("Set-Cookie") or ""
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/e/cookie-a" in cookie
    record = json.loads((tmp_path / "engagements" / "cookie-a" / "engagement.json").read_text(encoding="utf-8"))
    valid = (
        urllib.parse.quote(str(record["instance_id"]), safe="")
        + "."
        + urllib.parse.quote("Bob", safe="")
    )
    client.open("POST", "/", _new_fields(id="cookie-forged", consultants="Ada, Bob"))
    forged = urllib.parse.quote("not-this-instance", safe="") + "." + urllib.parse.quote("Eve", safe="")
    client.exchange(
        "POST",
        "/e/cookie-forged/close",
        {},
        extra={"Cookie": f"astrolabe_acting_as={forged}"},
    )
    audit = (tmp_path / "engagements" / "cookie-forged" / "audit.jsonl").read_text(encoding="utf-8")
    close = next(json.loads(line) for line in audit.splitlines() if '"close"' in line)
    assert close["actor"] == "Ada"
    assert "Eve" not in audit
    client.open("POST", "/", _new_fields(id="cookie-other", consultants="Ada, Bob"))
    other = urllib.parse.quote("00000000-0000-0000-0000-000000000000", safe="") + "." + urllib.parse.quote("Bob", safe="")
    client.exchange(
        "POST",
        "/e/cookie-other/close",
        {},
        extra={"Cookie": f"astrolabe_acting_as={other}"},
    )
    other_audit = (tmp_path / "engagements" / "cookie-other" / "audit.jsonl").read_text(encoding="utf-8")
    other_close = next(json.loads(line) for line in other_audit.splitlines() if '"close"' in line)
    assert other_close["actor"] == "Ada"
    assert other_close["actor"] != "Bob"
    status, page, _headers = client.exchange(
        "GET",
        "/e/cookie-a/report",
        extra={"Cookie": f"astrolabe_acting_as={valid}"},
    )
    assert status == 200
    assert "Locks the report. Requires every candidate confirmed or not actionable." in page
    assert 'value="Bob" selected' in page
    assert 'value="Ada" selected' not in page
    client.exchange(
        "POST",
        "/e/cookie-a/close",
        {},
        extra={"Cookie": f"astrolabe_acting_as={valid}"},
    )
    valid_audit = (tmp_path / "engagements" / "cookie-a" / "audit.jsonl").read_text(encoding="utf-8")
    valid_close = next(json.loads(line) for line in valid_audit.splitlines() if '"close"' in line)
    assert valid_close["actor"] == "Bob"


def test_posted_actor_must_be_a_consultant(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="actors"))
    status, page = client.open("POST", "/e/actors/close", {"actor": "Eve"})
    assert status == 400
    assert "Eve" in page
    audit = (tmp_path / "engagements" / "actors" / "audit.jsonl").read_text(encoding="utf-8")
    assert "Eve" not in audit
    assert json.loads((tmp_path / "engagements" / "actors" / "engagement.json").read_text(encoding="utf-8"))["state"] == "open"
    status, _page = client.open("POST", "/e/actors/close", {"actor": " Ada "})
    assert status == 200
    audit = (tmp_path / "engagements" / "actors" / "audit.jsonl").read_text(encoding="utf-8")
    close = next(json.loads(line) for line in audit.splitlines() if '"close"' in line)
    assert close["actor"] == "Ada"


def test_new_engagement_requires_reference_and_authorization(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, page = client.open("POST", "/", _new_fields(reference="  ", authorized=""))
    assert status == 400
    assert 'id="reference-error"' in page
    assert 'id="authorized-error"' in page
    assert not (tmp_path / "engagements" / "acme-2026").exists()
    status, page = client.open("POST", "/", _new_fields(authorized=""))
    assert status == 400
    assert 'id="authorized-error"' in page
    assert 'id="reference-error"' not in page


def test_create_records_an_instance_attestation(ui) -> None:
    from astrolabe.engagement import has_attestation, load_engagement, read_instance_attestation

    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, page = client.open("POST", "/", _new_fields(id="created-auth"))
    assert status == 200
    assert "Authorized:" in page
    assert "Record authorization" not in page
    authorize = page.split('id="authorize"', 1)[1].split("<section", 1)[0]
    assert "step-card--collapsed" in authorize
    assert ">Change</a>" not in authorize
    root = tmp_path / "engagements"
    record = load_engagement(root, "created-auth")
    line = read_instance_attestation(root, record)
    assert line is not None
    assert line["instance_id"] == record["instance_id"]
    assert line["actor"] == "Ada"
    assert line["reference"] == "SOW-14"
    assert line["scope"] == "Billing service"
    assert has_attestation(root, "created-auth") is True
    assert "attestation_failed" not in (root / "created-auth" / "engagement.json").read_text(encoding="utf-8")


def test_attest_append_failure_keeps_the_engagement_and_shows_authorize(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.engagement import has_attestation

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("astrolabe.engagement.attest", fail)
    client, _app, _entered, release, tmp_path = ui
    release.set()
    status, page = client.open("POST", "/", _new_fields(id="attest-fail"))
    assert status == 200
    assert "Authorization was not recorded. Record it below." in page
    assert 'id="authorization-missing"' in page
    assert "Record authorization" in page
    assert 'id="next-step"' in page
    assert "Next: record authorization." in page
    root = tmp_path / "engagements"
    assert (root / "attest-fail" / "engagement.json").is_file()
    assert "attestation_failed" not in (root / "attest-fail" / "engagement.json").read_text(encoding="utf-8")
    assert has_attestation(root, "attest-fail") is False


def test_scope_is_locked_after_attestation(ui) -> None:
    from astrolabe.engagement import load_engagement, read_instance_attestation

    client, _app, _entered, release, tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="scope-lock"))
    root = tmp_path / "engagements"
    before = read_instance_attestation(root, load_engagement(root, "scope-lock"))
    assert before is not None
    status, page = client.open(
        "POST",
        "/e/scope-lock/attest",
        {"actor": "Ada", "reference": "SOW-14", "scope": "A different scope", "authorized": "on"},
    )
    assert status == 400
    assert "locked" in page.lower()
    after = read_instance_attestation(root, load_engagement(root, "scope-lock"))
    assert after is not None
    assert after["scope"] == "Billing service"
    assert load_engagement(root, "scope-lock")["scope"] == "Billing service"


def test_legacy_record_shows_authorize_until_it_is_recorded(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    root = tmp_path / "engagements"
    _plant(root, "legacy-auth", "2026-01-01T00:00:00Z", "open", "a" * 64)
    status, page = client.open("GET", "/e/legacy-auth")
    assert status == 200
    assert "Confirm you have written permission from Acme to analyze this code." in page
    assert "Record authorization" in page
    assert 'id="scan-gate"' in page
    assert 'class="primary" disabled' in page
    assert 'class="secondary" disabled' in page
    status, page = client.open(
        "POST",
        "/e/legacy-auth/attest",
        {"reference": "SOW-14", "scope": "Billing", "authorized": "on"},
    )
    assert status == 200
    assert "Attestation recorded." in page
    assert 'id="scan-gate"' not in page
    assert 'class="primary" disabled' not in page
    assert 'class="primary"' in page
    assert "Authorized:" in page
    authorize = page.split('id="authorize"', 1)[1].split("<section", 1)[0]
    assert "step-card--collapsed" in authorize
    assert ">Change</a>" not in authorize


def test_next_step_names_the_current_action(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.engagement import load_engagement
    from astrolabe.purge import close_engagement

    client, _app, _entered, release, tmp_path = ui
    release.set()
    home = tmp_path / "home"
    monkeypatch.setattr("astrolabe.purge.Path.home", lambda *_args: home)
    root = tmp_path / "engagements"
    _plant(root, "banner-open", "2026-01-01T00:00:00Z", "open", None)
    _status, page = client.open("GET", "/e/banner-open")
    assert "Next: record authorization." in page
    client.open("POST", "/", _new_fields(id="banner"))
    _status, page = client.open("GET", "/e/banner")
    assert html.escape("Next: add the customer's code.") in page
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    client.open("POST", "/e/banner/intake/preview", {"path": str(source)})
    _status, page = client.open("POST", "/e/banner/intake/confirm", {})
    assert "Next: run a check." in page
    assert "Run a check to get candidates." in page
    assert "Locks the report." not in page
    assert "Requires every candidate confirmed or not actionable." not in page
    record = load_engagement(root, "banner")
    sha = str(record["snapshot_sha256"])
    (root / "banner" / "investigations.json").write_text(
        json.dumps(
            [
                {
                    "id": "inv-1",
                    "cwe": "CWE-89",
                    "exploratory": True,
                    "selection_source": "search",
                    "snapshot_sha256": sha,
                    "runs": [{"candidate_paths": ["app.py"]}],
                }
            ]
        ),
        encoding="utf-8",
    )
    (root / "banner" / "candidates.json").write_text(
        json.dumps(
            {
                "app.py|CWE-89": {
                    "file_path": "app.py",
                    "cwe": "CWE-89",
                    "state": "candidate",
                    "snapshot_sha256": sha,
                }
            }
        ),
        encoding="utf-8",
    )
    _status, page = client.open("GET", "/e/banner")
    assert "Next: review the candidates." in page
    assert "0 of 1 reviewed" in page
    store = json.loads((root / "banner" / "candidates.json").read_text(encoding="utf-8"))
    store["app.py|CWE-89"]["state"] = "confirmed"
    (root / "banner" / "candidates.json").write_text(json.dumps(store), encoding="utf-8")
    _status, page = client.open("GET", "/e/banner")
    assert "Next: generate the report." in page
    assert "1 of 1 reviewed" in page
    _status, report_page = client.open("GET", "/e/banner/report")
    assert "Locks the report. Requires every candidate confirmed or not actionable." in report_page
    assert 'value="Ada" selected' in report_page
    reports = root / "banner" / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "assessment.html").write_text("<p>Final assessment</p>", encoding="utf-8")
    (reports / "assessment-status.json").write_text(json.dumps({"status": "final"}), encoding="utf-8")
    _status, page = client.open("GET", "/e/banner")
    assert "Next: close the engagement." in page
    close_engagement(root, "banner", actor="Ada")
    _status, page = client.open("GET", "/e/banner")
    assert html.escape("Next: purge the customer's code.") in page


def test_intake_sources_are_available_without_javascript(ui) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="sources"))
    _status, page = client.open("GET", "/e/sources")
    for source in ("git", "folder", "archive", "file", "script"):
        assert f'data-intake-source="{source}"' in page
    assert 'data-intake-source="git" open' in page
    assert 'data-browse="directory"' in page
    assert 'data-browse="file"' in page
    assert 'name="script"' in page
    assert 'name="filename"' not in page
    assert page.count('name="include_tests"') == 1
    assert "Replace current code" not in page
    assert "Cloning contacts the git host." in page
    _status, script = client.open("GET", "/astrolabe.js")
    assert "intake_source" in script
    assert "data-browse" in script


def test_browse_returns_the_path_the_user_chose(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    status, page = client.open("POST", "/browse", {"kind": "other"})
    assert status == 400
    assert json.loads(page)["path"] == ""
    monkeypatch.setattr("astrolabe.ui.choose_local_path", lambda kind: f"/chosen/{kind}")
    status, page = client.open("POST", "/browse", {"kind": "directory"})
    assert status == 200
    assert json.loads(page) == {"path": "/chosen/directory"}
    monkeypatch.setattr("astrolabe.ui.choose_local_path", lambda _kind: "")
    status, page = client.open("POST", "/browse", {"kind": "file"})
    assert status == 200
    assert json.loads(page)["path"] == ""


def test_single_file_and_script_are_separate_intake_sources(ui, tmp_path: Path) -> None:
    client, _app, _entered, release, _root = ui
    release.set()
    client.open("POST", "/", _new_fields(id="picked"))
    chosen = tmp_path / "widget.py"
    chosen.write_text("print(1)\n", encoding="utf-8")
    status, page = client.open(
        "POST",
        "/e/picked/intake/preview",
        {"intake_source": "file", "file_path": str(chosen)},
    )
    assert status == 200
    assert "widget.py" in page
    status, page = client.open(
        "POST",
        "/e/picked/intake/preview",
        {"intake_source": "script", "script": "print(2)\n", "replace": "on"},
    )
    assert status == 200
    assert "script.py" in page
    status, page = client.open(
        "POST",
        "/e/picked/intake/preview",
        {"intake_source": "script", "replace": "on"},
    )
    assert status == 400
    assert "Paste a script" in page


def test_advisory_step_starts_blank_and_imports_a_file_or_directory(
    ui, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _app, _entered, release, _root = ui
    release.set()
    cache = tmp_path / "advisory-cache"
    cache.mkdir()
    (cache / "CVE-2099-1111.json").write_text(
        json.dumps({"id": "CVE-2099-1111", "summary": "Already stored", "details": "Hidden"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(cache))
    client.open("POST", "/", _new_fields(id="blank-advisory"))
    _status, page = client.open("GET", "/e/blank-advisory")
    assert "Nothing is selected yet." in page
    assert "CVE-2099-1111" not in page
    assert "Browse file" in page
    assert "Browse folder" in page
    single = tmp_path / "CVE-2099-2222.json"
    single.write_text(
        json.dumps({"id": "CVE-2099-2222", "summary": "Imported file", "details": "Local"}),
        encoding="utf-8",
    )
    status, page = client.open(
        "POST",
        "/e/blank-advisory/advisories/import",
        {"directory": str(single)},
    )
    assert status == 200
    assert "Imported CVE-2099-2222" in page
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (prepared / "GHSA-abcd-efgh-ijkl.json").write_text(
        json.dumps({"id": "GHSA-abcd-efgh-ijkl", "summary": "Imported folder", "details": "Local"}),
        encoding="utf-8",
    )
    status, page = client.open(
        "POST",
        "/e/blank-advisory/advisories/import",
        {"directory": str(prepared)},
    )
    assert status == 200
    assert "Imported GHSA-abcd-efgh-ijkl" in page
    assert (cache / "CVE-2099-2222.json").is_file()
    assert (cache / "GHSA-abcd-efgh-ijkl.json").is_file()


def test_review_counts_candidates_and_asks_for_a_check_first(ui) -> None:
    client, _app, _entered, release, _tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="review-count"))
    _status, page = client.open("GET", "/e/review-count")
    assert "Run a check to get candidates." in page
    assert "0 of 0 reviewed" not in page


def test_generate_writes_both_reports_and_keeps_the_assessment_if_the_handoff_fails(
    ui, monkeypatch: pytest.MonkeyPatch
) -> None:
    from astrolabe.engagement import EngagementError
    from astrolabe.reports import write_assessment

    client, _app, _entered, release, tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="gen-ok"))
    status, page = client.open("POST", "/e/gen-ok/reports/generate", {})
    assert status == 200
    assert "Assessment and remediation handoff written." in page
    reports = tmp_path / "engagements" / "gen-ok" / "reports"
    assert (reports / "assessment.html").is_file()
    assert (reports / "remediation.md").is_file()

    called: list[str] = []

    def assessment_fails(*_args: object, **_kwargs: object) -> None:
        raise EngagementError("assessment broke")

    def handoff_should_not_run(*_args: object, **_kwargs: object) -> None:
        called.append("handoff")
        raise AssertionError("handoff should not run")

    monkeypatch.setattr("astrolabe.ui.write_assessment", assessment_fails)
    monkeypatch.setattr("astrolabe.ui.write_remediation", handoff_should_not_run)
    client.open("POST", "/", _new_fields(id="gen-stop"))
    status, page = client.open("POST", "/e/gen-stop/reports/generate", {})
    assert status == 400
    assert "assessment broke" in page
    assert called == []
    assert not (tmp_path / "engagements" / "gen-stop" / "reports" / "remediation.md").exists()

    def handoff_fails(*_args: object, **_kwargs: object) -> None:
        raise EngagementError("handoff broke")

    monkeypatch.setattr("astrolabe.ui.write_assessment", write_assessment)
    monkeypatch.setattr("astrolabe.ui.write_remediation", handoff_fails)
    client.open("POST", "/", _new_fields(id="gen-keep"))
    status, page = client.open("POST", "/e/gen-keep/reports/generate", {})
    assert status == 200
    assert "The assessment was written. The handoff failed: handoff broke" in page
    kept = tmp_path / "engagements" / "gen-keep" / "reports"
    assert (kept / "assessment.html").is_file()
    assert not (kept / "remediation.md").exists()


def test_export_defaults_outside_the_engagement_and_full_export_waits_for_close(
    ui, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    home = tmp_path / "home"
    monkeypatch.setattr("astrolabe.purge.Path.home", lambda *_args: home)
    client.open("POST", "/", _new_fields(id="export-me"))
    _status, page = client.open("GET", "/e/export-me/report")
    report_path = home / "Astrolabe" / "exports" / "export-me-report"
    full_path = home / "Astrolabe" / "exports" / "export-me-full"
    assert str(report_path) in page
    assert str(full_path) in page
    exports = home / "Astrolabe" / "exports"
    assert exports.stat().st_mode & 0o777 == 0o700
    assert "group or world accessible" not in page
    exports.chmod(0o750)
    _status, page = client.open("GET", "/e/export-me/report")
    assert f"{exports} is group or world accessible." in page
    assert 'id="export-directory-warning"' in page
    assert exports.stat().st_mode & 0o777 == 0o750
    assert "Report only, for the customer (assessment HTML, status, PDF if present)" in page
    assert (
        "Full package, for your records (redacted records, reports, and traces; no source code). "
        "Available after Close."
    ) in page
    assert 'value="full" disabled' in page
    outside = tmp_path / "export.tar.gz"
    status, page = client.open(
        "POST",
        "/e/export-me/export",
        {"bundle": "full", "output": str(outside)},
    )
    assert status == 400
    assert "closed" in page.lower()
    assert not outside.exists()
    client.open("POST", "/e/export-me/reports/generate", {})
    inside = tmp_path / "engagements" / "export-me" / "customer.tar.gz"
    status, page = client.open(
        "POST",
        "/e/export-me/export",
        {"bundle": "report", "output": str(inside), "allow_draft": "on"},
    )
    assert status == 400
    assert "outside the engagements directory" in page
    assert not inside.exists()


def test_reintake_uses_the_actor_resolver(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from astrolabe.engagement import load_engagement, read_durable_audit

    client, app, _entered, release, tmp_path = ui
    release.set()
    monkeypatch.setattr("astrolabe.intake._probe_https", lambda _url: (200, None))

    def run(args: list[str]) -> CompletedProcess[str]:
        if "clone" in args:
            dest = Path(args[-1])
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "app.py").write_text("print(1)\n", encoding="utf-8")
            subprocess.run(["git", "init", dest], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", dest, "config", "user.email", "ada@example.com"],
                check=True,
                capture_output=True,
            )
            subprocess.run(["git", "-C", dest, "config", "user.name", "Ada"], check=True, capture_output=True)
            subprocess.run(["git", "-C", dest, "add", "app.py"], check=True, capture_output=True)
            subprocess.run(["git", "-C", dest, "commit", "-m", "init"], check=True, capture_output=True)
            return CompletedProcess(args, 0, "", "")
        if "rev-parse" in args:
            dest = Path(args[args.index("-C") + 1])
            sha = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"], text=True)
            return CompletedProcess(args, 0, sha, "")
        return CompletedProcess(args, 0, "", "")

    app.git = run
    client.open("POST", "/", _new_fields(id="reintake-actor", consultants="Ada, Bob"))
    status, _page = client.open(
        "POST",
        "/e/reintake-actor/intake/preview",
        {
            "intake_source": "git",
            "url": "https://github.com/example/widgets.git",
            "ref": "main",
            "actor": "Bob",
        },
    )
    assert status == 200
    status, _page = client.open("POST", "/e/reintake-actor/intake/confirm", {})
    assert status == 200
    root = tmp_path / "engagements"
    remembered = load_engagement(root, "reintake-actor")["recent_sources"]
    assert isinstance(remembered, list)
    assert remembered[-1]["actor"] == "Bob"
    status, page = client.open("POST", "/e/reintake-actor/intake/again", {})
    assert status == 200
    assert "Snapshot SHA-256" in page
    clones = [
        row
        for row in read_durable_audit(root, "reintake-actor")
        if row.get("action") == "intake_clone"
    ]
    assert [row["actor"] for row in clones] == ["Bob", "Ada"]
    again = load_engagement(root, "reintake-actor")["recent_sources"]
    assert isinstance(again, list)
    assert again[-1]["actor"] == "Ada"


def test_launch_and_missing_advisory_pages_use_the_resolver(ui, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="resolver-pages", consultants="Ada, Bob"))
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    client.open("POST", "/e/resolver-pages/intake/preview", {"path": str(source)})
    client.open("POST", "/e/resolver-pages/intake/confirm", {})
    status, page = client.open("POST", "/e/resolver-pages/select/advisory", {"ids": "CVE-2099-0001"})
    assert status == 200
    assert "CVE-2099-0001 is not in the local cache" in page
    assert 'name="actor"' not in page
    assert "<label>Actor" not in page
    seen: list[str] = []

    def fake_sync(_root: object, *, actor: str, ids: list[str] | None = None, **_kwargs: object) -> list[object]:
        seen.append(actor)
        return []

    monkeypatch.setattr("astrolabe.ui.sync_advisories", fake_sync)
    client.open("POST", "/e/resolver-pages/advisories/sync", {"ids": "CVE-2099-0001"})
    record = json.loads((tmp_path / "engagements" / "resolver-pages" / "engagement.json").read_text(encoding="utf-8"))
    valid = (
        urllib.parse.quote(str(record["instance_id"]), safe="")
        + "."
        + urllib.parse.quote("Bob", safe="")
    )
    client.exchange(
        "POST",
        "/e/resolver-pages/advisories/sync",
        {"ids": "CVE-2099-0001"},
        extra={"Cookie": f"astrolabe_acting_as={valid}"},
    )
    assert seen == ["Ada", "Bob"]
    status, page = client.open("POST", "/e/resolver-pages/review", {"choice": "search|CWE-89"})
    assert status == 200
    assert "Launch review" in page
    assert 'name="actor"' not in page
    assert "<label>Actor" not in page
    item = json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})
    status, _page = client.open("POST", "/e/resolver-pages/launch", {"item": item})
    assert status == 200
    root = tmp_path / "engagements" / "resolver-pages"
    assert _wait_investigation_actors(root) == ["Ada"]
    status, _page = client.exchange(
        "POST",
        "/e/resolver-pages/launch",
        {"item": item},
        extra={"Cookie": f"astrolabe_acting_as={valid}"},
    )[:2]
    assert status == 200
    assert _wait_investigation_actors(root) == ["Ada", "Bob"]


def _wait_investigation_actors(directory: Path) -> list[str]:
    audit = directory / "audit.jsonl"
    queue = directory / "launch-queue.json"
    for _ in range(50):
        if audit.is_file() and queue.is_file():
            queued = json.loads(queue.read_text(encoding="utf-8"))
            actors = [
                str(json.loads(line)["actor"])
                for line in audit.read_text(encoding="utf-8").splitlines()
                if '"investigate"' in line
            ]
            if queued and all(item.get("status") in {"completed", "failed", "cancelled"} for item in queued):
                if len(actors) >= len(queued):
                    return actors
        time.sleep(0.05)
    detail = audit.read_text(encoding="utf-8") if audit.is_file() else "no audit"
    raise AssertionError(detail)


def test_review_shows_advisory_context_and_keeps_a_rejected_note(
    ui, monkeypatch: pytest.MonkeyPatch
) -> None:
    from astrolabe.engagement import read_durable_audit
    from astrolabe.investigate import start_investigation

    client, _app, _entered, release, tmp_path = ui
    release.set()

    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network")

    monkeypatch.setattr("astrolabe.advisories.fetch_json", explode)
    cache = tmp_path / "advisories"
    cache.mkdir()
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(cache))
    (cache / "CVE-2022-29217.json").write_text(
        json.dumps(
            {
                "id": "CVE-2022-29217",
                "summary": "Key confusion & non-blocklisted formats",
                "details": "The failure is in jwt/algorithms.py.",
                "cwe_ids": ["CWE-327"],
            }
        ),
        encoding="utf-8",
    )
    client.open("POST", "/", _new_fields(id="advisory-review"))
    source = tmp_path / "checkout"
    (source / "jwt").mkdir(parents=True)
    (source / "jwt" / "algorithms.py").write_text("def decode():\n    return None\n", encoding="utf-8")
    client.open("POST", "/e/advisory-review/intake/preview", {"path": str(source)})
    client.open("POST", "/e/advisory-review/intake/confirm", {})
    root = tmp_path / "engagements"
    start_investigation(
        root,
        "advisory-review",
        cwe="CWE-327",
        actor="Ada",
        advisory_id="CVE-2022-29217",
        runner=_report_runner(["jwt/algorithms.py"]),
    )
    status, page = client.open("GET", "/e/advisory-review")
    assert status == 200
    assert "CVE-2022-29217" in page
    assert "Key confusion &amp; non-blocklisted formats" in page
    assert "Advisory names this file" in page
    assert "advisory text" in page
    assert "The failure is in jwt/algorithms.py." in page
    assert "Sync does not store fix-commit references." in page
    assert 'name="advisory_compared"' in page
    assert "I compared this file against the advisory and its fix, and it is not the affected code." in page
    kept = "kept note text for the rerender"
    status, page = client.open(
        "POST",
        "/e/advisory-review/verdict",
        {"path": "jwt/algorithms.py", "cwe": "CWE-327", "state": "not_actionable", "note": kept},
    )
    assert status == 400
    assert 'id="confirmed-error"' in page
    assert kept in page
    assert 'value="not_actionable" selected' in page
    opened = page.split('id="review"', 1)[1].split(">", 1)[0]
    assert "step-card--collapsed" not in opened
    status, page = client.open(
        "POST",
        "/e/advisory-review/verdict",
        {
            "path": "jwt/algorithms.py",
            "cwe": "CWE-327",
            "state": "not_actionable",
            "note": kept,
            "advisory_compared": "on",
        },
    )
    assert status == 400
    assert 'id="note-error"' in page
    assert kept in page
    long_note = "The HMAC check in this file is not the code the advisory describes."
    status, page = client.open(
        "POST",
        "/e/advisory-review/verdict",
        {
            "path": "jwt/algorithms.py",
            "cwe": "CWE-327",
            "state": "not_actionable",
            "note": long_note,
            "advisory_compared": "on",
        },
    )
    assert status == 200
    assert "Verdict recorded." in page
    stored = json.loads((root / "advisory-review" / "candidates.json").read_text(encoding="utf-8"))
    assert "confirmed" not in next(iter(stored.values()))
    verdicts = [row for row in read_durable_audit(root, "advisory-review") if row["action"] == "verdict"]
    assert verdicts[-1]["confirmed"] is True


def test_begin_excerpt_is_not_rendered_and_basename_uses_the_weaker_pill(
    ui, monkeypatch: pytest.MonkeyPatch
) -> None:
    from astrolabe.investigate import start_investigation

    client, _app, _entered, release, tmp_path = ui
    release.set()
    cache = tmp_path / "advisories"
    cache.mkdir()
    monkeypatch.setenv("ASTROLABE_ADVISORY_CACHE", str(cache))
    (cache / "CVE-2022-29217.json").write_text(
        json.dumps(
            {
                "id": "CVE-2022-29217",
                "summary": "Key confusion through non-blocklisted public key formats",
                "details": "The check is in jwt/algorithms.py " + ("-" * 5 + "BEGIN " + "PUBLIC KEY" + "-" * 5) + " marker.",
                "cwe_ids": ["CWE-327"],
            }
        ),
        encoding="utf-8",
    )
    client.open("POST", "/", _new_fields(id="begin-review"))
    source = tmp_path / "checkout"
    (source / "jwt").mkdir(parents=True)
    (source / "jwt" / "algorithms.py").write_text("x\n", encoding="utf-8")
    client.open("POST", "/e/begin-review/intake/preview", {"path": str(source)})
    client.open("POST", "/e/begin-review/intake/confirm", {})
    start_investigation(
        tmp_path / "engagements",
        "begin-review",
        cwe="CWE-327",
        actor="Ada",
        advisory_id="CVE-2022-29217",
        runner=_report_runner(["jwt/algorithms.py"]),
    )
    _status, page = client.open("GET", "/e/begin-review")
    context = page.split('class="advisory-context"', 1)[1]
    visible, collapsed = context.split("<details>", 1)
    assert ("-" * 5 + "BEGIN") not in visible
    assert "advisory-excerpt" not in visible
    assert "Advisory names this file" in visible
    assert ("-" * 5 + "BEGIN") in collapsed
    (cache / "CVE-2024-9004.json").write_text(
        json.dumps(
            {
                "id": "CVE-2024-9004",
                "summary": "A filename mention",
                "details": "The file algorithms.py is involved.",
                "cwe_ids": ["CWE-327"],
            }
        ),
        encoding="utf-8",
    )
    client.open("POST", "/", _new_fields(id="basename-review"))
    client.open("POST", "/e/basename-review/intake/preview", {"path": str(source)})
    client.open("POST", "/e/basename-review/intake/confirm", {})
    start_investigation(
        tmp_path / "engagements",
        "basename-review",
        cwe="CWE-327",
        actor="Ada",
        advisory_id="CVE-2024-9004",
        runner=_report_runner(["jwt/algorithms.py"], report_name="run-2"),
    )
    _status, page = client.open("GET", "/e/basename-review")
    assert "Advisory mentions this filename" in page
    assert "Advisory names this file" not in page
    source_label = page.split("Advisory mentions this filename", 1)[1].split("</p>", 1)[0]
    assert "advisory text" in source_label
    assert "pasted advisory" not in source_label
    status, page = client.open(
        "POST",
        "/e/basename-review/verdict",
        {
            "path": "jwt/algorithms.py",
            "cwe": "CWE-327",
            "state": "not_actionable",
            "note": "Short note.",
            "advisory_compared": "on",
        },
    )
    assert status == 200
    assert "Verdict recorded." in page


def test_exploratory_verdict_form_has_no_advisory_checkbox(ui) -> None:
    client, _app, entered, release, tmp_path = ui
    client.open("POST", "/", _new_fields(id="explore-form"))
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    client.open("POST", "/e/explore-form/intake/preview", {"path": str(source)})
    client.open("POST", "/e/explore-form/intake/confirm", {})
    client.open("POST", "/e/explore-form/review", {"choice": "search|CWE-89"})
    client.open(
        "POST",
        "/e/explore-form/launch",
        {"item": json.dumps({"source": "search", "cwe": "CWE-89", "advisory_text": "", "title": ""})},
    )
    assert entered.wait(timeout=5)
    release.set()
    page = ""
    for _ in range(40):
        _status, page = client.open("GET", "/e/explore-form")
        if "app.py" in page and 'id="progress"' not in page:
            break
        time.sleep(0.05)
    else:
        raise AssertionError(page)
    assert 'name="advisory_compared"' not in page
    status, page = client.open(
        "POST",
        "/e/explore-form/verdict",
        {"path": "app.py", "cwe": "CWE-89", "state": "not_actionable", "note": "Not this file."},
    )
    assert status == 200
    assert "Verdict recorded." in page
    from astrolabe.engagement import read_durable_audit

    verdicts = [
        row
        for row in read_durable_audit(tmp_path / "engagements", "explore-form")
        if row["action"] == "verdict"
    ]
    assert verdicts[-1]["to_state"] == "not_actionable"
    assert "confirmed" not in verdicts[-1]


def test_report_page_frames_the_assessment_same_origin_only(ui) -> None:
    client, _app, _entered, release, tmp_path = ui
    release.set()
    client.open("POST", "/", _new_fields(id="preview-me"))
    reports = tmp_path / "engagements" / "preview-me" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "assessment.html").write_text("<p>Draft assessment</p>\n", encoding="utf-8")
    (reports / "assessment-status.json").write_text(
        json.dumps({"status": "draft", "template_version": "1"}) + "\n",
        encoding="utf-8",
    )
    status, page = client.open("GET", "/e/preview-me")
    assert 'href="/e/preview-me/report"' in page
    status, page = client.open("GET", "/e/preview-me/report")
    assert status == 200
    assert 'id="report-state">Draft</p>' in page
    assert "preview-me" in page
    iframe = page.split("<iframe", 1)[1].split(">", 1)[0]
    assert " sandbox" in iframe or iframe.startswith(" sandbox")
    assert "allow-" not in iframe
    assert 'src="/e/preview-me/preview/assessment"' in iframe
    status, body, headers = client.exchange("GET", "/e/preview-me/preview/assessment")
    assert status == 200
    assert "Draft assessment" in body
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["Content-Security-Policy"] == (
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'"
    )
    status, _body, headers = client.exchange("GET", "/")
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Content-Security-Policy"] == "script-src 'self'; style-src 'self'"
    (reports / "assessment-status.json").write_text(
        json.dumps(
            {
                "status": "final",
                "actor": "Ada",
                "finalized_at": "2026-10-10T00:00:00Z",
                "template_version": "1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _status, page = client.open("GET", "/e/preview-me/report")
    assert "Finalized. Approved by Ada at 2026-10-10T00:00:00Z." in page


def _report_runner(paths: list[str], *, report_name: str = "run-1"):
    def run(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        report_dir = engagement / "antares-data" / "reports" / report_name
        report_dir.mkdir(parents=True)
        findings = [
            {"file_path": path, "submission_rank": index + 1, "cwe_ids": ["CWE-327"]}
            for index, path in enumerate(paths)
        ]
        (report_dir / "report.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")
        return CompletedProcess(command, 0)

    return run
