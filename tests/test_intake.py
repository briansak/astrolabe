"""Each intake option materializes a snapshot with the existing rules."""

from __future__ import annotations

import binascii
import io
import stat
import struct
import subprocess
import tarfile
import zipfile
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from astrolabe.engagement import EngagementError, create_engagement, load_engagement, read_durable_audit
from astrolabe.intake import (
    _extract_archive,
    assert_archive_within_caps,
    confirm_preview,
    intake_local,
    reintake,
    snapshot_content_hash,
    stage_archive_preview,
    stage_clone_preview,
    stage_folder_preview,
    stage_path_preview,
    stage_single_preview,
)
from astrolabe.candidates import list_candidates, observe_candidates, set_verdict


def _create(root: Path, engagement_id: str) -> None:
    create_engagement(
        root,
        engagement_id=engagement_id,
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
    )


def _equivalent(root: Path, body: str, *, relative: str = "app.py") -> str:
    _create(root, "plain")
    source = root.parent / "plain-src"
    target = source / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    record = intake_local(root, "plain", source)
    return str(record["snapshot_sha256"])


def test_folder_archive_and_single_file_match_a_directory_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    body = "print(1)\n"
    expected = _equivalent(root, body)

    _create(root, "folder")
    stage_folder_preview(root, "folder", [("app.py", body.encode())])
    folder = confirm_preview(root, "folder")
    assert folder["snapshot_sha256"] == expected
    assert (root / "folder" / "snapshot" / "app.py").read_text(encoding="utf-8") == body
    assert not (root / "folder" / "snapshot" / ".git").exists()

    _create(root, "script")
    stage_single_preview(root, "script", filename="app.py", content=body.encode())
    single = confirm_preview(root, "script")
    assert single["label"] == "single-file"
    assert single["intake"]["kind"] == "single-file"
    assert single["snapshot_sha256"] == expected

    archive = tmp_path / "app.zip"
    import io
    import zipfile

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as bundle:
        bundle.writestr("pkg/app.py", body)
    archive.write_bytes(payload.getvalue())
    _create(root, "zipped")
    preview = stage_archive_preview(root, "zipped", archive)
    assert preview["stripped_prefix"] == "pkg"
    zipped = confirm_preview(root, "zipped")
    assert zipped["snapshot_sha256"] == expected
    assert zipped["intake"]["stripped_prefix"] == "pkg"


def test_path_preview_counts_snapshot_exclusions_and_reintake_marks_a_change_stale(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "acme-2026")
    source = tmp_path / "checkout"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    (source / "tests").mkdir()
    (source / "tests" / "test_app.py").write_text("pass\n", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("git\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (source / "escape").symlink_to(outside)
    preview = stage_path_preview(root, "acme-2026", source)
    excluded = preview["excluded"]
    assert isinstance(excluded, dict)
    assert excluded["tests"] >= 1
    assert excluded["git"] >= 1
    assert excluded["symlinks"] >= 1
    record = confirm_preview(root, "acme-2026")
    assert record["snapshot_sha256"] == snapshot_content_hash(root / "acme-2026" / "snapshot")
    assert not (root / "acme-2026" / "snapshot" / "tests").exists()
    assert not (root / "acme-2026" / "snapshot" / ".git").exists()
    assert not (root / "acme-2026" / "snapshot" / "escape").exists()

    observe_candidates(
        root,
        "acme-2026",
        file_paths=["app.py"],
        cwe="CWE-89",
        investigation_id="inv-1",
        run=1,
    )
    set_verdict(
        root,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="Reviewed the first snapshot.",
    )
    (source / "app.py").write_text("print(2)\n", encoding="utf-8")
    replaced = reintake(root, "acme-2026")
    presented = next(item for item in list_candidates(root, "acme-2026"))
    assert presented["presentation_state"] == "stale"
    assert replaced["snapshot_sha256"] != record["snapshot_sha256"]


def test_clone_records_the_commit_and_refuses_credentials(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "cloned")
    body = "print(1)\n"
    expected = _equivalent(root, body)
    calls: list[list[str]] = []

    def run(args: list[str]) -> CompletedProcess[str]:
        calls.append(list(args))
        if "clone" in args:
            dest = Path(args[-1])
            _git_repo(dest, body)
            return CompletedProcess(args, 0, "", "")
        if "rev-parse" in args:
            dest = Path(args[args.index("-C") + 1])
            sha = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"], text=True)
            return CompletedProcess(args, 0, sha, "")
        return CompletedProcess(args, 0, "", "")

    url = "https://github.com/example/widgets.git"
    preview = stage_clone_preview(
        root,
        "cloned",
        url=url,
        ref="main",
        actor="Ada",
        run=run,
        probe=lambda _url: (200, None),
    )
    assert preview["commit"]
    cloned = confirm_preview(root, "cloned")
    assert cloned["snapshot_sha256"] == expected
    assert cloned["intake"]["url"] == url
    assert cloned["intake"]["commit"] == preview["commit"]
    assert cloned["label"] is None
    assert not (root / "cloned" / "snapshot" / ".git").exists()
    command = next(item for item in calls if "clone" in item)
    assert "--depth" in command
    assert "1" in command
    assert "--no-recurse-submodules" in command
    assert "credential.helper=" in command
    assert "protocol.allow=never" in command
    assert "protocol.https.allow=always" in command
    assert "submodule.recurse=false" in command
    assert "filter.lfs.smudge=" in command
    assert "filter.lfs.required=false" in command
    assert "http.followRedirects=false" in command
    assert url in command
    assert not any(arg == "submodule" for arg in command)
    audit = read_durable_audit(root, "cloned")
    row = next(item for item in audit if item.get("action") == "intake_clone")
    assert row["url"] == url
    assert row["commit"] == preview["commit"]
    assert row["actor"] == "Ada"

    def refuse(args: list[str]) -> CompletedProcess[str]:
        raise AssertionError(args)

    with pytest.raises(EngagementError, match="credentials"):
        stage_clone_preview(
            root,
            "cloned",
            url="https://user:not-a-secret@github.com/example/widgets.git",
            ref="main",
            actor="Ada",
            replace=True,
            run=refuse,
        )
    blob = (root.parent / "var" / "audit.jsonl").read_text(encoding="utf-8")
    assert "not-a-secret" not in blob
    assert "not-a-secret" not in (root / "cloned" / "engagement.json").read_text(encoding="utf-8")

    lock = root / "cloned" / "antares-data" / "run.lock"
    lock.write_text("run\n", encoding="utf-8")
    with pytest.raises(EngagementError, match="investigation is running"):
        stage_clone_preview(root, "cloned", url=url, ref="main", actor="Ada", replace=True, run=refuse)


def test_extraction_counts_bytes_and_files_while_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import astrolabe.intake as intake

    monkeypatch.setattr(intake, "DEFAULT_MAX_BYTES", 100)
    dest = tmp_path / "extract"
    archive = tmp_path / "lie.zip"
    archive.write_bytes(_lying_stored_zip(b"A" * 1000))
    with pytest.raises(EngagementError, match="during extraction"):
        _extract_archive(archive, dest)
    assert not dest.exists()

    monkeypatch.setattr(intake, "assert_archive_within_caps", lambda _path: None)
    monkeypatch.setattr(intake, "DEFAULT_MAX_BYTES", 100)
    tar_dest = tmp_path / "tar-extract"
    tar_archive = tmp_path / "lie.tar"
    tar_archive.write_bytes(_tar_regular("a.txt", b"B" * 1000))
    with pytest.raises(EngagementError, match="during extraction"):
        _extract_archive(tar_archive, tar_dest)
    assert not tar_dest.exists()

    monkeypatch.setattr(intake, "DEFAULT_MAX_FILES", 1)
    wide = tmp_path / "two.zip"
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as bundle:
        bundle.writestr("a.txt", "a")
        bundle.writestr("b.txt", "b")
    wide.write_bytes(payload.getvalue())
    wide_dest = tmp_path / "wide"
    with pytest.raises(EngagementError, match="during extraction"):
        _extract_archive(wide, wide_dest)
    assert not wide_dest.exists()


def test_data_descriptor_zip_extracts_the_member(tmp_path: Path) -> None:
    first = b"alpha-from-descriptor"
    second = b"bravo-from-descriptor"
    archive = tmp_path / "descriptor.zip"
    archive.write_bytes(_zip_with_data_descriptors({"a.txt": first, "b.txt": second}))
    raw = archive.read_bytes()
    flags = struct.unpack_from("<H", raw, 6)[0]
    local_compressed, local_uncompressed = struct.unpack_from("<II", raw, 18)
    assert flags & 0x08
    assert local_compressed == 0
    assert local_uncompressed == 0
    dest = tmp_path / "extract"
    _extract_archive(archive, dest)
    assert (dest / "a.txt").read_bytes() == first
    assert (dest / "b.txt").read_bytes() == second


def test_zip64_archive_extracts_the_member(tmp_path: Path) -> None:
    payload = b"zip64-ok"
    archive = tmp_path / "forced.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        with bundle.open("a.txt", "w", force_zip64=True) as member:
            member.write(payload)
    raw = archive.read_bytes()
    assert struct.unpack_from("<I", raw, 18)[0] == 0xFFFFFFFF
    dest = tmp_path / "extract"
    _extract_archive(archive, dest)
    assert (dest / "a.txt").read_bytes() == payload


def test_deflated_member_stops_on_decompressed_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import astrolabe.intake as intake

    source = tmp_path / "zeros.bin"
    source.write_bytes(b"\0" * (256 * 1024))
    archive = tmp_path / "zeros.zip"
    subprocess.run(["zip", "-q", "-6", archive.name, source.name], cwd=tmp_path, check=True)
    with zipfile.ZipFile(archive) as bundle:
        info = bundle.getinfo("zeros.bin")
    assert info.compress_type == zipfile.ZIP_DEFLATED
    cap = 64 * 1024
    assert info.compress_size < cap < info.file_size
    dest = tmp_path / "extract"
    _extract_archive(archive, dest)
    assert (dest / "zeros.bin").read_bytes() == source.read_bytes()

    monkeypatch.setattr(intake, "DEFAULT_MAX_BYTES", cap)
    monkeypatch.setattr(intake, "assert_archive_within_caps", lambda _path: None)
    with pytest.raises(EngagementError, match="during extraction"):
        _extract_archive(archive, dest)
    assert not dest.exists()


def test_zip_name_mismatch_is_refused(tmp_path: Path) -> None:
    raw = bytearray(_stored_zip("a.txt", b"hello"))
    assert raw[30:35] == b"a.txt"
    raw[30:35] = b"b.txt"
    archive = tmp_path / "name.zip"
    archive.write_bytes(raw)
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.namelist() == ["a.txt"]
    dest = tmp_path / "extract"
    with pytest.raises(EngagementError, match="central directory and local headers disagree"):
        _extract_archive(archive, dest)
    assert not dest.exists()
    with pytest.raises(EngagementError, match="central directory and local headers disagree"):
        assert_archive_within_caps(archive)


def test_zip_size_mismatch_is_refused(tmp_path: Path) -> None:
    raw = bytearray(_stored_zip("a.txt", b"hello"))
    assert struct.unpack_from("<H", raw, 6)[0] & 0x08 == 0
    struct.pack_into("<I", raw, 22, 4)
    archive = tmp_path / "size.zip"
    archive.write_bytes(raw)
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.getinfo("a.txt").file_size == 5
    dest = tmp_path / "extract"
    with pytest.raises(EngagementError, match="central directory and local headers disagree"):
        _extract_archive(archive, dest)
    assert not dest.exists()
    with pytest.raises(EngagementError, match="central directory and local headers disagree"):
        assert_archive_within_caps(archive)


def test_preview_and_extraction_share_the_zip_member_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import astrolabe.intake as intake

    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "zipped")
    archive = tmp_path / "app.zip"
    body = "print(1)\n"
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as bundle:
        bundle.writestr("pkg/app.py", body)
    archive.write_bytes(payload.getvalue())
    seen: list[list[object]] = []
    real = intake._parse_zip_members

    def spy(path: Path) -> list[object]:
        members = real(path)
        seen.append(members)
        return members

    monkeypatch.setattr(intake, "_parse_zip_members", spy)
    stage_archive_preview(root, "zipped", archive)
    assert len(seen) == 1
    assert [member.filename for member in seen[0]] == ["pkg/app.py"]
    extracted = root / "zipped" / "intake" / "pending" / "extract" / "pkg" / "app.py"
    assert extracted.read_text(encoding="utf-8") == body


@pytest.mark.parametrize(
    ("kind", "case"),
    [
        ("zip", "absolute"),
        ("tar", "absolute"),
        ("zip", "dotdot"),
        ("tar", "dotdot"),
        ("zip", "symlink"),
        ("tar", "symlink"),
        ("zip", "hardlink"),
        ("tar", "hardlink"),
    ],
)
def test_archive_rejects_escape_and_outside_links_before_write(tmp_path: Path, kind: str, case: str) -> None:
    sentinel = tmp_path / "outside.txt"
    sentinel.write_bytes(b"safe")
    dest = tmp_path / "extract"
    archive = tmp_path / f"bad.{kind}"
    archive.write_bytes(_crafted_archive(kind, case, sentinel))
    with pytest.raises(EngagementError, match="escapes the extract directory|outside the extraction directory"):
        _extract_archive(archive, dest)
    assert not dest.exists()
    assert sentinel.read_bytes() == b"safe"
    assert sentinel.is_file()
    assert not sentinel.is_symlink()
    assert sentinel.stat().st_nlink == 1


def test_clone_refuses_a_redirect_to_another_host(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "cloned")

    def run(args: list[str]) -> CompletedProcess[str]:
        raise AssertionError(args)

    with pytest.raises(EngagementError, match="different host"):
        stage_clone_preview(
            root,
            "cloned",
            url="https://github.com/example/widgets.git",
            ref="main",
            actor="Ada",
            run=run,
            probe=lambda _url: (302, "https://evil.example/widgets.git"),
        )
    with pytest.raises(EngagementError, match="credentials"):
        stage_clone_preview(
            root,
            "cloned",
            url="https://github.com/example/widgets.git",
            ref="main",
            actor="Ada",
            run=run,
            probe=lambda _url: (302, "https://user:not-a-secret@github.com/example/widgets.git"),
        )
    assert "not-a-secret" not in (root / "cloned" / "engagement.json").read_text(encoding="utf-8")
    assert "not-a-secret" not in (root / "cloned" / "audit.jsonl").read_text(encoding="utf-8")


def test_clone_follows_a_same_host_redirect(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "cloned")
    body = "print(1)\n"
    calls: list[list[str]] = []
    final = "https://github.com/example/widgets.git"

    def run(args: list[str]) -> CompletedProcess[str]:
        calls.append(list(args))
        if "clone" in args:
            _git_repo(Path(args[-1]), body)
            return CompletedProcess(args, 0, "", "")
        if "rev-parse" in args:
            dest = Path(args[args.index("-C") + 1])
            sha = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"], text=True)
            return CompletedProcess(args, 0, sha, "")
        return CompletedProcess(args, 0, "", "")

    def probe(url: str) -> tuple[int, str | None]:
        if url == final:
            return 200, None
        return 302, final

    stage_clone_preview(
        root,
        "cloned",
        url="https://github.com/example/widgets",
        ref="main",
        actor="Ada",
        run=run,
        probe=probe,
    )
    command = next(item for item in calls if "clone" in item)
    assert final in command
    assert "https://github.com/example/widgets" not in command


def test_clone_does_not_fetch_a_submodule(tmp_path: Path) -> None:
    parent = _repo_with_submodule(tmp_path)
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "cloned")
    url = "https://github.com/example/widgets.git"
    calls: list[list[str]] = []

    def run(args: list[str]) -> CompletedProcess[str]:
        calls.append(list(args))
        if "clone" in args:
            dest = Path(args[-1])
            rewritten = ["git", "-c", "protocol.file.allow=always"]
            rewritten.extend(parent.as_uri() if item == url else item for item in args[1:])
            completed = subprocess.run(rewritten, capture_output=True, text=True)
            return CompletedProcess(args, completed.returncode, completed.stdout, completed.stderr)
        if "rev-parse" in args:
            dest = Path(args[args.index("-C") + 1])
            sha = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"], text=True)
            return CompletedProcess(args, 0, sha, "")
        return CompletedProcess(args, 0, "", "")

    stage_clone_preview(
        root,
        "cloned",
        url=url,
        ref="main",
        actor="Ada",
        run=run,
        probe=lambda _url: (200, None),
    )
    tree = root / "cloned" / "intake" / "pending" / "tree"
    assert (tree / "app.py").is_file()
    assert not (tree / "vendor" / "secret.txt").exists()
    flat = [arg for call in calls for arg in call]
    assert parent.as_uri() not in flat
    assert "submodule" not in flat
    assert "--no-recurse-submodules" in flat
    assert "protocol.allow=never" in flat
    assert "protocol.https.allow=always" in flat


def _crafted_archive(kind: str, case: str, sentinel: Path) -> bytes:
    if case == "absolute":
        name = str(sentinel)
        return _zip_regular(name, b"x") if kind == "zip" else _tar_regular(name, b"x")
    if case == "dotdot":
        name = "../outside.txt"
        return _zip_regular(name, b"x") if kind == "zip" else _tar_regular(name, b"x")
    if case == "symlink":
        target = "../outside.txt"
        return _zip_symlink(target) if kind == "zip" else _tar_link(tarfile.SYMTYPE, target)
    target = str(sentinel)
    if kind == "zip":
        # ZIP has no hardlink type. The outside target is stored as a Unix symlink member.
        return _zip_symlink(target)
    return _tar_link(tarfile.LNKTYPE, "../outside.txt")


def _stored_zip(name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr(name, payload)
    return buffer.getvalue()


def _zip_regular(name: str, data: bytes) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as bundle:
        bundle.writestr(name, data)
    return payload.getvalue()


def _zip_symlink(target: str) -> bytes:
    info = zipfile.ZipInfo("alias")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as bundle:
        bundle.writestr(info, target.encode())
    return payload.getvalue()


def _tar_regular(name: str, data: bytes) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as bundle:
        bundle.addfile(info, io.BytesIO(data))
    return payload.getvalue()


def _tar_link(kind: bytes, target: str) -> bytes:
    info = tarfile.TarInfo("alias")
    info.type = kind
    info.linkname = target
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as bundle:
        bundle.addfile(info)
    return payload.getvalue()


class _Unseekable(io.RawIOBase):
    """ZipFile writes data descriptors when the destination cannot be rewound."""

    def __init__(self) -> None:
        self.buf = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, data: object) -> int:
        block = bytes(data)  # type: ignore[arg-type]
        self.buf.extend(block)
        return len(block)


def _zip_with_data_descriptors(members: dict[str, bytes]) -> bytes:
    sink = _Unseekable()
    with zipfile.ZipFile(sink, "w") as bundle:
        for name, payload in members.items():
            with bundle.open(name, "w") as member:
                member.write(payload)
    return bytes(sink.buf)


def _lying_stored_zip(data: bytes) -> bytes:
    name = b"a.txt"
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
        1,
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
        1,
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


def _repo_with_submodule(tmp_path: Path) -> Path:
    sub = tmp_path / "sub"
    _git_repo(sub, "secret\n")
    (sub / "app.py").unlink()
    (sub / "secret.txt").write_text("secret\n", encoding="utf-8")
    subprocess.run(["git", "-C", sub, "add", "secret.txt"], check=True, capture_output=True)
    subprocess.run(["git", "-C", sub, "commit", "-m", "secret"], check=True, capture_output=True)
    parent = tmp_path / "parent"
    parent.mkdir()
    _git_identity(parent)
    (parent / "app.py").write_text("print(1)\n", encoding="utf-8")
    subprocess.run(["git", "-C", parent, "add", "app.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", parent, "commit", "-m", "app"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", parent, "-c", "protocol.file.allow=always", "submodule", "add", sub.as_uri(), "vendor"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", parent, "commit", "-m", "vendor"], check=True, capture_output=True)
    return parent


def _git_identity(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", dest], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.email", "ada@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Ada"], check=True, capture_output=True)


def _git_repo(dest: Path, body: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "app.py").write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", dest], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.email", "ada@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Ada"], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "add", "app.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "commit", "-m", "init"], check=True, capture_output=True)


def test_unrecorded_source_tree_does_not_block_single_file_preview(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "acme")
    leftover = root / "acme" / "src"
    leftover.mkdir()
    (leftover / "partial.txt").write_text("partial\n", encoding="utf-8")
    stage_single_preview(root, "acme", filename="app.py", content=b"print(1)\n")
    record = confirm_preview(root, "acme")
    assert record["intake"]["kind"] == "single-file"
    assert (root / "acme" / "snapshot" / "app.py").read_text(encoding="utf-8") == "print(1)\n"
    assert not (root / "acme" / "snapshot" / "partial.txt").exists()


def test_recorded_intake_still_requires_replace(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "acme")
    source = tmp_path / "tree"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    intake_local(root, "acme", source)
    with pytest.raises(EngagementError, match="already has source intake"):
        stage_single_preview(root, "acme", filename="app.py", content=b"print(2)\n")


def test_a_file_path_asks_for_single_file(tmp_path: Path) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "acme")
    source = tmp_path / "app.py"
    source.write_text("print(1)\n", encoding="utf-8")
    with pytest.raises(EngagementError, match="Choose Single file"):
        stage_path_preview(root, "acme", source)


def test_failed_copy_removes_the_partial_source_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "engagements"
    root.mkdir()
    _create(root, "acme")
    source = tmp_path / "tree"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")

    def boom(_source: Path, dest: Path, **_kwargs: object) -> Path:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "partial.txt").write_text("partial\n", encoding="utf-8")
        raise ValueError("Snapshot exceeds max bytes (1)")

    monkeypatch.setattr("astrolabe.intake.materialize_snapshot", boom)
    with pytest.raises(EngagementError, match="Snapshot exceeds max bytes"):
        intake_local(root, "acme", source)
    assert not (root / "acme" / "src").exists()
    assert not (root / "acme" / "snapshot").exists()
    stage_single_preview(root, "acme", filename="app.py", content=b"print(1)\n")

