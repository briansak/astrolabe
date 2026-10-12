"""Intake into one engagement. Snapshot rules, then a content hash.

A local path or archive never contacts a git host. Clone is a separate,
explicit action: https only, no credentials in the URL, shallow fetch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from subprocess import CompletedProcess

from astrolabe.engagement import (
    EngagementError,
    append_durable_audit,
    engagement_dir,
    load_engagement,
    require_open,
    save_engagement,
)
from astrolabe.plan_store import clear_plans
from astrolabe.snapshot import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    materialize_snapshot,
    snapshot_preview,
)

_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")
_COMMIT = re.compile(r"^[0-9a-fA-F]{7,64}$")
_RECENT_LIMIT = 8
_GIT_CONFIGS = (
    "protocol.allow=never",
    "protocol.https.allow=always",
    "submodule.recurse=false",
    "filter.lfs.smudge=",
    "filter.lfs.process=",
    "filter.lfs.required=false",
    "http.followRedirects=false",
    "credential.helper=",
)
GitRun = Callable[[list[str]], CompletedProcess[str]]
RedirectProbe = Callable[[str], tuple[int, str | None]]

_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


def intake_local(
    root: Path,
    engagement_id: str,
    source: Path,
    *,
    include_test_paths: bool = False,
    replace: bool = False,
) -> dict[str, object]:
    """Materialize a local directory or archive into the engagement."""
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    _reject_already_intaken(directory, replace)
    _reject_git_host(str(source))
    if not source.exists():
        raise EngagementError(f"Intake source does not exist: {source}")
    stripped_prefix: str | None = None
    if source.is_dir():
        tree = source.resolve()
        if _is_inside(tree, directory):
            raise EngagementError("Intake source must sit outside the engagement directory")
        kind = "path"
        label = str(source)
        memory = {
            "kind": "path",
            "label": label,
            "path": label,
            "include_tests": include_test_paths,
        }
    elif _is_archive(source):
        parsed = assert_archive_within_caps(source)
        kind = "archive"
        label = source.name
        stored = directory / "intake" / Path(source.name).name
        stored.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != stored.resolve():
            shutil.copy2(source, stored)
        tree = _extract_archive(stored, directory / "intake" / "extract", parsed)
        tree, stripped_prefix = _strip_single_top_directory(tree)
        memory = {
            "kind": "archive",
            "label": label,
            "stored": stored.relative_to(directory).as_posix(),
            "include_tests": include_test_paths,
        }
    else:
        raise EngagementError("Intake source must be a directory or a zip/tar archive")

    try:
        return _finish_intake(
            root,
            directory,
            tree,
            kind=kind,
            label=label,
            stripped_prefix=stripped_prefix,
            include_test_paths=include_test_paths,
            memory=memory,
        )
    finally:
        if kind == "archive":
            shutil.rmtree(directory / "intake" / "extract", ignore_errors=True)


def snapshot_content_hash(root: Path) -> str:
    """SHA-256 of the hardened tree. This is a content hash, not a commit SHA."""
    digest = hashlib.sha256()
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _reject_git_host(value: str) -> None:
    text = value.strip()
    lowered = text.lower()
    if (
        "://" in text
        or text.startswith("git@")
        or lowered.startswith(("http:", "https:", "ssh:", "git:"))
    ):
        raise EngagementError("Intake accepts a local archive or directory, not a git host")


def _is_archive(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(_ARCHIVE_SUFFIXES)


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _strip_single_top_directory(tree: Path) -> tuple[Path, str | None]:
    """Drop a lone archive root such as pyjwt-2.3.0/ so paths are repo-relative."""
    children = [path for path in tree.iterdir() if path.name not in {".", ".."}]
    if len(children) == 1 and children[0].is_dir():
        return children[0], children[0].name
    return tree, None


def _extract_archive(
    archive: Path,
    dest: Path,
    members: list[_ZipMember] | None = None,
) -> Path:
    if archive.name.lower().endswith(".zip"):
        if members is None:
            parsed = assert_archive_within_caps(archive)
            members = parsed if isinstance(parsed, list) else _parse_zip_members(archive)
        _extract_zip_archive(archive, dest, members)
        return dest
    assert_archive_within_caps(archive)
    _extract_tree(archive, dest, zip_members=None)
    return dest


def _extract_zip_archive(archive: Path, dest: Path, members: list[_ZipMember]) -> None:
    _extract_tree(archive, dest, zip_members=members)


def _extract_tree(archive: Path, dest: Path, zip_members: list[_ZipMember] | None) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    budget = _ExtractBudget()
    try:
        if zip_members is not None:
            _extract_zip(archive, dest, budget, zip_members)
        else:
            _extract_tar(archive, dest, budget)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise


class _ExtractBudget:
    def __init__(self) -> None:
        self.files = 0
        self.nbytes = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > DEFAULT_MAX_FILES:
            raise EngagementError(
                f"Archive file count exceeds the snapshot cap ({DEFAULT_MAX_FILES}) during extraction"
            )

    def add_bytes(self, count: int) -> None:
        self.nbytes += count
        if self.nbytes > DEFAULT_MAX_BYTES:
            raise EngagementError(
                f"Archive decompressed size exceeds the snapshot cap ({DEFAULT_MAX_BYTES}) during extraction"
            )


def _extract_zip(archive: Path, dest: Path, budget: _ExtractBudget, members: list[_ZipMember]) -> None:
    for member in members:
        info = member.info
        _reject_member_name(info.filename)
        if info.is_dir():
            _place(dest, info.filename).mkdir(parents=True, exist_ok=True)
            continue
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            target = _zip_member_bytes(archive, info, budget).decode("utf-8", "surrogateescape")
            _reject_link_target(dest, info.filename, target, hardlink=False)
            raise EngagementError(f"Archive member is a symlink: {info.filename}")
        _reject_link_components(dest, info.filename)
        payload = _zip_member_bytes(archive, info, budget)
        budget.add_file()
        path = _place(dest, info.filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_new_file(path, payload)


def _extract_tar(archive: Path, dest: Path, budget: _ExtractBudget) -> None:
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            _reject_member_name(member.name)
            if member.issym() or member.islnk():
                _reject_link_target(dest, member.name, member.linkname or "", hardlink=member.islnk())
                kind = "hardlink" if member.islnk() else "symlink"
                raise EngagementError(f"Archive member is a {kind}: {member.name}")
            if member.isdir():
                _place(dest, member.name).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise EngagementError(f"Archive member is not a regular file: {member.name}")
            _reject_link_components(dest, member.name)
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise EngagementError(f"Archive member is empty: {member.name}")
            with extracted:
                payload = _read_stream(extracted, budget)
            budget.add_file()
            path = _place(dest, member.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_new_file(path, payload)


def _read_stream(source: object, budget: _ExtractBudget) -> bytes:
    parts: list[bytes] = []
    while True:
        block = source.read(64 * 1024)  # type: ignore[attr-defined]
        if not block:
            break
        budget.add_bytes(len(block))
        parts.append(block)
    return b"".join(parts)


def _write_new_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            offset += os.write(descriptor, view[offset : offset + 1024 * 1024])
    finally:
        os.close(descriptor)


_DATA_DESCRIPTOR = 0x08
_ZIP64_MARKER = 0xFFFFFFFF


def _zip_member_bytes(archive: Path, info: zipfile.ZipInfo, budget: _ExtractBudget) -> bytes:
    """Member bytes from the local file data. Declared uncompressed size is not a limit."""
    data = _zip_local_bytes(archive, info, budget, count=info.compress_type == zipfile.ZIP_STORED)
    if info.compress_type == zipfile.ZIP_STORED:
        return data
    if info.compress_type == zipfile.ZIP_DEFLATED:
        return _inflate_capped(data, budget, info.filename)
    return data


def _inflate_capped(data: bytes, budget: _ExtractBudget, filename: str) -> bytes:
    """Count decompressed bytes and stop once the snapshot cap is crossed."""
    decompressor = zlib.decompressobj(-15)
    parts: list[bytes] = []
    pending = data
    try:
        while True:
            piece = decompressor.decompress(pending, 64 * 1024)
            pending = decompressor.unconsumed_tail
            if piece:
                budget.add_bytes(len(piece))
                parts.append(piece)
            if decompressor.eof:
                break
            if not piece and not pending:
                raise EngagementError(f"Archive member could not be read: {filename}")
    except zlib.error as exc:
        raise EngagementError(f"Archive member could not be read: {filename}") from exc
    return b"".join(parts)


def _zip_local_bytes(
    archive: Path,
    info: zipfile.ZipInfo,
    budget: _ExtractBudget,
    *,
    count: bool,
) -> bytes:
    with archive.open("rb") as handle:
        local = _read_local_header(handle, int(info.header_offset), info.filename)
        handle.seek(local.data_start)
        remaining = _compressed_payload_length(
            local.flags,
            local.comp32,
            local.uncomp32,
            local.extra,
            int(info.compress_size),
            info.filename,
        )
        parts: list[bytes] = []
        buffered = 0
        while remaining:
            if count:
                room = max(1, DEFAULT_MAX_BYTES - budget.nbytes + 1)
            else:
                room = max(1, DEFAULT_MAX_BYTES - buffered + 1)
            block = handle.read(min(64 * 1024, remaining, room))
            if not block:
                break
            if count:
                budget.add_bytes(len(block))
            parts.append(block)
            buffered += len(block)
            remaining -= len(block)
            if not count and buffered > DEFAULT_MAX_BYTES:
                budget.add_bytes(buffered)
        return b"".join(parts)


def _compressed_payload_length(
    flags: int,
    comp32: int,
    uncomp32: int,
    extra: bytes,
    central: int,
    filename: str,
) -> int:
    """Byte length of the local payload. Sentinels and data-descriptor placeholders are not lengths."""
    central_size = central if 0 <= central < _ZIP64_MARKER else None
    if comp32 == _ZIP64_MARKER:
        local = _zip64_compressed_size(extra, uncomp32, filename)
        if local is None and central_size is None:
            raise EngagementError(f"ZIP64 member could not be read: {filename}")
    elif flags & _DATA_DESCRIPTOR:
        local = None
    else:
        local = comp32
    if local is None and central_size is None:
        raise EngagementError(f"Archive member could not be read: {filename}")
    if local is None:
        return central_size or 0
    if central_size is None:
        return local
    return max(local, central_size)


def _zip64_compressed_size(extra: bytes, uncomp32: int, filename: str) -> int | None:
    _uncompressed, compressed = _zip64_sizes(extra, uncomp32, _ZIP64_MARKER, filename)
    return compressed


def _zip64_sizes(
    extra: bytes,
    uncomp32: int,
    comp32: int,
    filename: str,
) -> tuple[int | None, int | None]:
    offset = 0
    while offset + 4 <= len(extra):
        kind, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if offset + size > len(extra):
            raise EngagementError(f"ZIP64 member could not be read: {filename}")
        block = extra[offset : offset + size]
        offset += size
        if kind != 0x0001:
            continue
        cursor = 0
        uncompressed: int | None = None
        compressed: int | None = None
        if uncomp32 == _ZIP64_MARKER:
            if len(block) < cursor + 8:
                raise EngagementError(f"ZIP64 member could not be read: {filename}")
            uncompressed = struct.unpack_from("<Q", block, cursor)[0]
            cursor += 8
        if comp32 == _ZIP64_MARKER:
            if len(block) < cursor + 8:
                raise EngagementError(f"ZIP64 member could not be read: {filename}")
            compressed = struct.unpack_from("<Q", block, cursor)[0]
        return uncompressed, compressed
    return None, None


class _LocalHeader:
    def __init__(
        self,
        flags: int,
        method: int,
        crc: int,
        comp32: int,
        uncomp32: int,
        name: str,
        extra: bytes,
        name_len: int,
        extra_len: int,
        data_start: int,
    ) -> None:
        self.flags = flags
        self.method = method
        self.crc = crc
        self.comp32 = comp32
        self.uncomp32 = uncomp32
        self.name = name
        self.extra = extra
        self.name_len = name_len
        self.extra_len = extra_len
        self.data_start = data_start


class _ZipMember:
    def __init__(
        self,
        info: zipfile.ZipInfo,
        header_offset: int,
        data_start: int,
        data_end: int,
        occupied_end: int,
    ) -> None:
        self.info = info
        self.header_offset = header_offset
        self.data_start = data_start
        self.data_end = data_end
        self.occupied_end = occupied_end

    @property
    def filename(self) -> str:
        return self.info.filename

    @property
    def file_size(self) -> int:
        return int(self.info.file_size)

    @property
    def is_dir(self) -> bool:
        return self.info.is_dir()


def _parse_zip_members(archive: Path) -> list[_ZipMember]:
    """Central-directory entries checked against the local headers they name."""
    try:
        with zipfile.ZipFile(archive) as bundle:
            central = list(bundle.infolist())
            start_dir = int(bundle.start_dir)
    except zipfile.BadZipFile as exc:
        raise EngagementError("Archive central directory and local headers disagree") from exc
    members: list[_ZipMember] = []
    with archive.open("rb") as handle:
        for info in central:
            offset = int(info.header_offset)
            local = _read_local_header(handle, offset, info.orig_filename)
            _require_local_matches_central(local, info)
            data_end = local.data_start + int(info.compress_size)
            occupied_end = data_end + _descriptor_length(handle, data_end, local, info)
            members.append(_ZipMember(info, offset, local.data_start, data_end, occupied_end))
        _reject_overlapping_members(members)
        _reject_orphan_local_headers(handle, members, start_dir)
    return members


def _read_local_header(handle: object, offset: int, filename: str) -> _LocalHeader:
    if offset < 0:
        raise EngagementError("Archive central directory and local headers disagree")
    handle.seek(offset)  # type: ignore[attr-defined]
    local = handle.read(30)  # type: ignore[attr-defined]
    if len(local) < 30 or local[:4] != b"PK\x03\x04":
        raise EngagementError(f"Archive central directory and local headers disagree: {_zip_label(filename)}")
    _signature, _version, flags, method, _time, _date, crc, comp32, uncomp32, name_len, extra_len = struct.unpack(
        "<IHHHHHIIIHH", local
    )
    raw_name = handle.read(name_len)  # type: ignore[attr-defined]
    extra = handle.read(extra_len)  # type: ignore[attr-defined]
    if len(raw_name) != name_len or len(extra) != extra_len:
        raise EngagementError(f"Archive central directory and local headers disagree: {_zip_label(filename)}")
    return _LocalHeader(
        flags,
        method,
        crc,
        comp32,
        uncomp32,
        _decode_zip_name(raw_name, flags),
        extra,
        name_len,
        extra_len,
        offset + 30 + name_len + extra_len,
    )


def _decode_zip_name(raw: bytes, flags: int) -> str:
    encoding = "utf-8" if flags & 0x800 else "cp437"
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise EngagementError("Archive central directory and local headers disagree") from exc


def _require_local_matches_central(local: _LocalHeader, info: zipfile.ZipInfo) -> None:
    if local.name != info.orig_filename or local.method != info.compress_type:
        raise EngagementError(
            f"Archive central directory and local headers disagree: {_zip_label(info.orig_filename)}"
        )
    crc, compressed, uncompressed = _recorded_local_measures(local, info.orig_filename)
    if crc is not None and crc != int(info.CRC):
        raise EngagementError(
            f"Archive central directory and local headers disagree: {_zip_label(info.orig_filename)}"
        )
    if compressed is not None and compressed != int(info.compress_size):
        raise EngagementError(
            f"Archive central directory and local headers disagree: {_zip_label(info.orig_filename)}"
        )
    if uncompressed is not None and uncompressed != int(info.file_size):
        raise EngagementError(
            f"Archive central directory and local headers disagree: {_zip_label(info.orig_filename)}"
        )


def _recorded_local_measures(local: _LocalHeader, filename: str) -> tuple[int | None, int | None, int | None]:
    """CRC and sizes the local header actually records. Data-descriptor placeholders are omitted."""
    descriptor = bool(local.flags & _DATA_DESCRIPTOR)
    zip64_uncompressed, zip64_compressed = (None, None)
    if local.comp32 == _ZIP64_MARKER or local.uncomp32 == _ZIP64_MARKER:
        zip64_uncompressed, zip64_compressed = _zip64_sizes(local.extra, local.uncomp32, local.comp32, filename)

    def recorded(field: int, zip64_value: int | None) -> int | None:
        if field == _ZIP64_MARKER:
            if descriptor and zip64_value in (None, 0):
                return None
            if zip64_value is None:
                raise EngagementError(f"ZIP64 member could not be read: {_zip_label(filename)}")
            return zip64_value
        if descriptor and field == 0:
            return None
        return field

    crc = None if descriptor and local.crc == 0 else local.crc
    return crc, recorded(local.comp32, zip64_compressed), recorded(local.uncomp32, zip64_uncompressed)


def _descriptor_length(handle: object, data_end: int, local: _LocalHeader, info: zipfile.ZipInfo) -> int:
    if not local.flags & _DATA_DESCRIPTOR:
        return 0
    zip64 = (
        local.comp32 == _ZIP64_MARKER
        or local.uncomp32 == _ZIP64_MARKER
        or int(info.compress_size) > _ZIP64_MARKER
        or int(info.file_size) > _ZIP64_MARKER
    )
    handle.seek(data_end)  # type: ignore[attr-defined]
    signature = handle.read(4)  # type: ignore[attr-defined]
    width = 8 if zip64 else 4
    return (4 if signature == b"PK\x07\x08" else 0) + 4 + width + width


def _reject_overlapping_members(members: list[_ZipMember]) -> None:
    last_end = -1
    for member in sorted(members, key=lambda item: (item.header_offset, item.occupied_end)):
        if member.header_offset < last_end:
            raise EngagementError("Archive central directory and local headers disagree: members overlap")
        last_end = max(last_end, member.occupied_end)


def _reject_orphan_local_headers(handle: object, members: list[_ZipMember], start_dir: int) -> None:
    if any(member.data_end > start_dir or member.occupied_end > start_dir for member in members):
        raise EngagementError("Archive central directory and local headers disagree: members overlap")
    spans = sorted((member.header_offset, member.occupied_end) for member in members)
    cursor = 0
    for start, end in spans:
        if _contains_local_header(handle, cursor, start):
            raise EngagementError("Archive central directory and local headers disagree")
        cursor = max(cursor, end)
    if _contains_local_header(handle, cursor, start_dir):
        raise EngagementError("Archive central directory and local headers disagree")


def _contains_local_header(handle: object, start: int, end: int) -> bool:
    if end <= start:
        return False
    handle.seek(start)  # type: ignore[attr-defined]
    remaining = end - start
    previous = b""
    while remaining > 0:
        block = handle.read(min(65536, remaining))  # type: ignore[attr-defined]
        if not block:
            return False
        remaining -= len(block)
        window = previous + block
        if b"PK\x03\x04" in window:
            return True
        previous = window[-3:]
    return False


def _zip_label(name: str) -> str:
    text = name.replace("\n", " ").replace("\r", " ")
    if len(text) <= 120:
        return text
    return text[:120] + "..."


def _reject_member_name(name: str) -> None:
    if _is_absolute_name(name) or any(part == ".." for part in _name_parts(name)):
        raise EngagementError(f"Archive member escapes the extract directory: {name}")
    if "\x00" in name:
        raise EngagementError(f"Archive member escapes the extract directory: {name}")


def _reject_link_components(dest: Path, name: str) -> None:
    cursor = dest
    for part in _name_parts(name)[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise EngagementError(f"Archive member escapes the extract directory: {name}")


def _reject_link_target(dest: Path, member_name: str, target: str, *, hardlink: bool) -> None:
    start = dest if hardlink else _place(dest, member_name).parent
    if _join_lexical(dest, start, target) is None:
        raise EngagementError("Archive link target is outside the extraction directory")


def _place(dest: Path, name: str) -> Path:
    _reject_member_name(name)
    return dest.joinpath(*_name_parts(name))


def _is_absolute_name(name: str) -> bool:
    text = name.replace("\\", "/")
    if text.startswith("/") or text.startswith("//"):
        return True
    return bool(re.match(r"^[A-Za-z]:", text))


def _name_parts(name: str) -> list[str]:
    parts: list[str] = []
    for part in name.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        parts.append(part)
    return parts


def _join_lexical(root: Path, start: Path, raw: str) -> Path | None:
    if _is_absolute_name(raw) or "\x00" in raw:
        return None
    if start != root and root not in start.parents:
        return None
    parts = list(start.relative_to(root).parts)
    for part in raw.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return root.joinpath(*parts)


def assert_archive_within_caps(archive: Path) -> list[_ZipMember] | None:
    """Refuse an oversized archive, then return the zip member list preview and extraction share."""
    if archive.name.lower().endswith(".zip"):
        count, total = _central_zip_totals(archive)
        if count > DEFAULT_MAX_FILES:
            raise EngagementError(
                f"Archive file count {count} exceeds the snapshot cap "
                f"({DEFAULT_MAX_FILES}) before extraction"
            )
        if total > DEFAULT_MAX_BYTES:
            raise EngagementError(
                f"Archive decompressed size {total} exceeds the snapshot cap "
                f"({DEFAULT_MAX_BYTES}) before extraction"
            )
        return _parse_zip_members(archive)
    count, total = _declared_archive_totals(archive)
    if count > DEFAULT_MAX_FILES:
        raise EngagementError(
            f"Archive file count {count} exceeds the snapshot cap "
            f"({DEFAULT_MAX_FILES}) before extraction"
        )
    if total > DEFAULT_MAX_BYTES:
        raise EngagementError(
            f"Archive decompressed size {total} exceeds the snapshot cap "
            f"({DEFAULT_MAX_BYTES}) before extraction"
        )
    return None


def stage_path_preview(
    root: Path,
    engagement_id: str,
    source: Path,
    *,
    include_test_paths: bool = False,
    replace: bool = False,
) -> dict[str, object]:
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    _reject_already_intaken(directory, replace)
    _reject_git_host(str(source))
    if source.is_file():
        raise EngagementError(f"{source} is a file. Choose Single file.")
    if not source.is_dir():
        raise EngagementError(f"Intake source does not exist: {source}")
    tree = source.resolve()
    if _is_inside(tree, directory):
        raise EngagementError("Intake source must sit outside the engagement directory")
    preview = snapshot_preview(tree, include_test_paths=include_test_paths)
    _write_pending(
        directory,
        {
            "kind": "path",
            "path": str(tree),
            "label": str(tree),
            "include_tests": include_test_paths,
            "replace": replace,
            "stripped_prefix": None,
        },
    )
    preview["stripped_prefix"] = None
    return preview


def stage_archive_preview(
    root: Path,
    engagement_id: str,
    archive: Path,
    *,
    include_test_paths: bool = False,
    replace: bool = False,
) -> dict[str, object]:
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    _reject_already_intaken(directory, replace)
    if not archive.is_file() or not _is_archive(archive):
        raise EngagementError("Intake source must be a directory or a zip/tar archive")
    parsed = assert_archive_within_caps(archive)
    label = Path(archive.name).name
    pending = _fresh_pending(directory)
    stored = directory / "intake" / label
    stored.parent.mkdir(parents=True, exist_ok=True)
    if archive.resolve() != stored.resolve():
        shutil.copy2(archive, stored)
    extracted = _extract_archive(stored, pending / "extract", parsed if isinstance(parsed, list) else None)
    tree, stripped = _strip_single_top_directory(extracted)
    preview = snapshot_preview(tree, include_test_paths=include_test_paths)
    preview["stripped_prefix"] = stripped
    _write_pending(
        directory,
        {
            "kind": "archive",
            "label": label,
            "tree": _relative_to(tree, directory),
            "stored": _relative_to(stored, directory),
            "include_tests": include_test_paths,
            "replace": replace,
            "stripped_prefix": stripped,
        },
    )
    return preview


def stage_folder_preview(
    root: Path,
    engagement_id: str,
    files: list[tuple[str, bytes]],
    *,
    include_test_paths: bool = False,
    replace: bool = False,
) -> dict[str, object]:
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    _reject_already_intaken(directory, replace)
    if not files:
        raise EngagementError("Folder intake needs at least one file")
    pending = _fresh_pending(directory)
    tree = pending / "tree"
    tree.mkdir(parents=True)
    for name, payload in files:
        _reject_member_name(name)
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not _is_inside(target, tree):
            raise EngagementError(f"Archive member escapes the extract directory: {name}")
        target.write_bytes(payload)
    preview = snapshot_preview(tree, include_test_paths=include_test_paths)
    preview["stripped_prefix"] = None
    _write_pending(
        directory,
        {
            "kind": "folder",
            "label": "uploaded folder",
            "tree": _relative_to(tree, directory),
            "include_tests": include_test_paths,
            "replace": replace,
            "stripped_prefix": None,
        },
    )
    return preview


def stage_single_preview(
    root: Path,
    engagement_id: str,
    *,
    filename: str,
    content: bytes,
    replace: bool = False,
) -> dict[str, object]:
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    _reject_already_intaken(directory, replace)
    safe = _single_filename(filename)
    if len(content) > DEFAULT_MAX_BYTES:
        raise EngagementError(
            f"Archive decompressed size {len(content)} exceeds the snapshot cap ({DEFAULT_MAX_BYTES}) before extraction"
        )
    pending = _fresh_pending(directory)
    tree = pending / "tree"
    tree.mkdir(parents=True)
    (tree / safe).write_bytes(content)
    preview = snapshot_preview(tree)
    preview["stripped_prefix"] = None
    _write_pending(
        directory,
        {
            "kind": "single-file",
            "label": safe,
            "filename": safe,
            "tree": _relative_to(tree, directory),
            "include_tests": False,
            "replace": replace,
            "stripped_prefix": None,
        },
    )
    return preview


def stage_clone_preview(
    root: Path,
    engagement_id: str,
    *,
    url: str,
    ref: str,
    actor: str,
    include_test_paths: bool = False,
    replace: bool = False,
    run: GitRun | None = None,
    probe: RedirectProbe | None = None,
) -> dict[str, object]:
    """Shallow-clone into the engagement, then preview. The snapshot is not written yet."""
    if not actor.strip():
        raise EngagementError("Clone requires an actor")
    clean_url = _require_https_without_credentials(url)
    clean_ref = _safe_ref(ref)
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    _reject_already_intaken(directory, replace)
    if (directory / "antares-data" / "run.lock").is_file():
        raise EngagementError("Clone is refused while an investigation is running")
    clean_url = _reject_cross_host_redirect(clean_url, probe)
    pending = _fresh_pending(directory)
    work = pending / "tree"
    git = run or _git
    try:
        _shallow_clone(clean_url, clean_ref, work, git)
        commit = _run_git(git, _git_command("-C", str(work), "rev-parse", "HEAD")).strip()
    except Exception:
        shutil.rmtree(pending, ignore_errors=True)
        _clear_pending_record(directory)
        raise
    if not _COMMIT.fullmatch(commit):
        shutil.rmtree(pending, ignore_errors=True)
        _clear_pending_record(directory)
        raise EngagementError("Clone did not resolve a commit")
    append_durable_audit(
        root,
        engagement_id,
        {"action": "intake_clone", "actor": actor.strip(), "url": clean_url, "commit": commit, "ref": clean_ref},
    )
    preview = snapshot_preview(work, include_test_paths=include_test_paths)
    preview["stripped_prefix"] = None
    preview["commit"] = commit
    _write_pending(
        directory,
        {
            "kind": "clone",
            "label": clean_url,
            "url": clean_url,
            "ref": clean_ref,
            "commit": commit,
            "actor": actor.strip(),
            "tree": _relative_to(work, directory),
            "include_tests": include_test_paths,
            "replace": replace,
            "stripped_prefix": None,
        },
    )
    return preview


def confirm_preview(root: Path, engagement_id: str) -> dict[str, object]:
    directory = engagement_dir(root, engagement_id)
    pending = _read_pending(directory)
    if pending is None:
        raise EngagementError("Confirm an intake preview first")
    kind = str(pending.get("kind") or "")
    include_tests = bool(pending.get("include_tests"))
    replace = bool(pending.get("replace"))
    _reject_already_intaken(directory, replace)
    try:
        if kind == "path":
            return intake_local(
                root,
                engagement_id,
                Path(str(pending.get("path") or "")),
                include_test_paths=include_tests,
                replace=replace,
            )
        tree = directory / str(pending.get("tree") or "")
        if not tree.is_dir() or not _is_inside(tree, directory / "intake" / "pending"):
            raise EngagementError("Confirm an intake preview first")
        extra: dict[str, object] | None = None
        memory: dict[str, object]
        if kind == "clone":
            extra = {"url": pending.get("url"), "commit": pending.get("commit"), "ref": pending.get("ref")}
            memory = {
                "kind": "clone",
                "label": str(pending.get("url") or ""),
                "url": pending.get("url"),
                "ref": pending.get("ref"),
                "actor": pending.get("actor"),
                "include_tests": include_tests,
            }
        elif kind == "archive":
            memory = {
                "kind": "archive",
                "label": str(pending.get("label") or ""),
                "stored": pending.get("stored"),
                "include_tests": include_tests,
            }
        elif kind == "single-file":
            memory = {
                "kind": "single-file",
                "label": str(pending.get("filename") or pending.get("label") or ""),
                "tree": pending.get("tree"),
                "include_tests": False,
            }
        else:
            memory = {
                "kind": kind or "folder",
                "label": str(pending.get("label") or "uploaded folder"),
                "tree": pending.get("tree"),
                "include_tests": include_tests,
            }
        if kind in {"folder", "single-file"}:
            kept = directory / "intake" / "kept"
            if kept.exists():
                shutil.rmtree(kept)
            shutil.copytree(tree, kept, symlinks=True)
            memory["tree"] = "intake/kept"
        prefix = pending.get("stripped_prefix")
        return _finish_intake(
            root,
            directory,
            tree,
            kind=kind,
            label=str(pending.get("label") or kind),
            stripped_prefix=prefix if isinstance(prefix, str) else None,
            include_test_paths=include_tests,
            extra=extra,
            memory=memory,
        )
    finally:
        shutil.rmtree(directory / "intake" / "pending", ignore_errors=True)
        _clear_pending_record(directory)


def reintake(
    root: Path,
    engagement_id: str,
    *,
    actor: str = "",
    run: GitRun | None = None,
    index: int | None = None,
) -> dict[str, object]:
    """Repeat a remembered source with replace, so a changed tree goes stale."""
    record = load_engagement(root, engagement_id)
    require_open(record)
    recent = record.get("recent_sources")
    if not isinstance(recent, list) or not recent:
        raise EngagementError("No intake source is remembered")
    chosen = recent[-1] if index is None else recent[index] if 0 <= index < len(recent) else None
    if not isinstance(chosen, dict):
        raise EngagementError("No intake source is remembered")
    last = chosen
    kind = str(last.get("kind") or "")
    include_tests = bool(last.get("include_tests"))
    directory = engagement_dir(root, engagement_id)
    if kind == "path":
        return intake_local(
            root,
            engagement_id,
            Path(str(last.get("path") or "")),
            include_test_paths=include_tests,
            replace=True,
        )
    if kind == "clone":
        return _reclone(root, engagement_id, last, actor=actor, include_tests=include_tests, run=run)
    if kind == "archive":
        stored = _stored_inside_intake(directory, str(last.get("stored") or ""))
        return intake_local(root, engagement_id, stored, include_test_paths=include_tests, replace=True)
    tree = _stored_inside_intake(directory, str(last.get("tree") or ""))
    if not tree.is_dir():
        raise EngagementError("No intake source is remembered")
    return _finish_intake(
        root,
        directory,
        tree,
        kind=kind,
        label=str(last.get("label") or kind),
        stripped_prefix=None,
        include_test_paths=include_tests,
        memory=dict(last),
    )


def load_pending(root: Path, engagement_id: str) -> dict[str, object] | None:
    return _read_pending(engagement_dir(root, engagement_id))


def _reclone(
    root: Path,
    engagement_id: str,
    last: dict[str, object],
    *,
    actor: str,
    include_tests: bool,
    run: GitRun | None,
) -> dict[str, object]:
    stage_clone_preview(
        root,
        engagement_id,
        url=str(last.get("url") or ""),
        ref=str(last.get("ref") or ""),
        actor=actor.strip(),
        include_test_paths=include_tests,
        replace=True,
        run=run,
    )
    return confirm_preview(root, engagement_id)


def _finish_intake(
    root: Path,
    directory: Path,
    tree: Path,
    *,
    kind: str,
    label: str,
    stripped_prefix: str | None,
    include_test_paths: bool,
    extra: dict[str, object] | None = None,
    memory: dict[str, object] | None = None,
) -> dict[str, object]:
    engagement_id = directory.name
    record = load_engagement(root, engagement_id)
    require_open(record)
    src = directory / "src"
    if src.exists():
        shutil.rmtree(src)
    snapshot = directory / "snapshot"
    if snapshot.exists():
        shutil.rmtree(snapshot)
    try:
        materialize_snapshot(tree, src, include_test_paths=include_test_paths)
        materialize_snapshot(src, snapshot, include_test_paths=include_test_paths)
        digest = snapshot_content_hash(snapshot)
    except ValueError as exc:
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(snapshot, ignore_errors=True)
        raise EngagementError(str(exc)) from exc
    except OSError:
        shutil.rmtree(src, ignore_errors=True)
        shutil.rmtree(snapshot, ignore_errors=True)
        raise
    record = load_engagement(root, engagement_id)
    record["snapshot_sha256"] = digest
    intake = {
        "kind": kind,
        "label": label,
        "snapshot_sha256": digest,
        "stripped_prefix": stripped_prefix,
    }
    if extra:
        intake.update(extra)
    record["intake"] = intake
    record["label"] = "single-file" if kind == "single-file" else None
    if memory is not None:
        _remember(record, memory)
    save_engagement(root, record)
    clear_plans(directory)
    return record


def _remember(record: dict[str, object], entry: dict[str, object]) -> None:
    recent = record.get("recent_sources")
    items = [item for item in recent if isinstance(item, dict)] if isinstance(recent, list) else []
    items.append(entry)
    record["recent_sources"] = items[-_RECENT_LIMIT:]


def _reject_already_intaken(directory: Path, replace: bool) -> None:
    if replace or not (directory / "src").exists():
        return
    if _intake_was_recorded(directory):
        raise EngagementError("This engagement already has source intake")


def _intake_was_recorded(directory: Path) -> bool:
    """A partial copy with no recorded intake is not a finished source."""
    path = directory / "engagement.json"
    if not path.is_file():
        return True
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return True
    if not isinstance(payload, dict):
        return True
    return bool(payload.get("snapshot_sha256") or payload.get("intake"))


def _central_zip_totals(archive: Path) -> tuple[int, int]:
    try:
        with zipfile.ZipFile(archive) as bundle:
            files = [info for info in bundle.infolist() if not info.is_dir()]
    except zipfile.BadZipFile as exc:
        raise EngagementError("Archive central directory and local headers disagree") from exc
    return len(files), sum(int(info.file_size) for info in files)


def _declared_archive_totals(archive: Path) -> tuple[int, int]:
    with tarfile.open(archive) as bundle:
        members = [member for member in bundle.getmembers() if member.isfile()]
        return len(members), sum(int(member.size) for member in members)


def _require_https_without_credentials(url: str) -> str:
    text = url.strip()
    parsed = urllib.parse.urlsplit(text)
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise EngagementError("Clone URL must not contain credentials")
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise EngagementError("Clone accepts an https URL")
    return text


def _safe_ref(ref: str) -> str:
    text = ref.strip()
    if not text or text.startswith("-") or any(character.isspace() for character in text) or ".." in Path(text).parts:
        raise EngagementError("Clone ref must be a branch, tag, or commit")
    return text


def _shallow_clone(url: str, ref: str, dest: Path, run: GitRun) -> None:
    if _COMMIT.fullmatch(ref):
        dest.mkdir(parents=True, exist_ok=True)
        _run_git(run, _git_command("init", str(dest)))
        _run_git(run, _git_command("-C", str(dest), "remote", "add", "origin", url))
        _run_git(
            run,
            _git_command("-C", str(dest), "fetch", "--depth", "1", "--no-recurse-submodules", "origin", ref),
        )
        _run_git(run, _git_command("-C", str(dest), "checkout", "--detach", "FETCH_HEAD"))
        return
    if dest.exists():
        shutil.rmtree(dest)
    _run_git(
        run,
        _git_command(
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-recurse-submodules",
            "--branch",
            ref,
            *[flag for item in _GIT_CONFIGS for flag in ("-c", item)],
            "--",
            url,
            str(dest),
        ),
    )


def _git_command(*args: str) -> list[str]:
    command = ["git"]
    for item in _GIT_CONFIGS:
        command.extend(["-c", item])
    command.extend(args)
    return command


def _reject_cross_host_redirect(url: str, probe: RedirectProbe | None) -> str:
    """Follow same-host HTTPS redirects. A different host is refused before git runs."""
    fetch = probe or _probe_https
    current = url
    origin = _endpoint(url)
    for _ in range(5):
        status, location = fetch(current)
        if status < 300 or status >= 400 or not location:
            return current
        target = urllib.parse.urljoin(current, location)
        parsed = urllib.parse.urlsplit(target)
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise EngagementError("Clone URL must not contain credentials")
        if parsed.scheme.lower() != "https" or _endpoint(target) != origin:
            raise EngagementError("Clone redirect to a different host was refused")
        current = target
    raise EngagementError("Clone redirect to a different host was refused")


def _endpoint(url: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port or 443
    return ((parsed.hostname or "").lower(), port)


def _probe_https(url: str) -> tuple[int, str | None]:
    probe = url.rstrip("/") + "/info/refs?service=git-upload-pack"
    request = urllib.request.Request(probe, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            response.read(1024)
            return int(response.status), None
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location") if exc.headers is not None else None
        return int(exc.code), location if isinstance(location, str) else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
    ) -> object:
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)  # type: ignore[arg-type]

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _run_git(run: GitRun, args: list[str]) -> str:
    completed = run(args)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        tail = detail[-1][:200] if detail else "git failed"
        raise EngagementError(f"Clone failed: {tail}")
    return completed.stdout or ""


def _git(args: list[str]) -> CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    env.pop("GIT_ASKPASS", None)
    env.pop("SSH_ASKPASS", None)
    return subprocess.run(args, check=False, capture_output=True, env=env, text=True)


def _single_filename(name: str) -> str:
    text = name.strip()
    if not text or text in {".", ".."} or "/" in text or "\\" in text or Path(text).name != text:
        raise EngagementError("Single-file intake needs one filename")
    return text


def _fresh_pending(directory: Path) -> Path:
    pending = directory / "intake" / "pending"
    if pending.exists():
        shutil.rmtree(pending)
    pending.mkdir(parents=True)
    return pending


def _write_pending(directory: Path, payload: dict[str, object]) -> None:
    path = directory / "intake" / "pending.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_pending(directory: Path) -> dict[str, object] | None:
    path = directory / "intake" / "pending.json"
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    return payload


def _clear_pending_record(directory: Path) -> None:
    (directory / "intake" / "pending.json").unlink(missing_ok=True)


def _relative_to(path: Path, directory: Path) -> str:
    return path.resolve().relative_to(directory.resolve()).as_posix()


def _stored_inside_intake(directory: Path, relative: str) -> Path:
    if not relative or relative.startswith("/") or ".." in Path(relative).parts:
        raise EngagementError("No intake source is remembered")
    path = (directory / relative).resolve()
    intake = (directory / "intake").resolve()
    if not _is_inside(path, intake):
        raise EngagementError("No intake source is remembered")
    return path
