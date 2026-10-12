"""Close, export a redacted bundle, then purge the engagement directory."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
from pathlib import Path

from astrolabe.engagement import (
    EngagementError,
    append_durable_audit,
    audit,
    engagement_dir,
    load_engagement,
    read_durable_audit,
    save_engagement,
    utc_now,
)
from astrolabe.redact import find_secret_matches, read_report, read_trace, redact_text, sanitize_export_value
from astrolabe.reports import assessment_is_draft


def close_engagement(root: Path, engagement_id: str, *, actor: str, end_date: str | None = None) -> dict[str, object]:
    if not actor.strip():
        raise EngagementError("Close requires an actor")
    record = load_engagement(root, engagement_id)
    if record.get("state") != "open":
        raise EngagementError(f"Engagement is {record.get('state')}, not open")
    record["state"] = "closed"
    if end_date:
        record["end_date"] = end_date
    elif not record.get("end_date"):
        record["end_date"] = utc_now()[:10]
    save_engagement(root, record)
    audit(engagement_dir(root, engagement_id), {"action": "close", "actor": actor.strip()})
    return record


def export_root() -> Path:
    return (Path.home() / "Astrolabe" / "exports").expanduser()


def export_directory() -> Path:
    """~/Astrolabe/exports, created at 0700 when it is missing.

    An existing directory is returned unchanged. Its mode is not altered.
    """
    directory = export_root()
    if directory.exists():
        return directory
    try:
        directory.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        return directory
    os.chmod(directory, 0o700)
    return directory


def export_access_warning() -> str:
    """Name an existing exports directory that is group or world accessible."""
    directory = export_root()
    if not directory.is_dir():
        return ""
    if directory.stat().st_mode & 0o077:
        return f"{directory} is group or world accessible."
    return ""


def default_export_destination(engagement_id: str, *, report_only: bool, create: bool = False) -> Path:
    suffix = "report" if report_only else "full"
    directory = export_directory() if create else export_root()
    return directory / f"{engagement_id}-{suffix}"


def export_engagement(
    root: Path,
    engagement_id: str,
    destination: Path,
    *,
    actor: str,
    allow_draft: bool = False,
    report_only: bool = False,
) -> Path:
    if not actor.strip():
        raise EngagementError("Export requires an actor")
    record = load_engagement(root, engagement_id)
    if not report_only and record.get("state") != "closed":
        raise EngagementError("Export is available after the engagement is closed")
    directory = engagement_dir(root, engagement_id)
    if assessment_is_draft(directory) and not allow_draft:
        raise EngagementError("Assessment report is a draft. Finalize it, or pass --allow-draft.")
    if report_only and not (directory / "reports" / "assessment.html").is_file():
        raise EngagementError("Generate an assessment report before exporting it")
    target = Path(destination).expanduser().resolve()
    if _is_inside(target, directory) or _is_inside(target, root.resolve()):
        raise EngagementError("Export destination must sit outside the engagements directory")
    if target.parent == export_root().resolve():
        export_directory()
    target.parent.mkdir(parents=True, exist_ok=True)
    _refuse_customer_report_secrets(directory)
    with tarfile.open(target, "w:gz") as bundle:
        if report_only:
            _add_assessment(bundle, directory)
        else:
            _add_full_bundle(bundle, directory)
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    append_durable_audit(
        root,
        engagement_id,
        {
            "action": "export",
            "actor": actor.strip(),
            "path": str(target),
            "sha256": digest.hexdigest(),
            "size": target.stat().st_size,
            "report_only": report_only,
        },
    )
    return target


def _add_full_bundle(bundle: tarfile.TarFile, directory: Path) -> None:
    for name in ("engagement.json", "coverage.json", "audit.jsonl", "investigations.json", "candidates.json"):
        path = directory / name
        if path.is_file():
            _add_bytes(bundle, name, _redacted_record(path))
    for report in sorted((directory / "antares-data" / "reports").glob("*/report.json")):
        sanitized = read_report(report)
        _add_bytes(bundle, f"reports-redacted/{report.parent.name}.json", json.dumps(sanitized, indent=2) + "\n")
    for trace in sorted((directory / "antares-data" / "traces").glob("*.jsonl")):
        events = read_trace(trace)
        body = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        _add_bytes(bundle, f"traces-redacted/{trace.name}", body)
    _add_customer_reports(bundle, directory)


_ASSESSMENT_REPORTS = ("assessment.html", "assessment-status.json", "assessment.pdf")
_REMEDIATION_REPORTS = ("remediation.md", "remediation.json")


def _refuse_customer_report_secrets(directory: Path) -> None:
    """Refuse export when a customer report matches a secret detector.

    The message names the file, line, and rule. It does not include the match.
    """
    reports = directory / "reports"
    hits: list[str] = []
    for name in _ASSESSMENT_REPORTS + _REMEDIATION_REPORTS:
        path = reports / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        text = raw.decode("latin-1") if path.suffix == ".pdf" else raw.decode("utf-8")
        for match in find_secret_matches(text):
            hits.append(f"{name}:{match.line} {match.rule}")
    if not hits:
        return
    listed = "; ".join(hits)
    raise EngagementError(
        f"Export refused. {listed}. Fix the source report and re-finalize."
    )


def _add_report_file(bundle: tarfile.TarFile, directory: Path, name: str) -> None:
    path = directory / "reports" / name
    if path.is_file():
        _add_file_bytes(bundle, f"reports/{name}", path.read_bytes())


def _add_assessment(bundle: tarfile.TarFile, directory: Path) -> None:
    for name in _ASSESSMENT_REPORTS:
        _add_report_file(bundle, directory, name)


def _add_customer_reports(bundle: tarfile.TarFile, directory: Path) -> None:
    for name in _ASSESSMENT_REPORTS + _REMEDIATION_REPORTS:
        _add_report_file(bundle, directory, name)


def exports_still_on_disk(root: Path, engagement_id: str) -> list[str]:
    """Export paths recorded for this engagement that are still files. Nothing is deleted."""
    remaining: list[str] = []
    for row in read_durable_audit(root, engagement_id):
        if row.get("action") != "export":
            continue
        recorded = row.get("path")
        if not isinstance(recorded, str) or not recorded:
            continue
        if Path(recorded).is_file():
            remaining.append(recorded)
    return remaining


def purge_engagement(
    root: Path,
    engagement_id: str,
    *,
    actor: str,
    confirm_exports_handled: bool = False,
) -> dict[str, object]:
    if not actor.strip():
        raise EngagementError("Purge requires an actor")
    record = load_engagement(root, engagement_id)
    if record.get("state") != "closed":
        raise EngagementError("Close the engagement before purge")
    remaining = exports_still_on_disk(root, engagement_id)
    if remaining and not confirm_exports_handled:
        listed = ", ".join(remaining)
        raise EngagementError(
            f"Exports still on disk: {listed}. "
            "Pass --confirm-exports-handled to purge without deleting them."
        )
    directory = engagement_dir(root, engagement_id)
    files_removed = sum(1 for path in directory.rglob("*") if path.is_file())
    shutil.rmtree(directory)
    if directory.exists():
        raise EngagementError("Engagement directory still exists after purge")
    for name in ("src", "snapshot", "antares-data", "socket", "reports"):
        if (directory / name).exists():
            raise EngagementError(f"{name} still exists after purge")
    return append_durable_audit(
        root,
        engagement_id,
        {
            "action": "purge",
            "actor": actor.strip(),
            "files_removed": files_removed,
            "exports_still_present": remaining,
        },
    )


def _redacted_record(path: Path) -> str:
    """Redact parsed JSON values so escaped newlines do not hide the next token."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return _redacted_json_lines(text)
    stripped = text.strip()
    if not stripped:
        return text
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return _redacted_json_lines(text)
    return json.dumps(sanitize_export_value(payload), indent=2) + "\n"


def _redacted_json_lines(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            lines.append(redact_text(line))
            continue
        sanitized = sanitize_export_value(payload)
        lines.append(json.dumps(sanitized, sort_keys=True))
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def _add_bytes(bundle: tarfile.TarFile, name: str, text: str) -> None:
    _add_file_bytes(bundle, name, text.encode("utf-8"))


def _add_file_bytes(bundle: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    import io

    bundle.addfile(info, io.BytesIO(payload))


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
