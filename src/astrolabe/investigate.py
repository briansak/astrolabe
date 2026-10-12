"""Advisory-guided and exploratory investigations. One run by default."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from subprocess import CompletedProcess

from astrolabe.activity import ActivityTailer
from astrolabe.candidates import observe_candidates
from astrolabe.coverage import rebuild_coverage
from astrolabe.engagement import (
    EngagementError,
    advisory_cache_dir,
    audit,
    engagement_dir,
    has_attestation,
    load_engagement,
    require_open,
    utc_now,
)
from astrolabe.offline import investigation_run
from astrolabe.redact import label_mitre_likelihood, read_report
from astrolabe.runner import cancel_event, container_slot, run_container
from astrolabe.snapshot import materialize_snapshot

CWE_PATTERN = re.compile(r"^CWE-\d+$")
ADVISORY_ID_PATTERN = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$")
Runner = Callable[[Path, list[str]], CompletedProcess[str]]


def _quiet_container(
    engagement: Path,
    command: list[str],
    *,
    needs_inference: bool = True,
) -> CompletedProcess[str]:
    """Run the CLI without streaming its summary onto the consultant's terminal."""
    return run_container(engagement, command, stream=False, needs_inference=needs_inference)


def consultant_line(investigation: dict[str, object]) -> str:
    """One status line. Candidates stay candidates until a consultant reviews them."""
    runs = investigation.get("runs")
    count = 0
    if isinstance(runs, list) and runs and isinstance(runs[-1], dict):
        paths = runs[-1].get("candidate_paths")
        if isinstance(paths, list):
            count = len(paths)
    mode = "exploratory" if investigation.get("exploratory") else "advisory-guided"
    return (
        f"{investigation['id']} mode={mode} cwe={investigation['cwe']} "
        f"candidates={count} pending consultant review"
    )


def start_investigation(
    root: Path,
    engagement_id: str,
    *,
    cwe: str,
    actor: str,
    advisory_id: str | None = None,
    advisory_text: str | None = None,
    exploratory: bool = False,
    cache: Path | None = None,
    runner: Runner = _quiet_container,
    selection_source: str | None = None,
    selection_title: str | None = None,
) -> dict[str, object]:
    if not actor.strip():
        raise EngagementError("Investigation requires the consultant running it")
    normalized_cwe = _normalize_cwe(cwe)
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    if not has_attestation(root, engagement_id):
        raise EngagementError("Authorization attestation is required before the first scan")
    if not (directory / "src").is_dir():
        raise EngagementError("Intake source before scanning")
    mode, query_text, resolved_id = _resolve_mode(
        exploratory=exploratory,
        advisory_id=advisory_id,
        advisory_text=advisory_text,
        cache=advisory_cache_dir(cache),
    )
    source = _recorded_source(selection_source, resolved_id, exploratory)
    _ensure_snapshot(directory)
    investigation = {
        "id": f"inv-{uuid.uuid4().hex[:12]}",
        "mode": mode,
        "exploratory": mode == "exploratory",
        "cwe": normalized_cwe,
        "advisory_id": resolved_id,
        "query_text": query_text,
        "selection_source": source,
        "snapshot_sha256": str(record.get("snapshot_sha256") or ""),
        "created_at": utc_now(),
        "runs": [],
    }
    if selection_title and selection_title.strip():
        investigation["selection_title"] = selection_title.strip()
    _execute_run(
        directory,
        investigation,
        run_index=1,
        runner=runner,
        actor=actor.strip(),
        snapshot_sha256=str(record.get("snapshot_sha256") or ""),
    )
    investigations = _load_investigations(directory)
    investigations.append(investigation)
    _save_investigations(directory, investigations)
    audit(
        directory,
        {
            "action": "investigate",
            "actor": actor.strip(),
            "investigation_id": investigation["id"],
            "mode": mode,
            "exploratory": investigation["exploratory"],
            "cwe": normalized_cwe,
            "selection_source": source,
            "snapshot_sha256": investigation["snapshot_sha256"],
        },
    )
    rebuild_coverage(root, engagement_id)
    return investigation


def rerun_investigation(
    root: Path,
    engagement_id: str,
    investigation_id: str,
    *,
    actor: str,
    runner: Runner = _quiet_container,
) -> dict[str, object]:
    if not actor.strip():
        raise EngagementError("A re-run requires the consultant running it")
    record = load_engagement(root, engagement_id)
    require_open(record)
    directory = engagement_dir(root, engagement_id)
    if not has_attestation(root, engagement_id):
        raise EngagementError("Authorization attestation is required before the first scan")
    investigations = _load_investigations(directory)
    investigation = next((item for item in investigations if item.get("id") == investigation_id), None)
    if investigation is None:
        raise EngagementError(f"No investigation {investigation_id}")
    next_run = len(investigation.get("runs") or []) + 1
    _execute_run(
        directory,
        investigation,
        run_index=next_run,
        runner=runner,
        actor=actor.strip(),
        snapshot_sha256=str(record.get("snapshot_sha256") or ""),
    )
    _save_investigations(directory, investigations)
    audit(
        directory,
        {
            "action": "rerun",
            "actor": actor.strip(),
            "investigation_id": investigation_id,
            "run": next_run,
            "mode": investigation["mode"],
            "exploratory": investigation["exploratory"],
            "cwe": investigation["cwe"],
            "increases_coverage": False,
        },
    )
    rebuild_coverage(root, engagement_id)
    return investigation


def _execute_run(
    directory: Path,
    investigation: dict[str, object],
    *,
    run_index: int,
    runner: Runner,
    actor: str,
    snapshot_sha256: str,
) -> None:
    command = [
        "antares",
        "query",
        "/workspace/repo",
        "--cwe",
        str(investigation["cwe"]),
    ]
    query_text = investigation.get("query_text")
    if isinstance(query_text, str):
        command.extend(["--query", query_text])
    exit_code = 0
    error = ""
    before = set(_report_paths(directory))
    lock = directory / "antares-data" / "run.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("run\n", encoding="utf-8")
    started = time.perf_counter()
    slot: dict[str, str] = {"name": ""}
    name_token = container_slot.set(slot)
    tailer = ActivityTailer(directory, container_slot=slot)
    activity: dict[str, object] = {}
    try:
        tailer.start()
        try:
            with investigation_run():
                try:
                    completed = runner(directory, command)
                    exit_code = int(completed.returncode)
                except Exception as exc:  # noqa: BLE001 — the attempt is still an investigation run
                    exit_code = 1
                    error = f"{type(exc).__name__}: {exc}"
        finally:
            elapsed = round(time.perf_counter() - started, 3)
            lock.unlink(missing_ok=True)
            event = cancel_event.get()
            activity = tailer.finish(
                exit_code=exit_code,
                cancelled=event is not None and event.is_set(),
            )
    finally:
        container_slot.reset(name_token)
    report_path = _report_from_this_run(directory, before)
    if report_path is not None:
        _label_saved_report(report_path)
    file_paths: list[str] = []
    if report_path is not None and exit_code == 0:
        file_paths = _candidate_paths(read_report(report_path))
        observe_candidates(
            directory.parent,
            str(directory.name),
            file_paths=file_paths,
            cwe=str(investigation["cwe"]),
            investigation_id=str(investigation["id"]),
            run=run_index,
        )
    relative_report = None
    if report_path is not None:
        relative_report = report_path.relative_to(directory).as_posix()
    runs = investigation.setdefault("runs", [])
    if not isinstance(runs, list):
        raise EngagementError("Investigation runs are not a list")
    runs.append(
        {
            "run": run_index,
            "actor": actor,
            "exit_code": exit_code,
            "error": error,
            "report": relative_report,
            "candidate_paths": file_paths,
            "snapshot_sha256": snapshot_sha256,
            "increases_coverage": run_index == 1,
            "elapsed_seconds": elapsed,
            "finished_at": utc_now(),
            "activity": activity,
        }
    )


def _resolve_mode(
    *,
    exploratory: bool,
    advisory_id: str | None,
    advisory_text: str | None,
    cache: Path,
) -> tuple[str, str | None, str | None]:
    supplied = sum(bool(item) for item in (exploratory, advisory_id, advisory_text))
    if supplied != 1:
        raise EngagementError(
            "Choose advisory-guided (--advisory-id or --advisory-text) or --exploratory"
        )
    if exploratory:
        return "exploratory", None, None
    if advisory_text is not None:
        if not advisory_text.strip():
            raise EngagementError("Pasted advisory text is empty")
        return "advisory", advisory_text, None
    if advisory_id is None or not ADVISORY_ID_PATTERN.fullmatch(advisory_id):
        raise EngagementError("Advisory id must be a CVE or GHSA id")
    return "advisory", _load_cached_advisory(cache, advisory_id), advisory_id


def _load_cached_advisory(cache: Path, advisory_id: str) -> str:
    path = cache / f"{advisory_id}.json"
    if not path.is_file():
        raise EngagementError(f"Advisory {advisory_id} is not in the local cache")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EngagementError("Cached advisory is not an object")
    summary = str(payload.get("summary") or "").strip()
    details = str(payload.get("details") or "").strip()
    text = "\n\n".join(part for part in (summary, details) if part)
    if not text:
        raise EngagementError(f"Cached advisory {advisory_id} has no summary or details")
    return text


def _ensure_snapshot(directory: Path) -> None:
    snapshot = directory / "snapshot"
    if snapshot.exists():
        return
    materialize_snapshot(directory / "src", snapshot, include_test_paths=False)


def _recorded_source(selection_source: str | None, advisory_id: str | None, exploratory: bool) -> str:
    if selection_source is not None and selection_source.strip():
        source = selection_source.strip()
        allowed = {"pasted", "recommended", "top25", "owasp", "search"}
        if source in allowed or ADVISORY_ID_PATTERN.fullmatch(source):
            return source
        raise EngagementError("Selection source is not an advisory id, pasted text, or a catalog choice")
    if exploratory:
        return ""
    if advisory_id:
        return advisory_id
    return "pasted"


def _normalize_cwe(cwe: str) -> str:
    text = cwe.strip().upper()
    if text.isdigit():
        text = f"CWE-{text}"
    if not CWE_PATTERN.fullmatch(text):
        raise EngagementError(f"CWE id must look like CWE-89: {cwe}")
    return text


def _report_paths(directory: Path) -> list[Path]:
    return list((directory / "antares-data" / "reports").glob("*/report.json"))


def _label_saved_report(path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return
    label_mitre_likelihood(payload)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _report_from_this_run(directory: Path, before: set[Path]) -> Path | None:
    appeared = [path for path in _report_paths(directory) if path not in before]
    if not appeared:
        return None
    return max(appeared, key=lambda path: path.stat().st_mtime_ns)


def _candidate_paths(report: dict[str, object]) -> list[str]:
    findings = report.get("findings")
    if not isinstance(findings, list):
        return []
    ranked = sorted(
        [item for item in findings if isinstance(item, dict)],
        key=lambda item: int(item.get("submission_rank") or 0),
    )
    paths: list[str] = []
    for finding in ranked:
        file_path = finding.get("file_path")
        if isinstance(file_path, str) and file_path:
            paths.append(file_path.lstrip("./"))
    return paths


def _load_investigations(directory: Path) -> list[dict[str, object]]:
    path = directory / "investigations.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Investigation store is not a list")
    return [item for item in payload if isinstance(item, dict)]


def _save_investigations(directory: Path, investigations: list[dict[str, object]]) -> None:
    path = directory / "investigations.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(investigations, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
