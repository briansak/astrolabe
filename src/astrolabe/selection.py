"""Investigation selection. The UI asks the CLI to plan and then starts one run per CWE."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from subprocess import CompletedProcess

from astrolabe.cwe import load_cwe_relations
from astrolabe.engagement import EngagementError
from astrolabe.investigate import ADVISORY_ID_PATTERN, _load_cached_advisory, _quiet_container
from astrolabe.offline import investigation_run

EXPLORATORY_NOTE = (
    "Exploratory checks identify the affected file far less often than advisory checks "
    "and often return files that are not affected."
)
CLASS_NOTE = "Broad weakness classes give the model less to search for."
REVIEW_LOAD_NOTE = (
    "Each investigation returns candidate files for you to review. "
    "A larger launch means more files to read before anything belongs in a customer report."
)
SINGLE_FILE_NOTE = (
    "Astrolabe identifies affected files, not lines. "
    "With one file, the result indicates whether the weakness appears present, not where."
)
INTAKE_REQUIRED = "Intake is required before an investigation."
INTAKE_BUSY = "A clone or re-intake is in progress."
LAUNCH_BUSY = "Another launch is still queuing for this engagement."
PLAN_EMPTY = "No plan yet"
PLAN_STALE = "This plan is out of date"
LAUNCH_CAP = 10
PRESET_MAX_CWES = "400"
OWASP_GROUP = "OWASP Top Ten 2025 RC1 (CWE-1450)"
EXCLUDED_EVIDENCE = "Evidence was only in excluded paths."
PLAN_EXCLUSION_NOTE = (
    "Path exclusions apply to the evidence shown here. "
    "antares plan has no exclude option, so ranking may still include excluded paths."
)
DEFAULT_EVIDENCE_EXCLUSIONS = ("docs/", "tests/", "examples/", "docs/conf.py", "setup.py", "noxfile.py")
_PATH_TOKEN = re.compile(r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+\.[A-Za-z0-9]+")
_SCORE_FIELDS = (
    "repository_evidence_score",
    "repository_specific_evidence_score",
    "repository_category_evidence_score",
    "repository_relationship_evidence_score",
)
EXPLORATORY_SOURCES = ("recommended", "top25", "owasp", "search")
Runner = type(_quiet_container)


def plan_command(scope: str | None) -> list[str]:
    command = ["antares", "plan", "/workspace/repo", "--format", "json"]
    if scope in {"top25", "owasp"}:
        command.extend(["--scope", scope, "--max-cwes", PRESET_MAX_CWES])
    return command


def plan_snapshot(
    engagement: Path,
    scope: str | None = None,
    runner: Runner = _quiet_container,
) -> dict[str, object]:
    """Run plan in the offline container. The command does not call the model."""
    if not (engagement / "snapshot").is_dir():
        raise EngagementError(INTAKE_REQUIRED)
    command = plan_command(scope)
    with investigation_run():
        completed = runner(engagement, command, needs_inference=False)
    if not isinstance(completed, CompletedProcess):
        raise EngagementError("Plan did not return a result")
    if int(completed.returncode) != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise EngagementError(detail or "Plan failed")
    return _parse_plan_stdout(completed.stdout or "")


def plan_rows(payload: dict[str, object], *, scope: str | None = None) -> list[dict[str, object]]:
    checks = payload.get("selected_checks")
    if not isinstance(checks, list):
        raise EngagementError("Plan did not list any checks")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            continue
        evidence, excluded_only = _filter_evidence(check)
        score = _evidence_score(check)
        cwe_ids = check.get("cwe_ids")
        if not isinstance(cwe_ids, list):
            continue
        for cwe_id in cwe_ids:
            cwe = str(cwe_id).strip().upper()
            if not cwe or cwe in seen:
                continue
            seen.add(cwe)
            reasons = [] if excluded_only else _kept_fragments(check.get("reasons"))
            evidence_paths = [] if excluded_only else _kept_fragments(check.get("evidence"))
            rows.append(
                {
                    "cwe": cwe,
                    "evidence": evidence,
                    "reasons": reasons,
                    "evidence_paths": evidence_paths,
                    "score": score,
                    "excluded_only": excluded_only,
                    "preselect": False,
                    "group": "",
                    "related": [],
                }
            )
    rows = _collapse_parent_child(rows)
    return _mark_preselect(rows, scope)


def evidence_exclusions() -> tuple[str, ...]:
    raw = os.environ.get("ASTROLABE_EVIDENCE_EXCLUSIONS", "").strip()
    if not raw:
        return DEFAULT_EVIDENCE_EXCLUSIONS
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def preselect_limit() -> int:
    raw = os.environ.get("ASTROLABE_PRESELECT_LIMIT", "5").strip()
    try:
        value = int(raw)
    except ValueError:
        return 5
    return value if value >= 0 else 5


def per_check_estimate_seconds() -> float:
    raw = os.environ.get("ASTROLABE_ESTIMATE_PER_CHECK", "120").strip()
    try:
        value = float(raw)
    except ValueError:
        return 120.0
    return value if value >= 0 else 120.0


def has_repository_evidence(check: dict[str, object]) -> bool:
    return _evidence_score(check) > 0


def estimate_seconds(investigations: list[dict[str, object]], count: int) -> float | None:
    samples: list[float] = []
    for investigation in investigations:
        runs = investigation.get("runs")
        if not isinstance(runs, list):
            continue
        for run in runs:
            if not isinstance(run, dict):
                continue
            elapsed = run.get("elapsed_seconds")
            if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
                samples.append(float(elapsed))
    if not samples or count <= 0:
        return None
    return (sum(samples) / len(samples)) * count


def status_estimate_text(investigations: list[dict[str, object]]) -> str:
    """Short per-check duration for a queue row. Recorded runs, otherwise the default."""
    seconds = estimate_seconds(investigations, 1)
    if seconds is None:
        seconds = per_check_estimate_seconds()
    return f"about {seconds:.0f} seconds"


def format_estimate(seconds: float | None, count: int) -> str:
    if count <= 0:
        return "Approximate total time is 0 seconds for 0 investigations."
    if seconds is None:
        each = per_check_estimate_seconds()
        total = each * count
        return (
            f"Approximate total time is {total:.0f} seconds, "
            f"using {each:.0f} seconds per check, for {count} investigations."
        )
    return (
        f"Approximate total time is {seconds:.0f} seconds, from the average recorded per-run time, "
        f"for {count} investigations."
    )


def confirmation_text(count: int, seconds: float | None) -> str:
    return f"{count} investigations need confirmation before they run. {format_estimate(seconds, count)}"


def short_sha(value: object) -> str:
    text = str(value or "")
    if len(text) <= 12:
        return text
    return text[:12]


def load_advisory(cache: Path, advisory_id: str) -> dict[str, object]:
    path = cache / f"{advisory_id}.json"
    if not path.is_file():
        return {"id": advisory_id, "cached": False, "text": "", "cwe_ids": [], "title": ""}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EngagementError("Cached advisory is not an object")
    cwe_ids = payload.get("cwe_ids") if isinstance(payload.get("cwe_ids"), list) else []
    return {
        "id": advisory_id,
        "cached": True,
        "text": _load_cached_advisory(cache, advisory_id),
        "cwe_ids": [str(item).strip().upper() for item in cwe_ids if str(item).strip()],
        "title": str(payload.get("summary") or advisory_id),
    }


def selection_source_for(source: str) -> str:
    if source in EXPLORATORY_SOURCES or source == "pasted" or ADVISORY_ID_PATTERN.fullmatch(source):
        return source
    raise EngagementError("Selection source is not an advisory id, pasted text, or a catalog choice")


def _evidence_score(check: dict[str, object]) -> int:
    scores: list[int] = []
    for key in _SCORE_FIELDS:
        try:
            scores.append(int(check.get(key) or 0))
        except (TypeError, ValueError):
            continue
    return max(scores) if scores else 0


def _kept_fragments(values: object) -> list[str]:
    """Drop fragments whose paths are all excluded. Prose and mixed fragments stay."""
    if not isinstance(values, list):
        return []
    kept: list[str] = []
    for item in values:
        for part in str(item).split(";"):
            fragment = part.strip()
            if not fragment:
                continue
            paths = _PATH_TOKEN.findall(fragment)
            if paths and all(_path_excluded(path) for path in paths):
                continue
            kept.append(fragment)
    return kept


def _filter_evidence(check: dict[str, object]) -> tuple[str, bool]:
    fragments: list[str] = []
    for key in ("reasons", "evidence"):
        values = check.get(key)
        if isinstance(values, list):
            for item in values:
                fragments.extend(part.strip() for part in str(item).split(";") if part.strip())
    kept: list[str] = []
    saw_path = False
    saw_kept_path = False
    for fragment in fragments:
        paths = _PATH_TOKEN.findall(fragment)
        if not paths:
            kept.append(fragment)
            continue
        saw_path = True
        if all(_path_excluded(path) for path in paths):
            continue
        saw_kept_path = True
        kept.append(fragment)
    if saw_path and not saw_kept_path:
        return EXCLUDED_EVIDENCE, True
    if kept:
        return "; ".join(kept), False
    return "The plan did not state evidence for this CWE.", False


def _path_excluded(path: str) -> bool:
    normal = path.replace("\\", "/").lstrip("./")
    parts = [part for part in normal.split("/") if part]
    for rule in evidence_exclusions():
        rule_norm = rule.replace("\\", "/").strip().strip("/")
        if not rule_norm:
            continue
        if normal == rule_norm or normal.startswith(rule_norm + "/"):
            return True
        rule_parts = [part for part in rule_norm.split("/") if part]
        if len(rule_parts) == 1 and rule_parts[0] in parts:
            return True
    return False


def _direct_parents(cwe: str) -> list[str]:
    parents: list[str] = []
    for parent, entry in load_cwe_relations().items():
        children = entry.get("children")
        if isinstance(children, list) and cwe in {str(item) for item in children}:
            parents.append(parent)
    return parents


def _collapse_parent_child(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_cwe = {str(row["cwe"]): row for row in rows}
    suppress: set[str] = set()
    for row in rows:
        related = row.get("related")
        if not isinstance(related, list):
            related = []
            row["related"] = related
        for parent in _direct_parents(str(row["cwe"])):
            other = by_cwe.get(parent)
            if other is None or other.get("evidence") != row.get("evidence"):
                continue
            suppress.add(parent)
            if parent not in related:
                related.append(parent)
    return [row for row in rows if str(row["cwe"]) not in suppress]


def _mark_preselect(rows: list[dict[str, object]], scope: str | None) -> list[dict[str, object]]:
    if scope == "owasp":
        for row in rows:
            row["preselect"] = False
            row["group"] = OWASP_GROUP
        return rows
    limit = preselect_limit() if scope in {None, "", "recommended", "top25"} else None
    chosen = 0
    order = sorted(range(len(rows)), key=lambda index: (-int(rows[index]["score"]), index))
    for index in order:
        row = rows[index]
        eligible = int(row["score"]) > 0 and not row.get("excluded_only")
        if eligible and (limit is None or chosen < limit):
            row["preselect"] = True
            chosen += 1
        else:
            row["preselect"] = False
        row["group"] = ""
    return rows


def _parse_plan_stdout(stdout: str) -> dict[str, object]:
    text = stdout.strip()
    if not text:
        raise EngagementError("Plan returned no output")
    start = text.find("{")
    if start > 0:
        text = text[start:]
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise EngagementError("Plan output is not an object")
    return payload
