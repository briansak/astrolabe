"""Coverage record for a later assessment report. Re-runs do not add CWEs."""

from __future__ import annotations

import json
from pathlib import Path

from astrolabe.candidates import confirmed_for_report, list_candidates
from astrolabe.engagement import engagement_dir

RERUN_NOTE = "Re-runs are recorded and do not increase CWE coverage."


def rebuild_coverage(root: Path, engagement_id: str) -> dict[str, object]:
    directory = engagement_dir(root, engagement_id)
    investigations = _load_investigations(directory)
    candidates = list_candidates(root, engagement_id)
    cwes: dict[str, dict[str, object]] = {}
    runs: list[dict[str, object]] = []
    for investigation in investigations:
        cwe = str(investigation["cwe"])
        exploratory = bool(investigation["exploratory"])
        mode = "exploratory" if exploratory else "advisory"
        source = str(investigation.get("selection_source") or "")
        snapshot = str(investigation.get("snapshot_sha256") or "")
        bucket = cwes.setdefault(
            f"{cwe}\0{mode}\0{source}\0{snapshot}",
            {
                "cwe": cwe,
                "mode": mode,
                "exploratory": exploratory,
                "selection_source": source,
                "snapshot_sha256": snapshot,
                "investigations": 0,
                "runs": 0,
                "coverage_count": 1,
            },
        )
        bucket["investigations"] = int(bucket["investigations"]) + 1
        for run in investigation.get("runs") or []:
            increases = bool(run.get("increases_coverage"))
            bucket["runs"] = int(bucket["runs"]) + 1
            runs.append(
                {
                    "investigation_id": investigation["id"],
                    "run": run["run"],
                    "cwe": cwe,
                    "mode": mode,
                    "exploratory": exploratory,
                    "increases_coverage": increases,
                    "selection_source": source,
                    "snapshot_sha256": snapshot,
                }
            )
    verdicts = {state: 0 for state in ("candidate", "confirmed", "not_actionable", "needs_more_info", "stale")}
    candidate_rows = []
    for candidate in candidates:
        state = str(candidate["state"])
        shown = str(candidate.get("presentation_state") or state)
        verdicts[shown] = verdicts.get(shown, 0) + 1
        candidate_rows.append(
            {
                "file_path": candidate["file_path"],
                "cwe": candidate["cwe"],
                "state": state,
                "stale": bool(candidate.get("stale")),
                "presentation_state": shown,
                "confirmed_for_report": confirmed_for_report(candidate),
                "snapshot_sha256": candidate.get("snapshot_sha256"),
                "fingerprint": candidate["fingerprint"],
            }
        )
    record = {
        "engagement_id": engagement_id,
        "cwes": list(cwes.values()),
        "cwe_coverage_count": len({str(item["cwe"]) for item in cwes.values()}),
        "runs": runs,
        "candidates": candidate_rows,
        "verdicts": verdicts,
        "reruns_do_not_increase_coverage": True,
        "note": RERUN_NOTE,
    }
    path = directory / "coverage.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return record


def load_coverage(root: Path, engagement_id: str) -> dict[str, object]:
    path = engagement_dir(root, engagement_id) / "coverage.json"
    if not path.is_file():
        return rebuild_coverage(root, engagement_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Coverage record is not an object")
    return payload


def _load_investigations(directory: Path) -> list[dict[str, object]]:
    path = directory / "investigations.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("Investigation store is not a list")
    return [item for item in payload if isinstance(item, dict)]
