"""Capture synthetic acme-2026 screenshots for the docs. Not part of the install path."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from subprocess import CompletedProcess

ROOT = Path(__file__).resolve().parents[1]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PORT = 8791


def main() -> None:
    home = Path(os.environ.get("DOCS_IMAGE_HOME", "/tmp/astrolabe-docs-home"))
    home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)
    work = Path(os.environ["DOCS_IMAGE_WORK"])
    os.environ["ASTROLABE_ENGAGEMENTS_DIR"] = str(work / "engagements")
    os.environ["ASTROLABE_AUDIT_LOG"] = str(work / "var" / "audit.jsonl")
    os.environ["ASTROLABE_ADVISORY_CACHE"] = str(work / "advisories")
    from astrolabe.candidates import set_verdict
    from astrolabe.engagement import attest, create_engagement
    from astrolabe.intake import intake_local
    from astrolabe.investigate import start_investigation
    from astrolabe.reports import write_assessment
    from astrolabe.ui import App

    source = work / "billing"
    source.mkdir(parents=True)
    (source / "app.py").write_text(
        "def lookup(name):\n    query = \"select * from users where name = '\" + name + \"'\"\n    return query\n",
        encoding="utf-8",
    )
    engagements = work / "engagements"
    create_engagement(
        engagements,
        engagement_id="acme-2026",
        customer="Acme",
        scope="Billing service",
        start_date="2026-10-09",
        consultants=["Ada"],
        reference="SOW-14",
    )
    attest(
        engagements,
        "acme-2026",
        actor="Ada",
        reference="SOW-14",
        scope="Billing service",
        attested_at="2026-10-09T15:00:00Z",
    )
    intake_local(engagements, "acme-2026", source)

    def runner(engagement: Path, command: list[str]) -> CompletedProcess[str]:
        report_dir = engagement / "antares-data" / "reports" / "run-1"
        report_dir.mkdir(parents=True)
        (report_dir / "report.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "file_path": "app.py",
                            "submission_rank": 1,
                            "cwe_ids": ["CWE-89"],
                            "likelihood_of_exploit": "High",
                        }
                    ],
                    "summary": {},
                }
            ),
            encoding="utf-8",
        )
        return CompletedProcess(command, 0)

    start_investigation(
        engagements,
        "acme-2026",
        cwe="CWE-89",
        actor="Ada",
        advisory_text="The billing lookup builds a SQL query from the name parameter.",
        runner=runner,
    )
    set_verdict(
        engagements,
        "acme-2026",
        file_path="app.py",
        cwe="CWE-89",
        state="confirmed",
        actor="Ada",
        note="The name parameter is concatenated into the SQL string.",
    )
    write_assessment(engagements, "acme-2026", actor="Ada")
    server = App(engagements).serve(PORT)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.5)
    images = ROOT / "docs" / "images"
    images.mkdir(parents=True, exist_ok=True)
    pages = {
        "landing.png": (f"http://127.0.0.1:{PORT}/", 1100),
        "engagement.png": (f"http://127.0.0.1:{PORT}/e/acme-2026", 1100),
        "review.png": (f"http://127.0.0.1:{PORT}/e/acme-2026?step=review", 2800),
        "report.png": (f"http://127.0.0.1:{PORT}/e/acme-2026/report", 1100),
    }
    only = os.environ.get("DOCS_IMAGE_ONLY", "")
    for name, (url, height) in pages.items():
        if only and name != only:
            continue
        profile = ROOT / ".chrome-docs"
        profile.mkdir(exist_ok=True)
        process = subprocess.Popen(
            [
                CHROME,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--disable-background-networking",
                "--hide-scrollbars",
                "--virtual-time-budget=2000",
                f"--user-data-dir={profile}",
                f"--window-size=1440,{height}",
                f"--screenshot={images / name}",
                url,
            ],
            start_new_session=True,
        )
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        written = images / name
        if not written.is_file() or written.stat().st_size < 1000:
            raise SystemExit(f"screenshot missing: {name}")
    server.shutdown()
    profile = ROOT / ".chrome-docs"
    if profile.exists():
        import shutil

        shutil.rmtree(profile, ignore_errors=True)
    print("wrote", images)


if __name__ == "__main__":
    main()
