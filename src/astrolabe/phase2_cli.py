"""Operator commands for an engagement, the advisory cache, and reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from astrolabe.advisories import import_advisories, load_id_list, sync_advisories
from astrolabe.candidates import set_verdict
from astrolabe.coverage import load_coverage, rebuild_coverage
from astrolabe.engagement import (
    EngagementError,
    attest,
    create_engagement,
    engagement_dir,
    engagements_root,
    load_engagement,
)
from astrolabe.intake import intake_local
from astrolabe.investigate import consultant_line, rerun_investigation, start_investigation
from astrolabe.purge import close_engagement, export_engagement, purge_engagement
from astrolabe.reports import finalize_assessment, write_assessment, write_remediation


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="astrolabe")
    sub = parser.add_subparsers(dest="command")

    engagement = sub.add_parser("engagement")
    engagement_action = engagement.add_subparsers(dest="action")
    create = engagement_action.add_parser("create")
    create.add_argument("--id", required=True)
    create.add_argument("--customer", required=True)
    create.add_argument("--scope", required=True)
    create.add_argument("--start", required=True)
    create.add_argument("--end")
    create.add_argument("--consultant", action="append", required=True)
    create.add_argument("--reference")
    create.add_argument("--authorized", action="store_true")
    create.add_argument("--engagements-root")
    close = engagement_action.add_parser("close")
    close.add_argument("--id", required=True)
    close.add_argument("--actor", required=True)
    close.add_argument("--end")
    close.add_argument("--engagements-root")
    show = engagement_action.add_parser("show")
    show.add_argument("--id", required=True)
    show.add_argument("--engagements-root")

    attest_cmd = sub.add_parser("attest")
    attest_cmd.add_argument("--engagement", required=True)
    attest_cmd.add_argument("--actor", required=True)
    attest_cmd.add_argument("--reference", required=True)
    attest_cmd.add_argument("--scope", required=True)
    attest_cmd.add_argument("--timestamp")
    attest_cmd.add_argument("--engagements-root")

    intake = sub.add_parser("intake")
    intake.add_argument("--engagement", required=True)
    intake.add_argument("--path", required=True)
    intake.add_argument("--include-tests", action="store_true")
    intake.add_argument("--replace", action="store_true")
    intake.add_argument("--engagements-root")

    investigate = sub.add_parser("investigate")
    investigate.add_argument("--engagement", required=True)
    investigate.add_argument("--cwe", required=True)
    investigate.add_argument("--actor", required=True)
    investigate.add_argument("--advisory-id")
    investigate.add_argument("--advisory-text")
    investigate.add_argument("--exploratory", action="store_true")
    investigate.add_argument("--engagements-root")
    investigate.add_argument("--advisory-cache")

    rerun = sub.add_parser("rerun")
    rerun.add_argument("--engagement", required=True)
    rerun.add_argument("--investigation", required=True)
    rerun.add_argument("--actor", required=True)
    rerun.add_argument("--engagements-root")

    verdict = sub.add_parser("verdict")
    verdict.add_argument("--engagement", required=True)
    verdict.add_argument("--path", required=True)
    verdict.add_argument("--cwe", required=True)
    verdict.add_argument("--state", required=True)
    verdict.add_argument("--actor", required=True)
    verdict.add_argument("--note", required=True)
    verdict.add_argument("--confirm-advisory", action="store_true")
    verdict.add_argument("--engagements-root")

    coverage = sub.add_parser("coverage")
    coverage.add_argument("--engagement", required=True)
    coverage.add_argument("--engagements-root")

    export_cmd = sub.add_parser("export")
    export_cmd.add_argument("--engagement", required=True)
    export_cmd.add_argument("--output", required=True)
    export_cmd.add_argument("--actor", required=True)
    export_cmd.add_argument("--allow-draft", action="store_true")
    export_cmd.add_argument("--report-only", action="store_true")
    export_cmd.add_argument("--engagements-root")

    purge = sub.add_parser("purge")
    purge.add_argument("--engagement", required=True)
    purge.add_argument("--actor", required=True)
    purge.add_argument("--confirm-exports-handled", action="store_true")
    purge.add_argument("--engagements-root")

    advisories = sub.add_parser("advisories")
    advisories_action = advisories.add_subparsers(dest="action")
    sync = advisories_action.add_parser("sync")
    sync.add_argument("--engagement")
    sync.add_argument("--id", action="append")
    sync.add_argument("--from-file")
    sync.add_argument("--actor", required=True)
    sync.add_argument("--cache")
    sync.add_argument("--engagements-root")
    import_cmd = advisories_action.add_parser("import")
    import_cmd.add_argument("directory")
    import_cmd.add_argument("--cache")

    report = sub.add_parser("report")
    report_action = report.add_subparsers(dest="action")
    assessment = report_action.add_parser("assessment")
    assessment.add_argument("--engagement", required=True)
    assessment.add_argument("--actor", required=True)
    assessment.add_argument("--include-unreviewed", action="store_true")
    assessment.add_argument("--html")
    assessment.add_argument("--pdf")
    assessment.add_argument("--engagements-root")
    remediation = report_action.add_parser("remediation")
    remediation.add_argument("--engagement", required=True)
    remediation.add_argument("--actor", required=True)
    remediation.add_argument("--markdown")
    remediation.add_argument("--json")
    remediation.add_argument("--engagements-root")
    finalize = report_action.add_parser("finalize")
    finalize.add_argument("--engagement", required=True)
    finalize.add_argument("--actor", required=True)
    finalize.add_argument("--engagements-root")

    if not argv:
        parser.print_help(sys.stderr)
        return 2
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except EngagementError as exc:
        print(str(exc), file=sys.stderr)
        return 2


def _require_consultant(root: Path, engagement_id: str, actor: str) -> str:
    """Same membership rule as the UI: the name must be on the engagement's consultant list."""
    record = load_engagement(root, engagement_id)
    allowed = [str(person).strip() for person in (record.get("consultants") or []) if str(person).strip()]
    name = actor.strip()
    if name not in allowed:
        raise EngagementError(f"Actor {name} is not a consultant on {engagement_id}.")
    return name


def _dispatch(args: argparse.Namespace) -> int:
    root = engagements_root(Path(args.engagements_root) if getattr(args, "engagements_root", None) else None)
    if args.command == "engagement" and args.action == "create":
        record = create_engagement(
            root,
            engagement_id=args.id,
            customer=args.customer,
            scope=args.scope,
            start_date=args.start,
            end_date=args.end,
            consultants=args.consultant,
            reference=args.reference,
            authorized=bool(args.authorized),
        )
        failed = bool(record.pop("attestation_failed", False))
        print(json.dumps(record, indent=2))
        attested = bool(args.reference and str(args.reference).strip() and args.authorized) and not failed
        if not attested:
            print("Attestation required: run astrolabe attest.")
        return 0
    if args.command == "engagement" and args.action == "close":
        actor = _require_consultant(root, args.id, args.actor)
        record = close_engagement(root, args.id, actor=actor, end_date=args.end)
        print(json.dumps(record, indent=2))
        return 0
    if args.command == "engagement" and args.action == "show":
        print(json.dumps(load_engagement(root, args.id), indent=2))
        return 0
    if args.command == "attest":
        actor = _require_consultant(root, args.engagement, args.actor)
        event = attest(
            root,
            args.engagement,
            actor=actor,
            reference=args.reference,
            scope=args.scope,
            attested_at=args.timestamp,
        )
        print(json.dumps(event, indent=2))
        return 0
    if args.command == "intake":
        record = intake_local(
            root,
            args.engagement,
            Path(args.path),
            include_test_paths=args.include_tests,
            replace=args.replace,
        )
        print(json.dumps(record["intake"], indent=2))
        return 0
    if args.command == "investigate":
        cache = Path(args.advisory_cache) if args.advisory_cache else None
        actor = _require_consultant(root, args.engagement, args.actor)
        investigation = start_investigation(
            root,
            args.engagement,
            cwe=args.cwe,
            actor=actor,
            advisory_id=args.advisory_id,
            advisory_text=args.advisory_text,
            exploratory=args.exploratory,
            cache=cache,
        )
        print(consultant_line(investigation))
        return 0
    if args.command == "rerun":
        actor = _require_consultant(root, args.engagement, args.actor)
        investigation = rerun_investigation(
            root,
            args.engagement,
            args.investigation,
            actor=actor,
        )
        print(consultant_line(investigation))
        return 0
    if args.command == "verdict":
        actor = _require_consultant(root, args.engagement, args.actor)
        candidate = set_verdict(
            root,
            args.engagement,
            file_path=args.path,
            cwe=args.cwe,
            state=args.state,
            actor=actor,
            note=args.note,
            confirmed=bool(args.confirm_advisory),
        )
        rebuild_coverage(root, args.engagement)
        print(json.dumps({"state": candidate["state"], "fingerprint": candidate["fingerprint"]}))
        return 0
    if args.command == "coverage":
        print(json.dumps(load_coverage(root, args.engagement), indent=2))
        return 0
    if args.command == "export":
        actor = _require_consultant(root, args.engagement, args.actor)
        path = export_engagement(
            root,
            args.engagement,
            Path(args.output),
            actor=actor,
            allow_draft=args.allow_draft,
            report_only=args.report_only,
        )
        print(path)
        return 0
    if args.command == "purge":
        actor = _require_consultant(root, args.engagement, args.actor)
        entry = purge_engagement(
            root,
            args.engagement,
            actor=actor,
            confirm_exports_handled=args.confirm_exports_handled,
        )
        print(json.dumps(entry))
        return 0
    if args.command == "advisories" and args.action == "sync":
        ids = list(args.id or [])
        if args.from_file:
            ids.extend(load_id_list(Path(args.from_file)))
        cache = Path(args.cache) if args.cache else None
        if args.engagement:
            if not (engagement_dir(root, args.engagement) / "engagement.json").is_file():
                raise EngagementError(f"Engagement {args.engagement} not found.")
            actor = _require_consultant(root, args.engagement, args.actor)
            sync_advisories(root, actor=actor, ids=ids, cache=cache, engagement_id=args.engagement)
        else:
            sync_advisories(root, actor=args.actor, ids=ids, cache=cache, cache_level=True)
        return 0
    if args.command == "advisories" and args.action == "import":
        cache = Path(args.cache) if args.cache else None
        imported = import_advisories(Path(args.directory), cache=cache)
        print(json.dumps(imported))
        return 0
    if args.command == "report" and args.action == "assessment":
        actor = _require_consultant(root, args.engagement, args.actor)
        paths = write_assessment(
            root,
            args.engagement,
            actor=actor,
            include_unreviewed=args.include_unreviewed,
            html_path=Path(args.html) if args.html else None,
            pdf_path=Path(args.pdf) if args.pdf else None,
        )
        print(json.dumps({key: str(value) for key, value in paths.items()}))
        return 0
    if args.command == "report" and args.action == "finalize":
        actor = _require_consultant(root, args.engagement, args.actor)
        result = finalize_assessment(root, args.engagement, actor=actor)
        print(json.dumps(result))
        return 0
    if args.command == "report" and args.action == "remediation":
        actor = _require_consultant(root, args.engagement, args.actor)
        paths = write_remediation(
            root,
            args.engagement,
            actor=actor,
            markdown_path=Path(args.markdown) if args.markdown else None,
            json_path=Path(args.json) if args.json else None,
        )
        print(json.dumps({key: str(value) for key, value in paths.items()}))
        return 0
    print("unknown command", file=sys.stderr)
    return 2
