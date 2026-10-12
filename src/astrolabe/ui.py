"""Loopback web UI. It calls the engagement commands and adds no rules of its own."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import subprocess
import tempfile
import threading
import urllib.parse
import uuid
from datetime import date
from contextvars import ContextVar
from importlib.resources import files
from contextlib import contextmanager
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from subprocess import CompletedProcess

from astrolabe.advisories import (
    NETWORK_NOTICE,
    ADVISORY_ID_PATTERN,
    advisory_cache_dir,
    import_advisory_path,
    sync_advisories,
)
from astrolabe.advisory_review import (
    COMPARE_LABEL,
    NOTE_HINT,
    REVIEW_MATCH_NOTE,
    AdvisoryContext,
    advisory_contexts,
    normalize_repo_path,
)
from astrolabe.candidates import VerdictError, list_candidates, set_verdict
from astrolabe.coverage import RERUN_NOTE, load_coverage
from astrolabe import cwe_catalog
from astrolabe.cwe import (
    base_variant_children,
    cwe_abstraction,
    cwe_name,
    displayed_mitigations,
    is_broad_cwe,
    search_cwes,
)
from astrolabe.engagement import (
    EngagementError,
    FieldError,
    attest,
    create_engagement,
    engagement_dir,
    engagements_root,
    has_attestation,
    index_attestation_recorded,
    load_engagement,
    load_engagement_readonly,
    read_audit,
    read_instance_attestation,
    validate_new_engagement,
)
from astrolabe.environment import Check, cached_checks, check_location, run_checks, status_label
from astrolabe.intake import (
    confirm_preview,
    load_pending,
    reintake,
    stage_archive_preview,
    stage_clone_preview,
    stage_folder_preview,
    stage_path_preview,
    stage_single_preview,
)
from astrolabe.snapshot import DEFAULT_MAX_BYTES, snapshot_preview
from astrolabe.investigate import rerun_investigation, start_investigation
from astrolabe.runner import cancel_event
from astrolabe.plan_store import (
    clear_pasted_advisory,
    load_pasted_advisory,
    load_plan,
    save_pasted_advisory,
    save_plan,
)
from astrolabe.selection import (
    CLASS_NOTE,
    EXPLORATORY_NOTE,
    INTAKE_BUSY,
    INTAKE_REQUIRED,
    LAUNCH_BUSY,
    LAUNCH_CAP,
    PLAN_EMPTY,
    PLAN_EXCLUSION_NOTE,
    PLAN_STALE,
    REVIEW_LOAD_NOTE,
    SINGLE_FILE_NOTE,
    _PATH_TOKEN,
    confirmation_text,
    estimate_seconds,
    format_estimate,
    load_advisory,
    per_check_estimate_seconds,
    status_estimate_text,
    plan_rows,
    plan_snapshot,
    preselect_limit,
    selection_source_for,
    short_sha,
)
from astrolabe.purge import (
    close_engagement,
    default_export_destination,
    export_access_warning,
    export_engagement,
    exports_still_on_disk,
    purge_engagement,
)
from astrolabe.activity import (
    counter_line,
    fetch_generation,
    load_activity,
    model_server_line,
    progress_detail,
)
from astrolabe.redact import MITRE_LIKELIHOOD_LABEL, find_secret_matches, read_report, read_trace
from astrolabe.search_hits import (
    line_hits,
    model_title,
    read_snapshot_lines,
    resolve_inside,
    resolve_trace,
    trace_export_document,
)
from astrolabe.reports import (
    _read_status,
    assessment_is_draft,
    finalize_assessment,
    write_assessment,
    write_remediation,
)

logger = logging.getLogger("astrolabe.ui")

LOOPBACK = "127.0.0.1"
UPLOAD_MAX_BYTES = DEFAULT_MAX_BYTES
Runner = Callable[[Path, list[str]], CompletedProcess[str]]
GitRun = Callable[[list[str]], CompletedProcess[str]]
SCAN_GATE = "Scans stay off until an authorization attestation is recorded."
CLONE_NOTICE = "This clone contacts the git host."
REVIEW_VERDICTS = ("confirmed", "not_actionable", "needs_more_info")
AUTH_NOT_RECORDED = "Authorization was not recorded. Record it below."
ACTING_COOKIE = "astrolabe_acting_as"
PLAN_ORDER = ("advisory", "recommended", "top25", "owasp", "search")
PLAN_LABEL = {
    "advisory": "Advisory",
    "recommended": "Recommended",
    "top25": "Top 25",
    "owasp": "OWASP",
    "search": "Search",
}
PLAN_INTRO = {
    "advisory": "Advisory checks use the CWEs named by a cached advisory.",
    "recommended": "Recommended checks are ranked by evidence found in this snapshot.",
    "top25": "Top 25 checks are the MITRE CWE Top 25, ranked by evidence found in this snapshot.",
    "owasp": "OWASP checks are one list, OWASP Top Ten 2025 RC1 (CWE-1450).",
    "search": "Search chooses CWEs from the local catalog.",
}


class UploadLimit(Exception):
    """The request body passed the snapshot byte cap while it was being read."""
_SECURITY_HEADERS = (
    ("Content-Security-Policy", "script-src 'self'; style-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
)


class Form:
    def __init__(self) -> None:
        self.fields: dict[str, str] = {}
        self.lists: dict[str, list[str]] = {}
        self.filename: str | None = None
        self.file_bytes: bytes | None = None
        self.files: list[tuple[str, str, bytes]] = []

    def get(self, name: str) -> str:
        return self.fields.get(name, "").strip()

    def raw(self, name: str) -> str:
        return self.fields.get(name, "")

    def values(self, name: str) -> list[str]:
        return [item.strip() for item in self.lists.get(name, []) if item.strip()]

    def checked(self, name: str) -> bool:
        return self.fields.get(name, "") in {"on", "true", "1"}


def _consultants(record: dict[str, object]) -> list[str]:
    return [str(person).strip() for person in (record.get("consultants") or []) if str(person).strip()]


def _cookie_consultant(record: dict[str, object], headers: object | None) -> str:
    """Acting-as is a preference. A bad cookie is ignored and never returned."""
    if headers is None:
        return ""
    raw = str(getattr(headers, "get")("Cookie", "") or "")
    allowed = _consultants(record)
    instance_id = str(record.get("instance_id") or "")
    for part in raw.split(";"):
        name, separator, value = part.strip().partition("=")
        if not separator or name != ACTING_COOKIE:
            continue
        left, dot, right = value.partition(".")
        if not dot:
            return ""
        cookie_instance = urllib.parse.unquote(left)
        cookie_name = urllib.parse.unquote(right).strip()
        if cookie_instance == instance_id and cookie_name in allowed:
            return cookie_name
        return ""
    return ""


def resolve_actor(record: dict[str, object], form: Form | None, headers: object | None) -> str:
    """Posted name, then a matching acting-as cookie, then the first consultant."""
    allowed = _consultants(record)
    if not allowed:
        raise EngagementError("This engagement has no consultants")
    posted = form.raw("actor").strip() if form is not None else ""
    if posted:
        if posted not in allowed:
            raise EngagementError(f"{posted} is not a consultant on this engagement")
        return posted
    cookie = _cookie_consultant(record, headers)
    if cookie:
        return cookie
    return allowed[0]


def _acting_cookie(engagement_id: str, instance_id: str, consultant: str) -> str:
    value = urllib.parse.quote(instance_id, safe="") + "." + urllib.parse.quote(consultant, safe="")
    return f"{ACTING_COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/e/{engagement_id}"


class App:
    def __init__(self, root: Path, runner: Runner | None = None, git: GitRun | None = None) -> None:
        self.root = root
        self.runner = runner
        self.git = git
        self._lock = threading.Lock()
        self._running: set[str] = set()
        self._launching: set[str] = set()
        self._intake_busy: set[str] = set()
        self._item_events: dict[str, threading.Event] = {}
        self._message: dict[str, str] = {}
        self._auth_warning: set[str] = set()

    def serve(self, port: int = 8765, host: str = LOOPBACK) -> ThreadingHTTPServer:
        if host != LOOPBACK:
            raise EngagementError("The UI listens on 127.0.0.1 only")
        self.root.mkdir(parents=True, exist_ok=True)
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._respond()

            def do_POST(self) -> None:
                self._respond()

            def _respond(self) -> None:
                client = self.client_address[0]
                if client not in {LOOPBACK, "::1"}:
                    self._send(403, b"Refused\n", "text/plain; charset=utf-8")
                    return
                host = str(self.headers.get("Host", ""))
                port = int(self.server.server_address[1])
                if not _host_allowed(host, port):
                    self._send(403, b"Refused\n", "text/plain; charset=utf-8")
                    return
                if self.command == "POST" and not _origin_allowed(self.headers, host.strip()):
                    self._send(403, b"Refused\n", "text/plain; charset=utf-8")
                    return
                if self.command == "POST" and _declared_length_over_cap(self.headers):
                    self._send(413, b"Upload exceeds the size cap\n", "text/plain; charset=utf-8")
                    return
                try:
                    result = app.dispatch(self.command, self.path, self.headers, self.rfile)
                except UploadLimit:
                    self._send(413, b"Upload exceeds the size cap\n", "text/plain; charset=utf-8")
                    return
                extra: dict[str, str] = {}
                if len(result) == 4:
                    status, body, content_type, extra = result
                else:
                    status, body, content_type = result
                payload = body if isinstance(body, bytes) else body.encode("utf-8")
                self._send(status, payload, content_type, extra)

            def _send(
                self,
                status: int,
                payload: bytes,
                content_type: str,
                extra: dict[str, str] | None = None,
            ) -> None:
                self.send_response(status)
                for name, value in (extra or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                overridden = {name.lower() for name in (extra or {})}
                for name, value in _SECURITY_HEADERS:
                    if name.lower() not in overridden:
                        self.send_header(name, value)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        return ThreadingHTTPServer((host, port), Handler)

    def dispatch(
        self,
        method: str,
        url: str,
        headers: object,
        body_stream: object,
    ) -> tuple[int, str | bytes, str]:
        parsed = urllib.parse.urlsplit(url)
        parts = [item for item in parsed.path.split("/") if item]
        form = Form()
        if method == "POST":
            raw = _read_request_body(body_stream, headers)
            content_type = str(getattr(headers, "get")("Content-Type", ""))
            form = _parse_body(raw, content_type)
        token = _request_root.set(self.root)
        header_token = _request_headers.set(headers)
        query_token = _request_query.set(urllib.parse.parse_qs(parsed.query))
        try:
            return self.route(method, parts, form)
        except EngagementError as exc:
            target = parts[1] if len(parts) > 1 and parts[0] == "e" else ""
            if target:
                verdict = exc if isinstance(exc, VerdictError) else None
                return (
                    400,
                    self.engagement_page(target, error=str(exc), verdict=verdict),
                    "text/html; charset=utf-8",
                )
            if method == "POST" and not parts:
                errors = exc.errors if isinstance(exc, FieldError) else None
                return (
                    400,
                    self.new_page(error="" if errors else str(exc), errors=errors, values=form),
                    "text/html; charset=utf-8",
                )
            return 400, self.index_page(error=str(exc)), "text/html; charset=utf-8"
        except Exception:
            logger.exception("Unhandled UI error")
            return 500, _server_error_page(), "text/html; charset=utf-8"
        except SystemExit as exc:
            logger.error("UI request stopped: %s", exc)
            return 500, _server_error_page(), "text/html; charset=utf-8"
        finally:
            _request_query.reset(query_token)
            _request_headers.reset(header_token)
            _request_root.reset(token)

    def route(self, method: str, parts: list[str], form: Form) -> tuple[int, str | bytes, str]:
        if not parts:
            if method == "POST":
                record = self._create(form)
                location = f"/e/{record['id']}"
                body = _layout("Engagement", f"<p><a href=\"{_esc(location)}\">Continue</a></p>")
                return 303, body, "text/html; charset=utf-8", {"Location": location}
            return 200, self.index_page(), "text/html; charset=utf-8"
        if parts == ["astrolabe.css"]:
            return 200, _stylesheet(), "text/css; charset=utf-8"
        if parts == ["astrolabe.png"]:
            return 200, _logo(), "image/png"
        if parts == ["astrolabe.js"]:
            return 200, _SCRIPT, "text/javascript; charset=utf-8"
        if parts == ["new"]:
            return 200, self.new_page(), "text/html; charset=utf-8"
        if parts == ["about"] and method == "GET":
            return 200, _about_page(), "text/html; charset=utf-8"
        if parts == ["environment"] and method == "GET":
            checks = run_checks(self.root)
            return 200, _environment_page(self.root, checks), "text/html; charset=utf-8"
        if parts == ["browse"] and method == "POST":
            try:
                chosen = choose_local_path(form.get("kind"))
            except EngagementError as exc:
                return 400, json.dumps({"path": "", "error": str(exc)}), "application/json; charset=utf-8"
            return 200, json.dumps({"path": chosen}), "application/json; charset=utf-8"
        if parts[0] == "cwe" and method == "GET":
            if parts == ["cwe"]:
                return 200, _cwe_index(), "text/html; charset=utf-8"
            if len(parts) == 2:
                return _cwe_entry_response(parts[1])
            return 404, _layout("Not found", "<p>That page is not part of an engagement.</p>"), "text/html; charset=utf-8"
        if parts == ["environment", "recheck"] and method == "POST":
            run_checks(self.root, force=True)
            location = _safe_next(form.get("next"))
            body = _layout("Engagements", f"<p><a href=\"{_esc(location)}\">Continue</a></p>")
            return 303, body, "text/html; charset=utf-8", {"Location": location}
        if len(parts) >= 2 and parts[0] == "e":
            engagement_id = parts[1]
            tail = parts[2:]
            if method == "GET" and tail == ["report"]:
                return 200, self.report_page(engagement_id), "text/html; charset=utf-8"
            if method == "GET" and tail == ["preview", "assessment"]:
                return self._preview(engagement_id, "assessment.html", "text/html; charset=utf-8")
            if method == "GET" and tail == ["preview", "assessment.pdf"]:
                return self._preview(engagement_id, "assessment.pdf", "application/pdf")
            if method == "GET" and len(tail) == 4 and tail[0] == "runs" and tail[3] in {"trace", "trace.jsonl"}:
                return self._show_trace(
                    engagement_id,
                    tail[1],
                    tail[2],
                    download=tail[3] == "trace.jsonl",
                )
            if method == "POST" and tail == ["acting-as"]:
                return self._acting_as(engagement_id, form)
            if method == "GET" and len(tail) == 2 and tail[0] == "plan":
                status, body = self._show_plan(engagement_id, tail[1])
                return status, body, "text/html; charset=utf-8"
            if method == "POST" and tail == ["select", "advisory"]:
                return self._post_advisory(engagement_id, form)
            if method == "POST" and tail == ["select", "explore"]:
                return self._post_explore(engagement_id, form)
            if method == "POST" and tail in (["launch"], ["investigate"]):
                return self._post_launch(engagement_id, form)
            if method == "POST" and tail:
                override = self._post(engagement_id, tail, form)
                if override is not None:
                    return 200, override, "text/html; charset=utf-8"
            return 200, self.engagement_page(engagement_id), "text/html; charset=utf-8"
        return 404, _layout("Not found", "<p>That page is not part of an engagement.</p>"), "text/html; charset=utf-8"

    def index_page(self, error: str = "") -> str:
        body = f"{_error(error)}{_engagements_card(_index_rows(self.root))}"
        return _layout("Engagements", body)

    def new_page(
        self,
        error: str = "",
        values: Form | None = None,
        errors: dict[str, str] | None = None,
    ) -> str:
        submitted = values is not None
        form = values or Form()
        field_errors = dict(errors or {})
        if error and "id" not in field_errors:
            field_errors["id"] = error
        start = form.raw("start") if submitted else date.today().isoformat()
        consultants = form.raw("consultants") if submitted else getpass.getuser()
        warning = _readiness_warning(cached_checks(self.root))
        fields = (
            _new_field("customer", form.raw("customer"), field_errors.get("customer", ""))
            + _new_field("id", form.raw("id"), field_errors.get("id", ""))
            + _new_field("scope", form.raw("scope"), field_errors.get("scope", ""))
            + _new_field("reference", form.raw("reference"), field_errors.get("reference", ""))
            + _authorization_box(form.checked("authorized"), field_errors.get("authorized", ""))
            + '<div class="form-row">'
            + _new_field("start", start, field_errors.get("start", ""))
            + _new_field("end", form.raw("end"), field_errors.get("end", ""), start=start)
            + "</div>"
            + _new_field("consultants", consultants, field_errors.get("consultants", ""))
        )
        body = (
            '<section class="card form-card"><div class="card-body">'
            "<h1>New engagement</h1>"
            '<p class="prose">Creates a local workspace. Authorization is recorded on this form. '
            "Checks stay off until it is stored.</p>"
            f"{warning}"
            '<form id="new-engagement" method="post" action="/">'
            f"{_form_errors(field_errors)}"
            '<p class="env-hint">* Required</p>'
            f"{fields}"
            '<p><a href="/">Cancel</a> '
            '<button class="primary" type="submit">Create engagement</button></p>'
            "</form></div></section>"
        )
        return _layout("New engagement", body)

    def engagement_page(
        self,
        engagement_id: str,
        error: str = "",
        verdict: VerdictError | None = None,
    ) -> str:
        record = load_engagement(self.root, engagement_id)
        attested = has_attestation(self.root, engagement_id)
        active = engagement_id in self._running or _queue_is_running(self.root, engagement_id)
        running = active or _queue_has_work(self.root, engagement_id)
        message = self._message.pop(engagement_id, "")
        with self._lock:
            warn = engagement_id in self._auth_warning
            self._auth_warning.discard(engagement_id)
        actor = resolve_actor(record, None, _request_headers.get())
        current, sentence = self._next_step(record, attested)
        requested = _requested_step()
        opened = {current}
        if requested in {"code", "advisory", "investigate", "review", "report", "close"}:
            opened.add(requested)
        if running:
            opened.add("investigate")
        if verdict is not None:
            opened.add("review")
        warning = (
            f'<p class="error" id="authorization-missing">{_esc(AUTH_NOT_RECORDED)}</p>' if warn else ""
        )
        sections = [
            _error(error),
            _note(message),
            self._engagement_header(record),
            f'<p id="next-step" class="notice">{_esc(sentence)}</p>',
            warning,
            self._authorize_section(record, attested),
            self._code_section(record, opened="code" in opened),
            self._preview_section(engagement_id),
            self._advisory_section(engagement_id, opened="advisory" in opened),
            self._investigation_section(engagement_id, attested, opened="investigate" in opened),
            self._review_section(engagement_id, opened="review" in opened, verdict=verdict),
            self._report_section(engagement_id, record, actor, opened="report" in opened),
            self._close_section(engagement_id, record, opened="close" in opened),
        ]
        return _layout(
            str(record["id"]),
            "\n".join(sections),
            refresh=active,
            record=record,
            actor=actor,
        )

    def _next_step(self, record: dict[str, object], attested: bool) -> tuple[str, str]:
        engagement_id = str(record["id"])
        if not attested:
            return "authorize", "Next: record authorization."
        if record.get("state") == "closed":
            return "close", "Next: purge the customer's code."
        if not record.get("snapshot_sha256"):
            return "code", "Next: add the customer's code."
        candidates = list_candidates(self.root, engagement_id)
        if any(item.get("presentation_state") == "candidate" for item in candidates):
            return "review", "Next: review the candidates."
        investigations = _investigations(self.root, engagement_id)
        if not investigations and not candidates:
            return "investigate", "Next: run a check."
        directory = engagement_dir(self.root, engagement_id)
        final = (directory / "reports" / "assessment.html").is_file() and not assessment_is_draft(directory)
        if not final:
            return "report", "Next: generate the report."
        return "close", "Next: close the engagement."

    def _engagement_header(self, record: dict[str, object]) -> str:
        state = str(record.get("state") or "")
        kind = "healthy" if state == "closed" else "accent"
        label = record.get("label")
        label_line = f'<p class="prose">{_esc(label)}</p>' if label else ""
        return (
            '<header class="engagement-header">'
            f'<h1><span class="mono">{_esc(record.get("id"))}</span> {_esc(record.get("customer"))}</h1>'
            f"{_pill(state, kind)}</header>{label_line}"
        )

    def _actor(self, engagement_id: str, form: Form) -> str:
        record = load_engagement(self.root, engagement_id)
        return resolve_actor(record, form, _request_headers.get())

    def _acting_as(self, engagement_id: str, form: Form) -> tuple[int, str, str, dict[str, str]]:
        record = load_engagement(self.root, engagement_id)
        name = form.raw("consultant").strip()
        if name not in _consultants(record):
            raise EngagementError(f"{name} is not a consultant on this engagement")
        cookie = _acting_cookie(engagement_id, str(record.get("instance_id") or ""), name)
        location = f"/e/{engagement_id}"
        body = _layout("Engagement", f'<p><a href="{_esc(location)}">Continue</a></p>', record=record, actor=name)
        return 303, body, "text/html; charset=utf-8", {"Location": location, "Set-Cookie": cookie}

    def _create(self, form: Form) -> dict[str, object]:
        consultants = [part.strip() for part in form.raw("consultants").split(",") if part.strip()]
        end = form.raw("end")
        reference = form.raw("reference")
        errors = validate_new_engagement(
            self.root,
            engagement_id=form.raw("id"),
            customer=form.raw("customer"),
            scope=form.raw("scope"),
            start_date=form.raw("start"),
            end_date=end,
            consultants=consultants,
        )
        if not reference.strip():
            errors["reference"] = "Authorization reference is required."
        elif len(reference.strip()) > 200:
            errors["reference"] = "Authorization reference must be at most 200 characters."
        if not form.checked("authorized"):
            errors["authorized"] = "Confirm the customer's written authorization covers this scope."
        if errors:
            raise FieldError(errors)
        record = create_engagement(
            self.root,
            engagement_id=form.raw("id"),
            customer=form.raw("customer"),
            scope=form.raw("scope"),
            start_date=form.raw("start"),
            consultants=consultants,
            end_date=end if end.strip() else None,
            reference=reference,
            authorized=True,
        )
        if record.get("attestation_failed"):
            with self._lock:
                self._auth_warning.add(str(record["id"]))
        return record

    def _post(self, engagement_id: str, tail: list[str], form: Form) -> str | None:
        action = "/".join(tail)
        if action == "attest":
            if not has_attestation(self.root, engagement_id) and not form.checked("authorized"):
                raise EngagementError("Confirm the customer's written authorization covers this scope.")
            attest(
                self.root,
                engagement_id,
                actor=self._actor(engagement_id, form),
                reference=form.get("reference"),
                scope=form.get("scope"),
            )
            self._message[engagement_id] = "Attestation recorded."
            return
        if action in {"intake", "intake/preview"}:
            with self._hold_intake(engagement_id):
                self._stage_intake(engagement_id, form)
            return
        if action == "intake/confirm":
            record = confirm_preview(self.root, engagement_id)
            intake = record.get("intake") if isinstance(record.get("intake"), dict) else {}
            prefix = intake.get("stripped_prefix") if isinstance(intake, dict) else None
            self._message[engagement_id] = (
                f"Snapshot SHA-256 {record.get('snapshot_sha256')}. Stripped prefix: {prefix or 'none'}."
            )
            return
        if action == "intake/again":
            source_index = form.get("source")
            with self._hold_intake(engagement_id):
                record = reintake(
                    self.root,
                    engagement_id,
                    actor=self._actor(engagement_id, form),
                    run=self.git,
                    index=int(source_index) if source_index.isdigit() else None,
                )
            intake = record.get("intake") if isinstance(record.get("intake"), dict) else {}
            prefix = intake.get("stripped_prefix") if isinstance(intake, dict) else None
            self._message[engagement_id] = (
                f"Snapshot SHA-256 {record.get('snapshot_sha256')}. Stripped prefix: {prefix or 'none'}."
            )
            return
        if action == "advisories/sync":
            self._sync(engagement_id, form)
            return
        if action == "advisories/import":
            imported = import_advisory_path(Path(form.get("directory")).expanduser())
            self._message[engagement_id] = "Imported " + ", ".join(imported)
            return
        if action == "review":
            return self._review_launch(engagement_id, form)
        if action == "cancel":
            self._cancel(engagement_id, form)
            return
        if action == "start":
            self._start(engagement_id, form)
            return
        if action == "rerun":
            self._rerun(engagement_id, form)
            return
        if action == "verdict":
            set_verdict(
                self.root,
                engagement_id,
                file_path=form.get("path"),
                cwe=form.get("cwe"),
                state=form.get("state"),
                actor=self._actor(engagement_id, form),
                note=form.raw("note"),
                confirmed=form.checked("advisory_compared"),
            )
            self._message[engagement_id] = "Verdict recorded."
            return
        if action == "reports/assessment":
            write_assessment(self.root, engagement_id, actor=self._actor(engagement_id, form))
            self._message[engagement_id] = "Assessment draft written."
            return
        if action == "reports/remediation":
            write_remediation(self.root, engagement_id, actor=self._actor(engagement_id, form))
            self._message[engagement_id] = "Remediation handoff written."
            return
        if action == "reports/generate":
            actor = self._actor(engagement_id, form)
            write_assessment(self.root, engagement_id, actor=actor)
            try:
                write_remediation(self.root, engagement_id, actor=actor)
            except EngagementError as exc:
                self._message[engagement_id] = f"The assessment was written. The handoff failed: {exc}"
                return
            self._message[engagement_id] = "Assessment and remediation handoff written."
            return
        if action == "reports/finalize":
            actor = self._actor(engagement_id, form)
            result = finalize_assessment(self.root, engagement_id, actor=actor)
            self._message[engagement_id] = f"Final. Approved by {actor} at {result['finalized_at']}."
            return
        if action == "export":
            actor = self._actor(engagement_id, form)
            bundle = form.raw("bundle").strip()
            if bundle == "full":
                report_only = False
            elif bundle == "report":
                report_only = True
            else:
                report_only = form.checked("report_only")
            output = form.raw("output").strip()
            report_default = default_export_destination(engagement_id, report_only=True)
            full_default = default_export_destination(engagement_id, report_only=False)
            if not output:
                destination = report_default if report_only else full_default
            else:
                destination = Path(output).expanduser()
                if not report_only and destination == report_default:
                    destination = full_default
            path = export_engagement(
                self.root,
                engagement_id,
                destination,
                actor=actor,
                allow_draft=form.checked("allow_draft"),
                report_only=report_only,
            )
            self._message[engagement_id] = f"Exported {path}"
            return
        if action == "close":
            close_engagement(self.root, engagement_id, actor=self._actor(engagement_id, form))
            self._message[engagement_id] = "Engagement closed."
            return
        if action == "purge":
            actor = self._actor(engagement_id, form)
            entry = purge_engagement(
                self.root,
                engagement_id,
                actor=actor,
                confirm_exports_handled=form.checked("confirm_exports_handled"),
            )
            kept = entry.get("exports_still_present") or []
            kept_text = ", ".join(str(item) for item in kept) if isinstance(kept, list) else "none"
            return _layout(
                "Purged",
                "<h1>Purged</h1>"
                f"<p>Files removed: {_esc(entry.get('files_removed'))}.</p>"
                f"<p>Exports still present: {_esc(kept_text or 'none')}.</p>"
                "<p><a href=\"/\">Engagements</a></p>",
            )
        raise EngagementError("Unknown action")

    def _stage_intake(self, engagement_id: str, form: Form) -> None:
        include_tests = form.checked("include_tests")
        replace = form.checked("replace")
        folder = [(name, data) for field, name, data in form.files if field == "files"]
        archive = next(((name, data) for field, name, data in form.files if field == "archive"), None)
        script_file = next(((name, data) for field, name, data in form.files if field == "script_file"), None)
        selected = [
            name
            for name, present in (
                ("path", bool(form.get("path"))),
                ("archive", archive is not None),
                ("folder", bool(folder)),
                ("clone", bool(form.get("url"))),
                ("file-path", bool(form.get("file_path"))),
                ("single-file", script_file is not None or bool(form.get("script")) or bool(form.get("filename"))),
            )
            if present
        ]
        chosen = form.get("intake_source")
        if chosen == "git":
            selected = ["clone"]
        elif chosen == "archive":
            selected = ["archive"]
        elif chosen == "file":
            selected = ["file-path"]
        elif chosen == "script":
            selected = ["script"]
        elif chosen == "folder":
            if bool(folder) == bool(form.get("path")):
                raise EngagementError("Choose one intake option")
            selected = ["folder"] if folder else ["path"]
        if len(selected) != 1:
            raise EngagementError("Choose one intake option")
        if selected[0] == "clone" and engagement_id in self._running:
            raise EngagementError("Clone is refused while an investigation is running")
        if selected[0] == "path":
            stage_path_preview(
                self.root,
                engagement_id,
                Path(form.get("path")),
                include_test_paths=include_tests,
                replace=replace,
            )
        elif selected[0] == "archive":
            if archive is None:
                raise EngagementError("Choose an archive")
            filename, payload = archive
            temporary = _temporary_archive(filename, payload)
            try:
                stage_archive_preview(
                    self.root,
                    engagement_id,
                    temporary,
                    include_test_paths=include_tests,
                    replace=replace,
                )
            finally:
                temporary.unlink(missing_ok=True)
        elif selected[0] == "folder":
            stage_folder_preview(
                self.root,
                engagement_id,
                folder,
                include_test_paths=include_tests,
                replace=replace,
            )
        elif selected[0] == "clone":
            stage_clone_preview(
                self.root,
                engagement_id,
                url=form.get("url"),
                ref=form.get("ref"),
                actor=self._actor(engagement_id, form),
                include_test_paths=include_tests,
                replace=replace,
                run=self.git,
            )
        elif selected[0] == "file-path":
            chosen_file = Path(form.get("file_path")).expanduser()
            if not chosen_file.is_file():
                raise EngagementError("Choose a file")
            if chosen_file.stat().st_size > UPLOAD_MAX_BYTES:
                raise EngagementError(f"File exceeds the snapshot cap ({UPLOAD_MAX_BYTES})")
            stage_single_preview(
                self.root,
                engagement_id,
                filename=chosen_file.name,
                content=chosen_file.read_bytes(),
                replace=replace,
            )
        elif selected[0] == "script":
            if not form.raw("script").strip():
                raise EngagementError("Paste a script")
            stage_single_preview(
                self.root,
                engagement_id,
                filename="script.py",
                content=form.raw("script").encode("utf-8"),
                replace=replace,
            )
        else:
            if script_file is not None:
                filename, content = script_file
            else:
                filename, content = form.get("filename"), form.get("script").encode("utf-8")
            stage_single_preview(
                self.root,
                engagement_id,
                filename=filename,
                content=content,
                replace=replace,
            )
        self._message[engagement_id] = "Review the intake preview, then confirm."

    def _sync(self, engagement_id: str, form: Form) -> None:
        import io
        from contextlib import redirect_stdout

        ids = [item for item in form.get("ids").replace(",", " ").split() if item]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            sync_advisories(self.root, actor=self._actor(engagement_id, form), ids=ids)
        self._message[engagement_id] = buffer.getvalue().strip()

    @contextmanager
    def _hold_intake(self, engagement_id: str):
        with self._lock:
            self._intake_busy.add(engagement_id)
        try:
            yield
        finally:
            with self._lock:
                self._intake_busy.discard(engagement_id)

    def _ready(self, engagement_id: str) -> dict[str, object]:
        record = load_engagement(self.root, engagement_id)
        if not has_attestation(self.root, engagement_id):
            raise EngagementError("Authorization attestation is required before the first scan")
        if not record.get("snapshot_sha256"):
            raise EngagementError(INTAKE_REQUIRED)
        return record

    def _post_advisory(self, engagement_id: str, form: Form) -> tuple[int, str, str] | tuple[int, str, str, dict[str, str]]:
        blocked = self._plan_blocked(engagement_id)
        if blocked is not None:
            return blocked
        ids_text = form.get("ids")
        pasted = form.get("advisory_text")
        if ids_text and pasted:
            raise EngagementError("Choose advisory ids or pasted text")
        record = load_engagement(self.root, engagement_id)
        if ids_text or pasted:
            directory = engagement_dir(self.root, engagement_id)
            payload: dict[str, object] = {
                "snapshot_sha256": str(record.get("snapshot_sha256") or ""),
                "ids": _advisory_ids(ids_text) if ids_text else [],
                "title": form.get("title"),
                "query": form.get("q"),
            }
            if pasted:
                payload["advisory_sha256"] = save_pasted_advisory(directory, pasted)
            else:
                clear_pasted_advisory(directory)
            save_plan(directory, "advisory", payload)
        return self._redirect(engagement_id, "/plan/advisory")

    def _post_explore(self, engagement_id: str, form: Form) -> tuple[int, str, str] | tuple[int, str, str, dict[str, str]]:
        blocked = self._plan_blocked(engagement_id)
        if blocked is not None:
            return blocked
        record = load_engagement(self.root, engagement_id)
        picker = form.get("picker")
        if picker == "search":
            directory = engagement_dir(self.root, engagement_id)
            save_plan(
                directory,
                "search",
                {
                    "snapshot_sha256": str(record.get("snapshot_sha256") or ""),
                    "query": form.get("q"),
                },
            )
            return self._redirect(engagement_id, "/plan/search")
        if picker in {"recommended", "top25", "owasp"}:
            directory = engagement_dir(self.root, engagement_id)
            scope = None if picker == "recommended" else picker
            if self.runner is None:
                payload = plan_snapshot(directory, scope)
            else:
                payload = plan_snapshot(directory, scope, runner=self.runner)
            rows = plan_rows(payload, scope=scope)
            save_plan(
                directory,
                picker,
                {
                    "snapshot_sha256": str(record.get("snapshot_sha256") or ""),
                    "rows": rows,
                },
            )
            return self._redirect(engagement_id, f"/plan/{picker}")
        status, body = self._show_plan(engagement_id, "")
        return status, body, "text/html; charset=utf-8"

    def _post_launch(self, engagement_id: str, form: Form) -> tuple[int, str, str] | tuple[int, str, str, dict[str, str]]:
        try:
            self._launch(engagement_id, form)
        except EngagementError as exc:
            if not _plan_refusal(exc):
                raise
            return 400, self._refusal_page(engagement_id, form, str(exc)), "text/html; charset=utf-8"
        return self._redirect(engagement_id, "?step=investigate#progress")

    def _redirect(
        self, engagement_id: str, suffix: str
    ) -> tuple[int, str, str, dict[str, str]]:
        record = load_engagement(self.root, engagement_id)
        actor = resolve_actor(record, None, _request_headers.get())
        location = f"/e/{engagement_id}{suffix}"
        body = _layout(
            "Continue",
            f'<p><a href="{_esc(location)}">Continue</a></p>',
            record=record,
            actor=actor,
        )
        return 303, body, "text/html; charset=utf-8", {"Location": location}

    def _review_launch(self, engagement_id: str, form: Form) -> str:
        record = self._ready(engagement_id)
        items = _items_from_form(form)
        _require_cached_advisories(items)
        return self._review_page(engagement_id, record, items)

    def _launch(self, engagement_id: str, form: Form) -> None:
        record = self._ready(engagement_id)
        directory = engagement_dir(self.root, engagement_id)
        items = _items_from_form(form)
        _require_cached_advisories(items)
        posted = form.get("snapshot_sha256")
        current = str(record.get("snapshot_sha256") or "")
        if posted and posted != current:
            raise EngagementError(PLAN_STALE)
        seconds = estimate_seconds(_investigations(self.root, engagement_id), len(items))
        if len(items) > LAUNCH_CAP and not form.checked("confirm_over_cap"):
            raise EngagementError(confirmation_text(len(items), seconds))
        actor = self._actor(engagement_id, form)
        if not actor:
            raise EngagementError("Investigation requires the consultant running it")
        queue = _new_queue(items)
        with self._lock:
            if engagement_id in self._intake_busy:
                raise EngagementError(INTAKE_BUSY)
            if engagement_id in self._launching or (directory / "antares-data" / "run.lock").is_file():
                raise EngagementError(LAUNCH_BUSY)
            _write_queue(directory, queue)
            self._launching.add(engagement_id)
            self._running.add(engagement_id)
        self._start_worker(engagement_id, directory, actor, queue)

    def _start(self, engagement_id: str, form: Form) -> None:
        self._ready(engagement_id)
        directory = engagement_dir(self.root, engagement_id)
        queue_id = form.get("queue_id")
        actor = self._actor(engagement_id, form)
        if not actor:
            raise EngagementError("Investigation requires the consultant running it")
        with self._lock:
            if engagement_id in self._intake_busy:
                raise EngagementError(INTAKE_BUSY)
            if engagement_id in self._launching or engagement_id in self._running:
                raise EngagementError(LAUNCH_BUSY)
            if (directory / "antares-data" / "run.lock").is_file():
                raise EngagementError(LAUNCH_BUSY)
            rows = _read_queue(directory)
            chosen = next((row for row in rows if row.get("id") == queue_id), None)
            if chosen is None:
                raise EngagementError("That investigation is not in the queue")
            status = str(chosen.get("status") or "")
            if status == "cancelled":
                chosen["status"] = "queued"
                chosen["elapsed_seconds"] = None
                _write_queue(directory, rows)
            elif status != "queued":
                raise EngagementError("Only a queued or cancelled investigation can be started")
            self._launching.add(engagement_id)
            self._running.add(engagement_id)
        self._start_worker(engagement_id, directory, actor, [chosen])

    def _start_worker(
        self,
        engagement_id: str,
        directory: Path,
        actor: str,
        items: list[dict[str, object]],
    ) -> None:
        def work() -> None:
            token = None
            try:
                for item in items:
                    claimed = self._claim_queue_item(directory, str(item["id"]))
                    if claimed is None:
                        continue
                    event = threading.Event()
                    self._item_events[str(item["id"])] = event
                    token = cancel_event.set(event)
                    stop = False
                    try:
                        if event.is_set():
                            self._update_queue_item(directory, str(item["id"]), {"status": "cancelled"})
                            continue
                        kwargs: dict[str, object] = {
                            "cwe": str(item["cwe"]),
                            "actor": actor,
                            "advisory_id": item.get("advisory_id"),
                            "advisory_text": item.get("advisory_text"),
                            "exploratory": item["mode"] == "exploratory",
                            "selection_source": str(item["source"]),
                            "selection_title": item.get("title"),
                        }
                        if self.runner is not None:
                            kwargs["runner"] = self.runner
                        investigation = start_investigation(
                            self.root,
                            engagement_id,
                            **kwargs,  # type: ignore[arg-type]
                        )
                        runs = investigation.get("runs") if isinstance(investigation.get("runs"), list) else []
                        elapsed = runs[-1].get("elapsed_seconds") if runs and isinstance(runs[-1], dict) else None
                        cancelled_run = event.is_set()
                        self._update_queue_item(
                            directory,
                            str(item["id"]),
                            {
                                "investigation_id": investigation["id"],
                                "elapsed_seconds": elapsed,
                                "status": "cancelled" if cancelled_run else "completed",
                            },
                        )
                        stop = cancelled_run
                    except EngagementError as exc:
                        self._update_queue_item(
                            directory,
                            str(item["id"]),
                            {"status": "cancelled" if event.is_set() else "failed", "error": str(exc)},
                        )
                        if not event.is_set():
                            self._message[engagement_id] = str(exc)
                        stop = event.is_set()
                    finally:
                        if token is not None:
                            cancel_event.reset(token)
                            token = None
                    if stop:
                        break
            finally:
                with self._lock:
                    self._launching.discard(engagement_id)
                    self._running.discard(engagement_id)

        worker = threading.Thread(target=work, name=f"astrolabe-{engagement_id}", daemon=True)
        worker.start()
        worker.join(timeout=0.3)
        if engagement_id in self._running:
            self._message[engagement_id] = "Investigation running."

    def _claim_queue_item(self, directory: Path, queue_id: str) -> dict[str, object] | None:
        with self._lock:
            rows = _read_queue(directory)
            for row in rows:
                if row.get("id") != queue_id or row.get("status") != "queued":
                    continue
                row["status"] = "running"
                _write_queue(directory, rows)
                return row
        return None

    def _update_queue_item(self, directory: Path, queue_id: str, changes: dict[str, object]) -> None:
        with self._lock:
            rows = _read_queue(directory)
            for row in rows:
                if row.get("id") == queue_id:
                    row.update(changes)
            _write_queue(directory, rows)

    def _cancel(self, engagement_id: str, form: Form) -> None:
        queue_id = form.get("queue_id")
        directory = engagement_dir(self.root, engagement_id)
        with self._lock:
            rows = _read_queue(directory)
            for row in rows:
                if row.get("id") != queue_id:
                    continue
                if row.get("status") not in {"queued", "running"}:
                    raise EngagementError("Only a queued or running investigation can be cancelled")
                row["status"] = "cancelled"
                event = self._item_events.get(queue_id)
                if event is not None:
                    event.set()
                _write_queue(directory, rows)
                self._message[engagement_id] = "Investigation cancelled."
                return
        raise EngagementError("That investigation is not in the queue")

    def _rerun(self, engagement_id: str, form: Form) -> None:
        if engagement_id in self._intake_busy:
            raise EngagementError(INTAKE_BUSY)
        if engagement_id in self._launching:
            raise EngagementError(LAUNCH_BUSY)
        kwargs: dict[str, object] = {"actor": self._actor(engagement_id, form)}
        if self.runner is not None:
            kwargs["runner"] = self.runner
        rerun_investigation(
            self.root,
            engagement_id,
            form.get("investigation_id"),
            **kwargs,  # type: ignore[arg-type]
        )
        self._message[engagement_id] = RERUN_NOTE

    def _authorize_section(self, record: dict[str, object], attested: bool) -> str:
        engagement_id = str(record["id"])
        if attested:
            current = read_instance_attestation(self.root, record) or {}
            when = str(current.get("attested_at") or "")
            shown = when[:10] if len(when) >= 10 else when
            line = (
                f"Authorized: {_esc(current.get('reference'))}, "
                f"by {_esc(current.get('actor'))}, {_esc(shown)}."
            )
            return _step(
                "authorize",
                "Authorize",
                f"<p>{line}</p>",
                opened=False,
                summary=f"<p>{line}</p>",
            )
        scope = str(record.get("scope") or "")
        body = (
            f"<p>Confirm you have written permission from {_esc(record.get('customer'))} "
            "to analyze this code.</p>"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/attest\">"
            "<label>Authorization reference <input name=\"reference\" required maxlength=\"200\"></label>"
            f"<label>Scope <input name=\"scope\" value=\"{_esc(scope)}\" readonly></label>"
            "<label><input type=\"checkbox\" name=\"authorized\" required> "
            "The customer's written authorization covers this scope.</label>"
            "<button type=\"submit\">Record authorization</button>"
            "</form>"
        )
        return _step("authorize", "Authorize", body, opened=True)

    def _code_section(self, record: dict[str, object], *, opened: bool) -> str:
        engagement_id = str(record["id"])
        intake = record.get("intake") if isinstance(record.get("intake"), dict) else {}
        prefix = intake.get("stripped_prefix") if isinstance(intake, dict) else None
        summary = ""
        if record.get("snapshot_sha256"):
            summary = (
                "<dl>"
                f"<dt>Snapshot SHA-256</dt><dd class=\"mono\">{_esc(record.get('snapshot_sha256'))}</dd>"
                f"<dt>Stripped prefix</dt><dd>{_esc(prefix or 'none')}</dd>"
                "</dl>"
            )
        recent = record.get("recent_sources")
        again = ""
        if isinstance(recent, list):
            buttons = []
            for index, item in enumerate(recent):
                if not isinstance(item, dict):
                    continue
                buttons.append(
                    f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/intake/again\">"
                    f"<button name=\"source\" value=\"{_esc(index)}\">Re-intake {_esc(item.get('label'))}</button>"
                    "</form>"
                )
            again = "".join(buttons)
        has_code = bool(record.get("snapshot_sha256") or record.get("intake"))
        replace = (
            "<label><input type=\"checkbox\" name=\"replace\"> Replace current code</label>" if has_code else ""
        )
        action = f"/e/{_esc(engagement_id)}/intake/preview"
        form = (
            f"<form method=\"post\" action=\"{action}\" enctype=\"multipart/form-data\">"
            '<fieldset><legend>Source</legend>'
            '<label><input type="radio" name="intake_source" value="git" checked> Git</label>'
            '<label><input type="radio" name="intake_source" value="folder"> Local folder</label>'
            '<label><input type="radio" name="intake_source" value="archive"> Archive</label>'
            '<label><input type="radio" name="intake_source" value="file"> Single file</label>'
            '<label><input type="radio" name="intake_source" value="script"> Script</label>'
            "</fieldset>"
            '<details id="intake-clone" class="intake-source" data-intake-source="git" open>'
            "<summary>Git</summary>"
            f"<p class=\"notice\">{_esc(CLONE_NOTICE)}</p>"
            "<p>Cloning contacts the git host.</p>"
            "<label>HTTPS URL <input name=\"url\" placeholder=\"https://github.com/org/repo.git\"></label>"
            "<label>Branch, tag, or commit <input name=\"ref\"></label>"
            "</details>"
            '<details id="intake-folder" class="intake-source" data-intake-source="folder">'
            "<summary>Local folder</summary>"
            "<label>Local directory <input id=\"folder-path\" name=\"path\" spellcheck=\"false\"></label>"
            "<p><button type=\"button\" class=\"secondary\" data-browse=\"directory\" data-browse-target=\"folder-path\">Browse</button></p>"
            "<details><summary>Upload from browser instead</summary>"
            "<label>Directory upload <input type=\"file\" name=\"files\" webkitdirectory directory multiple></label>"
            "</details></details>"
            '<details id="intake-archive" class="intake-source" data-intake-source="archive">'
            "<summary>Archive</summary>"
            "<div id=\"archive-drop\">Drop a zip or tar here, or choose a file.</div>"
            "<label>Archive <input id=\"archive-file\" type=\"file\" name=\"archive\" accept=\".zip,.tar,.gz,.tgz\"></label>"
            "</details>"
            '<details id="intake-single" class="intake-source" data-intake-source="file">'
            "<summary>Single file</summary>"
            "<label>File <input id=\"single-file-path\" name=\"file_path\" spellcheck=\"false\"></label>"
            "<p><button type=\"button\" class=\"secondary\" data-browse=\"file\" data-browse-target=\"single-file-path\">Browse</button></p>"
            "</details>"
            '<details id="intake-script" class="intake-source" data-intake-source="script">'
            "<summary>Script</summary>"
            "<label>Script <textarea name=\"script\" spellcheck=\"false\"></textarea></label>"
            "</details>"
            "<label><input type=\"checkbox\" name=\"include_tests\"> Include test paths</label>"
            f"{replace}"
            "<button type=\"submit\">Preview</button></form>"
        )
        change = f"/e/{engagement_id}?step=code" if record.get("snapshot_sha256") else ""
        return _step(
            "intake",
            "Add code",
            summary + again + form,
            opened=opened,
            summary=summary or "No code yet.",
            change=change,
        )

    def _preview_section(self, engagement_id: str) -> str:
        pending = load_pending(self.root, engagement_id)
        if not pending:
            return ""
        directory = engagement_dir(self.root, engagement_id)
        include_tests = bool(pending.get("include_tests"))
        if pending.get("kind") == "path":
            tree = Path(str(pending.get("path") or ""))
        else:
            tree = directory / str(pending.get("tree") or "")
        if not tree.is_dir():
            return ""
        described = snapshot_preview(tree, include_test_paths=include_tests)
        files = described.get("files") if isinstance(described.get("files"), list) else []
        excluded = described.get("excluded") if isinstance(described.get("excluded"), dict) else {}
        total = int(described.get("total_bytes") or 0)
        guidance = int(described.get("guidance_bytes") or 0)
        relation = "within" if total <= guidance else "past"
        rows = []
        for item in files[:200]:
            if isinstance(item, dict):
                rows.append(
                    f"<li class=\"mono\">{_esc(item.get('path'))} ({_esc(item.get('bytes'))} bytes)</li>"
                )
        extra = ""
        if len(files) > 200:
            extra = f"<li>{len(files) - 200} more files</li>"
        prefix = pending.get("stripped_prefix") or "none"
        commit = pending.get("commit")
        commit_line = f"<p>Resolved commit {_esc(commit)}</p>" if commit else ""
        return _card(
            "intake-preview",
            "Intake preview",
            f"<p>Total size {total} bytes, {relation} the 10 MB guidance.</p>"
            f"<ul id=\"excluded\">"
            f"<li>Excluded tests: {_esc(excluded.get('tests', 0))}</li>"
            f"<li>Excluded .git: {_esc(excluded.get('git', 0))}</li>"
            f"<li>Excluded symlinks: {_esc(excluded.get('symlinks', 0))}</li>"
            f"<li>Excluded outside hardlinks: {_esc(excluded.get('external_hardlinks', 0))}</li>"
            "</ul>"
            f"<p>Stripped prefix: {_esc(prefix)}</p>"
            f"{commit_line}"
            f"<ul class=\"tree\">{''.join(rows)}{extra}</ul>"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/intake/confirm\">"
            "<button type=\"submit\">Use this code</button></form>",
        )

    def _advisory_section(self, engagement_id: str, *, opened: bool) -> str:
        summary = "Optional."
        body = (
            "<p>Nothing is selected yet.</p>"
            "<p>No advisory? Skip. You can still run exploratory checks.</p>"
            "<h3>Add an advisory</h3>"
            "<p>Uses the network (OSV, GitHub).</p>"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/advisories/sync\">"
            "<label>CVE or GHSA ids <textarea name=\"ids\" required></textarea></label>"
            "<button type=\"submit\">Fetch</button></form>"
            "<details><summary>Network detail</summary>"
            f"<p class=\"notice\">{_esc(NETWORK_NOTICE)}</p></details>"
            "<details><summary>Offline? Import advisory files</summary>"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/advisories/import\">"
            "<label>Advisory file or directory <input id=\"advisory-cache-path\" name=\"directory\" required spellcheck=\"false\"></label>"
            "<p><button type=\"button\" class=\"secondary\" data-browse=\"file\" data-browse-target=\"advisory-cache-path\">Browse file</button> "
            "<button type=\"button\" class=\"secondary\" data-browse=\"directory\" data-browse-target=\"advisory-cache-path\">Browse folder</button></p>"
            "<button type=\"submit\">Import</button></form></details>"
        )
        return _step(
            "advisories",
            "Advisory",
            body,
            opened=opened,
            summary=summary,
            change=f"/e/{engagement_id}?step=advisory",
        )

    def _plan_blocked(self, engagement_id: str) -> tuple[int, str, str] | None:
        record = load_engagement(self.root, engagement_id)
        attested = has_attestation(self.root, engagement_id)
        has_code = bool(record.get("snapshot_sha256"))
        if attested and has_code:
            return None
        links = []
        gates = []
        if not attested:
            links.append(f'<a href="/e/{_esc(engagement_id)}#authorize">Authorize</a>')
            gates.append(f'<p id="scan-gate">{_esc(SCAN_GATE)}</p>')
        if not has_code:
            links.append(f'<a href="/e/{_esc(engagement_id)}#intake">Add code</a>')
            gates.append(f'<p id="selection-gate">{_esc(INTAKE_REQUIRED)}</p>')
        body = f'<p class="needs">Needs: {", ".join(links)}.</p>' + "".join(gates)
        return 400, self._plan_frame(record, "", body), "text/html; charset=utf-8"

    def _show_plan(self, engagement_id: str, picker: str) -> tuple[int, str]:
        if picker and picker not in PLAN_LABEL:
            return 404, _layout("Not found", "<p>That page is not part of an engagement.</p>")
        record = load_engagement(self.root, engagement_id)
        attested = has_attestation(self.root, engagement_id)
        has_code = bool(record.get("snapshot_sha256"))
        if not attested or not has_code:
            blocked = self._plan_blocked(engagement_id)
            if blocked is not None:
                return blocked[0], blocked[1]
        if not picker:
            return 200, self._plan_frame(record, "", _exploratory_notes(record))
        directory = engagement_dir(self.root, engagement_id)
        stored = load_plan(directory, picker)
        current = str(record.get("snapshot_sha256") or "")
        fresh = isinstance(stored, dict) and stored.get("snapshot_sha256") == current
        stale = isinstance(stored, dict) and not fresh
        if picker in {"recommended", "top25", "owasp"}:
            body = self._runner_plan_body(
                engagement_id,
                record,
                picker,
                stored if fresh else None,
                stale=stale,
            )
        elif picker == "advisory":
            body = self._advisory_plan_body(engagement_id, record, stored if fresh else None, stale=bool(stored) and not fresh)
        else:
            body = self._search_plan_body(engagement_id, record, stored if fresh else None, stale=bool(stored) and not fresh)
        return 200, self._plan_frame(record, picker, body)

    def _refusal_page(self, engagement_id: str, form: Form, message: str) -> str:
        record = load_engagement(self.root, engagement_id)
        items = _items_from_form(form)
        source = str(items[0]["source"])
        picker = _picker_for_source(source)
        directory = engagement_dir(self.root, engagement_id)
        stored = load_plan(directory, picker)
        rows: list[dict[str, object]] = []
        if isinstance(stored, dict) and isinstance(stored.get("rows"), list):
            rows = [row for row in stored["rows"] if isinstance(row, dict)]
        have = {str(row.get("cwe")) for row in rows}
        for item in items:
            if str(item["source"]) != source or str(item["cwe"]) in have:
                continue
            rows.append(
                {
                    "cwe": str(item["cwe"]),
                    "evidence": "",
                    "reasons": [],
                    "evidence_paths": [],
                    "score": 0,
                    "excluded_only": False,
                    "preselect": False,
                    "group": rows[0].get("group") if rows else "",
                    "related": [],
                }
            )
        checked = {str(item["cwe"]) for item in items if str(item["source"]) == source}
        callout = _callout(message)
        run = _run_plan_button(engagement_id, picker) if message == PLAN_STALE else ""
        table = ""
        if rows:
            table = self._plan_results(
                engagement_id,
                record,
                picker,
                source,
                rows,
                checked,
                allow_top=picker in {"recommended", "top25"},
                honor_excluded=False,
            )
        return self._plan_frame(record, picker, callout + run + table)

    def _plan_frame(self, record: dict[str, object], picker: str, body: str) -> str:
        actor = resolve_actor(record, None, _request_headers.get())
        title = PLAN_LABEL.get(picker, "Investigate")
        return _layout(
            title,
            self._engagement_header(record) + _breadcrumb(str(record.get("id") or ""), picker) + _plan_tabs(str(record.get("id") or ""), picker) + body,
            record=record,
            actor=actor,
        )

    def _runner_plan_body(
        self,
        engagement_id: str,
        record: dict[str, object],
        picker: str,
        stored: dict[str, object] | None,
        *,
        stale: bool,
    ) -> str:
        intro = f"<p>{_esc(PLAN_INTRO[picker])}</p>"
        notes = _exploratory_notes(record)
        if stored is None:
            message = PLAN_STALE if stale else PLAN_EMPTY
            return intro + notes + _callout(message) + _run_plan_button(engagement_id, picker)
        rows = stored.get("rows") if isinstance(stored.get("rows"), list) else []
        plan_rows_list = [row for row in rows if isinstance(row, dict)]
        checked = _row_checked(plan_rows_list, _query_param("sel"), allow_top=picker in {"recommended", "top25"})
        exclusion = f"<p>{_esc(PLAN_EXCLUSION_NOTE)}</p>"
        return intro + notes + exclusion + self._plan_results(
            engagement_id,
            record,
            picker,
            picker,
            plan_rows_list,
            checked,
            allow_top=picker in {"recommended", "top25"},
            honor_excluded=True,
        )

    def _plan_results(
        self,
        engagement_id: str,
        record: dict[str, object],
        picker: str,
        source: str,
        rows: list[dict[str, object]],
        checked: set[str],
        *,
        allow_top: bool,
        honor_excluded: bool,
    ) -> str:
        selected = 0
        body_rows = []
        group = ""
        for row in rows:
            if row.get("group") and not group:
                group = str(row["group"])
            cwe = str(row["cwe"])
            on = cwe in checked and not (honor_excluded and row.get("excluded_only"))
            if on:
                selected += 1
            name = cwe_name(cwe)
            mark = " checked" if on else ""
            related = row.get("related") if isinstance(row.get("related"), list) else []
            related_html = "".join(
                f'<p class="related">Also covers parent {cwe_ref(str(parent), new_tab=True)}</p>' for parent in related
            )
            abstraction = cwe_abstraction(cwe)
            pill = _pill(abstraction, "muted") if abstraction else ""
            body_rows.append(
                f'<tr data-plan-row data-cwe="{_esc(cwe)}" data-name="{_esc(name)}">'
                f'<td><label><input type="checkbox" name="choice" value="{_esc(source)}|{_esc(cwe)}"{mark}> '
                f'{_esc(name)}</label> {cwe_ref(cwe, new_tab=True)}</td>'
                f'<td>{cwe_ref(cwe, new_tab=True)}</td>'
                f"<td>{_esc(name)}{related_html}</td>"
                f"<td>{pill}</td>"
                f"<td>{_esc(row.get('score'))}</td>"
                f"<td>{_evidence_html(row)}</td>"
                "</tr>"
            )
        heading = f"<h2>{_esc(group)}</h2>" if group else ""
        filt = ""
        if picker == "owasp":
            filt = '<p><label>Filter <input id="owasp-filter" type="search" autocomplete="off"></label></p>'
        investigations = _investigations(self.root, engagement_id)
        one = estimate_seconds(investigations, 1)
        sampled = "1" if one is not None else "0"
        each = one if one is not None else per_check_estimate_seconds()
        estimate = format_estimate(estimate_seconds(investigations, selected), selected)
        none_href = f"/e/{_esc(engagement_id)}/plan/{_esc(picker)}?sel=none"
        top_link = ""
        if allow_top:
            top_href = f"/e/{_esc(engagement_id)}/plan/{_esc(picker)}?sel=top"
            top_link = f' <a href="{top_href}">Select top {_esc(preselect_limit())}</a>'
        summary = (
            f'<div class="plan-summary" data-plan-summary data-each="{_esc(each)}" data-sampled="{sampled}">'
            f'<p aria-live="polite"><span data-selected-count>{selected}</span> selected</p>'
            f'<p data-estimate>{_esc(estimate)}</p>'
            f'<p class="plan-actions"><a href="{none_href}">Select none</a>{top_link} '
            '<button class="primary" type="submit" form="plan-launch">Launch</button></p>'
            "</div>"
        )
        table = (
            f"{heading}{filt}"
            '<form id="plan-launch" method="post" action="/e/' + _esc(engagement_id) + '/review">'
            '<table class="plan-rows"><thead><tr>'
            "<th>Select</th><th>CWE</th><th>Name</th><th>Abstraction</th><th>Score</th><th>Evidence</th>"
            "</tr></thead><tbody>"
            + "".join(body_rows)
            + "</tbody></table></form>"
        )
        return summary + table

    def _advisory_plan_body(
        self,
        engagement_id: str,
        record: dict[str, object],
        stored: dict[str, object] | None,
        *,
        stale: bool,
    ) -> str:
        intro = f"<p>{_esc(PLAN_INTRO['advisory'])}</p>"
        forms = _advisory_forms(engagement_id, run_plan=stale, prefill=_query_param("id") or "")
        if stale:
            return intro + _callout(PLAN_STALE) + forms
        if not stored:
            return intro + forms
        text = load_pasted_advisory(
            engagement_dir(self.root, engagement_id),
            str(stored.get("advisory_sha256") or ""),
        )
        if text:
            return intro + forms + self._pasted_results(engagement_id, text, str(stored.get("title") or ""), str(stored.get("query") or ""))
        ids = stored.get("ids") if isinstance(stored.get("ids"), list) else []
        query = str(stored.get("query") or "")
        return intro + forms + self._advisory_results(engagement_id, record, [str(item) for item in ids], query)

    def _advisory_results(self, engagement_id: str, record: dict[str, object], ids: list[str], query: str) -> str:
        advisories = [load_advisory(advisory_cache_dir(), advisory_id) for advisory_id in ids]
        lines = []
        for item in advisories:
            state = "cached" if item["cached"] else "is not in the local cache"
            lines.append(f"<p>{_esc(item['id'])} {_esc(state)}</p>")
        missing = [str(item["id"]) for item in advisories if not item["cached"]]
        if missing:
            notice = (
                f'<p class="notice">{_esc(NETWORK_NOTICE)}</p>'
                f'<form method="post" action="/e/{_esc(engagement_id)}/advisories/sync">'
                f'<input type="hidden" name="ids" value="{_esc(" ".join(missing))}">'
                "<button type=\"submit\">Sync advisories</button></form>"
            )
            return "".join(lines) + notice
        sel = _query_param("sel")
        blocks = []
        choice_rows: list[str] = []
        selected = 0
        for item in advisories:
            advisory_id = str(item["id"])
            listed = [str(cwe) for cwe in item.get("cwe_ids") or []]
            children: list[str] = []
            for cwe in listed:
                if is_broad_cwe(cwe):
                    children.extend(base_variant_children(cwe))
            found = [entry["id"] for entry in search_cwes(query)] if query and not listed else []
            checked = _advisory_checked(listed, children + found, sel)
            block = (
                f'<section class="advisory"><h2>{_esc(advisory_id)}</h2>'
                "<details><summary>Advisory text</summary>"
                f'<pre class="query-text">{_esc(item.get("text") or "")}</pre></details>'
            )
            if not listed:
                block += "<p>This advisory lists no CWE. Choose one from the catalog.</p>"
                block += (
                    f'<form method="post" action="/e/{_esc(engagement_id)}/select/advisory">'
                    f'<input type="hidden" name="ids" value="{_esc(advisory_id)}">'
                    "<label>Search the catalog by id, name, or description <input name=\"q\" required></label>"
                    "<button type=\"submit\">Search</button></form>"
                )
            blocks.append(block + "</section>")
            seen: set[str] = set()
            for cwe in listed:
                if cwe in checked:
                    selected += 1
                choice_rows.append(_plan_choice_row(f"{advisory_id}|{cwe}", cwe, checked=cwe in checked))
                if is_broad_cwe(cwe):
                    choice_rows.append(
                        f'<tr><td colspan="6"><p class="class-note">{_esc(CLASS_NOTE)}</p></td></tr>'
                    )
                    for child in base_variant_children(cwe):
                        if child in seen:
                            continue
                        seen.add(child)
                        if child in checked:
                            selected += 1
                        choice_rows.append(
                            _plan_choice_row(f"{advisory_id}|{child}", child, checked=child in checked, child=True)
                        )
            for cwe in found:
                if cwe in seen or cwe in listed:
                    continue
                if cwe in checked:
                    selected += 1
                choice_rows.append(_plan_choice_row(f"{advisory_id}|{cwe}", cwe, checked=cwe in checked))
        if not choice_rows:
            return "".join(lines) + "".join(blocks)
        investigations = _investigations(self.root, engagement_id)
        one = estimate_seconds(investigations, 1)
        sampled = "1" if one is not None else "0"
        each = one if one is not None else per_check_estimate_seconds()
        estimate = format_estimate(estimate_seconds(investigations, selected), selected)
        summary = (
            f'<div class="plan-summary" data-plan-summary data-each="{_esc(each)}" data-sampled="{sampled}">'
            f'<p aria-live="polite"><span data-selected-count>{selected}</span> selected</p>'
            f'<p data-estimate>{_esc(estimate)}</p>'
            f'<p class="plan-actions"><a href="/e/{_esc(engagement_id)}/plan/advisory?sel=none">Select none</a> '
            '<button class="primary" type="submit" form="plan-launch">Launch</button></p></div>'
        )
        table = (
            '<form id="plan-launch" method="post" action="/e/' + _esc(engagement_id) + '/review">'
            '<table class="plan-rows"><thead><tr>'
            "<th>Select</th><th>CWE</th><th>Name</th><th>Abstraction</th><th>Score</th><th>Evidence</th>"
            "</tr></thead><tbody>"
            + "".join(choice_rows)
            + "</tbody></table></form>"
        )
        return "".join(lines) + "".join(blocks) + summary + table

    def _pasted_results(self, engagement_id: str, text: str, title: str, query: str) -> str:
        hidden = (
            f'<textarea name="advisory_text" readonly class="query-text">{_esc(text)}</textarea>'
            f'<input type="hidden" name="title" value="{_esc(title)}">'
        )
        results = search_cwes(query) if query else []
        checked = _advisory_checked([], [item["id"] for item in results], _query_param("sel"))
        rows = []
        selected = 0
        for item in results:
            on = item["id"] in checked
            if on:
                selected += 1
            rows.append(_plan_choice_row(f"pasted|{item['id']}", item["id"], checked=on))
        search = (
            f'<form method="post" action="/e/{_esc(engagement_id)}/select/advisory">'
            f"{hidden}"
            "<label>Search the catalog by id, name, or description <input name=\"q\" required></label>"
            "<button type=\"submit\">Search</button></form>"
        )
        if not rows:
            return "<p>Pasted advisory</p>" + search
        investigations = _investigations(self.root, engagement_id)
        one = estimate_seconds(investigations, 1)
        sampled = "1" if one is not None else "0"
        each = one if one is not None else per_check_estimate_seconds()
        estimate = format_estimate(estimate_seconds(investigations, selected), selected)
        summary = (
            f'<div class="plan-summary" data-plan-summary data-each="{_esc(each)}" data-sampled="{sampled}">'
            f'<p aria-live="polite"><span data-selected-count>{selected}</span> selected</p>'
            f'<p data-estimate>{_esc(estimate)}</p>'
            f'<p class="plan-actions"><a href="/e/{_esc(engagement_id)}/plan/advisory?sel=none">Select none</a> '
            '<button class="primary" type="submit" form="plan-launch">Launch</button></p></div>'
        )
        table = (
            "<p>Pasted advisory</p>"
            + search
            + summary
            + '<form id="plan-launch" method="post" action="/e/'
            + _esc(engagement_id)
            + '/review">'
            + hidden
            + '<table class="plan-rows"><thead><tr>'
            "<th>Select</th><th>CWE</th><th>Name</th><th>Abstraction</th><th>Score</th><th>Evidence</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></form>"
        )
        return table

    def _search_plan_body(
        self,
        engagement_id: str,
        record: dict[str, object],
        stored: dict[str, object] | None,
        *,
        stale: bool,
    ) -> str:
        intro = f"<p>{_esc(PLAN_INTRO['search'])}</p>{_exploratory_notes(record)}"
        requested = _query_param("q")
        if requested is not None:
            form = (
                f'<form method="post" action="/e/{_esc(engagement_id)}/select/explore">'
                '<input type="hidden" name="picker" value="search">'
                f'<label>Search the catalog by id, name, or description <input name="q" value="{_esc(requested)}"></label>'
                '<button type="submit">Search</button></form>'
            )
            return intro + form
        query = str(stored.get("query") or "") if stored else ""
        form = (
            f'<form method="post" action="/e/{_esc(engagement_id)}/select/explore">'
            '<input type="hidden" name="picker" value="search">'
            f'<label>Search the catalog by id, name, or description <input name="q" value="{_esc(query)}"></label>'
            f'<button type="submit">{"Run plan" if stale else "Search"}</button></form>'
        )
        if stale:
            return intro + _callout(PLAN_STALE) + form
        if not query:
            return intro + form + "<p>Enter an id, name, or description to search.</p>"
        results = search_cwes(query)
        checked = _advisory_checked([], [item["id"] for item in results], _query_param("sel"))
        if _query_param("sel") is None:
            checked = set()
        rows = [
            {
                "cwe": item["id"],
                "evidence": "",
                "reasons": [],
                "evidence_paths": [],
                "score": "",
                "excluded_only": False,
                "preselect": False,
                "group": "",
                "related": [],
            }
            for item in results
        ]
        table = self._plan_results(
            engagement_id,
            record,
            "search",
            "search",
            rows,
            checked,
            allow_top=False,
            honor_excluded=True,
        )
        return intro + form + table

    def _review_page(
        self,
        engagement_id: str,
        record: dict[str, object],
        items: list[dict[str, object]],
    ) -> str:
        seconds = estimate_seconds(_investigations(self.root, engagement_id), len(items))
        snapshot = short_sha(record.get("snapshot_sha256"))
        source = str(items[0]["source"]) if items else "recommended"
        picker = _picker_for_source(source)
        stored = load_plan(engagement_dir(self.root, engagement_id), picker)
        bound = str(record.get("snapshot_sha256") or "")
        if isinstance(stored, dict) and stored.get("snapshot_sha256"):
            bound = str(stored["snapshot_sha256"])
        rows = []
        hidden = []
        exploratory = False
        for item in items:
            if item["mode"] == "exploratory":
                exploratory = True
            rows.append(
                "<tr>"
                f'<td>{cwe_ref(str(item["cwe"]), new_tab=True)}</td>'
                f"<td>{_esc(item['mode'])}</td>"
                f"<td>{_esc(item['source'])}</td>"
                f'<td class="mono">{_esc(snapshot)}</td>'
                "</tr>"
            )
            hidden.append(f'<input type="hidden" name="item" value="{_esc(_item_json(item))}">')
        confirm = ""
        if len(items) > LAUNCH_CAP:
            confirm = (
                f'<p id="over-cap">{_esc(confirmation_text(len(items), seconds))}</p>'
                '<label><input type="checkbox" name="confirm_over_cap"> '
                f"Run these {_esc(len(items))} investigations. {_esc(format_estimate(seconds, len(items)))}</label>"
            )
        note = _exploratory_notes(record) if exploratory else ""
        selected = ",".join(str(item["cwe"]) for item in items)
        back = f"/e/{engagement_id}/plan/{picker}?sel={urllib.parse.quote(selected, safe=',')}"
        body = (
            "<h1>Launch review</h1>"
            f'<p><a href="{_esc(back)}">Back to plan</a></p>'
            f"{note}"
            '<table id="launch-review"><thead><tr><th>CWE</th><th>Mode</th><th>Selection source</th>'
            "<th>Snapshot</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            f"<p>{_esc(format_estimate(seconds, len(items)))}</p>"
            f"<p>{_esc(REVIEW_LOAD_NOTE)}</p>"
            f'<form method="post" action="/e/{_esc(engagement_id)}/launch">'
            f'<input type="hidden" name="snapshot_sha256" value="{_esc(bound)}">'
            f"{''.join(hidden)}{confirm}"
            "<button type=\"submit\">Launch</button></form>"
        )
        return self._plan_frame(record, picker, body)


    def _investigation_section(self, engagement_id: str, attested: bool, *, opened: bool) -> str:
        record = load_engagement(self.root, engagement_id)
        reasons = []
        if not attested:
            reasons.append(f"<p id=\"scan-gate\">{_esc(SCAN_GATE)}</p>")
        if not record.get("snapshot_sha256"):
            reasons.append(f"<p id=\"selection-gate\">{_esc(INTAKE_REQUIRED)}</p>")
        needs = ""
        if reasons:
            links = []
            if not attested:
                links.append('<a href="#authorize">Authorize</a>')
            if not record.get("snapshot_sha256"):
                links.append('<a href="#intake">Add code</a>')
            needs = f'<p class="needs">Needs: {", ".join(links)}.</p>'
        disabled = " disabled" if reasons else ""
        single = (
            f"<p id=\"single-file-note\">{_esc(SINGLE_FILE_NOTE)}</p>"
            if record.get("label") == "single-file"
            else ""
        )
        buttons = (
            "<div id=\"selection\">"
            f"{needs}{''.join(reasons)}"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/select/advisory\">"
            f"<button class=\"primary\"{disabled} type=\"submit\">Check an advisory</button></form>"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/select/explore\">"
            "<p class=\"exploratory-label\">Exploratory</p>"
            f"<p>{_esc(EXPLORATORY_NOTE)}</p>{single}"
            f"<button class=\"secondary\"{disabled} type=\"submit\">Explore without an advisory</button>"
            "</form></div>"
        )
        change = f"/e/{engagement_id}?step=investigate" if _investigations(self.root, engagement_id) else ""
        return _step(
            "investigations",
            "Investigate",
            f"{buttons}{self._queue_table(engagement_id)}",
            opened=opened,
            summary="Checks have been run." if not reasons else "Needs a previous step.",
            change=change,
            blocked=bool(reasons),
        )

    def _queue_table(self, engagement_id: str) -> str:
        directory = engagement_dir(self.root, engagement_id)
        pending = {
            (str(item["file_path"]), str(item["cwe"]))
            for item in list_candidates(self.root, engagement_id)
            if item.get("presentation_state") == "candidate"
        }
        linked: set[str] = set()
        cancelled_ids = {
            str(item.get("investigation_id") or "")
            for item in _read_queue(directory)
            if item.get("status") == "cancelled" and item.get("investigation_id")
        }
        rows: list[str] = []
        exploratory = False
        single = load_engagement(self.root, engagement_id).get("label") == "single-file"
        queue = _read_queue(directory)
        idle = engagement_id not in self._running and not any(
            item.get("status") == "running" for item in queue
        )
        estimate = status_estimate_text(_investigations(self.root, engagement_id))
        for item in queue:
            if item.get("status") == "completed":
                continue
            if item.get("mode") == "exploratory":
                exploratory = True
            elapsed = item.get("elapsed_seconds")
            elapsed_text = f"{elapsed} seconds" if isinstance(elapsed, (int, float)) else ""
            status = str(item.get("status") or "")
            active = status == "running"
            fresh = True
            if active:
                _detail, fresh = progress_detail(load_activity(directory))
            actions = _queue_actions(engagement_id, item, idle=idle)
            status_html = (
                f'<span class="run-mark" aria-hidden="true"></span>{_esc(status)}'
                if active and fresh
                else _esc(status)
            )
            estimate_html = f'<span class="status-estimate">{_esc(estimate)}</span>'
            row_class = ' class="is-running"' if active else ""
            rows.append(
                f"<tr{row_class}>"
                f"<td>{_esc(item.get('mode'))}</td>"
                f"<td>{cwe_ref(str(item.get('cwe') or ''))}</td>"
                f"<td>{_esc(item.get('source'))}</td>"
                f"<td>{_esc(elapsed_text)}</td>"
                f"<td>{status_html}{estimate_html}</td>"
                f"<td>{actions}</td>"
                "</tr>"
            )
            if active:
                rows.append(
                    '<tr class="run-detail"><td colspan="6">'
                    '<details id="run-status" open><summary>Status</summary>'
                    f"{_progress_html(directory)}"
                    "</details></td></tr>"
                )
        for investigation in _investigations(self.root, engagement_id):
            investigation_id = str(investigation.get("id") or "")
            if investigation_id in linked or investigation_id in cancelled_ids:
                continue
            linked.add(investigation_id)
            runs = investigation.get("runs") if isinstance(investigation.get("runs"), list) else []
            last = runs[-1] if runs and isinstance(runs[-1], dict) else {}
            paths = last.get("candidate_paths") if isinstance(last.get("candidate_paths"), list) else []
            cwe = str(investigation.get("cwe") or "")
            waiting = any((str(path), cwe) in pending for path in paths)
            mode = "exploratory" if investigation.get("exploratory") else "advisory"
            if mode == "exploratory":
                exploratory = True
            elapsed = last.get("elapsed_seconds")
            elapsed_text = f"{elapsed} seconds" if isinstance(elapsed, (int, float)) else ""
            status = "pending review" if waiting else "completed"
            rerun = (
                f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/rerun\">"
                f"<input type=\"hidden\" name=\"investigation_id\" value=\"{_esc(investigation_id)}\">"
                "<button type=\"submit\">Re-run</button></form>"
            )
            rows.append(
                "<tr>"
                f"<td>{_esc(mode)}</td>"
                f"<td>{cwe_ref(cwe)}</td>"
                f"<td>{_esc(investigation.get('selection_source') or '')}</td>"
                f"<td>{_esc(elapsed_text)}</td>"
                f"<td>{_esc(status)}</td>"
                f"<td>{rerun}</td>"
                "</tr>"
            )
        if not rows:
            return ""
        note = _exploratory_notes({"label": "single-file" if single else ""}) if exploratory else ""
        rerun_note = f"<p>{_esc(RERUN_NOTE)}</p>" if any("Re-run" in row for row in rows) else ""
        return (
            f"{note}{rerun_note}"
            "<table id=\"queue\"><thead><tr><th>Mode</th><th>CWE</th><th>Selection source</th>"
            "<th>Elapsed</th><th>Status</th><th></th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _coverage_section(self, engagement_id: str) -> str:
        coverage = load_coverage(self.root, engagement_id)
        cwes = coverage.get("cwes") if isinstance(coverage.get("cwes"), list) else []

        def block(mode: str, title: str) -> str:
            body = []
            for item in cwes:
                if not isinstance(item, dict) or item.get("mode") != mode:
                    continue
                body.append(
                    "<tr>"
                    f"<td>{cwe_ref(str(item.get('cwe') or ''), new_tab=True)}</td>"
                    f"<td>{_esc(item.get('selection_source') or '')}</td>"
                    f"<td class=\"mono\">{_esc(short_sha(item.get('snapshot_sha256')))}</td>"
                    "</tr>"
                )
            if not body:
                body.append("<tr><td colspan=\"3\">None.</td></tr>")
            note = f"<p>{_esc(EXPLORATORY_NOTE)}</p>" if mode == "exploratory" else ""
            return (
                f"<h3>{_esc(title)}</h3>{note}"
                "<table><thead><tr><th>CWE</th><th>Selection source</th><th>Snapshot</th></tr></thead>"
                f"<tbody>{''.join(body)}</tbody></table>"
            )

        empty = not any(isinstance(item, dict) and item.get("mode") in {"advisory", "exploratory"} for item in cwes)
        opened = "" if empty else " open"
        return (
            f"<details id=\"coverage\"{opened}><summary>What was checked</summary>"
            f"{block('advisory', 'Advisory')}{block('exploratory', 'Exploratory')}</details>"
        )

    def _review_section(
        self,
        engagement_id: str,
        *,
        opened: bool,
        verdict: VerdictError | None = None,
    ) -> str:
        record = load_engagement(self.root, engagement_id)
        candidates = list_candidates(self.root, engagement_id)
        investigations = _investigations(self.root, engagement_id)
        reviewed = sum(1 for item in candidates if item.get("presentation_state") != "candidate")
        total = len(candidates)
        guided = False
        directory = engagement_dir(self.root, engagement_id)
        current = str(record.get("snapshot_sha256") or "")
        prefix = _intake_prefix(record)
        groups = []
        for investigation in investigations:
            cwe = str(investigation.get("cwe") or "")
            runs = [run for run in (investigation.get("runs") or []) if isinstance(run, dict)]
            if not isinstance(investigation.get("runs"), list):
                runs = []
            paths: set[str] = set()
            for run in runs:
                listed = run.get("candidate_paths") if isinstance(run.get("candidate_paths"), list) else []
                paths.update(str(item) for item in listed)
            matched = [
                candidate
                for candidate in candidates
                if str(candidate.get("cwe")) == cwe and str(candidate.get("file_path")) in paths
            ]
            ranks, likelihoods = _best_submission(directory, runs, cwe)
            matched.sort(
                key=lambda candidate: (
                    ranks.get(normalize_repo_path(str(candidate.get("file_path") or "")), 10**9),
                    str(candidate.get("file_path") or ""),
                )
            )
            exploratory = bool(investigation.get("exploratory"))
            note = _exploratory_notes(record) if exploratory else ""
            if not exploratory and matched:
                guided = True
            prepared = _named_run_traces(directory, runs, current)
            cards = "".join(
                self._candidate_card(
                    engagement_id,
                    candidate,
                    verdict,
                    rank_line=_card_rank(candidate, runs, ranks, likelihoods),
                    detail=_candidate_detail(
                        directory,
                        candidate,
                        prepared,
                        prefix=prefix,
                        exploratory=exploratory,
                    ),
                )
                for candidate in matched
            )
            empty = _no_candidate_suggestions(
                engagement_id,
                cwe,
                exploratory=exploratory,
                early=_early_end_word(_latest_run(runs)),
            ) if not paths else ""
            summaries = "".join(
                _activity_summary_html(
                    run.get("activity"),
                    extra=_run_detail_extra(engagement_id, investigation, run, ranks, likelihoods, directory),
                )
                for run in runs
            )
            count_line = ""
            if paths:
                counted = "1 candidate file" if len(paths) == 1 else f"{len(paths)} candidate files"
                count_line = f"<p>{counted}</p>"
            groups.append(
                "<section class=\"investigation-results\" "
                f"data-investigation=\"{_esc(investigation.get('id'))}\">"
                f"{_result_heading(investigation, runs)}{count_line}"
                f"{note}{empty}{summaries}{cards}</section>"
            )
        match_note = (
            f'<p class="prose" id="advisory-match-note">{_esc(REVIEW_MATCH_NOTE)}</p>' if guided else ""
        )
        if investigations or candidates:
            count = f'<p id="review-count">{reviewed} of {total} reviewed</p>'
            body = count + match_note + self._coverage_section(engagement_id) + "".join(groups)
            summary = f"{reviewed} of {total} reviewed"
        else:
            body = '<p>Run a check to get candidates.</p>' + self._coverage_section(engagement_id)
            summary = "Run a check to get candidates."
        change = f"/e/{engagement_id}?step=review" if candidates else ""
        return _step("review", "Review", body, opened=opened, summary=summary, change=change)

    def _candidate_card(
        self,
        engagement_id: str,
        candidate: dict[str, object],
        verdict: VerdictError | None = None,
        *,
        rank_line: str = "",
        detail: str = "",
    ) -> str:
        file_path = str(candidate["file_path"])
        cwe = str(candidate["cwe"])
        status = _status_label(str(candidate.get("presentation_state") or candidate.get("state")))
        stale = status == "stale"
        stale_mark = (
            "<p class=\"stale\">Stale verdict. Re-confirm against the current snapshot.</p>" if stale else ""
        )
        draft = verdict if verdict is not None and verdict.path == file_path and verdict.cwe == cwe else None
        chosen = draft.state if draft is not None else ""
        options = "".join(
            f'<option value="{_esc(item)}"{" selected" if item == chosen else ""}>{_esc(item)}</option>'
            for item in REVIEW_VERDICTS
        )
        contexts = advisory_contexts(self.root, engagement_id, candidate)
        evidence = _advisory_evidence(contexts)
        guard = _dismissal_fields(contexts, draft)
        note_text = _esc(draft.note) if draft is not None else ""
        return (
            "<article class=\"candidate\">"
            f"<h3 class=\"mono\">{_esc(file_path)}</h3>"
            f"<p>Status: {_esc(status)}</p>"
            f"<p>CWE: {cwe_ref(cwe, new_tab=True)}</p>"
            f"{rank_line}"
            f"{stale_mark}{detail}{evidence}"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/verdict\">"
            f"<input type=\"hidden\" name=\"path\" value=\"{_esc(file_path)}\">"
            f"<input type=\"hidden\" name=\"cwe\" value=\"{_esc(cwe)}\">"
            f"<label>Verdict <select name=\"state\" required>{options}</select></label>"
            f"{guard}"
            '<p class="env-hint" id="report-note-hint">Notes on confirmed candidates appear in the customer report.</p>'
            f"<label>Note <textarea name=\"note\" required>{note_text}</textarea></label>"
            f"{_field_error('note', draft)}"
            "<button type=\"submit\">Record verdict</button>"
            "</form></article>"
        )

    def _show_trace(
        self,
        engagement_id: str,
        investigation_id: str,
        run_text: str,
        *,
        download: bool,
    ) -> tuple[int, str, str] | tuple[int, str, str, dict[str, str]]:
        found = _lookup_run(self.root, engagement_id, investigation_id, run_text)
        if found is None:
            return _trace_not_found()
        _investigation, run = found
        directory = engagement_dir(self.root, engagement_id)
        activity = run.get("activity") if isinstance(run.get("activity"), dict) else {}
        trace_meta = activity.get("trace") if isinstance(activity.get("trace"), dict) else {}
        path = resolve_trace(directory / "antares-data" / "traces", str(trace_meta.get("name") or ""))
        if path is None:
            return _trace_not_found()
        try:
            events = read_trace(path)
        except (OSError, ValueError):
            return _trace_not_found()
        if download:
            lines = trace_meta.get("lines")
            source_lines = lines if isinstance(lines, int) and not isinstance(lines, bool) else 0
            document = trace_export_document(
                events,
                source_sha256=str(trace_meta.get("sha256") or ""),
                source_lines=source_lines,
            )
            filename = _trace_filename(engagement_id, investigation_id, run_text)
            return (
                200,
                document,
                "application/x-ndjson",
                {
                    "Cache-Control": "no-store",
                    "Content-Disposition": f'attachment; filename="{filename}"',
                },
            )
        record = load_engagement(self.root, engagement_id)
        actor = resolve_actor(record, None, _request_headers.get())
        page = _page_number()
        start = (page - 1) * _TRACE_PAGE
        shown = events[start : start + _TRACE_PAGE]
        previous = f'<a href="?page={page - 1}">Previous</a>' if page > 1 else ""
        following = f'<a href="?page={page + 1}">Next</a>' if start + _TRACE_PAGE < len(events) else ""
        download_href = f"/e/{_esc(engagement_id)}/runs/{_esc(investigation_id)}/{_esc(run_text)}/trace.jsonl"
        body = (
            f"{self._engagement_header(record)}"
            f"<h2>Trace</h2>"
            f"<p>{previous} {following}</p>"
            f'<p><a href="{download_href}">Download</a></p>'
            + "".join(_trace_event_html(event) for event in shown)
        )
        return 200, _layout("Trace", body, record=record, actor=actor), "text/html; charset=utf-8"

    def report_page(self, engagement_id: str) -> str:
        record = load_engagement(self.root, engagement_id)
        actor = resolve_actor(record, None, _request_headers.get())
        directory = engagement_dir(self.root, engagement_id)
        status = _read_status(directory)
        html_ready = (directory / "reports" / "assessment.html").is_file()
        final = html_ready and status.get("status") == "final"
        if final:
            banner = (
                f'<p class="notice" id="report-state">Finalized. Approved by '
                f"{_esc(status.get('actor'))} at {_esc(status.get('finalized_at'))}.</p>"
            )
        elif html_ready:
            banner = '<p class="notice" id="report-state">Draft</p>'
        else:
            banner = '<p class="notice" id="report-state">Not generated</p>'
        banner += _pdf_notice(directory)
        frame = ""
        if html_ready:
            frame = (
                f'<iframe sandbox title="Assessment" '
                f'src="/e/{_esc(engagement_id)}/preview/assessment"></iframe>'
            )
        body = (
            f"{self._engagement_header(record)}"
            f"{banner}"
            f"{self._report_actions(engagement_id, record, actor)}"
            f"{frame}"
        )
        return _layout("Assessment", body, record=record, steps=True, actor=actor)

    def _report_actions(self, engagement_id: str, record: dict[str, object], actor: str) -> str:
        people = _consultants(record)
        options = "".join(
            f'<option value="{_esc(person)}"{" selected" if person == actor else ""}>{_esc(person)}</option>'
            for person in people
        )
        report_path = default_export_destination(engagement_id, report_only=True, create=True)
        full_path = default_export_destination(engagement_id, report_only=False, create=False)
        access = export_access_warning()
        access_html = (
            f'<p class="notice" id="export-directory-warning">{_esc(access)}</p>' if access else ""
        )
        full_disabled = "" if record.get("state") == "closed" else " disabled"
        return (
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/reports/generate\">"
            "<button class=\"primary\" type=\"submit\">"
            "Builds the customer assessment and the developer remediation handoff.</button></form>"
            "<div class=\"report-finish\">"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/reports/finalize\">"
            f"<label>Approving consultant <select name=\"actor\">{options}</select></label>"
            "<p>Locks the report. Requires every candidate confirmed or not actionable.</p>"
            "<button type=\"submit\">Finalize</button></form>"
            f"{access_html}"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/export\">"
            f"<label>Output path <input id=\"export-output\" name=\"output\" required "
            f"value=\"{_esc(report_path)}\" data-report-path=\"{_esc(report_path)}\" "
            f"data-full-path=\"{_esc(full_path)}\"></label>"
            "<fieldset><legend>Export</legend>"
            '<label><input type="radio" name="bundle" value="report" checked> '
            "Report only, for the customer (assessment HTML, status, PDF if present)</label>"
            f'<label><input type="radio" name="bundle" value="full"{full_disabled}> '
            "Full package, for your records (redacted records, reports, and traces; no source code). "
            "Available after Close.</label>"
            "</fieldset>"
            "<details><summary>Advanced</summary>"
            "<label><input type=\"checkbox\" name=\"allow_draft\"> Allow draft</label>"
            "</details>"
            "<button type=\"submit\">Export</button></form>"
            "</div>"
        )

    def _report_section(
        self,
        engagement_id: str,
        record: dict[str, object],
        actor: str,
        *,
        opened: bool,
    ) -> str:
        directory = engagement_dir(self.root, engagement_id)
        draft = assessment_is_draft(directory)
        html_ready = (directory / "reports" / "assessment.html").is_file()
        state = "Draft" if draft else "Final" if html_ready else "Not generated"
        body = (
            f"<p>Assessment status: {_esc(state)}</p>"
            f'<p><a href="/e/{_esc(engagement_id)}/report">Open the assessment</a></p>'
        )
        change = f"/e/{engagement_id}?step=report" if html_ready or opened else ""
        return _step(
            "reports",
            "Report",
            body,
            opened=opened,
            summary=f"Assessment status: {state}",
            change=change if not opened else "",
        )

    def _close_section(self, engagement_id: str, record: dict[str, object], *, opened: bool) -> str:
        remaining = exports_still_on_disk(self.root, engagement_id)
        listed = (
            "".join(f"<li class=\"mono\">{_esc(path)}</li>" for path in remaining)
            or "<li>No exports recorded on disk.</li>"
        )
        close = ""
        if record.get("state") == "open":
            close = (
                "<p>Ends the engagement. No further checks or verdicts.</p>"
                f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/close\">"
                "<button type=\"submit\">Close</button></form>"
            )
        purge = (
            "<p>Deletes the customer's code from this machine. Exports are kept.</p>"
            f"<form method=\"post\" action=\"/e/{_esc(engagement_id)}/purge\">"
            "<p>Exports still on disk are left in place. Confirm they have been handled before purge.</p>"
            f"<ul id=\"purge-exports\">{listed}</ul>"
            "<label><input type=\"checkbox\" name=\"confirm_exports_handled\"> "
            "Confirm exports have been handled</label>"
            "<button class=\"btn-danger\" type=\"submit\">Purge</button></form>"
        )
        summary = "Closed." if record.get("state") == "closed" else "Open."
        return _step(
            "close",
            "Close",
            f"{close}<div class=\"purge-block\">{purge}</div>",
            opened=opened,
            summary=summary,
        )

    def _preview(self, engagement_id: str, name: str, content_type: str) -> tuple[int, str | bytes, str]:
        path = engagement_dir(self.root, engagement_id) / "reports" / name
        if not path.is_file():
            raise EngagementError("Generate the assessment before previewing it")
        data = path.read_bytes()
        if name.endswith(".html"):
            return (
                200,
                data.decode("utf-8"),
                content_type,
                {
                    "Content-Security-Policy": (
                        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'"
                    ),
                    "X-Frame-Options": "SAMEORIGIN",
                },
            )
        return 200, data, content_type


def main(argv: list[str] | None = None) -> int:
    from astrolabe.runner import cleanup_orphaned_relays

    cleanup_orphaned_relays()
    parser = argparse.ArgumentParser(prog="astrolabe ui")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--engagements-root")
    args = parser.parse_args(argv)
    root = Path(args.engagements_root) if args.engagements_root else engagements_root()
    server = App(root).serve(args.port)
    print(f"Astrolabe UI at http://{LOOPBACK}:{server.server_address[1]}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


def _advisory_evidence(contexts: list[AdvisoryContext]) -> str:
    blocks = []
    for item in contexts:
        if item.match.kind == "path":
            pill = (
                '<p><span class="advisory-pill">Advisory names this file</span> '
                f"{_esc(item.match.source)}</p>"
            )
        elif item.match.kind == "filename":
            pill = (
                '<p><span class="advisory-pill">Advisory mentions this filename</span> '
                f"{_esc(item.match.source)}</p>"
            )
        else:
            pill = ""
        excerpt = (
            f'<p class="advisory-excerpt">{_esc(item.match.excerpt)}</p>' if item.match.excerpt else ""
        )
        blocks.append(
            '<div class="advisory-context">'
            f"<p>{_esc(item.label)}</p>"
            f"<p>{_esc(item.summary)}</p>"
            f"{excerpt}{pill}"
            "<details><summary>Advisory text</summary>"
            f"<p>{_esc(item.full_text)}</p></details>"
            "</div>"
        )
    return "".join(blocks)


def _dismissal_fields(contexts: list[AdvisoryContext], draft: VerdictError | None) -> str:
    if not contexts:
        return ""
    checked = " checked" if draft is not None and draft.confirmed else ""
    hint = ""
    if any(item.names_file for item in contexts):
        hint = f'<p class="env-hint" id="note-hint">{_esc(NOTE_HINT)}</p>'
    return (
        f'<label><input type="checkbox" name="advisory_compared"{checked}> {_esc(COMPARE_LABEL)}</label>'
        f"{_field_error('confirmed', draft)}"
        f"{hint}"
    )


def _field_error(name: str, draft: VerdictError | None) -> str:
    if draft is None or name not in draft.errors:
        return ""
    return f'<p class="field-error" id="{name}-error">{_esc(draft.errors[name])}</p>'


def _plan_refusal(exc: EngagementError) -> bool:
    text = str(exc)
    if text in {INTAKE_BUSY, LAUNCH_BUSY, PLAN_STALE}:
        return True
    return "investigations need confirmation before they run." in text


def _picker_for_source(source: str) -> str:
    if source in {"recommended", "top25", "owasp", "search"}:
        return source
    return "advisory"


def _query_param(name: str) -> str | None:
    query = _request_query.get()
    if not query:
        return None
    values = query.get(name) or []
    if not values:
        return None
    return values[0]


def _top_ids(rows: list[dict[str, object]]) -> set[str]:
    limit = preselect_limit()
    chosen: list[str] = []
    order = sorted(range(len(rows)), key=lambda index: (-int(rows[index].get("score") or 0), index))
    for index in order:
        row = rows[index]
        if int(row.get("score") or 0) > 0 and not row.get("excluded_only"):
            chosen.append(str(row["cwe"]))
            if len(chosen) >= limit:
                break
    return set(chosen)


def _row_checked(rows: list[dict[str, object]], sel: str | None, *, allow_top: bool) -> set[str]:
    known = {str(row["cwe"]) for row in rows}
    excluded = {str(row["cwe"]) for row in rows if row.get("excluded_only")}
    if sel is None:
        chosen = {str(row["cwe"]) for row in rows if row.get("preselect")}
    elif sel == "none" or (sel == "top" and not allow_top):
        chosen = set()
    elif sel == "top":
        chosen = _top_ids(rows)
    else:
        chosen = set()
        for part in sel.split(","):
            cwe = part.strip().upper()
            if cwe in known:
                chosen.add(cwe)
    return chosen - excluded


def _advisory_checked(listed: list[str], extra: list[str], sel: str | None) -> set[str]:
    if sel is None:
        return set(listed)
    if sel in {"none", "top"}:
        return set()
    available = {item.upper() for item in listed + extra}
    chosen = set()
    for part in sel.split(","):
        cwe = part.strip().upper()
        if cwe in available:
            chosen.add(cwe)
    return chosen


def _callout(message: str) -> str:
    return f'<p class="callout" role="status">{_esc(message)}</p>'


def _run_plan_button(engagement_id: str, picker: str) -> str:
    if picker in {"recommended", "top25", "owasp"}:
        return (
            f'<form method="post" action="/e/{_esc(engagement_id)}/select/explore">'
            f'<input type="hidden" name="picker" value="{_esc(picker)}">'
            "<button type=\"submit\">Run plan</button></form>"
        )
    if picker == "search":
        return (
            f'<form method="post" action="/e/{_esc(engagement_id)}/select/explore">'
            '<input type="hidden" name="picker" value="search">'
            "<button type=\"submit\">Run plan</button></form>"
        )
    return (
        f'<form method="post" action="/e/{_esc(engagement_id)}/select/advisory">'
        "<button type=\"submit\">Run plan</button></form>"
    )


def _breadcrumb(engagement_id: str, picker: str) -> str:
    parts = [
        f'<a href="/e/{_esc(engagement_id)}"><span class="mono">{_esc(engagement_id)}</span></a>',
        f'<a href="/e/{_esc(engagement_id)}?step=investigate">Investigate</a>',
    ]
    if picker in PLAN_LABEL:
        parts.append(
            f'<a href="/e/{_esc(engagement_id)}/plan/{_esc(picker)}">{_esc(PLAN_LABEL[picker])}</a>'
        )
    separator = ' <span aria-hidden="true">›</span> '
    return f'<nav class="plan-crumb" aria-label="Breadcrumb">{separator.join(parts)}</nav>'


def _plan_tabs(engagement_id: str, picker: str) -> str:
    tabs = []
    for name in PLAN_ORDER:
        label = PLAN_LABEL[name]
        current = ' aria-current="page"' if name == picker else ""
        if name in {"recommended", "top25", "owasp"}:
            tabs.append(
                f'<form method="post" action="/e/{_esc(engagement_id)}/select/explore">'
                f'<input type="hidden" name="picker" value="{name}">'
                f'<button type="submit"{current}>{label}</button></form>'
            )
        else:
            tabs.append(f'<a href="/e/{_esc(engagement_id)}/plan/{name}"{current}>{label}</a>')
    return f'<nav class="plan-tabs" aria-label="Check source">{"".join(tabs)}</nav>'


def _advisory_forms(engagement_id: str, *, run_plan: bool, prefill: str = "") -> str:
    lookup = "Run plan" if run_plan else "Look up advisories"
    return (
        f'<form method="post" action="/e/{_esc(engagement_id)}/select/advisory">'
        f'<label>CVE or GHSA ids <textarea name="ids">{_esc(prefill)}</textarea></label>'
        f"<button type=\"submit\">{lookup}</button></form>"
        "<h2>Paste advisory text</h2>"
        f'<form method="post" action="/e/{_esc(engagement_id)}/select/advisory">'
        "<label>Title <input name=\"title\"></label>"
        "<label>Advisory text <textarea name=\"advisory_text\" required></textarea></label>"
        "<button type=\"submit\">Use pasted advisory</button></form>"
    )


def _plan_choice_row(value: str, cwe: str, *, checked: bool, child: bool = False) -> str:
    name = cwe_name(cwe)
    mark = " checked" if checked else ""
    kind = " cwe-child" if child else ""
    abstraction = cwe_abstraction(cwe)
    pill = _pill(abstraction, "muted") if abstraction else ""
    return (
        f'<tr class="{kind.strip()}" data-plan-row data-cwe="{_esc(cwe)}" data-name="{_esc(name)}">'
        f'<td><label class="{kind.strip()}"><input type="checkbox" name="choice" value="{_esc(value)}"{mark}> '
        f'{_esc(name)}</label> {cwe_ref(cwe, new_tab=True)}</td>'
        f'<td>{cwe_ref(cwe, new_tab=True)}</td>'
        f"<td>{_esc(name)}</td><td>{pill}</td><td></td><td></td></tr>"
    )


def _evidence_html(row: dict[str, object]) -> str:
    raw = str(row.get("evidence") or "")
    if row.get("excluded_only"):
        return f"<p>{_esc(raw)}</p><details><summary>Raw evidence</summary><p>{_esc(raw)}</p></details>"
    reasons = [str(item) for item in row.get("reasons") or [] if isinstance(row.get("reasons"), list)]
    if not isinstance(row.get("reasons"), list):
        reasons = []
    else:
        reasons = [str(item) for item in row["reasons"] if str(item)]
    evidence_paths = row.get("evidence_paths") if isinstance(row.get("evidence_paths"), list) else []
    paths: list[str] = []
    mixed: list[str] = []
    for item in evidence_paths:
        fragment = str(item).strip()
        if not fragment:
            continue
        tokens = _PATH_TOKEN.findall(fragment)
        if len(tokens) == 1 and fragment == tokens[0]:
            if tokens[0] not in paths:
                paths.append(tokens[0])
            continue
        mixed.append(fragment)
        for token in tokens:
            if token not in paths:
                paths.append(token)
    path_html = ""
    if paths:
        path_html = "<ul class=\"plan-paths\">" + "".join(f'<li class="mono">{_esc(path)}</li>' for path in paths) + "</ul>"
    mixed_html = "".join(f"<p>{_esc(item)}</p>" for item in mixed)
    visible = "".join(f"<p>{_esc(item)}</p>" for item in reasons[:3])
    extra = reasons[3:]
    more = ""
    if extra:
        more = (
            f"<details><summary>+{len(extra)} more</summary>"
            + "".join(f"<p>{_esc(item)}</p>" for item in extra)
            + "</details>"
        )
    raw_html = f"<details><summary>Raw evidence</summary><p>{_esc(raw)}</p></details>"
    return path_html + mixed_html + visible + more + raw_html


def _mitre_href(cwe: str) -> str:
    number = cwe.upper().removeprefix("CWE-")
    if number.isdigit():
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    return "https://cwe.mitre.org/"


def cwe_ref(cwe: str, *, new_tab: bool = False) -> str:
    raw = "" if cwe is None else str(cwe).strip()
    if not raw:
        return ""
    canonical = cwe_catalog.canonical_cwe_id(raw)
    entry = cwe_catalog.catalog_entry(canonical) if canonical else None
    if canonical is None or entry is None:
        return f"<code>{_esc(raw)}</code>"
    blank = ' target="_blank" rel="noopener"' if new_tab else ""
    title = cwe_catalog.cwe_title(entry)
    return (
        f'<a class="cwe-ref" href="/cwe/{_esc(canonical)}"{blank} title="{_esc(title)}">{_esc(canonical)}</a>'
    )


def _cwe_query(name: str) -> str:
    value = _query_param(name)
    return "" if value is None else value


def _cwe_page_href(query: str, abstraction: str, view: str, page: int) -> str:
    params = urllib.parse.urlencode(
        {"q": query, "abstraction": abstraction, "view": view, "page": str(page)}
    )
    return f"/cwe?{params}"


def _cwe_index() -> str:
    catalog = cwe_catalog.load_cwe_catalog()
    if catalog is None:
        return _layout("CWE dictionary", f"<h1>CWE dictionary</h1><p>{_esc(cwe_catalog.CATALOG_MISSING)}</p>")
    query = _cwe_query("q")[: cwe_catalog.QUERY_LIMIT]
    abstraction = _cwe_query("abstraction")
    view = _cwe_query("view")
    chosen_abstraction = abstraction if abstraction in cwe_catalog.ABSTRACTIONS else ""
    chosen_view = view if view in cwe_catalog.VIEWS else ""
    rows = cwe_catalog.filter_entries(query, chosen_abstraction, chosen_view)
    total_pages = max(1, (len(rows) + cwe_catalog.PAGE_SIZE - 1) // cwe_catalog.PAGE_SIZE)
    page = cwe_catalog.clamp_page(_cwe_query("page"), total_pages)
    start = (page - 1) * cwe_catalog.PAGE_SIZE
    visible = rows[start : start + cwe_catalog.PAGE_SIZE]
    abstraction_options = ['<option value="">Any</option>']
    for name in cwe_catalog.ABSTRACTIONS:
        selected = " selected" if name == chosen_abstraction else ""
        abstraction_options.append(f'<option value="{name}"{selected}>{name}</option>')
    view_options = ['<option value="">Any</option>']
    for name in cwe_catalog.VIEWS:
        selected = " selected" if name == chosen_view else ""
        view_options.append(
            f'<option value="{name}"{selected}>{_esc(cwe_catalog.VIEW_LABELS[name])}</option>'
        )
    body_rows = []
    for entry in visible:
        cwe_id = str(entry.get("id") or "")
        name = str(entry.get("name") or "")
        description = cwe_catalog.truncate_description(str(entry.get("description") or ""))
        pill = _pill(str(entry.get("abstraction") or ""), "muted")
        body_rows.append(
            "<tr>"
            f"<td>{cwe_ref(cwe_id)}</td>"
            f"<td>{_esc(name)}</td>"
            f"<td>{pill}</td>"
            f'<td class="cwe-desc">{_esc(description)}</td>'
            "</tr>"
        )
    previous = ""
    if page > 1:
        previous = f'<a href="{_esc(_cwe_page_href(query, chosen_abstraction, chosen_view, page - 1))}">Previous</a>'
    following = ""
    if page < total_pages:
        following = f'<a href="{_esc(_cwe_page_href(query, chosen_abstraction, chosen_view, page + 1))}">Next</a>'
    version = str(catalog.get("version") or "")
    released = str(catalog.get("release_date") or "")
    body = (
        "<h1>CWE dictionary</h1>"
        '<form method="get" action="/cwe">'
        f'<label>Search <input type="search" name="q" value="{_esc(query)}" maxlength="100"></label>'
        f'<label>Abstraction <select name="abstraction">{"".join(abstraction_options)}</select></label>'
        f'<label>View <select name="view">{"".join(view_options)}</select></label>'
        "<button type=\"submit\">Apply</button></form>"
        f"<p>{len(rows)} matched</p>"
        "<table><thead><tr><th>ID</th><th>Name</th><th>Abstraction</th><th>Description</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
        f"<p>Page {page} of {total_pages} {previous} {following}</p>"
        "<p>CWE™ content © The MITRE Corporation. Used under the CWE Terms of Use.</p>"
        f"<p>MITRE CWE {_esc(version)}, released {_esc(released)}.</p>"
    )
    return _layout("CWE dictionary", body)


def _cwe_entry_response(raw: str) -> tuple[int, str, str] | tuple[int, str, str, dict[str, str]]:
    canonical = cwe_catalog.canonical_cwe_id(raw)
    if canonical is None:
        return 404, _layout("Not found", "<p>That page is not part of an engagement.</p>"), "text/html; charset=utf-8"
    if raw != canonical:
        location = f"/cwe/{canonical}"
        body = _layout("CWE dictionary", f'<p><a href="{_esc(location)}">Continue</a></p>')
        return 303, body, "text/html; charset=utf-8", {"Location": location}
    entry = cwe_catalog.catalog_entry(canonical)
    if entry is None:
        return (
            404,
            _layout("Not found", "<p>Not in the local CWE catalog.</p>"),
            "text/html; charset=utf-8",
        )
    return 200, _cwe_entry(entry), "text/html; charset=utf-8"


def _cwe_link_list(values: object) -> str:
    if not isinstance(values, list) or not values:
        return "<p>None.</p>"
    items = "".join(f"<li>{cwe_ref(str(item))}</li>" for item in values)
    return f"<ul>{items}</ul>"


def _cwe_entry(entry: dict[str, object]) -> str:
    cwe_id = str(entry.get("id") or "")
    name = str(entry.get("name") or "")
    abstraction = str(entry.get("abstraction") or "")
    note = f'<p class="class-note">{_esc(CLASS_NOTE)}</p>' if abstraction in {"Class", "Pillar"} else ""
    views = entry.get("views") if isinstance(entry.get("views"), list) else []
    view_items = "".join(
        f"<li>{_esc(cwe_catalog.VIEW_LABELS[str(item)])}</li>"
        for item in views
        if str(item) in cwe_catalog.VIEW_LABELS
    )
    view_html = f"<ul>{view_items}</ul>" if view_items else "<p>None.</p>"
    mitre = _mitre_href(cwe_id)
    body = (
        f"<h1><span class=\"mono\">{_esc(cwe_id)}</span> {_esc(name)}</h1>"
        f"<p>{_pill(abstraction, 'muted')}</p>"
        f"<p>{_esc(entry.get('description') or '')}</p>"
        f"{note}"
        f"<h2>{_esc(cwe_catalog.PARENTS_LABEL)}</h2>"
        f"{_cwe_link_list(entry.get('parents'))}"
        "<h2>Children</h2>"
        f"{_cwe_link_list(entry.get('children'))}"
        "<h2>Views</h2>"
        f"{view_html}"
        f"<p>{_esc(mitre)}</p>"
    )
    return _layout(cwe_id, body)



def _exploratory_notes(record: dict[str, object]) -> str:
    single = ""
    if record.get("label") == "single-file":
        single = f"<p id=\"single-file-note\">{_esc(SINGLE_FILE_NOTE)}</p>"
    return f"<p class=\"exploratory-note\">{_esc(EXPLORATORY_NOTE)}</p>{single}"


def _cwe_choice(value: str, cwe: str, *, checked: bool, child: bool = False) -> str:
    mark = " checked" if checked else ""
    kind = " class=\"cwe-child\"" if child else ""
    return (
        f"<label{kind}><input type=\"checkbox\" name=\"choice\" value=\"{_esc(value)}\"{mark}> "
        f"{_esc(cwe_name(cwe))}</label> {cwe_ref(cwe, new_tab=True)}"
    )


def _search_choice_lines(source: str, query: str) -> list[str]:
    return [
        _cwe_choice(f"{source}|{item['id']}", item["id"], checked=False)
        for item in search_cwes(query)
    ]


def _advisory_ids(text: str) -> list[str]:
    found = [item for item in text.replace(",", " ").split() if item]
    if not found:
        raise EngagementError("Enter a CVE or GHSA id")
    for advisory_id in found:
        if not ADVISORY_ID_PATTERN.fullmatch(advisory_id):
            raise EngagementError(f"Advisory id must be a CVE or GHSA id: {advisory_id}")
    return found


def _items_from_form(form: Form) -> list[dict[str, object]]:
    raw_items = form.values("item")
    if raw_items:
        items = [_item_from_json(value) for value in raw_items]
    else:
        choices = form.values("choice")
        if not choices and form.get("source") and form.values("cwe"):
            choices = [f"{form.get('source')}|{cwe}" for cwe in form.values("cwe")]
        if not choices:
            raise EngagementError("Choose at least one CWE")
        items = []
        seen: set[tuple[str, str]] = set()
        for choice in choices:
            if "|" not in choice:
                raise EngagementError("Choose at least one CWE")
            source, cwe = choice.split("|", 1)
            key = (source, cwe)
            if key in seen:
                continue
            seen.add(key)
            items.append(
                _normalize_item(
                    {
                        "source": source,
                        "cwe": cwe,
                        "advisory_text": form.get("advisory_text"),
                        "title": form.get("title"),
                    }
                )
            )
    if not items:
        raise EngagementError("Choose at least one CWE")
    for cwe_values in (item["cwe"] for item in items):
        if not isinstance(cwe_values, str) or "," in cwe_values:
            raise EngagementError("Each investigation takes one CWE")
    return items


def _item_from_json(value: str) -> dict[str, object]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise EngagementError("A launch item is not an object") from exc
    if not isinstance(payload, dict):
        raise EngagementError("A launch item is not an object")
    return _normalize_item(payload)


def _normalize_item(payload: dict[str, object]) -> dict[str, object]:
    source = selection_source_for(str(payload.get("source") or ""))
    cwe = str(payload.get("cwe") or "").strip().upper()
    if cwe.isdigit():
        cwe = f"CWE-{cwe}"
    number = cwe.removeprefix("CWE-")
    if not cwe.startswith("CWE-") or not number.isdigit():
        raise EngagementError(f"CWE id must look like CWE-89: {cwe}")
    exploratory = source in {"recommended", "top25", "owasp", "search"}
    advisory_text = str(payload.get("advisory_text") or "").strip()
    if source == "pasted" and not advisory_text:
        raise EngagementError("Pasted advisory text is empty")
    title = str(payload.get("title") or "").strip()
    return {
        "source": source,
        "cwe": cwe,
        "mode": "exploratory" if exploratory else "advisory",
        "advisory_id": source if ADVISORY_ID_PATTERN.fullmatch(source) else None,
        "advisory_text": advisory_text if source == "pasted" else None,
        "title": title or None,
    }


def _item_json(item: dict[str, object]) -> str:
    return json.dumps(
        {
            "source": item["source"],
            "cwe": item["cwe"],
            "advisory_text": item.get("advisory_text") or "",
            "title": item.get("title") or "",
        }
    )


def _require_cached_advisories(items: list[dict[str, object]]) -> None:
    cache = advisory_cache_dir()
    for item in items:
        advisory_id = item.get("advisory_id")
        if isinstance(advisory_id, str) and not (cache / f"{advisory_id}.json").is_file():
            raise EngagementError(f"Advisory {advisory_id} is not in the local cache")


def _new_queue(items: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in items:
        rows.append(
            {
                "id": f"q-{uuid.uuid4().hex[:12]}",
                "status": "queued",
                "investigation_id": "",
                "elapsed_seconds": None,
                "source": item["source"],
                "cwe": item["cwe"],
                "mode": item["mode"],
                "advisory_id": item.get("advisory_id"),
                "advisory_text": item.get("advisory_text"),
                "title": item.get("title"),
            }
        )
    return rows


def _queue_actions(engagement_id: str, item: dict[str, object], *, idle: bool) -> str:
    status = str(item.get("status") or "")
    queue_id = _esc(item.get("id"))
    forms: list[str] = []
    if idle and status == "queued":
        forms.append(
            f'<form method="post" action="/e/{_esc(engagement_id)}/start">'
            f'<input type="hidden" name="queue_id" value="{queue_id}">'
            '<button type="submit">Start</button></form>'
        )
    if idle and status == "cancelled":
        forms.append(
            f'<form method="post" action="/e/{_esc(engagement_id)}/start">'
            f'<input type="hidden" name="queue_id" value="{queue_id}">'
            '<button type="submit">Restart</button></form>'
        )
    if status in {"queued", "running"}:
        forms.append(
            f'<form method="post" action="/e/{_esc(engagement_id)}/cancel">'
            f'<input type="hidden" name="queue_id" value="{queue_id}">'
            '<button type="submit">Cancel</button></form>'
        )
    if not forms:
        return ""
    return f'<div class="row-actions">{"".join(forms)}</div>'


def _queue_is_running(root: Path, engagement_id: str) -> bool:
    try:
        rows = _read_queue(engagement_dir(root, engagement_id))
    except (EngagementError, OSError):
        return False
    return any(item.get("status") == "running" for item in rows)


def _queue_has_work(root: Path, engagement_id: str) -> bool:
    try:
        rows = _read_queue(engagement_dir(root, engagement_id))
    except (EngagementError, OSError):
        return False
    return any(item.get("status") in {"queued", "running"} for item in rows)


def _read_queue(directory: Path) -> list[dict[str, object]]:
    path = directory / "launch-queue.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _write_queue(directory: Path, rows: list[dict[str, object]]) -> None:
    path = directory / "launch-queue.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _investigations(root: Path, engagement_id: str) -> list[dict[str, object]]:
    path = engagement_dir(root, engagement_id) / "investigations.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _verdict_counts(root: Path, engagement_id: str) -> dict[str, int]:
    counts = {label: 0 for label in ("pending review", "confirmed", "not_actionable", "needs_more_info", "stale")}
    try:
        candidates = list_candidates(root, engagement_id)
    except EngagementError:
        return counts
    for candidate in candidates:
        label = _status_label(str(candidate.get("presentation_state") or candidate.get("state")))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _status_label(state: str) -> str:
    if state == "candidate":
        return "pending review"
    return state


def _modes_for_candidates(root: Path, engagement_id: str) -> dict[tuple[str, str], str]:
    modes: dict[tuple[str, str], str] = {}
    for investigation in _investigations(root, engagement_id):
        mode = "exploratory" if investigation.get("exploratory") else "advisory-guided"
        cwe = str(investigation.get("cwe") or "")
        runs = investigation.get("runs") if isinstance(investigation.get("runs"), list) else []
        for run in runs:
            if not isinstance(run, dict):
                continue
            paths = run.get("candidate_paths") if isinstance(run.get("candidate_paths"), list) else []
            for file_path in paths:
                modes[(str(file_path), cwe)] = mode
    return modes


def _progress_html(directory: Path) -> str:
    activity = load_activity(directory)
    detail, fresh = progress_detail(activity)
    raw_detail = str(activity.get("detail") or "") if activity else ""
    mark = '<span class="run-mark" aria-hidden="true"></span>' if fresh else ""
    generating = model_server_line(raw_detail, fetch_generation())
    generated = f"<p>{_esc(generating)}</p>" if generating else ""
    last = str(activity.get("last_action") or "") if activity else ""
    last_html = f'<p id="last-action">{_esc(last)}</p>' if last else ""
    return (
        '<div id="progress">'
        f'<p class="is-running">{mark}Investigation running. {_esc(detail)}</p>'
        f"{last_html}"
        f"<p>{_esc(counter_line(activity))}</p>"
        f"{generated}"
        "</div>"
    )


def _activity_summary_html(activity: object, *, extra: str = "") -> str:
    if not isinstance(activity, dict):
        return ""
    counters = activity.get("counters") if isinstance(activity.get("counters"), dict) else {}
    loop = activity.get("loop_control") if isinstance(activity.get("loop_control"), dict) else {}
    phases = activity.get("phases") if isinstance(activity.get("phases"), dict) else {}
    trace = activity.get("trace") if isinstance(activity.get("trace"), dict) else {}
    phase_line = ", ".join(f"{_esc(name)} {_esc(stamp)}" for name, stamp in phases.items())
    return (
        '<details class="activity-summary"><summary>Run details</summary>'
        "<table><tbody>"
        f"<tr><td>Start {_esc(activity.get('start'))}. End {_esc(activity.get('end'))}.</td></tr>"
        f"<tr><td>Exit status: {_esc(activity.get('exit_status'))}</td></tr>"
        f"<tr><td>Phases: {phase_line}</td></tr>"
        f"<tr><td>{_esc(counter_line({'counters': counters, 'loop_control': loop}))}</td></tr>"
        f"<tr><td>Trace {_esc(trace.get('name'))}, {_esc(trace.get('lines'))} lines, "
        f"SHA-256 {_esc(trace.get('sha256'))}</td></tr>"
        "</tbody></table>"
        f"{extra}</details>"
    )


_TRACE_PAGE = 200
_EARLIER_SNAPSHOT = "Search matches are from an earlier snapshot. Re-run to refresh."
_NO_CANDIDATES = "No candidate files. No candidate is not evidence of no weakness."


def _intake_prefix(record: dict[str, object]) -> str | None:
    intake = record.get("intake")
    if not isinstance(intake, dict):
        return None
    prefix = intake.get("stripped_prefix")
    return prefix if isinstance(prefix, str) and prefix else None


def _latest_run(runs: list[dict[str, object]]) -> dict[str, object] | None:
    return runs[-1] if runs else None


def _result_heading(investigation: dict[str, object], runs: list[dict[str, object]]) -> str:
    cwe = str(investigation.get("cwe") or "")
    mode = "exploratory" if investigation.get("exploratory") else "advisory-guided"
    latest = _latest_run(runs)
    outcome = ""
    duration = ""
    if isinstance(latest, dict):
        activity = latest.get("activity") if isinstance(latest.get("activity"), dict) else {}
        status = str(activity.get("exit_status") or "")
        if status:
            outcome = f"<p>Outcome: {_esc(status)}</p>"
        elapsed = latest.get("elapsed_seconds")
        if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
            duration = f"<p>Duration: {_esc(elapsed)} seconds</p>"
    return (
        f"<h3>{cwe_ref(cwe, new_tab=True)} {_esc(cwe_name(cwe))}</h3>"
        f"<p>{_esc(mode)}</p>{outcome}{duration}"
    )


def _early_end_word(run: dict[str, object] | None) -> str:
    if not isinstance(run, dict):
        return ""
    activity = run.get("activity") if isinstance(run.get("activity"), dict) else {}
    status = str(activity.get("exit_status") or "")
    loop = activity.get("loop_control") if isinstance(activity.get("loop_control"), dict) else {}
    budget = loop.get("budget")
    if status in {"failed", "cancelled"}:
        return status
    if isinstance(budget, int) and not isinstance(budget, bool) and budget > 0:
        return "budget"
    return ""


def _cached_advisory_ids() -> list[str]:
    cache = advisory_cache_dir()
    if not cache.is_dir():
        return []
    return sorted(path.stem for path in cache.glob("*.json") if ADVISORY_ID_PATTERN.fullmatch(path.stem))


def _no_candidate_suggestions(
    engagement_id: str,
    cwe: str,
    *,
    exploratory: bool,
    early: str,
) -> str:
    parts = [f"<p>{_esc(_NO_CANDIDATES)}</p>"]
    if exploratory:
        for advisory_id in _cached_advisory_ids():
            href = f"/e/{engagement_id}/plan/advisory?id={urllib.parse.quote(advisory_id)}"
            parts.append(f'<p><a href="{_esc(href)}">Advisory-guided check for {_esc(advisory_id)}</a></p>')
    if is_broad_cwe(cwe):
        parts.append(f'<p class="class-note">{_esc(CLASS_NOTE)}</p>')
        children = [
            child
            for child in base_variant_children(cwe)
            if cwe_abstraction(child) in {"Base", "Variant"}
        ]
        if children:
            links = []
            for child in children:
                href = f"/e/{engagement_id}/plan/search?q={urllib.parse.quote(child)}"
                links.append(f'<li><a href="{_esc(href)}">{_esc(child)}</a></li>')
            parts.append("<ul>" + "".join(links) + "</ul>")
    if early:
        parts.append(f"<p>The run ended early ({_esc(early)}); the search was incomplete.</p>")
    return "".join(parts)


def _best_submission(
    directory: Path,
    runs: list[dict[str, object]],
    cwe: str,
) -> tuple[dict[str, int], dict[str, str]]:
    ranks: dict[str, int] = {}
    likelihoods: dict[str, str] = {}
    for run in runs:
        relative = run.get("report")
        if not isinstance(relative, str) or not relative:
            continue
        path = resolve_inside(directory, relative)
        if path is None or not path.is_file():
            continue
        try:
            payload = read_report(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        rows = payload.get("findings")
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            cwes = row.get("cwe_ids") if isinstance(row.get("cwe_ids"), list) else []
            if cwe not in {str(item) for item in cwes}:
                continue
            file_path = normalize_repo_path(str(row.get("file_path") or ""))
            if not file_path:
                continue
            rank = row.get("submission_rank")
            rank_value = rank if isinstance(rank, int) and not isinstance(rank, bool) else None
            labeled = row.get("mitre_likelihood")
            line = ""
            if isinstance(labeled, dict):
                line = (
                    f"<p>{_esc(labeled.get('label') or MITRE_LIKELIHOOD_LABEL)}: "
                    f"{_esc(labeled.get('value'))}</p>"
                )
            previous = ranks.get(file_path)
            if rank_value is not None and (previous is None or rank_value < previous):
                ranks[file_path] = rank_value
                if line:
                    likelihoods[file_path] = line
            elif file_path not in likelihoods and line:
                likelihoods[file_path] = line
    return ranks, likelihoods


def _submitted_many(runs: list[dict[str, object]], file_path: str) -> bool:
    for run in runs:
        listed = run.get("candidate_paths") if isinstance(run.get("candidate_paths"), list) else []
        paths = [str(item) for item in listed]
        if file_path in paths and len(paths) > 1:
            return True
    return False


def _card_rank(
    candidate: dict[str, object],
    runs: list[dict[str, object]],
    ranks: dict[str, int],
    likelihoods: dict[str, str],
) -> str:
    file_path = str(candidate.get("file_path") or "")
    if not _submitted_many(runs, file_path):
        return ""
    key = normalize_repo_path(file_path)
    rank = ranks.get(key)
    return (
        f"<p>Rank: {_esc(rank if rank is not None else 'not recorded')}</p>"
        f"{likelihoods.get(key, '')}"
    )


def _named_run_traces(
    directory: Path,
    runs: list[dict[str, object]],
    current_snapshot: str,
) -> list[tuple[dict[str, object], list[dict[str, object]], bool]]:
    prepared: list[tuple[dict[str, object], list[dict[str, object]], bool]] = []
    traces = directory / "antares-data" / "traces"
    for run in runs:
        activity = run.get("activity") if isinstance(run.get("activity"), dict) else {}
        trace_meta = activity.get("trace") if isinstance(activity.get("trace"), dict) else {}
        name = trace_meta.get("name")
        events: list[dict[str, object]] = []
        if isinstance(name, str) and name:
            path = resolve_trace(traces, name)
            if path is not None:
                try:
                    loaded = read_trace(path)
                except (OSError, ValueError):
                    loaded = []
                events = [event for event in loaded if isinstance(event, dict)]
        snapshot = str(run.get("snapshot_sha256") or "")
        prepared.append((run, events, bool(current_snapshot) and snapshot == current_snapshot))
    return prepared


def _candidate_detail(
    directory: Path,
    candidate: dict[str, object],
    prepared: list[tuple[dict[str, object], list[dict[str, object]], bool]],
    *,
    prefix: str | None,
    exploratory: bool,
) -> str:
    file_path = str(candidate.get("file_path") or "")
    cwe = str(candidate.get("cwe") or "")
    numbers: list[int] = []
    stale = False
    title = ""
    for _run, events, current in prepared:
        if not events:
            continue
        if not title:
            title = model_title(events, file_path, prefix)
        hits = line_hits(events, file_path, prefix)
        if not hits:
            continue
        if current:
            for number in hits:
                if number not in numbers:
                    numbers.append(number)
                if len(numbers) >= 5:
                    break
        else:
            stale = True
    line_number = numbers[0] if numbers else None
    return (
        _look_for_html(file_path, cwe)
        + _mitigation_html(cwe)
        + _model_label_html(title)
        + _matched_lines_html(directory / "snapshot", file_path, numbers, stale=stale and not numbers)
        + _next_step_html(file_path, cwe, line_number, exploratory=exploratory)
    )


def _look_for_html(file_path: str, cwe: str) -> str:
    name = cwe_name(cwe) or cwe
    sentence = f"Look through {file_path} for {name}. Confirm the weakness before changing code."
    return f"<p>{_esc(sentence)}</p>"


def _mitigation_html(cwe: str) -> str:
    items = displayed_mitigations(cwe)
    if not items:
        return ""
    first = f"<p>{_esc(items[0])}</p>"
    if len(items) == 1:
        return first
    rest = "".join(f"<li>{_esc(item)}</li>" for item in items[1:])
    return first + f"<details><summary>More mitigations</summary><ul>{rest}</ul></details>"


def _model_label_html(title: str) -> str:
    if not title:
        return ""
    return f"<p>Model's label (unverified): {_esc(title)}</p>"


def _matched_lines_html(snapshot_root: Path, file_path: str, numbers: list[int], *, stale: bool) -> str:
    if not numbers:
        return f"<p>{_esc(_EARLIER_SNAPSHOT)}</p>" if stale else ""
    lines = read_snapshot_lines(snapshot_root, file_path, numbers)
    if lines is None:
        return ""
    items: list[str] = []
    for number in numbers:
        text = lines.get(number)
        if text is None:
            continue
        if find_secret_matches(text):
            items.append(f"<li>line {number} (hidden: looks like a secret)</li>")
            continue
        items.append(f'<li>line {number}: <span class="mono">{_esc(text[:160])}</span></li>')
    if not items:
        return ""
    return '<h4>Where the searches matched this file</h4><ol class="match-lines">' + "".join(items) + "</ol>"


def _next_step_html(file_path: str, cwe: str, line: int | None, *, exploratory: bool) -> str:
    if exploratory:
        name = cwe_name(cwe) or cwe
        sentence = f"Open {file_path}:{line} and check {name}" if line else f"Open {file_path} and check {name}"
    else:
        sentence = f"Open {file_path} and check it against the advisory"
    return f"<p>{_esc(sentence)}</p>"


def _run_detail_extra(
    engagement_id: str,
    investigation: dict[str, object],
    run: dict[str, object],
    ranks: dict[str, int],
    likelihoods: dict[str, str],
    directory: Path,
) -> str:
    listed = run.get("candidate_paths") if isinstance(run.get("candidate_paths"), list) else []
    paths = [str(item) for item in listed]
    extra = ""
    if len(paths) == 1:
        key = normalize_repo_path(paths[0])
        rank = ranks.get(key)
        extra += f"<p>Rank: {_esc(rank if rank is not None else 'not recorded')}</p>"
        extra += likelihoods.get(key, "")
    activity = run.get("activity") if isinstance(run.get("activity"), dict) else {}
    trace_meta = activity.get("trace") if isinstance(activity.get("trace"), dict) else {}
    name = trace_meta.get("name")
    if isinstance(name, str) and resolve_trace(directory / "antares-data" / "traces", name) is not None:
        run_number = run.get("run")
        href = f"/e/{engagement_id}/runs/{investigation.get('id')}/{run_number}/trace"
        extra += f'<p><a href="{_esc(href)}">Trace</a></p>'
    return extra


def _lookup_run(
    root: Path,
    engagement_id: str,
    investigation_id: str,
    run_text: str,
) -> tuple[dict[str, object], dict[str, object]] | None:
    if not run_text.isdigit():
        return None
    run_number = int(run_text)
    try:
        investigations = _investigations(root, engagement_id)
    except EngagementError:
        return None
    for investigation in investigations:
        if str(investigation.get("id") or "") != investigation_id:
            continue
        runs = investigation.get("runs") if isinstance(investigation.get("runs"), list) else []
        for run in runs:
            if isinstance(run, dict) and run.get("run") == run_number:
                return investigation, run
    return None


def _trace_not_found() -> tuple[int, str, str]:
    return 404, _layout("Not found", "<p>That page is not part of an engagement.</p>"), "text/html; charset=utf-8"


def _trace_filename(engagement_id: str, investigation_id: str, run_text: str) -> str:
    def clean(value: str) -> str:
        kept = "".join(char if char.isalnum() or char in "-_" else "-" for char in value)
        return kept or "trace"

    return f"{clean(engagement_id)}-{clean(investigation_id)}-{clean(run_text)}.trace.jsonl"


def _page_number() -> int:
    raw = _query_param("page")
    if raw and raw.isdigit() and int(raw) >= 1:
        return int(raw)
    return 1


def _trace_event_html(event: dict[str, object]) -> str:
    phase = str(event.get("phase") or "")
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    if phase == "message":
        role = str(payload.get("role") or "message")
        content = str(payload.get("content") or "")
        return (
            f'<details class="trace-message"><summary>{_esc(role)}</summary>'
            f'<pre class="mono">{_esc(content)}</pre></details>'
        )
    if phase == "tool_call":
        tool = str(payload.get("tool_name") or "")
        arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
        rendered = json.dumps(arguments, ensure_ascii=False)
        return f"<p>{_esc(tool)}</p><pre class=\"mono\">{_esc(rendered)}</pre>"
    if phase == "tool_result":
        return f'<pre class="mono">{_esc(payload.get("result_summary") or "")}</pre>'
    label = "candidate submitted" if phase == "finding" else phase
    return f"<p>{_esc(label)}</p>"


def _parse_body(raw: bytes, content_type: str) -> Form:
    form = Form()
    if content_type.startswith("multipart/form-data"):
        boundary = ""
        for piece in content_type.split(";"):
            item = piece.strip()
            if item.startswith("boundary="):
                boundary = item.split("=", 1)[1].strip('"')
        return _parse_multipart(raw, boundary)
    parsed = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
    form.fields = {key: values[-1] for key, values in parsed.items()}
    form.lists = {key: list(values) for key, values in parsed.items()}
    return form


def _parse_multipart(raw: bytes, boundary: str) -> Form:
    form = Form()
    if not boundary:
        return form
    marker = b"--" + boundary.encode("ascii")
    for part in raw.split(marker):
        if part in {b"", b"--", b"--\r\n"} or part.startswith(b"--"):
            continue
        chunk = part[2:] if part.startswith(b"\r\n") else part
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        header_blob, separator, data = chunk.partition(b"\r\n\r\n")
        if separator != b"\r\n\r\n":
            continue
        header = header_blob.decode("utf-8", "replace")
        disposition = ""
        for line in header.split("\r\n"):
            if line.lower().startswith("content-disposition:"):
                disposition = line
        name = _disposition_value(disposition, "name")
        filename = _disposition_value(disposition, "filename")
        if not name:
            continue
        if filename:
            form.files.append((name, filename, data))
            form.filename = filename
            form.file_bytes = data
        else:
            text = data.decode("utf-8")
            form.lists.setdefault(name, []).append(text)
            form.fields[name] = text
    return form


def _disposition_value(header: str, key: str) -> str:
    token = f"{key}=\""
    start = header.find(token)
    if start < 0:
        return ""
    rest = header[start + len(token) :]
    end = rest.find("\"")
    return rest[:end] if end >= 0 else ""


def _error(message: str) -> str:
    if not message:
        return ""
    return f"<p class=\"error\">{_esc(message)}</p>"


def _note(message: str) -> str:
    if not message:
        return ""
    return f"<p class=\"note\">{_esc(message)}</p>"


def _esc(value: object) -> str:
    import html

    return html.escape("" if value is None else str(value))


_PEEK = object()
_request_root: ContextVar[Path | None] = ContextVar("astrolabe_request_root", default=None)
_request_headers: ContextVar[object | None] = ContextVar("astrolabe_request_headers", default=None)
_request_query: ContextVar[dict[str, list[str]] | None] = ContextVar("astrolabe_request_query", default=None)


def _requested_step() -> str:
    query = _request_query.get()
    if not query:
        return ""
    values = query.get("step") or []
    return values[0] if values else ""


def _layout(
    title: str,
    body: str,
    refresh: bool = False,
    *,
    record: dict[str, object] | None = None,
    steps: bool = False,
    status_checks: list[Check] | None | object = _PEEK,
    actor: str = "",
) -> str:
    shown: list[Check] | None
    if status_checks is _PEEK:
        root = _request_root.get()
        shown = cached_checks(root) if root is not None else None
    elif isinstance(status_checks, list):
        shown = status_checks
    else:
        shown = None
    poll = ' data-poll="progress"' if refresh else ""
    index = _step_index() if steps else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<link rel="stylesheet" href="/astrolabe.css">
</head>
<body{poll}>
{_topbar(record, shown, actor)}
<main class="app-main">
{index}
{body}
</main>
{_status_dialog()}
<script src="/astrolabe.js"></script>
</body>
</html>
"""


def _topbar(
    record: dict[str, object] | None,
    status_checks: list[Check] | None,
    actor: str = "",
) -> str:
    ident = ""
    state_pill = ""
    acting = ""
    if record:
        state = str(record.get("state") or "")
        kind = "healthy" if state == "closed" else "accent"
        ident = f'<span class="mono topbar-id">{_esc(record.get("id"))}</span>'
        state_pill = _pill(state, kind)
        acting = _acting_control(record, actor or (_consultants(record)[:1] or [""])[0])
    pill_kind, label = status_label(status_checks)
    status = (
        f'<a id="status-pill" class="status-pill status-pill--{pill_kind}" '
        'href="/environment" aria-haspopup="dialog">'
        f'<span class="status-pill-dot"></span>{_esc(label)}</a>'
    )
    return (
        '<header class="app-topbar">'
        '<span class="app-topbar-product"><img class="app-logo" src="/astrolabe.png" alt="">Astrolabe</span>'
        '<a href="/">Engagements</a>'
        '<a href="/cwe">CWE dictionary</a>'
        '<a href="/about">About</a>'
        f'<span class="topbar-meta">{acting}{ident}{state_pill}{status}</span>'
        "</header>"
    )


def _acting_control(record: dict[str, object], actor: str) -> str:
    people = _consultants(record)
    if len(people) <= 1:
        shown = people[0] if people else actor
        return f'<span class="acting-as">Acting as {_esc(shown)}</span>'
    options = "".join(
        f'<option value="{_esc(person)}"{" selected" if person == actor else ""}>{_esc(person)}</option>'
        for person in people
    )
    return (
        f'<form id="acting-as-form" class="acting-as" method="post" action="/e/{_esc(record.get("id"))}/acting-as">'
        f'<label for="acting-as">Acting as <select id="acting-as" name="consultant">{options}</select></label>'
        '<button type="submit">Set</button></form>'
    )


def _step(
    section_id: str,
    title: str,
    body: str,
    *,
    opened: bool,
    summary: str = "",
    change: str = "",
    blocked: bool = False,
) -> str:
    classes = "card step-card"
    if blocked:
        classes += " step-card--blocked"
    if not opened:
        classes += " step-card--collapsed"
    action = f'<a href="{_esc(change)}">Change</a>' if change and not opened else ""
    summary_html = f'<div class="step-summary">{summary}</div>' if summary and not opened else ""
    return (
        f'<section id="{section_id}" class="{classes}">'
        f'<div class="card-head"><h2>{_esc(title)}</h2>{action}</div>'
        f"{summary_html}"
        f'<div class="card-body">{body}</div></section>'
    )


def _status_dialog() -> str:
    return (
        '<dialog id="status-dialog" class="status-dialog">'
        '<form method="dialog"><button type="submit">Close</button></form>'
        '<div data-status-body></div>'
        "</dialog>"
    )


def _safe_next(value: str) -> str:
    if (
        value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and ":" not in value
    ):
        return value
    return "/"


def _readiness_warning(checks: list[Check] | None) -> str:
    if not checks:
        return ""
    ignored = {"Advisory cache", "PDF rendering"}
    blocked = [item.name for item in checks if item.name not in ignored and item.status != "ok"]
    if not blocked:
        return ""
    return (
        f'<p class="notice">Not ready: {_esc(", ".join(blocked))}. '
        "You can still create an engagement.</p>"
    )


def _step_index() -> str:
    steps = (
        ("attestation", "Attestation"),
        ("intake", "Intake"),
        ("advisories", "Advisories"),
        ("investigations", "Investigations"),
        ("coverage", "Coverage"),
        ("review", "Review"),
        ("reports", "Reports"),
    )
    links = "".join(f'<a href="#{section_id}">{label}</a>' for section_id, label in steps)
    return f'<nav class="step-index" aria-label="Engagement steps">{links}</nav>'


def _pill(label: str, kind: str) -> str:
    return (
        f'<span class="status-pill status-pill--{kind}">'
        f'<span class="status-pill-dot"></span>{_esc(label)}</span>'
    )


def _card(
    section_id: str,
    title: str,
    body: str,
    *,
    status: str = "",
    blocked: bool = False,
    action: str = "",
) -> str:
    classes = "card step-card"
    if blocked:
        classes += " step-card--blocked"
    pill = f'<div class="step-status">{status}</div>' if status else ""
    return (
        f'<section id="{section_id}" class="{classes}">'
        f'<div class="card-head"><h2>{_esc(title)}</h2>{action}{pill}</div>'
        f'<div class="card-body">{body}</div></section>'
    )


ABOUT = (
    "Astrolabe is a local, consultant-led code triage tool. "
    "It checks a customer repository snapshot against a published advisory or selected CWEs, "
    "using the Antares-1B model in a sandboxed container. "
    "Model output is a candidate for consultant review, not a finding."
)


def _astrolabe_version() -> str:
    from astrolabe import __version__

    return __version__


def _pdf_notice(directory: Path) -> str:
    html_ready = (directory / "reports" / "assessment.html").is_file()
    pdf_ready = (directory / "reports" / "assessment.pdf").is_file()
    if html_ready and not pdf_ready:
        return '<p class="notice" id="pdf-missing">The PDF was not produced.</p>'
    return ""


def _antares_version() -> str:
    try:
        from importlib.resources import files

        text = files("astrolabe").joinpath("sandbox", "versions.lock").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return "1.0.0"
    try:
        for line in text.splitlines():
            if line.startswith("antares-cli=="):
                return line.split("==", 1)[1].strip()
    except OSError:
        pass
    return "1.0.0"


def _about_page() -> str:
    versions = (
        '<dl class="version-list">'
        f"<dt>Astrolabe</dt><dd>{_esc(_astrolabe_version())}</dd>"
        f"<dt>Antares</dt><dd>{_esc(_antares_version())}</dd>"
        "</dl>"
    )
    body = f"<h1>About</h1><p class=\"prose\">{_esc(ABOUT)}</p>{versions}"
    return _layout("About", body)


def _environment_page(root: Path, checks: list[Check]) -> str:
    rows = []
    for item in checks:
        kind = {"ok": "healthy", "warn": "warn"}.get(item.status, "danger")
        fix = item.hint if item.status != "ok" else ""
        rows.append(
            "<tr>"
            f"<td>{_esc(item.name)}</td>"
            f"<td>{_pill(item.status, kind)}</td>"
            f'<td class="mono">{_esc(check_location(item.name, root))}</td>'
            f"<td>{_esc(item.detail)}</td>"
            f"<td>{_esc(fix)}</td>"
            "</tr>"
        )
    table = (
        '<table id="environment-checks"><thead><tr>'
        "<th>Check</th><th>Health</th><th>Location</th><th>Detail</th><th>Fix</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )
    form = (
        '<form id="recheck" method="post" action="/environment/recheck">'
        '<input type="hidden" name="next" value="/environment">'
        '<button type="submit">Re-check</button></form>'
    )
    return _layout("Status", f"<h1>Status</h1>{table}{form}", status_checks=checks)


def _engagements_card(rows: list[dict[str, object]]) -> str:
    rendered = []
    for row in rows:
        state = str(row.get("state") or "")
        kind = "healthy" if state == "closed" else "accent" if state == "open" else "muted"
        sha = str(row.get("snapshot") or "")
        if sha:
            snapshot = f'<span class="mono" title="{_esc(sha)}">{_esc(sha[:12])}</span>'
        else:
            snapshot = "none"
        attestation = "recorded" if row.get("attested") else "required"
        rendered.append(
            "<tr>"
            f"<td><a class=\"mono\" href=\"/e/{_esc(row.get('id'))}\">{_esc(row.get('id'))}</a></td>"
            f"<td>{_esc(row.get('customer'))}</td>"
            f"<td>{_pill(state, kind)}</td>"
            f"<td>{attestation}</td>"
            f"<td>{snapshot}</td>"
            f"<td class=\"mono\">{_esc(row.get('created'))}</td>"
            f"<td class=\"mono\">{_esc(row.get('last'))}</td>"
            "</tr>"
        )
    empty = '<tr><td colspan="7">No engagements yet.</td></tr>'
    body = (
        "<table><thead><tr><th>ID</th><th>Customer</th><th>State</th><th>Attestation</th>"
        "<th>Snapshot</th><th>Created</th><th>Last activity</th></tr></thead>"
        f"<tbody>{''.join(rendered) or empty}</tbody></table>"
    )
    action = '<a class="btn-primary" href="/new">New engagement</a>'
    return _card("engagements", "Engagements", body, action=action)


def _index_rows(root: Path) -> list[dict[str, object]]:
    if not root.is_dir():
        return []
    rows: list[dict[str, object]] = []
    for path in root.iterdir():
        if not path.is_dir() or not (path / "engagement.json").is_file():
            continue
        try:
            record = load_engagement_readonly(root, path.name)
        except (EngagementError, OSError):
            continue
        if str(record.get("state") or "") == "purged":
            continue
        created, last = _activity(root, path.name)
        rows.append(
            {
                "id": record.get("id") or path.name,
                "customer": record.get("customer") or "",
                "state": record.get("state") or "",
                "attested": index_attestation_recorded(root, record),
                "snapshot": record.get("snapshot_sha256") or "",
                "created": created,
                "last": last,
            }
        )
    rows.sort(key=lambda item: str(item["last"]), reverse=True)
    return rows


def _activity(root: Path, engagement_id: str) -> tuple[str, str]:
    try:
        entries = read_audit(engagement_dir(root, engagement_id))
    except (EngagementError, OSError):
        return "", ""
    created = ""
    last = ""
    for entry in entries:
        stamp = str(entry.get("timestamp") or "")
        if stamp:
            last = stamp
        if entry.get("action") == "create" and stamp and not created:
            created = stamp
    return created, last


_NEW_LABELS = {
    "customer": "Customer",
    "id": "Engagement ID",
    "scope": "Scope",
    "reference": "Authorization reference",
    "authorized": "Authorization",
    "start": "Start",
    "end": "End (optional)",
    "consultants": "Consultants",
}
_NEW_HINTS = {
    "id": "Lowercase letters, digits, hyphens. Can't be changed or reused after purge.",
    "scope": "What the customer authorized. Confirmed at attestation.",
    "reference": "A SOW, contract, ticket, or email that a reviewer could locate later.",
    "consultants": "Comma-separated. The first name is recorded as the creator.",
}
_NEW_REQUIRED = {"customer", "id", "scope", "reference", "start", "consultants"}
_ID_PATTERN = "^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$"


def _form_errors(errors: dict[str, str]) -> str:
    if not errors:
        return ""
    rows = []
    for name, message in errors.items():
        label = _NEW_LABELS.get(name, name)
        rows.append(f'<li><a href="#{name}">{_esc(label)}</a>: {_esc(message)}</li>')
    return (
        '<div id="form-errors" class="error" role="alert" tabindex="-1">'
        f"<ul>{''.join(rows)}</ul></div>"
    )


def _new_field(name: str, value: str, error: str, *, start: str = "") -> str:
    label = _NEW_LABELS[name]
    if name in _NEW_REQUIRED:
        label += " *"
    described: list[str] = []
    hint = _NEW_HINTS.get(name, "")
    if hint:
        described.append(f"{name}-hint")
    if error:
        described.append(f"{name}-error")
    attrs = [f'id="{name}"', f'name="{name}"']
    if name == "scope":
        attrs.append('maxlength="2000"')
        attrs.append('rows="3"')
    elif name == "start":
        attrs.append('type="date"')
    elif name == "end":
        attrs.append('type="date"')
        if start:
            attrs.append(f'min="{_esc(start)}"')
    elif name == "id":
        attrs.append('type="text"')
        attrs.append('class="mono"')
        attrs.append(f'pattern="{_ID_PATTERN}"')
    else:
        attrs.append('type="text"')
        if name in {"customer", "reference"}:
            attrs.append('maxlength="200"')
    if name != "scope":
        attrs.append(f'value="{_esc(value)}"')
    if described:
        attrs.append(f'aria-describedby="{" ".join(described)}"')
    if error:
        attrs.append('aria-invalid="true"')
    if name in _NEW_REQUIRED:
        attrs.append("required")
    if name == "scope":
        control = f"<textarea {' '.join(attrs)}>{_esc(value)}</textarea>"
    else:
        control = f"<input {' '.join(attrs)}>"
    hint_html = f'<p id="{name}-hint" class="env-hint">{_esc(hint)}</p>' if hint else ""
    error_html = f'<p id="{name}-error" class="field-error">{_esc(error)}</p>' if error else ""
    return f'<div class="field"><label for="{name}">{_esc(label)}</label>{control}{hint_html}{error_html}</div>'


def _authorization_box(checked: bool, error: str) -> str:
    described = ["authorized-error"] if error else []
    attrs = ['id="authorized"', 'name="authorized"', 'type="checkbox"', "required"]
    if checked:
        attrs.append("checked")
    if described:
        attrs.append(f'aria-describedby="{" ".join(described)}"')
    if error:
        attrs.append('aria-invalid="true"')
    error_html = f'<p id="authorized-error" class="field-error">{_esc(error)}</p>' if error else ""
    return (
        '<div class="field"><label for="authorized">'
        f'<input {" ".join(attrs)}> '
        "The customer's written authorization covers this scope.</label>"
        f"{error_html}</div>"
    )


def _stylesheet() -> str:
    css = files("astrolabe").joinpath("static", "css")
    theme = css.joinpath("theme.css").read_text(encoding="utf-8")
    components = css.joinpath("components.css").read_text(encoding="utf-8")
    return theme + "\n" + components


def _logo() -> bytes:
    return files("astrolabe").joinpath("static", "astrolabe.png").read_bytes()


def _host_allowed(value: str, port: int) -> bool:
    host = value.strip()
    return host in {f"127.0.0.1:{port}", f"localhost:{port}"}


def _origin_allowed(headers: object, host: str) -> bool:
    origin = str(getattr(headers, "get")("Origin", "") or "").strip()
    # Current Chrome sends Origin: null on a same-origin form navigation when
    # Referrer-Policy is no-referrer. Sec-Fetch-Site is a forbidden header, so
    # another site cannot claim same-origin.
    if origin.lower() == "null":
        site = str(getattr(headers, "get")("Sec-Fetch-Site", "") or "").strip().lower()
        return site == "same-origin"
    if origin:
        return _same_endpoint(origin, host)
    referer = str(getattr(headers, "get")("Referer", "") or "")
    if referer.strip():
        return _same_endpoint(referer, host)
    return False


def _same_endpoint(value: str, host: str) -> bool:
    parsed = urllib.parse.urlsplit(value.strip())
    return parsed.scheme == "http" and parsed.netloc == host


def _is_chunked(headers: object) -> bool:
    encoding = str(getattr(headers, "get")("Transfer-Encoding", "") or "")
    return "chunked" in encoding.lower()


def _declared_length_over_cap(headers: object) -> bool:
    if _is_chunked(headers):
        return False
    raw = str(getattr(headers, "get")("Content-Length", "") or "").strip()
    if raw == "":
        return False
    try:
        length = int(raw)
    except ValueError:
        return True
    return length < 0 or length > UPLOAD_MAX_BYTES


def _read_request_body(stream: object, headers: object) -> bytes:
    if _is_chunked(headers):
        return _read_chunked(stream)
    raw = str(getattr(headers, "get")("Content-Length", "") or "").strip()
    if raw == "":
        return b""
    length = int(raw)
    if length < 0 or length > UPLOAD_MAX_BYTES:
        raise UploadLimit
    return _read_exact(stream, length)


def _read_exact(stream: object, length: int) -> bytes:
    parts: list[bytes] = []
    remaining = length
    seen = 0
    while remaining:
        block = stream.read(min(64 * 1024, remaining))  # type: ignore[attr-defined]
        if not block:
            break
        seen += len(block)
        if seen > UPLOAD_MAX_BYTES:
            raise UploadLimit
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


def _read_chunked(stream: object) -> bytes:
    parts: list[bytes] = []
    total = 0
    while True:
        line = _read_line(stream, 128)
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text or b"0", 16)
        except ValueError as exc:
            raise UploadLimit from exc
        if size < 0 or size > UPLOAD_MAX_BYTES or total + size > UPLOAD_MAX_BYTES:
            raise UploadLimit
        if size == 0:
            while True:
                trailer = _read_line(stream, 1024)
                if trailer in {b"", b"\n", b"\r\n"}:
                    break
            return b"".join(parts)
        block = _read_exact(stream, size)
        total += len(block)
        if total > UPLOAD_MAX_BYTES:
            raise UploadLimit
        parts.append(block)
        newline = _read_exact(stream, 2)
        if newline not in {b"\r\n", b"\n"}:
            raise UploadLimit


def _read_line(stream: object, limit: int) -> bytes:
    line = bytearray()
    while len(line) <= limit:
        char = stream.read(1)  # type: ignore[attr-defined]
        if not char:
            break
        line.extend(char)
        if char == b"\n":
            break
    if len(line) > limit:
        raise UploadLimit
    return bytes(line)


def _temporary_archive(filename: str, payload: bytes) -> Path:
    suffix = Path(filename).suffix
    if filename.endswith(".tar.gz"):
        suffix = ".tar.gz"
    handle = tempfile.NamedTemporaryFile(prefix="astrolabe-intake-", suffix=suffix, delete=False)
    handle.write(payload)
    handle.close()
    return Path(handle.name)



def choose_local_path(kind: str) -> str:
    """Open the Mac file dialog and return the path the user chose."""
    if kind == "directory":
        prompt = "Choose a folder"
        command = "folder"
    elif kind == "file":
        prompt = "Choose a file"
        command = "file"
    else:
        raise EngagementError("Browse needs a file or a folder")
    try:
        completed = subprocess.run(
            ["osascript", "-e", f'POSIX path of (choose {command} with prompt "{prompt}")'],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EngagementError("The file browser could not open") from exc
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip().rstrip("/")


def _server_error_page() -> str:
    return _layout(
        "Error",
        "<h1>Something went wrong</h1><p>The request failed. The error was logged.</p>",
    )


_SCRIPT = """
const zone = document.getElementById("archive-drop");
const input = document.getElementById("archive-file");
if (zone && input) {
  zone.addEventListener("dragover", (event) => event.preventDefault());
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    const files = event.dataTransfer && event.dataTransfer.files;
    if (files && files.length) {
      input.files = files;
    }
  });
}
if (document.body && document.body.getAttribute("data-poll") === "progress") {
  let delay = 2000;
  let failures = 0;
  const lost = "Lost connection to Astrolabe. Reload to resume.";
  const giveUp = () => {
    const note = document.createElement("p");
    note.id = "poll-lost";
    note.textContent = lost;
    const live = document.getElementById("progress");
    if (live) {
      live.replaceWith(note);
    } else {
      document.body.prepend(note);
    }
  };
  const tick = () => {
    if (!document.body || document.body.getAttribute("data-poll") !== "progress") {
      return;
    }
    fetch(location.pathname, { headers: { Accept: "text/html" } })
      .then((response) => {
        if (!response.ok) {
          throw new Error("status");
        }
        return response.text();
      })
      .then((html) => {
        failures = 0;
        delay = 2000;
        const doc = new DOMParser().parseFromString(html, "text/html");
        const next = doc.getElementById("progress");
        const live = document.getElementById("progress");
        if (!next || !live) {
          location.reload();
          return;
        }
        live.replaceWith(next);
        window.setTimeout(tick, delay);
      })
      .catch(() => {
        failures += 1;
        if (failures >= 5) {
          giveUp();
          return;
        }
        window.setTimeout(tick, delay);
        delay = Math.min(delay * 2, 30000);
      });
  };
  window.setTimeout(tick, delay);
}
const statusPill = document.getElementById("status-pill");
const statusDialog = document.getElementById("status-dialog");
if (statusPill && statusDialog) {
  const statusBody = statusDialog.querySelector("[data-status-body]");
  statusPill.addEventListener("click", (event) => {
    event.preventDefault();
    fetch("/environment", { headers: { Accept: "text/html" } })
      .then((response) => {
        if (!response.ok) {
          throw new Error("status");
        }
        return response.text();
      })
      .then((html) => {
        const doc = new DOMParser().parseFromString(html, "text/html");
        const table = doc.getElementById("environment-checks");
        const form = doc.getElementById("recheck");
        const fetched = doc.getElementById("status-pill");
        if (!table || !form || !statusBody) {
          throw new Error("missing");
        }
        const next = form.querySelector('input[name="next"]');
        const path = location.pathname;
        if (
          next &&
          path.charAt(0) === "/" &&
          path.charAt(1) !== "/" &&
          path.indexOf("\\\\") < 0 &&
          path.indexOf(":") < 0
        ) {
          next.value = path;
        }
        statusBody.replaceChildren(document.importNode(table, true), document.importNode(form, true));
        if (fetched) {
          statusPill.className = fetched.className;
          statusPill.innerHTML = fetched.innerHTML;
        }
        statusDialog.showModal();
      })
      .catch(() => {
        location.assign("/environment");
      });
  });
  statusDialog.addEventListener("close", () => {
    statusPill.focus();
  });
}
const engagementForm = document.getElementById("new-engagement");
if (engagementForm) {
  const createButton = engagementForm.querySelector("button[type='submit']");
  engagementForm.addEventListener("submit", () => {
    if (createButton) {
      createButton.disabled = true;
    }
  });
  engagementForm.addEventListener("invalid", () => {
    if (createButton) {
      createButton.disabled = false;
    }
  }, true);
  const customerInput = document.getElementById("customer");
  const startInput = document.getElementById("start");
  const endInput = document.getElementById("end");
  const idInput = document.getElementById("id");
  if (idInput && customerInput && startInput) {
    let idEdited = idInput.value !== "";
    idInput.addEventListener("input", () => {
      idEdited = true;
    });
    const suggestId = () => {
      if (idEdited) {
        return;
      }
      const year = (startInput.value || "").slice(0, 4);
      if (!/^\\d{4}$/.test(year)) {
        return;
      }
      let slug = customerInput.value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
      const suffix = "-" + year;
      if (slug.length > 64 - suffix.length) {
        slug = slug.slice(0, 64 - suffix.length).replace(/-+$/g, "");
      }
      idInput.value = slug ? slug + suffix : "";
    };
    customerInput.addEventListener("input", suggestId);
    startInput.addEventListener("input", suggestId);
    startInput.addEventListener("change", suggestId);
  }
  if (startInput && endInput) {
    const syncEnd = () => {
      endInput.min = startInput.value;
    };
    startInput.addEventListener("input", syncEnd);
    startInput.addEventListener("change", syncEnd);
  }
}
const formErrors = document.getElementById("form-errors");
if (formErrors) {
  formErrors.focus();
}
const acting = document.getElementById("acting-as");
if (acting) {
  acting.addEventListener("change", () => {
    const form = document.getElementById("acting-as-form");
    if (form) {
      form.submit();
    }
  });
}
const intakeSource = document.querySelectorAll('input[name="intake_source"]');
const syncIntake = () => {
  const chosen = document.querySelector('input[name="intake_source"]:checked');
  const value = chosen ? chosen.value : "git";
  document.querySelectorAll("[data-intake-source]").forEach((panel) => {
    const match = panel.getAttribute("data-intake-source") === value;
    panel.hidden = !match;
    if (match && panel.tagName === "DETAILS") {
      panel.open = true;
    }
  });
};
if (intakeSource.length) {
  intakeSource.forEach((radio) => radio.addEventListener("change", syncIntake));
  syncIntake();
}
document.querySelectorAll("[data-browse]").forEach((button) => {
  button.addEventListener("click", () => {
    const kind = button.getAttribute("data-browse") || "";
    const target = document.getElementById(button.getAttribute("data-browse-target") || "");
    if (!target) {
      return;
    }
    button.disabled = true;
    fetch("/browse", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": location.origin,
      },
      body: "kind=" + encodeURIComponent(kind),
    })
      .then((response) => response.json())
      .then((payload) => {
        if (payload && payload.path) {
          target.value = payload.path;
        }
      })
      .finally(() => {
        button.disabled = false;
      });
  });
});
const exportOutput = document.getElementById("export-output");
const bundleChoice = document.querySelectorAll('input[name="bundle"]');
if (exportOutput && bundleChoice.length) {
  const reportPath = exportOutput.getAttribute("data-report-path") || "";
  const fullPath = exportOutput.getAttribute("data-full-path") || "";
  const syncBundle = () => {
    const chosen = document.querySelector('input[name="bundle"]:checked');
    if (!chosen || chosen.disabled) {
      return;
    }
    exportOutput.value = chosen.value === "full" ? fullPath : reportPath;
  };
  bundleChoice.forEach((radio) => radio.addEventListener("change", syncBundle));
}
const planSummary = document.querySelector("[data-plan-summary]");
if (planSummary) {
  planSummary.classList.add("is-sticky");
  const planForm = document.getElementById("plan-launch");
  const countNode = planSummary.querySelector("[data-selected-count]");
  const estimateNode = planSummary.querySelector("[data-estimate]");
  const each = Number(planSummary.getAttribute("data-each") || "0");
  const sampled = planSummary.getAttribute("data-sampled") === "1";
  const estimateText = (count) => {
    if (count <= 0) {
      return "Approximate total time is 0 seconds for 0 investigations.";
    }
    const total = Math.round(each * count);
    const per = Math.round(each);
    if (sampled) {
      return "Approximate total time is " + total + " seconds, from the average recorded per-run time, for " + count + " investigations.";
    }
    return "Approximate total time is " + total + " seconds, using " + per + " seconds per check, for " + count + " investigations.";
  };
  const updatePlan = () => {
    if (!planForm || !countNode || !estimateNode) {
      return;
    }
    const count = planForm.querySelectorAll('input[name="choice"]:checked').length;
    countNode.textContent = String(count);
    estimateNode.textContent = estimateText(count);
  };
  planForm && planForm.addEventListener("change", updatePlan);
}
const intakePreview = document.getElementById("intake-preview");
if (intakePreview) {
  intakePreview.scrollIntoView();
}
const owaspFilter = document.getElementById("owasp-filter");
if (owaspFilter) {
  owaspFilter.addEventListener("input", () => {
    const query = owaspFilter.value.trim().toLowerCase();
    document.querySelectorAll("[data-plan-row]").forEach((row) => {
      const hay = ((row.getAttribute("data-cwe") || "") + " " + (row.getAttribute("data-name") || "")).toLowerCase();
      row.hidden = query !== "" && hay.indexOf(query) < 0;
    });
  });
}
const cweSearch = document.querySelector('form[action="/cwe"] input[name="q"]');
if (cweSearch && cweSearch.form) {
  let cweSearchTimer = 0;
  cweSearch.addEventListener("input", () => {
    window.clearTimeout(cweSearchTimer);
    cweSearchTimer = window.setTimeout(() => {
      const params = new URLSearchParams(new FormData(cweSearch.form));
      params.delete("page");
      const query = params.toString();
      location.assign(query ? "/cwe?" + query : "/cwe");
    }, 300);
  });
}
let cweTooltip = null;
let cweTooltipAnchor = null;
let cweTooltipSeq = 0;
const hideCweTooltip = () => {
  if (cweTooltip) {
    cweTooltip.remove();
    cweTooltip = null;
  }
  if (cweTooltipAnchor) {
    cweTooltipAnchor.removeAttribute("aria-describedby");
    cweTooltipAnchor = null;
  }
};
const showCweTooltip = (anchor) => {
  if (!anchor || anchor === cweTooltipAnchor) {
    return;
  }
  hideCweTooltip();
  const title = anchor.getAttribute("title") || anchor.getAttribute("data-cwe-title") || "";
  if (!title) {
    return;
  }
  anchor.setAttribute("data-cwe-title", title);
  anchor.removeAttribute("title");
  cweTooltipSeq += 1;
  const id = "cwe-tip-" + cweTooltipSeq;
  const tip = document.createElement("div");
  tip.id = id;
  tip.className = "cwe-tooltip";
  tip.setAttribute("role", "tooltip");
  tip.textContent = title;
  document.body.appendChild(tip);
  const rect = anchor.getBoundingClientRect();
  const width = Math.min(28 * 16, window.innerWidth - 16);
  tip.style.width = width + "px";
  let left = rect.left;
  if (left + width > window.innerWidth - 8) {
    left = Math.max(8, window.innerWidth - width - 8);
  }
  tip.style.left = left + "px";
  tip.style.top = (rect.bottom + 6) + "px";
  anchor.setAttribute("aria-describedby", id);
  cweTooltip = tip;
  cweTooltipAnchor = anchor;
};
document.addEventListener("mouseover", (event) => {
  const anchor = event.target && event.target.closest ? event.target.closest(".cwe-ref") : null;
  if (anchor) {
    showCweTooltip(anchor);
  }
});
document.addEventListener("mouseout", (event) => {
  if (!cweTooltipAnchor) {
    return;
  }
  const anchor = event.target && event.target.closest ? event.target.closest(".cwe-ref") : null;
  if (anchor === cweTooltipAnchor) {
    hideCweTooltip();
  }
});
document.addEventListener("focusin", (event) => {
  const anchor = event.target && event.target.closest ? event.target.closest(".cwe-ref") : null;
  if (anchor) {
    showCweTooltip(anchor);
  }
});
document.addEventListener("focusout", (event) => {
  if (cweTooltipAnchor && event.target === cweTooltipAnchor) {
    hideCweTooltip();
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    hideCweTooltip();
  }
});
const cweTooltipObserver = new MutationObserver(() => {
  if (cweTooltipAnchor && !cweTooltipAnchor.isConnected) {
    hideCweTooltip();
  }
});
cweTooltipObserver.observe(document.body, { childList: true, subtree: true });
"""

