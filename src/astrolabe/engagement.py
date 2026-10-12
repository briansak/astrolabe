"""One directory per engagement. Customer code and derived data stay inside it."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("astrolabe.engagement")

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STATES = ("open", "closed", "purged")
RUNTIME_DIRS = ("antares-data", "socket", "reports")


class EngagementError(ValueError):
    """A refused engagement operation."""


class FieldError(EngagementError):
    """Per-field reasons a new engagement was refused."""

    def __init__(self, errors: dict[str, str]) -> None:
        self.errors = errors
        super().__init__(" ".join(errors.values()))


NEW_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$")
DATE_TEXT = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CUSTOMER_MAX = 200
SCOPE_MAX = 2000
CONSULTANT_MAX = 100


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def home_root() -> Path:
    """Per-user Astrolabe directory. Engagements, the audit log, and the advisory cache live here."""
    return Path.home() / "Astrolabe"


def engagements_root(root: Path | None = None) -> Path:
    if root is not None:
        return root
    configured = os.environ.get("ASTROLABE_ENGAGEMENTS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return home_root() / "engagements"


def purge_log_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    configured = os.environ.get("ASTROLABE_PURGE_LOG", "").strip()
    if configured:
        return Path(configured).expanduser()
    return home_root() / "var" / "purge-log.jsonl"


def durable_audit_path(root: Path, override: Path | None = None) -> Path:
    """Audit log outside engagements/<id>/, beside var/purge-log.jsonl."""
    if override is not None:
        return override
    configured = os.environ.get("ASTROLABE_AUDIT_LOG", "").strip()
    if configured:
        return Path(configured)
    return root.resolve().parent / "var" / "audit.jsonl"


def advisory_cache_dir(path: Path | None = None) -> Path:
    if path is not None:
        return path
    configured = os.environ.get("ASTROLABE_ADVISORY_CACHE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return home_root() / "advisories"


def engagement_dir(root: Path, engagement_id: str) -> Path:
    if not SAFE_ID.fullmatch(engagement_id):
        raise EngagementError(f"Engagement id is not a single path segment: {engagement_id}")
    directory = (root / engagement_id).resolve()
    if directory.parent != root.resolve():
        raise EngagementError("Engagement path escapes the engagements directory")
    return directory


def validate_new_engagement(
    root: Path,
    *,
    engagement_id: str,
    customer: str,
    scope: str,
    start_date: str,
    end_date: str,
    consultants: list[str],
) -> dict[str, str]:
    """Field errors for a new engagement. An empty dict means the values can be stored."""
    errors: dict[str, str] = {}
    id_error = _id_field_error(root, engagement_id)
    if id_error:
        errors["id"] = id_error
    if not customer.strip():
        errors["customer"] = "Customer is required."
    elif len(customer.strip()) > CUSTOMER_MAX:
        errors["customer"] = "Customer must be at most 200 characters."
    if not scope.strip():
        errors["scope"] = "Scope is required."
    elif len(scope.strip()) > SCOPE_MAX:
        errors["scope"] = "Scope must be at most 2000 characters."
    start_ok = _valid_date(start_date)
    if not start_date.strip():
        errors["start"] = "Start is required."
    elif not start_ok:
        errors["start"] = "Start must be YYYY-MM-DD."
    if end_date.strip():
        if not _valid_date(end_date):
            errors["end"] = "End must be YYYY-MM-DD."
        elif start_ok and end_date < start_date:
            errors["end"] = "End must be on or after start."
    people = [person.strip() for person in consultants if person.strip()]
    if not people:
        errors["consultants"] = "Consultants is required."
    elif any(len(person) > CONSULTANT_MAX for person in people):
        errors["consultants"] = "Each consultant name must be at most 100 characters."
    return errors


def create_engagement(
    root: Path,
    *,
    engagement_id: str,
    customer: str,
    scope: str,
    start_date: str,
    consultants: list[str],
    end_date: str | None = None,
    reference: str | None = None,
    authorized: bool = False,
) -> dict[str, object]:
    errors = validate_new_engagement(
        root,
        engagement_id=engagement_id,
        customer=customer,
        scope=scope,
        start_date=start_date,
        end_date=end_date or "",
        consultants=consultants,
    )
    if errors:
        raise FieldError(errors)
    people = [person.strip() for person in consultants if person.strip()]
    directory = engagement_dir(root, engagement_id)
    if directory.exists() or _live_engagement_exists(root, engagement_id):
        raise EngagementError(f"Engagement already exists: {engagement_id}")
    if _has_purge_record(root, engagement_id):
        raise EngagementError(
            f"{engagement_id} was purged. Use a new id, for example {engagement_id}b."
        )
    directory.mkdir(parents=True)
    for name in RUNTIME_DIRS:
        (directory / name).mkdir()
    record = {
        "id": engagement_id,
        "instance_id": str(uuid.uuid4()),
        "attestation_migrated": True,
        "customer": customer.strip(),
        "scope": scope.strip(),
        "start_date": start_date,
        "end_date": end_date if end_date and end_date.strip() else None,
        "consultants": people,
        "state": "open",
        "snapshot_sha256": None,
        "intake": None,
    }
    should_attest = bool(reference and str(reference).strip() and authorized)
    attestation_failed = False
    with _engagement_lock(directory):
        _write_json(directory / "engagement.json", record)
        audit(directory, {"action": "create", "actor": people[0][:CONSULTANT_MAX]})
        if should_attest:
            try:
                attest(
                    root,
                    engagement_id,
                    actor=people[0],
                    reference=str(reference),
                    scope=str(record["scope"]),
                )
            except Exception:
                logger.exception("Attest append failed for %s", engagement_id)
                attestation_failed = True
    if attestation_failed:
        return {**record, "attestation_failed": True}
    return record


def load_engagement(root: Path, engagement_id: str) -> dict[str, object]:
    directory = engagement_dir(root, engagement_id)
    path = directory / "engagement.json"
    if not path.is_file():
        raise EngagementError(f"No engagement {engagement_id}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EngagementError("Engagement record is not an object")
    return _migrate_instance(root, payload)


def load_engagement_readonly(root: Path, engagement_id: str) -> dict[str, object]:
    """Read engagement.json for the index. Does not assign an instance id or write."""
    directory = engagement_dir(root, engagement_id)
    path = directory / "engagement.json"
    if not path.is_file():
        raise EngagementError(f"No engagement {engagement_id}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EngagementError("Engagement record is not an object") from exc
    if not isinstance(payload, dict):
        raise EngagementError("Engagement record is not an object")
    return payload


def index_attestation_recorded(root: Path, record: dict[str, object]) -> bool:
    """Same decision as migration, without assigning an instance id or copying lines."""
    engagement_id = str(record.get("id") or "")
    rows = read_durable_audit(root, engagement_id)
    instance_id = str(record.get("instance_id") or "")
    if instance_id and any(
        row.get("action") == "attest" and row.get("instance_id") == instance_id for row in rows
    ):
        return True
    if instance_id and record.get("attestation_migrated") is True:
        return False
    create_ts = _local_create_timestamp(root, engagement_id)
    if not create_ts:
        return False
    for row in rows:
        if row.get("action") != "attest" or row.get("instance_id"):
            continue
        attest_ts = str(row.get("timestamp") or "")
        if attest_ts <= create_ts:
            continue
        if _purge_between(rows, create_ts, row):
            continue
        return True
    return False


def save_engagement(root: Path, record: dict[str, object]) -> None:
    directory = engagement_dir(root, str(record["id"]))
    _write_json(directory / "engagement.json", record)


def require_open(record: dict[str, object]) -> None:
    if record.get("state") != "open":
        raise EngagementError(f"Engagement is {record.get('state')}, not open")


def audit(directory: Path, event: dict[str, object]) -> None:
    entry = {"timestamp": utc_now(), **event}
    with (directory / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def read_audit(directory: Path) -> list[dict[str, object]]:
    path = directory / "audit.jsonl"
    if not path.is_file():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def append_durable_audit(
    root: Path,
    engagement_id: str,
    event: dict[str, object],
    *,
    log_path: Path | None = None,
    include_engagement_id: bool = True,
) -> dict[str, object]:
    path = durable_audit_path(root, log_path)
    if _path_is_inside(path, root):
        raise EngagementError("Durable audit log must live outside the engagements directory")
    if include_engagement_id:
        entry = {"timestamp": utc_now(), "engagement_id": engagement_id, **event}
    else:
        entry = {"timestamp": utc_now(), **event}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def read_durable_audit(
    root: Path,
    engagement_id: str,
    *,
    log_path: Path | None = None,
) -> list[dict[str, object]]:
    path = durable_audit_path(root, log_path)
    if not path.is_file():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict) and payload.get("engagement_id") == engagement_id:
            rows.append(payload)
    return rows


def read_attestation(
    root: Path,
    engagement_id: str,
    *,
    log_path: Path | None = None,
) -> dict[str, object] | None:
    matches = [row for row in read_durable_audit(root, engagement_id, log_path=log_path) if row.get("action") == "attest"]
    if not matches:
        return None
    return matches[-1]


def read_instance_attestation(
    root: Path,
    record: dict[str, object],
    *,
    log_path: Path | None = None,
) -> dict[str, object] | None:
    instance_id = str(record.get("instance_id") or "")
    if not instance_id:
        return None
    matches = [
        row
        for row in read_durable_audit(root, str(record.get("id") or ""), log_path=log_path)
        if row.get("action") == "attest" and row.get("instance_id") == instance_id
    ]
    if not matches:
        return None
    return matches[-1]


def has_attestation(root: Path, engagement_id: str, *, log_path: Path | None = None) -> bool:
    record = load_engagement(root, engagement_id)
    return read_instance_attestation(root, record, log_path=log_path) is not None


def attest(
    root: Path,
    engagement_id: str,
    *,
    actor: str,
    reference: str,
    scope: str,
    attested_at: str | None = None,
) -> dict[str, object]:
    if not actor.strip() or not reference.strip() or not scope.strip():
        raise EngagementError("Attestation requires who attests, a reference, and scope")
    record = load_engagement(root, engagement_id)
    require_open(record)
    existing = read_instance_attestation(root, record)
    if existing is not None and scope.strip() != str(existing.get("scope") or "").strip():
        raise EngagementError("Scope is locked after attestation")
    when = attested_at or utc_now()
    _parse_timestamp(when)
    return append_durable_audit(
        root,
        engagement_id,
        {
            "action": "attest",
            "instance_id": str(record.get("instance_id") or ""),
            "actor": actor.strip(),
            "reference": reference.strip(),
            "scope": scope.strip(),
            "attested_at": when,
        },
    )


def _id_key(engagement_id: str) -> str:
    return engagement_id.casefold().strip()


def _live_engagement_exists(root: Path, engagement_id: str) -> bool:
    wanted = _id_key(engagement_id)
    if not root.is_dir():
        return False
    for path in root.iterdir():
        if path.is_dir() and (path / "engagement.json").is_file() and _id_key(path.name) == wanted:
            return True
    return False


def _has_purge_record(root: Path, engagement_id: str) -> bool:
    wanted = _id_key(engagement_id)
    path = durable_audit_path(root)
    if not path.is_file():
        return False
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get("action") != "purge":
            continue
        if _id_key(str(payload.get("engagement_id") or "")) == wanted:
            return True
    return False


def _migrate_instance(root: Path, record: dict[str, object]) -> dict[str, object]:
    """Assign an instance id once. Carry a legacy attest line only for this life of the id."""
    if record.get("instance_id") and record.get("attestation_migrated") is True:
        return record
    directory = engagement_dir(root, str(record.get("id") or ""))
    with _engagement_lock(directory):
        current = _read_record_file(directory)
        if current.get("instance_id") and current.get("attestation_migrated") is True:
            return current
        if not current.get("instance_id"):
            current["instance_id"] = str(uuid.uuid4())
        save_engagement(root, current)
        if current.get("attestation_migrated") is not True:
            _carry_legacy_attestation(root, current)
            current["attestation_migrated"] = True
            save_engagement(root, current)
        return current


def _read_record_file(directory: Path) -> dict[str, object]:
    try:
        payload = json.loads((directory / "engagement.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EngagementError("Engagement record is not an object") from exc
    if not isinstance(payload, dict):
        raise EngagementError("Engagement record is not an object")
    return payload


@contextmanager
def _engagement_lock(directory: Path):
    handle = (directory / ".instance.lock").open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _carry_legacy_attestation(root: Path, record: dict[str, object]) -> None:
    engagement_id = str(record.get("id") or "")
    instance_id = str(record.get("instance_id") or "")
    rows = read_durable_audit(root, engagement_id)
    if any(row.get("action") == "attest" and row.get("instance_id") == instance_id for row in rows):
        return
    create_ts = _local_create_timestamp(root, engagement_id)
    if not create_ts:
        return
    chosen: dict[str, object] | None = None
    for row in rows:
        if row.get("action") != "attest" or row.get("instance_id"):
            continue
        attest_ts = str(row.get("timestamp") or "")
        if attest_ts <= create_ts:
            continue
        if _purge_between(rows, create_ts, row):
            continue
        chosen = row
    if chosen is None:
        return
    append_durable_audit(
        root,
        engagement_id,
        {
            "action": "attest",
            "instance_id": instance_id,
            "actor": chosen.get("actor") or "",
            "reference": chosen.get("reference") or "",
            "scope": chosen.get("scope") or "",
            "attested_at": chosen.get("attested_at") or "",
            "migrated_from": "engagement_id",
        },
    )


def _local_create_timestamp(root: Path, engagement_id: str) -> str:
    created = [row for row in read_audit(engagement_dir(root, engagement_id)) if row.get("action") == "create"]
    if not created:
        return ""
    return str(created[-1].get("timestamp") or "")


def _purge_between(rows: list[dict[str, object]], create_ts: str, attest_row: dict[str, object]) -> bool:
    attest_ts = str(attest_row.get("timestamp") or "")
    for row in rows:
        if row is attest_row:
            break
        if row.get("action") != "purge":
            continue
        stamp = str(row.get("timestamp") or "")
        if create_ts < stamp <= attest_ts:
            return True
    return False


def _path_is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _id_field_error(root: Path, engagement_id: str) -> str | None:
    if SAFE_ID.fullmatch(engagement_id) and (root / engagement_id).exists():
        return f"Engagement already exists: {engagement_id}"
    if _live_engagement_exists(root, engagement_id):
        return f"Engagement already exists: {engagement_id}"
    if _has_purge_record(root, engagement_id):
        return f"{engagement_id} was purged. Use a new id, for example {engagement_id}b."
    if NEW_ID.fullmatch(engagement_id):
        return None
    if not engagement_id.strip():
        return "Engagement ID is required."
    suggested = engagement_id.strip().lower()
    if suggested != engagement_id and NEW_ID.fullmatch(suggested):
        return f"Engagement ID differs only by case or whitespace. Use {suggested}."
    return (
        "Use lowercase letters, digits, and hyphens, 3 to 64 characters, "
        "with no leading or trailing hyphen."
    )


def _valid_date(value: str) -> bool:
    if not DATE_TEXT.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _parse_date(value: str) -> None:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise EngagementError(f"Date must be YYYY-MM-DD: {value}") from exc


def _parse_timestamp(value: str) -> None:
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise EngagementError(f"Timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ: {value}") from exc


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
