"""Local advisory cache. Sync is the only network command; investigations only read files."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from astrolabe.engagement import EngagementError, advisory_cache_dir, append_durable_audit, utc_now
from astrolabe.offline import in_investigation_run, investigation_lock_present

ADVISORY_ID_PATTERN = re.compile(r"^(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$")
NETWORK_NOTICE = (
    "This command contacts the OSV API at https://api.osv.dev and the GitHub Advisory API "
    "at https://api.github.com. It is the only Astrolabe command that uses the network. "
    "Investigation runs stay offline and fail closed when a cache file is missing."
)
USER_AGENT = "astrolabe-advisory-cache"
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
}


class GitHubRateLimit(EngagementError):
    """GitHub returned a rate-limit response. The message must not include a token."""


CACHE_FIELDS = ("id", "summary", "details", "aliases", "cwe_ids", "source_urls", "fetched_at")


def refuse_network_during_investigation(root: Path | None = None) -> None:
    if in_investigation_run() or investigation_lock_present(root):
        raise EngagementError("advisories sync is refused during an investigation run")


def github_headers() -> dict[str, str]:
    """Read GITHUB_TOKEN at call time. The value is a request header only."""
    headers = dict(GITHUB_HEADERS)
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _is_github_rate_limit(exc: urllib.error.HTTPError) -> bool:
    if exc.code not in (403, 429):
        return False
    remaining = ""
    if exc.headers is not None:
        remaining = str(exc.headers.get("X-RateLimit-Remaining", "")).strip()
    try:
        body = exc.read().decode("utf-8", "replace").lower()
    except Exception:
        body = ""
    if remaining == "0":
        return True
    return "rate limit" in body


def fetch_json(
    url: str,
    headers: dict[str, str] | None = None,
    *,
    opener=None,
) -> dict:
    refuse_network_during_investigation()
    request_headers = dict(headers or {"User-Agent": USER_AGENT})
    if "api.github.com" in url and "Authorization" not in request_headers:
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=request_headers)
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if "api.github.com" in url and _is_github_rate_limit(exc):
            raise GitHubRateLimit("GitHub rate limit reached") from None
        raise EngagementError(f"Advisory fetch failed for {url}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise EngagementError(f"Advisory fetch failed for {url}: {exc.reason}") from exc
    if not isinstance(payload, dict):
        raise EngagementError(f"Advisory fetch for {url} did not return an object")
    return payload


def fetch_advisory_record(advisory_id: str, *, opener=None) -> dict[str, object]:
    """Fetch OSV, then the GHSA alias when one is present. Caller must be outside a run."""
    if not ADVISORY_ID_PATTERN.fullmatch(advisory_id):
        raise EngagementError(f"Advisory id must be a CVE or GHSA id: {advisory_id}")
    refuse_network_during_investigation()
    osv = fetch_json(f"https://api.osv.dev/v1/vulns/{advisory_id}", opener=opener)
    aliases = _strings(osv.get("aliases"))
    if advisory_id not in aliases:
        aliases.append(advisory_id)
    ghsa_ids = [item for item in aliases if item.startswith("GHSA-")]
    if advisory_id.startswith("GHSA-") and advisory_id not in ghsa_ids:
        ghsa_ids.insert(0, advisory_id)
    summary = str(osv.get("summary") or "").strip()
    details = str(osv.get("details") or "").strip()
    cwe_ids = _cwe_ids(osv.get("database_specific"))
    source_urls = [f"https://osv.dev/vulnerability/{advisory_id}"]
    source = "osv"
    if ghsa_ids:
        if opener is None:
            time.sleep(0.4)
        ghsa = fetch_json(
            f"https://api.github.com/advisories/{ghsa_ids[0]}",
            github_headers(),
            opener=opener,
        )
        summary = str(ghsa.get("summary") or summary).strip()
        details = str(ghsa.get("description") or details).strip()
        for alias in _strings(ghsa.get("aliases")):
            if alias not in aliases:
                aliases.append(alias)
        ghsa_id = str(ghsa.get("ghsa_id") or ghsa_ids[0])
        if ghsa_id not in aliases:
            aliases.append(ghsa_id)
        cwe_ids = _unique(cwe_ids + _cwe_ids(ghsa.get("cwes")))
        source_urls.append(str(ghsa.get("html_url") or f"https://github.com/advisories/{ghsa_id}"))
        source = "osv+github-advisory"
    if not summary and not details:
        raise EngagementError(f"Advisory {advisory_id} has no summary or details")
    return {
        "id": advisory_id,
        "summary": summary,
        "details": details,
        "aliases": aliases,
        "cwe_ids": cwe_ids,
        "source_urls": source_urls,
        "source": source,
        "fetched_at": utc_now(),
    }


def sync_advisories(
    root: Path,
    *,
    actor: str,
    ids: list[str],
    cache: Path | None = None,
    opener=None,
    engagement_id: str | None = None,
    cache_level: bool = False,
) -> list[dict[str, object]]:
    if not actor.strip():
        raise EngagementError("Advisory sync requires an actor")
    if not ids:
        raise EngagementError("Advisory sync requires at least one CVE or GHSA id")
    refuse_network_during_investigation(root)
    destination = advisory_cache_dir(cache)
    destination.mkdir(parents=True, exist_ok=True)
    pending = [advisory_id for advisory_id in ids if not (destination / f"{advisory_id}.json").is_file()]
    cached_count = len(ids) - len(pending)
    if pending:
        print(NETWORK_NOTICE, flush=True)
    records: list[dict[str, object]] = []
    for index, advisory_id in enumerate(ids):
        if advisory_id not in pending:
            continue
        try:
            record = fetch_advisory_record(advisory_id, opener=opener)
        except GitHubRateLimit:
            remaining = [item for item in ids[index:] if item in pending or item == advisory_id]
            _audit_sync(
                root,
                actor.strip(),
                records,
                remaining=remaining,
                engagement_id=engagement_id,
                cache_level=cache_level,
            )
            fetched = [str(item["id"]) for item in records]
            fetched_text = ", ".join(fetched) if fetched else "none"
            remaining_text = ", ".join(remaining)
            raise EngagementError(
                f"GitHub rate limit reached. Fetched {len(fetched)}: {fetched_text}. "
                f"Remaining {len(remaining)}: {remaining_text}. "
                "Run advisories sync again with the remaining ids to resume."
            ) from None
        _write_cache(destination, record)
        records.append(record)
    _audit_sync(
        root,
        actor.strip(),
        records,
        remaining=[],
        engagement_id=engagement_id,
        cache_level=cache_level,
    )
    print(f"{cached_count} cached, {len(records)} fetched", flush=True)
    return records


def _audit_sync(
    root: Path,
    actor: str,
    records: list[dict[str, object]],
    *,
    remaining: list[str],
    engagement_id: str | None = None,
    cache_level: bool = False,
) -> None:
    if not records and not remaining:
        return
    source_urls: list[str] = []
    for record in records:
        for url in record.get("source_urls", []):
            if isinstance(url, str) and url not in source_urls:
                source_urls.append(url)
    detail: dict[str, object] = {
        "action": "advisories_sync",
        "actor": actor,
        "ids": [str(record["id"]) for record in records],
        "source": "osv+github-advisory",
        "source_urls": source_urls,
    }
    if remaining:
        detail["remaining"] = list(remaining)
    if cache_level and not engagement_id:
        detail["scope"] = "advisory_cache"
        append_durable_audit(root, "", detail, include_engagement_id=False)
        return
    append_durable_audit(root, engagement_id or "advisory-cache", detail)


def import_advisory_path(source: Path, *, cache: Path | None = None) -> list[str]:
    """Import one advisory JSON file, or every JSON file in a directory."""
    if source.is_file():
        destination = advisory_cache_dir(cache)
        destination.mkdir(parents=True, exist_ok=True)
        return [_import_advisory_file(source, destination)]
    return import_advisories(source, cache=cache)


def import_advisories(source: Path, *, cache: Path | None = None) -> list[str]:
    """Copy a cache prepared on another machine. This does not use the network."""
    if not source.is_dir():
        raise EngagementError(f"Advisory import source is not a directory: {source}")
    destination = advisory_cache_dir(cache)
    destination.mkdir(parents=True, exist_ok=True)
    imported = [_import_advisory_file(path, destination) for path in sorted(source.glob("*.json"))]
    if not imported:
        raise EngagementError(f"No advisory JSON files in {source}")
    return imported


def _import_advisory_file(path: Path, destination: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EngagementError(f"Advisory file could not be read: {path.name}") from exc
    if not isinstance(payload, dict):
        raise EngagementError(f"Advisory file is not an object: {path.name}")
    advisory_id = str(payload.get("id") or path.stem)
    if not ADVISORY_ID_PATTERN.fullmatch(advisory_id):
        raise EngagementError(f"Advisory file name is not a CVE or GHSA id: {path.name}")
    if not str(payload.get("summary") or "").strip() and not str(payload.get("details") or "").strip():
        raise EngagementError(f"Advisory {advisory_id} has no summary or details")
    payload["id"] = advisory_id
    target = destination / f"{advisory_id}.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return advisory_id


def load_id_list(path: Path) -> list[str]:
    ids: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            ids.append(text)
    return ids


def _write_cache(cache: Path, record: dict[str, object]) -> None:
    body = {field: record[field] for field in CACHE_FIELDS}
    target = cache / f"{record['id']}.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


def _cwe_ids(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        found.extend(_cwe_ids(value.get("cwe_ids")))
        cwe_id = value.get("cwe_id")
        if isinstance(cwe_id, str):
            found.append(_normalize_cwe(cwe_id))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                found.append(_normalize_cwe(item))
            else:
                found.extend(_cwe_ids(item))
    return _unique(found)


def _normalize_cwe(value: str) -> str:
    text = value.strip().upper()
    if text.isdigit():
        return f"CWE-{text}"
    if text.startswith("CWE-"):
        return text
    return text


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered
