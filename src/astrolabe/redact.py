"""Read path for CLI traces and reports.

This is the CLI export redaction chokepoint (message content, tool arguments,
tool results, ingest text, and secret record keys). Callers that load a trace
or a report back onto the host go through these functions and do not keep the
raw payload.
"""

from __future__ import annotations

import json
import math
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REDACTED = "<redacted>"
REDACTED_TRACE = "<redacted from portable export>"
CONFIGURED = "<configured>"

# Shift-Left presentation heuristic (secret_values.is_secret_shaped_for_prose).
# Applied here to high-entropy tokens in source text. Keyword field names stay a fallback.
_AMBIGUOUS_SECRET_VALUES = frozenset(
    {"public", "private", "cisco", "admin", "secret", "password", "manager", "monitor"}
)
_AWS_KEY = re.compile(r"\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
    re.DOTALL,
)
_CONNECTION_USERINFO = re.compile(
    r"\b([a-z][a-z0-9+.-]*://)([^\s/:@]+):([^\s/@]+)@",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/-]{8,})")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SSH_KEY_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:sk-ecdsa-|sk-ssh-|ecdsa-sha2-|ssh-)[A-Za-z0-9@.+/=_-]*"
    r"(?:[ \t]+[A-Za-z0-9+/=]{8,})?"
)
_SECRET_SHAPED_TOKEN = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9+/_=-]{20,})(?![A-Za-z0-9])")
_HYPHENATED_LABEL = re.compile(r"[A-Za-z]+(?:-[A-Za-z]+)+")
_LONG_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_=-])([A-Za-z0-9+/_=-]{40,})(?![A-Za-z0-9+/_=-])")
_IDENTIFIER_HEX = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")

_SECRET_OPTION_NAMES = {
    "--api-key",
    "--endpoint",
    "--token",
    "--password",
    "--secret",
}
_SECRET_RECORD_KEYS = {
    "api_key",
    "authorization",
    "password",
    "secret",
    "token",
}
_MAX_TRACE_BYTES = 50 * 1024 * 1024


def read_trace(path: Path) -> list[dict[str, object]]:
    """Return sanitized trace events. Raw message and tool text is not returned."""
    if path.stat().st_size > _MAX_TRACE_BYTES:
        raise ValueError(f"Investigation trace exceeds the {_MAX_TRACE_BYTES:,}-byte limit")
    events: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(sanitize_trace_event(event))
    return events


MITRE_LIKELIHOOD_LABEL = "MITRE likelihood for this weakness class (not model confidence)"


def read_report(path: Path) -> dict[str, object]:
    """Return a report with secret fields redacted. Finding paths are kept."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("CLI report must be a JSON object")
    sanitized = sanitize_export_value(payload)
    if not isinstance(sanitized, dict):
        raise ValueError("CLI report must be a JSON object")
    return label_mitre_likelihood(sanitized)


def label_mitre_likelihood(payload: dict[str, object]) -> dict[str, object]:
    """Name the CWE likelihood so it is not read as model confidence."""
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return payload
    labeled: list[object] = []
    for finding in findings:
        if not isinstance(finding, dict) or "likelihood_of_exploit" not in finding:
            labeled.append(finding)
            continue
        rewritten = dict(finding)
        value = rewritten.pop("likelihood_of_exploit")
        rewritten["mitre_likelihood"] = {"value": value, "label": MITRE_LIKELIHOOD_LABEL}
        labeled.append(rewritten)
    payload["findings"] = labeled
    return payload


def sanitize_trace_event(event: dict[str, object]) -> dict[str, object]:
    sanitized = sanitize_export_value(event)
    if not isinstance(sanitized, dict):
        return event
    return sanitized


def redact_text(text: str) -> str:
    """Pattern scan, then the Shift-Left secret-shaped check on high-entropy tokens."""
    redacted = _PEM_BLOCK.sub(REDACTED, text)
    redacted = _SSH_KEY_TOKEN.sub(REDACTED, redacted)
    redacted = _AWS_KEY.sub(REDACTED, redacted)
    redacted = _JWT.sub(REDACTED, redacted)
    redacted = _BEARER.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = _CONNECTION_USERINFO.sub(lambda match: f"{match.group(1)}{REDACTED}@", redacted)
    redacted = _SECRET_SHAPED_TOKEN.sub(_redact_secret_shaped, redacted)
    return _LONG_BASE64.sub(_redact_long_base64, redacted)


@dataclass(frozen=True)
class SecretMatch:
    """A detector hit. The matched text is not stored."""

    line: int
    rule: str


def find_secret_matches(text: str) -> list[SecretMatch]:
    """Same detectors as redact_text, without rewriting or returning the value."""
    found: list[SecretMatch] = []
    seen: set[tuple[int, str]] = set()

    def add(rule: str, start: int) -> None:
        item = SecretMatch(text.count("\n", 0, start) + 1, rule)
        key = (item.line, item.rule)
        if key in seen:
            return
        seen.add(key)
        found.append(item)

    for match in _PEM_BLOCK.finditer(text):
        add("pem", match.start())
    for match in _SSH_KEY_TOKEN.finditer(text):
        add("ssh_key", match.start())
    for match in _AWS_KEY.finditer(text):
        add("aws_key", match.start())
    for match in _JWT.finditer(text):
        add("jwt", match.start())
    for match in _BEARER.finditer(text):
        add("bearer", match.start())
    for match in _CONNECTION_USERINFO.finditer(text):
        add("connection_userinfo", match.start())
    for match in _SECRET_SHAPED_TOKEN.finditer(text):
        if _redact_secret_shaped(match) == REDACTED:
            add("secret_shaped", match.start())
    for match in _LONG_BASE64.finditer(text):
        if _redact_long_base64(match) == REDACTED:
            add("long_base64", match.start())
    return found


def _redact_long_base64(match: re.Match[str]) -> str:
    token = match.group(1)
    if _IDENTIFIER_HEX.fullmatch(token):
        return token
    return REDACTED


def is_secret_shaped(value: str) -> bool:
    """Shift-Left prose heuristic: mixed classes, not a short dictionary word."""
    if value.strip().lower() in _AMBIGUOUS_SECRET_VALUES:
        return False
    stripped = value.strip()
    if len(stripped) < 6:
        return False
    if stripped.isalpha() and stripped.isascii() and len(stripped) < 12:
        return False
    classes: set[str] = set()
    for char in stripped:
        if char.islower():
            classes.add("lower")
        elif char.isupper():
            classes.add("upper")
        elif char.isdigit():
            classes.add("digit")
        else:
            classes.add("special")
    if len(classes) < 2:
        return False
    if len(stripped) >= 8:
        return True
    return "digit" in classes or "special" in classes


def _redact_secret_shaped(match: re.Match[str]) -> str:
    token = match.group(1)
    if _IDENTIFIER_HEX.fullmatch(token):
        return token
    if _HYPHENATED_LABEL.fullmatch(token):
        return token
    if not is_secret_shaped(token):
        return token
    if _class_count(token) < 3 or _shannon_entropy(token) < 3.5:
        return token
    return REDACTED


def _class_count(value: str) -> int:
    classes: set[str] = set()
    for char in value:
        if char.islower():
            classes.add("lower")
        elif char.isupper():
            classes.add("upper")
        elif char.isdigit():
            classes.add("digit")
        else:
            classes.add("special")
    return len(classes)


def _shannon_entropy(value: str) -> float:
    length = len(value)
    if length == 0:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            redacted.append(REDACTED)
            skip_next = False
        elif arg in _SECRET_OPTION_NAMES:
            redacted.append(arg)
            skip_next = True
        elif "=" in arg and arg.partition("=")[0] in _SECRET_OPTION_NAMES:
            redacted.append(f"{arg.partition('=')[0]}={REDACTED}")
        else:
            redacted.append(arg)
    return redacted


def sanitize_export_value(value: object, *, key: str | None = None) -> object:
    normalized_key = key.lower() if key is not None else None
    if normalized_key in _SECRET_RECORD_KEYS and value is not None:
        return REDACTED
    if normalized_key == "endpoint" and value:
        return CONFIGURED
    if normalized_key == "remote_url" and isinstance(value, str):
        return sanitize_git_remote_url(value)
    if isinstance(value, dict):
        return {
            str(nested_key): sanitize_export_value(nested_value, key=str(nested_key))
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [sanitize_export_value(item) for item in value]
    if isinstance(value, str) and normalized_key != "file_path":
        return redact_text(value)
    return value


def sanitize_git_remote_url(remote_url: str | None) -> str | None:
    if remote_url is None or "://" not in remote_url:
        return remote_url
    try:
        parsed = urlsplit(remote_url)
        hostname = parsed.hostname
        if hostname is None:
            return None
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except ValueError:
        return None


def redact_invocation(record: dict[str, object]) -> dict[str, object]:
    sanitized = sanitize_export_value(record)
    if not isinstance(sanitized, dict):
        raise TypeError("Sanitized run record must remain an object")
    original = record.get("invocation")
    updated = sanitized.get("invocation")
    if isinstance(original, dict) and isinstance(updated, dict):
        raw_argv = original.get("argv")
        if isinstance(raw_argv, list) and all(isinstance(item, str) for item in raw_argv):
            redacted_argv = redact_argv(raw_argv)
        else:
            raw_command = original.get("command")
            try:
                parsed = shlex.split(raw_command) if isinstance(raw_command, str) else []
            except ValueError:
                parsed = []
            redacted_argv = redact_argv(parsed)
        updated["argv"] = redacted_argv
        updated["command"] = shlex.join(redacted_argv)
    return sanitized
