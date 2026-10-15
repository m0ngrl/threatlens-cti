"""
ThreatLens - database conformance layer.
Database schema v1.5 (SQLite)
ZEIT3118 Capstone Project

Single source of truth for turning extractor and quality-checker output into
values the SQLite schema will actually accept.

The three components currently speak different dialects:

    extraction engine   ioc_type "ip" / "hash"
    quality checker     dimension scores on a 0-5 rubric; owns indicators.confidence
    database            confidence 0-100 int, CHECK constraints, JSON as TEXT

Every write path into the indicators table should pass through this module, so
a mismatch fails loudly here with a readable message instead of silently
truncating a value (int(0.96) == 0) or tripping a CHECK constraint at commit
time, which SQLite reports without naming the offending row.

Nothing in this module touches the database. It only converts and validates,
so it can be unit tested without a connection.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

# Bounds enforced by the indicators table CHECK constraints.
SCORE_MIN = 0
SCORE_MAX = 100

# The quality rubric scores each dimension 0-5 (paper Table 7).
RUBRIC_MAX = 5.0

# Context keys the completeness dimension expects, mirroring the
# scoring_config row seeded by seed.py.
#
# These are the SDO entity types the extraction engine actually emits, so every
# key here is reachable from extractor output. The earlier set included tlp and
# severity, which no extractor field can supply - completeness was therefore
# capped at 50% for every indicator in the repository regardless of how well
# described it was. malware_family was dropped with it; build_document_context()
# still writes that key when a report names malware, so the ctx_malware computed
# column keeps working, it just no longer counts toward the score.
EXPECTED_CONTEXT_KEYS = ("threat_actor", "campaign", "vulnerability", "tool")


class ConformanceError(ValueError):
    """Raised when a value cannot be represented in the database schema."""


# ---------------------------------------------------------------------------
# Numeric conversion
# ---------------------------------------------------------------------------

def _as_finite_number(value: Any, field: str) -> float:
    """Reject anything that is not a real, finite number.

    bool is excluded deliberately: it subclasses int in Python, so True would
    otherwise sail through as the number 1.
    """
    if isinstance(value, bool):
        raise ConformanceError(f"{field} must be numeric, got bool {value!r}")
    if not isinstance(value, (int, float)):
        raise ConformanceError(
            f"{field} must be numeric, got {type(value).__name__} {value!r}"
        )

    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise ConformanceError(f"{field} must be finite, got {value!r}")
    return numeric


def confidence_from_unit_interval(value: float) -> int:
    """Convert an extractor confidence (0.0-1.0) to the database's 0-100 int.

    This is the conversion the pipeline gets wrong most easily. The extractor
    emits 0.96; the column is an integer with CHECK (0..100). Truncating gives
    0 and the row still commits, so the error is invisible until someone reads
    the scores back.

    round() rather than int() matters: 0.29 * 100 is 28.999999999999996 in
    binary floating point, which int() would truncate to 28.
    """
    numeric = _as_finite_number(value, "confidence")

    if not 0.0 <= numeric <= 1.0:
        raise ConformanceError(
            f"confidence must be in the unit interval 0.0-1.0, got {value!r}. "
            "If this value is already a percentage, call "
            "confidence_from_percent() instead."
        )

    return round(numeric * SCORE_MAX)


def confidence_from_percent(value: float) -> int:
    """Normalise an already-percentage confidence to a 0-100 int."""
    numeric = _as_finite_number(value, "confidence")

    if not SCORE_MIN <= numeric <= SCORE_MAX:
        raise ConformanceError(
            f"confidence must be between {SCORE_MIN} and {SCORE_MAX}, "
            f"got {value!r}"
        )

    return round(numeric)


def quality_score_from_rubric(
    weighted_score: float,
    rubric_max: float = RUBRIC_MAX,
) -> int:
    """Convert a weighted 0-5 rubric score to the database's 0-100 int.

    The quality checker produces sum(weight * dimension_score) where the
    weights sum to 1.0, so the result shares the 0-5 range of the individual
    dimensions.
    """
    if rubric_max <= 0:
        raise ConformanceError(f"rubric_max must be positive, got {rubric_max!r}")

    numeric = _as_finite_number(weighted_score, "quality_score")

    if not 0.0 <= numeric <= rubric_max:
        raise ConformanceError(
            f"quality_score must be between 0 and {rubric_max}, got {value_repr(weighted_score)}"
        )

    return round(numeric / rubric_max * SCORE_MAX)


def value_repr(value: Any) -> str:
    """Short repr helper so error messages stay readable for long values."""
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


# ---------------------------------------------------------------------------
# Document identity
# ---------------------------------------------------------------------------

_SHA256_TEXT = re.compile(r"^[a-f0-9]{64}$")


def document_sha256(value: Any) -> str:
    """Normalise and validate a digest for raw_documents.sha256.

    That column is the whole of document-level deduplication: it carries
    CHECK (length(sha256) = 64) and a UNIQUE constraint, and re-ingesting a
    report is recognised by matching it. A digest that is merely the wrong
    *case* still compares unequal, so the same report ingested twice would
    produce two sources and double every sighting count - silently, and in the
    dimension that carries the heaviest weight.

    Normalising to lower case here is therefore not cosmetic.
    """
    if not isinstance(value, str):
        raise ConformanceError(
            f"sha256 must be a string, got {type(value).__name__} "
            f"{value_repr(value)}"
        )

    digest = value.strip().lower()
    if not _SHA256_TEXT.fullmatch(digest):
        raise ConformanceError(
            f"sha256 must be 64 hexadecimal characters, got "
            f"{value_repr(value)} ({len(digest)} characters)"
        )

    return digest


# ---------------------------------------------------------------------------
# Indicator type vocabulary
# ---------------------------------------------------------------------------

# Extractor IndicatorType value -> database ioc_type.
# The database side is the vocabulary the allowlist table is seeded with, so
# these names are what a false-positive lookup will actually match against.
_SIMPLE_IOC_TYPES: dict[str, str] = {
    "domain": "domain",
    "url": "url",
    "hostname": "hostname",
    "port": "port",
    "certificate": "certificate",
    "user_agent": "user_agent",
    "filename": "filename",
    "filepath": "filepath",
    "registry": "registry_key",
    "mutex": "mutex",
    "process": "process",
    "service": "service",
    "scheduled_task": "scheduled_task",
    "email_address": "email_address",
    "email_domain": "email_domain",
    "email_subject": "email_subject",
    "email_header": "email_header",
    "attachment": "attachment",
}

_BEHAVIOUR_IOC_TYPES = frozenset({
    "beaconing",
    "process_chain",
    "lateral_movement",
    "persistence",
    "exfiltration",
})

# Intelligence entities describe an indicator rather than being one. seed.py
# lists malware_family and campaign as expected *context* keys, so these are
# folded into indicators.context rather than given their own rows.
CONTEXT_ONLY_TYPES = frozenset({
    "malware",
    "threat_actor",
    "campaign",
    "tool",
    "vulnerability",
    "ttp",
})

_HASH_ALGORITHMS = frozenset({"md5", "sha1", "sha256", "sha512"})


def to_ioc_type(
    indicator_type: str,
    attributes: Mapping[str, Any] | None = None,
) -> str:
    """Map an extractor indicator_type to the database ioc_type vocabulary.

    Two extractor types are deliberately coarser than the database's, and are
    narrowed using the attributes the extractor already supplies:

        ip   + attributes["ip_version"]  -> ipv4 / ipv6
        hash + attributes["algorithm"]   -> md5 / sha1 / sha256 / sha512

    The narrowing is not cosmetic. The seeded allowlist stores patterns under
    "ipv4", so an indicator left as "ip" would never match a false positive.
    """
    attributes = attributes or {}
    key = str(indicator_type).strip().lower()

    if key == "ip":
        version = attributes.get("ip_version")
        if version == 4:
            return "ipv4"
        if version == 6:
            return "ipv6"
        raise ConformanceError(
            "ip indicators require attributes['ip_version'] of 4 or 6, "
            f"got {value_repr(version)}"
        )

    if key == "hash":
        algorithm = str(attributes.get("algorithm", "")).strip().lower()
        if algorithm in _HASH_ALGORITHMS:
            return algorithm
        raise ConformanceError(
            "hash indicators require attributes['algorithm'] to be one of "
            f"{sorted(_HASH_ALGORITHMS)}, got {value_repr(algorithm)}"
        )

    if key in _SIMPLE_IOC_TYPES:
        return _SIMPLE_IOC_TYPES[key]

    if key in _BEHAVIOUR_IOC_TYPES:
        return key

    if key in CONTEXT_ONLY_TYPES:
        raise ConformanceError(
            f"{key!r} is an intelligence entity, not an indicator. Fold it into "
            "the context JSON of the indicator it describes rather than "
            "inserting it as its own row."
        )

    raise ConformanceError(f"unmapped indicator_type {value_repr(indicator_type)}")


def is_context_only(indicator_type: str) -> bool:
    """Return whether this extractor type belongs in context, not its own row."""
    return str(indicator_type).strip().lower() in CONTEXT_ONLY_TYPES


# ---------------------------------------------------------------------------
# Text-encoded column types
# ---------------------------------------------------------------------------

def to_iso8601(value: datetime | str | None = None) -> str:
    """Return an ISO-8601 UTC timestamp string, the format models.py expects.

    Naive datetimes are assumed to be UTC rather than local time, so that two
    team members in different timezones seed comparable data.
    """
    if value is None:
        moment = datetime.now(UTC)
    elif isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ConformanceError(
                f"timestamp {value_repr(value)} is not valid ISO-8601: {exc}"
            ) from exc
    else:
        raise ConformanceError(
            f"timestamp must be datetime, str or None, got {type(value).__name__}"
        )

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)

    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_json_text(value: Any) -> str | None:
    """Serialise a value for a TEXT column guarded by a json_valid() CHECK.

    Strings are passed through but validated, so a caller that has already
    serialised does not get double-encoded into a JSON string containing JSON.
    """
    if value is None:
        return None

    if isinstance(value, str):
        try:
            json.loads(value)
        except json.JSONDecodeError as exc:
            raise ConformanceError(
                f"context/score_components string is not valid JSON: {exc}"
            ) from exc
        return value

    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ConformanceError(
            f"value is not JSON-serialisable: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------

def from_extraction(extraction: Mapping[str, Any]) -> dict[str, Any]:
    """Build an indicators row from one extractor record.

    Accepts the dictionaries produced by CTIExtractor - either Extraction.to_dict()
    or an element of the JSON written by extract_pdf_iocs.py.

    confidence is left None here - the extractor no longer supplies it. It is
    the quality checker's column to fill in via confidence_from_unit_interval()
    or confidence_from_percent(), same as quality_score.
    """
    if not isinstance(extraction, Mapping):
        raise ConformanceError(
            f"extraction must be a mapping, got {type(extraction).__name__}"
        )

    for required in ("indicator_type", "value", "normalized_value"):
        if not extraction.get(required):
            raise ConformanceError(f"extraction is missing {required!r}")

    indicator_type = extraction["indicator_type"]
    attributes = extraction.get("attributes") or {}

    row: dict[str, Any] = {
        "ioc_type": to_ioc_type(indicator_type, attributes),
        "value": str(extraction["value"]),
        "normalised": str(extraction["normalized_value"]),
        "confidence": None,
        "context": None,
        "quality_score": None,
        "score_components": None,
        "first_seen": None,
        "last_seen": None,
        "scored_at": None,
    }

    # The extractor's free-text context window is evidence, not structured
    # context. It is kept under a namespaced key so the quality checker can add
    # malware_family / campaign / tlp / severity alongside it.
    context: dict[str, Any] = {}
    if extraction.get("context"):
        context["excerpt"] = str(extraction["context"])
    if extraction.get("method"):
        context["extraction_method"] = str(extraction["method"])
    if attributes:
        context["attributes"] = dict(attributes)
    if context:
        row["context"] = to_json_text(context)

    return row


def validate_indicator_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Check a row against the indicators table constraints before insert.

    Mirrors the CHECK constraints in models.py so a violation is reported with
    the column name and value, rather than as a generic SQLite IntegrityError.
    """
    if not isinstance(row, Mapping):
        raise ConformanceError(f"row must be a mapping, got {type(row).__name__}")

    for required in ("ioc_type", "value", "normalised"):
        if not row.get(required):
            raise ConformanceError(f"row is missing required column {required!r}")

    for column in ("confidence", "quality_score"):
        score = row.get(column)
        if score is None:
            continue
        if isinstance(score, bool) or not isinstance(score, int):
            raise ConformanceError(
                f"{column} must be an int for the CHECK constraint, got "
                f"{type(score).__name__} {value_repr(score)}"
            )
        if not SCORE_MIN <= score <= SCORE_MAX:
            raise ConformanceError(
                f"{column} must be between {SCORE_MIN} and {SCORE_MAX}, "
                f"got {score}"
            )

    for column in ("context", "score_components"):
        encoded = row.get(column)
        if encoded is None:
            continue
        if not isinstance(encoded, str):
            raise ConformanceError(
                f"{column} must already be JSON text; call to_json_text() first"
            )
        try:
            json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise ConformanceError(
                f"{column} would fail the json_valid() CHECK: {exc}"
            ) from exc

    for column in ("first_seen", "last_seen", "scored_at"):
        stamp = row.get(column)
        if stamp is not None:
            to_iso8601(stamp)

    return dict(row)
