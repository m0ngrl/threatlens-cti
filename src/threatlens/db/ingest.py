"""
ThreatLens - ingest layer.
Database schema v1.5 (SQLite)
ZEIT3118 Capstone Project

Writes extractor output into the four operational tables:

    sources -> raw_documents -> indicators -> sightings

Design notes worth knowing before changing this module:

* Ingest is idempotent. A document is identified by the SHA-256 of its bytes
  (or of its text when no file is available), and raw_documents.sha256 is
  UNIQUE. Re-running ingest on the same report reuses the existing source
  rather than creating a second one, so sighting counts stay honest.

* sightings has a composite primary key of (indicator_id, source_id), so an
  indicator appearing forty times in one report is one sighting, not forty.
  That is what makes the accuracy dimension meaningful: it counts corroborating
  *sources*, not repetitions.

* indicators is deduplicated by the uq_indicator_type_norm UNIQUE constraint on
  (ioc_type, normalised). The database is the deduplication mechanism; this
  module does not reimplement it, it just respects it.

* Intelligence entities (malware, campaign, threat actor, ...) are skipped
  rather than inserted. They describe indicators instead of being indicators.
  See conformance.CONTEXT_ONLY_TYPES.

* sources.extraction_engine records which verifier judged the report
  ('python', 'llm', or 'llm+python'). Re-ingesting a known report with the
  other engine widens it to 'llm+python' rather than overwriting it, since
  the source then holds sightings from both.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatlens.db import conformance
from threatlens.db.models import Indicator, RawDocument, Sighting, Source

_CONTENT_TYPES = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".json": "application/json",
    ".html": "text/html",
    ".htm": "text/html",
}


@dataclass
class IngestResult:
    """Summary of one ingest run, for reporting and for tests to assert on."""

    source_id: int | None = None
    source_created: bool = False
    indicators_created: int = 0
    indicators_updated: int = 0
    sightings_created: int = 0
    skipped_context_only: int = 0
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"source_id={self.source_id} "
            f"({'new' if self.source_created else 'existing'}), "
            f"indicators +{self.indicators_created}/~{self.indicators_updated}, "
            f"sightings +{self.sightings_created}, "
            f"context-only skipped {self.skipped_context_only}, "
            f"errors {len(self.errors)}"
        )


# ---------------------------------------------------------------------------
# Document identity
# ---------------------------------------------------------------------------

def resolve_sha256(
    sha256: str | None = None,
    file_path: Path | str | None = None,
    raw_text: str | None = None,
) -> str:
    """Return the document identity to store, preferring a supplied digest.

    The extraction engine already hashes the report it read and emits it as
    metadata.file_sha256, so a caller working from extractor JSON knows the
    document's true identity even without the original PDF to hand. Hashing
    the JSON instead would mint a *different* identity for the same document,
    and raw_documents.sha256 UNIQUE would then happily store it twice - the
    exact duplication the constraint exists to prevent.

    Falls back to compute_sha256() when no digest is supplied.
    """
    if sha256:
        return conformance.document_sha256(sha256)
    return compute_sha256(Path(file_path) if file_path else None, raw_text)


def compute_sha256(file_path: Path | None = None, raw_text: str | None = None) -> str:
    """Return the SHA-256 that identifies a document.

    Prefers the file's bytes so the same report ingested from two different
    directories is recognised as one document. Falls back to the extracted text
    when the original file is not available.
    """
    if file_path is not None:
        path = Path(file_path)
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            return digest.hexdigest()

    if raw_text:
        return hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    raise conformance.ConformanceError(
        "cannot identify document: provide an existing file_path or raw_text"
    )


def _guess_content_type(file_path: Path | None) -> str:
    if file_path is None:
        return "text/plain"
    return _CONTENT_TYPES.get(Path(file_path).suffix.lower(), "application/octet-stream")


# ---------------------------------------------------------------------------
# Extraction engine
# ---------------------------------------------------------------------------

EXTRACTION_ENGINES = ("python", "llm", "llm+python")

# The verification_model the Python verifier reports; any other non-empty
# model name is an LLM.
PYTHON_VERIFIER_MODEL = "python-heuristics"


def engine_for_model(verification_model: str | None) -> str | None:
    """'python' or 'llm' for a verifier's model name; None when unknown."""
    model = (verification_model or "").strip().lower()
    if not model or model == "unknown":
        return None
    return "python" if model == PYTHON_VERIFIER_MODEL else "llm"


def combine_engines(*engines: str | None) -> str | None:
    """Union of engine labels: 'llm' + 'python' -> 'llm+python'."""
    parts = {
        part
        for engine in engines
        if engine
        for part in engine.split("+")
    }
    unknown = parts - {"python", "llm"}
    if unknown:
        raise conformance.ConformanceError(
            f"unknown extraction engine {sorted(unknown)!r}; expected one of {EXTRACTION_ENGINES}"
        )
    if not parts:
        return None
    return "+".join(sorted(parts))  # "llm+python" sorts that way already


def _combine_models(*models: str | None) -> str | None:
    """Comma-joined distinct model names, first-seen order."""
    seen: list[str] = []
    for model in models:
        for name in (model or "").split(","):
            name = name.strip()
            if name and name not in seen:
                seen.append(name)
    return ", ".join(seen) or None


# ---------------------------------------------------------------------------
# Source / raw document
# ---------------------------------------------------------------------------

def get_or_create_source(
    session: Session,
    *,
    name: str,
    source_type: str,
    sha256: str,
    url: str | None = None,
    raw_text: str | None = None,
    file_path: Path | str | None = None,
    content_type: str | None = None,
    reliability: int | None = None,
    metadata: Mapping[str, Any] | None = None,
    extraction_engine: str | None = None,
    verification_model: str | None = None,
) -> tuple[Source, bool]:
    """Return (source, created). Reuses the source when the document is known.

    A reused source has this run's engine and model merged into its own.
    """
    extraction_engine = combine_engines(extraction_engine)

    existing = session.execute(
        select(RawDocument).where(RawDocument.sha256 == sha256)
    ).scalars().first()

    if existing is not None:
        source = existing.source
        source.extraction_engine = combine_engines(source.extraction_engine, extraction_engine)
        source.verification_model = _combine_models(source.verification_model, verification_model)
        return source, False

    if reliability is not None:
        reliability = conformance.confidence_from_percent(reliability)

    source = Source(
        name=name,
        source_type=source_type,
        url=url,
        raw_metadata=conformance.to_json_text(metadata) if metadata else None,
        reliability=reliability,
        ingested_at=conformance.to_iso8601(),
        extraction_engine=extraction_engine,
        verification_model=_combine_models(verification_model),
    )
    session.add(source)
    session.flush()  # assign source.id before the FK below

    size_bytes = None
    if file_path is not None and Path(file_path).is_file():
        size_bytes = Path(file_path).stat().st_size
    elif raw_text:
        size_bytes = len(raw_text.encode("utf-8"))

    session.add(
        RawDocument(
            source_id=source.id,
            content_type=content_type or _guess_content_type(
                Path(file_path) if file_path else None
            ),
            # The CHECK constraint requires at least one of these to be present.
            raw_text=raw_text,
            file_path=str(file_path) if file_path else None,
            sha256=sha256,
            size_bytes=size_bytes,
            archived_at=conformance.to_iso8601(),
        )
    )
    session.flush()
    return source, True


# ---------------------------------------------------------------------------
# Indicators and sightings
# ---------------------------------------------------------------------------

def _collapse_by_identity(
    extractions: Iterable[Mapping[str, Any]],
) -> tuple[dict[tuple[str, str], tuple[dict, Mapping]], int, list[str]]:
    """Reduce many extractions to one row per (ioc_type, normalised).

    The extractor already deduplicates within a page, but a report is extracted
    page by page, so the same indicator legitimately arrives several times. The
    occurrence with the longer context excerpt wins, matching the extractor's
    own tie-break (extractions no longer carry a confidence value to compare).
    """
    best: dict[tuple[str, str], tuple[dict, Mapping]] = {}
    skipped = 0
    errors: list[str] = []

    for extraction in extractions:
        indicator_type = extraction.get("indicator_type", "")

        if conformance.is_context_only(indicator_type):
            skipped += 1
            continue

        try:
            row = conformance.from_extraction(extraction)
        except conformance.ConformanceError as exc:
            errors.append(str(exc))
            continue

        key = (row["ioc_type"], row["normalised"])
        current = best.get(key)

        if current is None or len(str(extraction.get("context") or "")) > len(
            str(current[1].get("context") or "")
        ):
            best[key] = (row, extraction)

    return best, skipped, errors


def dedupe_extractions(
    extractions: Iterable[Mapping[str, Any]],
) -> tuple[list[Mapping[str, Any]], int, list[str]]:
    """Reduce many extractions to one per (ioc_type, normalised) identity.

    Public, DB-free wrapper around _collapse_by_identity(): a report is
    extracted page by page, so the same indicator legitimately arrives
    several times before it ever reaches a database. Callers that score
    before ingesting (see ingest_scored_rows()) use this first, so the
    quality checker scores each unique indicator once rather than once per
    occurrence.

    Returns the surviving raw extractions (not database rows), context-only
    entities skipped, and conformance errors - the same accounting
    ingest_extractions() folds into its IngestResult.
    """
    collapsed, skipped, errors = _collapse_by_identity(extractions)
    surviving = [original for _row, original in collapsed.values()]
    return surviving, skipped, errors


def ingest_scored_rows(
    session: Session,
    scored: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    source_name: str,
    source_type: str = "report",
    url: str | None = None,
    raw_text: str | None = None,
    file_path: Path | str | None = None,
    content_type: str | None = None,
    reliability: int | None = None,
    metadata: Mapping[str, Any] | None = None,
    seen_at: str | None = None,
    sha256: str | None = None,
    extraction_engine: str | None = None,
    verification_model: str | None = None,
) -> IngestResult:
    """Ingest rows the quality checker has already scored.

    Companion to ingest_extractions(): that function derives a row from a raw
    extraction via conformance.from_extraction() and leaves scoring to a
    later rescore_indicators() pass over the database. This one takes rows
    the caller already ran through quality_checker.check_report() - so they
    already carry confidence/quality_score/score_components/scored_at - and
    writes them as given rather than re-deriving them.

    `scored` pairs each row with its original extraction (dedupe_extractions()
    output), purely so the sighting can still record the excerpt/offset the
    row itself does not carry. The caller is responsible for committing.

    Pass `sha256` when the document's true digest is already known - the
    extractor supplies it as metadata.file_sha256 - so the identity is the
    report itself rather than whatever text happened to be available.
    """
    result = IngestResult()
    seen_at = conformance.to_iso8601(seen_at)

    sha256 = resolve_sha256(sha256, file_path, raw_text)

    source, created = get_or_create_source(
        session,
        name=source_name,
        source_type=source_type,
        sha256=sha256,
        url=url,
        raw_text=raw_text,
        file_path=file_path,
        content_type=content_type,
        reliability=reliability,
        metadata=metadata,
        extraction_engine=extraction_engine,
        verification_model=verification_model,
    )
    result.source_id = source.id
    result.source_created = created

    touched: set[int] = set()

    for row, original in scored:
        row = dict(row)
        ioc_type = row["ioc_type"]
        normalised = row["normalised"]

        indicator = session.execute(
            select(Indicator).where(
                Indicator.ioc_type == ioc_type,
                Indicator.normalised == normalised,
            )
        ).scalars().first()

        if indicator is None:
            # Report dates only: the row's last_seen is the report's publish
            # date (None if unknown). refresh_seen_dates() below settles both
            # columns across every report that sighted the indicator.
            row["first_seen"] = row.get("last_seen")
            conformance.validate_indicator_row(row)
            indicator = Indicator(**row)
            session.add(indicator)
            session.flush()
            result.indicators_created += 1
        else:
            # Already-scored values win, since they reflect this run's
            # determination; only fall back to what's there if this row
            # genuinely did not carry a value. first_seen / last_seen are not
            # set here: refresh_seen_dates() derives them below.
            indicator.quality_score = row.get("quality_score", indicator.quality_score)
            indicator.score_components = row.get("score_components", indicator.score_components)
            indicator.scored_at = row.get("scored_at", indicator.scored_at)
            if indicator.context is None and row.get("context") is not None:
                indicator.context = row["context"]
            result.indicators_updated += 1

        existing_sighting = session.get(Sighting, (indicator.id, source.id))
        if existing_sighting is None:
            session.add(
                Sighting(
                    indicator_id=indicator.id,
                    source_id=source.id,
                    seen_at=seen_at,
                    excerpt_start=original.get("start"),
                    excerpt_end=original.get("end"),
                    excerpt=(original.get("context") or None),
                )
            )
            result.sightings_created += 1
        touched.add(indicator.id)

    session.flush()
    refresh_seen_dates(session, touched)
    return result


def refresh_seen_dates(
    session: Session,
    indicator_ids: Iterable[int] | None = None,
) -> int:
    """Set first_seen / last_seen from the publish dates of sighting reports.

    first_seen is the earliest and last_seen the latest publish_date among the
    reports (sources.raw_metadata) that sighted each indicator, so the result
    does not depend on the order reports were ingested in. Ingest time is never
    used: an indicator whose reports carry no parseable publish date gets NULL
    for both, which timeliness scores as unknown.

    `indicator_ids` limits the refresh to those indicators; None means all.
    Returns the number of indicators updated. The caller commits.
    """
    ids = None if indicator_ids is None else set(indicator_ids)
    if ids is not None and not ids:
        return 0

    stmt = select(Sighting.indicator_id, Source.raw_metadata).join(
        Source, Source.id == Sighting.source_id
    )
    if ids is not None:
        stmt = stmt.where(Sighting.indicator_id.in_(ids))

    dates: dict[int, list[str]] = {}
    report_dates: dict[str | None, str | None] = {}
    for indicator_id, raw_metadata in session.execute(stmt).all():
        if raw_metadata not in report_dates:
            report_dates[raw_metadata] = _publish_date(raw_metadata)
        published = report_dates[raw_metadata]
        bucket = dates.setdefault(indicator_id, [])
        if published:
            bucket.append(published)

    query = select(Indicator)
    if ids is not None:
        query = query.where(Indicator.id.in_(ids))

    updated = 0
    for indicator in session.execute(query).scalars():
        found = dates.get(indicator.id) or []
        first, last = (min(found), max(found)) if found else (None, None)
        if (indicator.first_seen, indicator.last_seen) != (first, last):
            indicator.first_seen, indicator.last_seen = first, last
            updated += 1
    return updated


def _publish_date(raw_metadata: str | None) -> str | None:
    """A source's publish_date as ISO-8601 UTC, or None if absent/unparseable."""
    if not raw_metadata:
        return None
    try:
        published = json.loads(raw_metadata).get("publish_date")
    except (json.JSONDecodeError, AttributeError):
        return None
    if not published:
        return None
    try:
        return conformance.to_iso8601(str(published))
    except conformance.ConformanceError:
        return None


def ingest_extractions(
    session: Session,
    extractions: Iterable[Mapping[str, Any]],
    *,
    source_name: str,
    source_type: str = "report",
    url: str | None = None,
    raw_text: str | None = None,
    file_path: Path | str | None = None,
    content_type: str | None = None,
    reliability: int | None = None,
    metadata: Mapping[str, Any] | None = None,
    seen_at: str | None = None,
    sha256: str | None = None,
    extraction_engine: str | None = None,
    verification_model: str | None = None,
) -> IngestResult:
    """Ingest one document's worth of extractor output.

    Pass `sha256` when the document's true digest is already known; see
    resolve_sha256().

    The caller is responsible for committing. Nothing here commits, so a failed
    ingest can be rolled back as a unit.
    """
    result = IngestResult()
    seen_at = conformance.to_iso8601(seen_at)

    sha256 = resolve_sha256(sha256, file_path, raw_text)

    source, created = get_or_create_source(
        session,
        name=source_name,
        source_type=source_type,
        sha256=sha256,
        url=url,
        raw_text=raw_text,
        file_path=file_path,
        content_type=content_type,
        reliability=reliability,
        metadata=metadata,
        extraction_engine=extraction_engine,
        verification_model=verification_model,
    )
    result.source_id = source.id
    result.source_created = created

    collapsed, skipped, errors = _collapse_by_identity(extractions)
    result.skipped_context_only = skipped
    result.errors.extend(errors)

    for (ioc_type, normalised), (row, original) in collapsed.items():
        indicator = session.execute(
            select(Indicator).where(
                Indicator.ioc_type == ioc_type,
                Indicator.normalised == normalised,
            )
        ).scalars().first()

        if indicator is None:
            row["first_seen"] = seen_at
            row["last_seen"] = seen_at
            conformance.validate_indicator_row(row)
            indicator = Indicator(**row)
            session.add(indicator)
            session.flush()
            result.indicators_created += 1
        else:
            # Extend the last_seen window. Existing context is not overwritten.
            # indicator.confidence is not touched here - it is the quality
            # checker's column, recomputed by rescore_indicators().
            indicator.last_seen = seen_at
            if indicator.context is None and row.get("context") is not None:
                indicator.context = row["context"]
            result.indicators_updated += 1

        existing_sighting = session.get(Sighting, (indicator.id, source.id))
        if existing_sighting is None:
            session.add(
                Sighting(
                    indicator_id=indicator.id,
                    source_id=source.id,
                    seen_at=seen_at,
                    excerpt_start=original.get("start"),
                    excerpt_end=original.get("end"),
                    excerpt=(original.get("context") or None),
                )
            )
            result.sightings_created += 1

    return result


def ingest_extraction_file(
    session: Session,
    json_path: Path | str,
    *,
    source_name: str | None = None,
    **kwargs: Any,
) -> IngestResult:
    """Ingest a JSON file produced by the extraction engine.

    Accepts the current form written by cli.py (a metadata block plus an
    indicators array) as well as the flat list and grouped-by-category forms
    the archived extractors produced.

    Document identity comes from metadata.file_sha256 where the extractor
    supplied it, then from the original document path, and only then from the
    JSON text. That order matters: hashing the JSON would give the same report
    two identities if it were ever ingested from its PDF as well.
    """
    json_path = Path(json_path)
    data = json.loads(json_path.read_text(encoding="utf-8"))

    file_metadata: Mapping[str, Any] = {}

    if isinstance(data, Mapping):
        if data.get("verification_model"):
            kwargs.setdefault("verification_model", str(data["verification_model"]))
            kwargs.setdefault(
                "extraction_engine", engine_for_model(str(data["verification_model"]))
            )
        if isinstance(data.get("metadata"), Mapping):
            file_metadata = data["metadata"]
            if file_metadata.get("file_sha256"):
                kwargs.setdefault("sha256", file_metadata["file_sha256"])

        records: list[Mapping[str, Any]] = []
        indicators = data.get("indicators")
        if isinstance(indicators, list):
            records.extend(r for r in indicators if isinstance(r, Mapping))
        else:
            for key, group in data.items():
                if key == "accepted_by_category" or not isinstance(group, list):
                    continue
                records.extend(r for r in group if isinstance(r, Mapping))
    elif isinstance(data, list):
        records = data
    else:
        raise conformance.ConformanceError(
            f"unexpected JSON structure in {json_path}: {type(data).__name__}"
        )

    origin = next(
        (r["source"] for r in records if isinstance(r.get("source"), Mapping)),
        {},
    )

    kwargs.setdefault("file_path", origin.get("path"))
    # The recorded path is from the machine that ran the extractor and will not
    # exist on a teammate's checkout. raw_documents requires *some* content, so
    # archive the JSON when the original is unreachable. Identity is unaffected:
    # it still comes from metadata.file_sha256 where the extractor supplied it.
    if not kwargs.get("file_path") or not Path(kwargs["file_path"]).is_file():
        kwargs["file_path"] = None
        kwargs.setdefault("raw_text", json_path.read_text(encoding="utf-8"))

    return ingest_extractions(
        session,
        records,
        source_name=(
            source_name
            or origin.get("filename")
            or file_metadata.get("filename")
            or json_path.name
        ),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Queries the quality checker needs
# ---------------------------------------------------------------------------

def count_sightings(session: Session, indicator_id: int) -> int:
    """Number of distinct sources corroborating an indicator.

    This is the input the accuracy dimension is defined against in
    scoring_config: "count of corroborating sources (sightings); none scores 0".
    """
    return session.execute(
        select(func.count())
        .select_from(Sighting)
        .where(Sighting.indicator_id == indicator_id)
    ).scalar_one()


def sighting_counts(session: Session) -> dict[int, int]:
    """Sighting counts for every indicator, as one query rather than N."""
    rows = session.execute(
        select(Sighting.indicator_id, func.count())
        .group_by(Sighting.indicator_id)
    ).all()
    return {indicator_id: count for indicator_id, count in rows}
