"""ThreatLens dashboard - indicator list/detail/edit/delete routes.

get_indicator() is what the indicator detail page (/indicators/{id}) renders:
besides the raw row it unpacks score_components into a per-dimension quality
breakdown and a confidence breakdown, using the quality checker's own
functions and policy, so the page explains a score with the same arithmetic
that produced it rather than a copy of it.

An indicator's extraction engine is not stored on the indicator: it is the
union of sources.extraction_engine across the reports it was sighted in
(see _extraction_engines), so one value seen by both engines reads
'llm+python'. None means no sighting came from a report with a recorded
engine.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatlens.dashboard.db import get_session
from threatlens.db.ingest import combine_engines
from threatlens.db.models import Indicator, QualityFlag, ScoringConfig, Sighting, Source
from threatlens.quality import quality_checker
from threatlens.quality.quality_checker import Agreement, ScoringPolicy, Verdict

router = APIRouter(prefix="/api/indicators", tags=["indicators"])


class IndicatorUpdate(BaseModel):
    ioc_type: str | None = None
    value: str | None = None
    normalised: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: int | None = None
    context: str | None = None
    quality_score: int | None = None


def _serialise(
    indicator: Indicator, sighting_count: int = 0, extraction_engine: str | None = None
) -> dict[str, Any]:
    return {
        "id": indicator.id,
        "ioc_type": indicator.ioc_type,
        "value": indicator.value,
        "normalised": indicator.normalised,
        "first_seen": indicator.first_seen,
        "last_seen": indicator.last_seen,
        "confidence": indicator.confidence,
        "context": indicator.context,
        "quality_score": indicator.quality_score,
        "score_components": indicator.score_components,
        "scored_at": indicator.scored_at,
        "sighting_count": sighting_count,
        "extraction_engine": extraction_engine,
    }


def _extraction_engines(session: Session, indicator_ids: list[int]) -> dict[int, str | None]:
    """Each indicator's engine: the union over the reports it was sighted in."""
    by_indicator: dict[int, list[str]] = {}
    for indicator_id, engine in session.execute(
        select(Sighting.indicator_id, Source.extraction_engine)
        .join(Source, Sighting.source_id == Source.id)
        .where(Sighting.indicator_id.in_(indicator_ids), Source.extraction_engine.is_not(None))
        .distinct()
    ).all():
        by_indicator.setdefault(indicator_id, []).append(engine)
    return {indicator_id: combine_engines(*engines) for indicator_id, engines in by_indicator.items()}


def _sighted_by_engine(engine: str) -> Any:
    """WHERE clause: sighted in a report the given engine verified."""
    sighted = (
        select(Sighting.indicator_id)
        .join(Source, Sighting.source_id == Source.id)
        .where(Sighting.indicator_id == Indicator.id)
        .correlate(Indicator)
    )
    if engine == "unknown":
        return ~exists(sighted.where(Source.extraction_engine.is_not(None)))
    return exists(sighted.where(Source.extraction_engine.in_([engine, "llm+python"])))


def _sighting_count() -> Any:
    return (
        select(func.count())
        .where(Sighting.indicator_id == Indicator.id)
        .correlate(Indicator)
        .scalar_subquery()
    )


# The columns the Indicators table can be sorted by, keyed by the API's name.
SORT_COLUMNS: dict[str, Any] = {
    "id": lambda: Indicator.id,
    "ioc_type": lambda: Indicator.ioc_type,
    "value": lambda: Indicator.value,
    "confidence": lambda: Indicator.confidence,
    "quality_score": lambda: Indicator.quality_score,
    "sighting_count": _sighting_count,
    "last_seen": lambda: Indicator.last_seen,
}
SortKey = Literal["id", "ioc_type", "value", "confidence", "quality_score", "sighting_count", "last_seen"]


@router.get("")
def list_indicators(
    ioc_type: str | None = None,
    search: str | None = None,
    min_score: int | None = None,
    max_score: int | None = None,
    engine: Literal["llm", "python", "unknown"] | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    sort: SortKey = "id",
    order: Literal["asc", "desc"] = "asc",
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Sorted server-side, since the table is paged: a sort has to span every page."""
    stmt = select(Indicator)

    if ioc_type:
        stmt = stmt.where(Indicator.ioc_type == ioc_type)
    if search:
        stmt = stmt.where(Indicator.value.contains(search))
    if min_score is not None:
        stmt = stmt.where(Indicator.quality_score >= min_score)
    if max_score is not None:
        stmt = stmt.where(Indicator.quality_score <= max_score)
    if engine:
        stmt = stmt.where(_sighted_by_engine(engine))

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()

    rows = (
        session.execute(
            stmt.order_by(_sort_clause(sort, order), Indicator.id).limit(limit).offset(offset)
        )
        .scalars()
        .all()
    )

    counts = dict(
        session.execute(
            select(Sighting.indicator_id, func.count())
            .where(Sighting.indicator_id.in_([row.id for row in rows]))
            .group_by(Sighting.indicator_id)
        ).all()
    )

    engines = _extraction_engines(session, [row.id for row in rows])

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "sort": sort,
        "order": order,
        "items": [
            _serialise(row, counts.get(row.id, 0), engines.get(row.id)) for row in rows
        ],
    }


def _sort_clause(sort: str, order: str) -> Any:
    """ORDER BY for `sort`, empty values last in either direction."""
    column = SORT_COLUMNS[sort]()
    if sort == "value":
        column = func.lower(func.trim(column))
    clause = column.desc() if order == "desc" else column.asc()
    return clause.nulls_last()


def _load_json(raw: str | None) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def _title_from_metadata(raw_metadata: str | None, fallback: str) -> str:
    metadata = _load_json(raw_metadata)
    title = metadata.get("title") if isinstance(metadata, dict) else None
    return title or fallback


def _as_verdict(value: Any) -> Verdict | None:
    try:
        return Verdict(value) if value else None
    except ValueError:
        return None


def _confidence_breakdown(
    indicator: Indicator, agreement: dict[str, Any] | None, flags: list[QualityFlag]
) -> dict[str, Any] | None:
    """How indicators.confidence was reached - see quality_checker.compare_verifiers."""
    if not agreement:
        return None

    try:
        grade = Agreement(agreement.get("agreement"))
    except ValueError:
        grade = None
    multiplier = ScoringPolicy.configured().agreement_multipliers.get(grade, 1.0) if grade else None

    python_malice = quality_checker.maliciousness_from_verdict(
        _as_verdict(agreement.get("python_status")), agreement.get("python_confidence")
    )
    llm_malice = quality_checker.maliciousness_from_verdict(
        _as_verdict(agreement.get("llm_status")), agreement.get("llm_confidence")
    )
    if grade is Agreement.AGREE:
        readings = [m for m in (python_malice, llm_malice) if m is not None]
        base = sum(readings) / len(readings) if readings else None
    else:
        base = llm_malice if agreement.get("winner") == "llm" else python_malice

    screened_by = [
        flag.flag_type for flag in flags if flag.flag_type in quality_checker.SCREENED_FLAGS
    ]
    return {
        **agreement,
        "multiplier": multiplier,
        "python_maliciousness": python_malice,
        "llm_maliciousness": llm_malice,
        "base_maliciousness": base,
        # A screened observable is forced to 0 whatever the verifiers said.
        "screened_by": screened_by,
        "stored_confidence": indicator.confidence,
    }


def _quality_breakdown(
    session: Session, indicator: Indicator, components: dict[str, Any]
) -> dict[str, Any]:
    """Each dimension's score, weight and share of quality_score."""
    dimensions = components.get("dimensions") or {}
    weights = components.get("weights") or {}

    # The rule each dimension was scored by, from the latest scoring_config row.
    rules: dict[str, Any] = {}
    for row in session.execute(select(ScoringConfig).order_by(ScoringConfig.effective_from)).scalars():
        rules[row.dimension] = _load_json(row.parameters)

    applied_weight = sum(w for name, w in weights.items() if name in dimensions and w > 0)
    rows = []
    for name, score in dimensions.items():
        weight = weights.get(name, 0.0)
        share = weight / applied_weight if applied_weight and weight > 0 else 0.0
        rule = rules.get(name)
        rows.append(
            {
                "dimension": name,
                "score": score,
                "weight": weight,
                # Points out of 100 this dimension contributed: score/5 * share.
                "points": round(score / 5 * share * 100, 1) if score is not None else None,
                "rule": rule.get("note") if isinstance(rule, dict) else None,
            }
        )

    return {
        "quality_score": indicator.quality_score,
        "grade": components.get("grade"),
        "dimensions": rows,
    }


@router.get("/{indicator_id}")
def get_indicator(indicator_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    indicator = session.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")

    sightings = session.execute(
        select(Sighting, Source)
        .join(Source, Sighting.source_id == Source.id)
        .where(Sighting.indicator_id == indicator_id)
        .order_by(Sighting.seen_at, Source.id)
    ).all()

    flags = (
        session.execute(
            select(QualityFlag)
            .where(QualityFlag.indicator_id == indicator_id)
            .order_by(QualityFlag.raised_at, QualityFlag.id)
        )
        .scalars()
        .all()
    )

    # Other indicators sighted in the same reports - what this one travels with.
    source_ids = [source.id for _, source in sightings]
    related = session.execute(
        select(Indicator, func.count(func.distinct(Sighting.source_id)))
        .join(Sighting, Sighting.indicator_id == Indicator.id)
        .where(Sighting.source_id.in_(source_ids), Indicator.id != indicator_id)
        .group_by(Indicator.id)
        .order_by(func.count(func.distinct(Sighting.source_id)).desc(), Indicator.quality_score.desc())
        .limit(50)
    ).all() if source_ids else []

    components = _load_json(indicator.score_components) or {}

    data = _serialise(
        indicator,
        len(sightings),
        combine_engines(*(source.extraction_engine for _, source in sightings)),
    )
    data["context_data"] = _load_json(indicator.context)
    data["stix"] = components.get("stix")
    data["quality_breakdown"] = _quality_breakdown(session, indicator, components)
    data["confidence_breakdown"] = _confidence_breakdown(
        indicator, components.get("agreement"), flags
    )
    data["sightings"] = [
        {
            "source_id": source.id,
            "source_name": source.name,
            "source_title": _title_from_metadata(source.raw_metadata, fallback=source.name),
            "source_type": source.source_type,
            "source_url": source.url,
            "reliability": source.reliability,
            "extraction_engine": source.extraction_engine,
            "verification_model": source.verification_model,
            "ingested_at": source.ingested_at,
            "seen_at": sighting.seen_at,
            "excerpt": sighting.excerpt,
            "excerpt_start": sighting.excerpt_start,
            "excerpt_end": sighting.excerpt_end,
        }
        for sighting, source in sightings
    ]
    data["quality_flags"] = [
        {
            "id": flag.id,
            "flag_type": flag.flag_type,
            "dimension": flag.dimension,
            "detail": flag.detail,
            "severity": flag.severity,
            "status": flag.status,
            "raised_at": flag.raised_at,
        }
        for flag in flags
    ]
    data["related_indicators"] = [
        {
            "id": other.id,
            "ioc_type": other.ioc_type,
            "value": other.value,
            "confidence": other.confidence,
            "quality_score": other.quality_score,
            "shared_reports": shared,
        }
        for other, shared in related
    ]
    return data


@router.patch("/{indicator_id}")
def update_indicator(
    indicator_id: int, update: IndicatorUpdate, session: Session = Depends(get_session)
) -> dict[str, Any]:
    indicator = session.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")

    changes = update.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(indicator, field, value)

    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=409, detail=f"Update violates a database constraint: {exc.orig}"
        ) from exc

    session.refresh(indicator)
    sighting_count = session.execute(
        select(func.count()).select_from(Sighting).where(Sighting.indicator_id == indicator_id)
    ).scalar_one()
    return _serialise(
        indicator, sighting_count, _extraction_engines(session, [indicator_id]).get(indicator_id)
    )


@router.delete("/{indicator_id}")
def delete_indicator(indicator_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    indicator = session.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")

    session.delete(indicator)
    session.commit()
    return {"ok": True, "deleted": indicator_id}
