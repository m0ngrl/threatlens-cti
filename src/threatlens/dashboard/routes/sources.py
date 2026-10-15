"""ThreatLens dashboard - report (source document) list/detail/delete routes.

The dashboard calls these "Reports" - the project's actual scope is CTI
reports, and Source.name is usually just a hash or filename, not anything
a reviewer would recognise a report by. The model/table/route stay "source"
(matching threatlens.db.models), but the API surfaces the report's real
title, pulled out of Source.raw_metadata (see extractors.*.DocumentMetadata,
which every ingested document already carries a "title" heuristic for).

The primary value for a report is its quality score - the mean
quality_score across every indicator sighted in it - so list_sources()
computes that alongside each row, and get_source() breaks it down per
indicator (type/value/dimensions/grade/confidence) for the report detail
page.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatlens.dashboard import pdf_view
from threatlens.dashboard.db import get_session
from threatlens.db.ingest import refresh_seen_dates
from threatlens.db.models import Indicator, QualityFlag, RawDocument, Sighting, Source

router = APIRouter(prefix="/api/sources", tags=["sources"])


def _title_from_metadata(raw_metadata: str | None, fallback: str) -> str:
    if raw_metadata:
        try:
            title = json.loads(raw_metadata).get("title")
        except (TypeError, ValueError, AttributeError):
            title = None
        if title:
            return title
    return fallback


def _serialise(
    source: Source, indicator_count: int = 0, avg_quality_score: float | None = None
) -> dict[str, Any]:
    return {
        "id": source.id,
        "title": _title_from_metadata(source.raw_metadata, fallback=source.name),
        "filename": source.name,
        "source_type": source.source_type,
        "url": source.url,
        "ingested_at": source.ingested_at,
        "reliability": source.reliability,
        "extraction_engine": source.extraction_engine,
        "verification_model": source.verification_model,
        "indicator_count": indicator_count,
        "avg_quality_score": round(avg_quality_score, 1) if avg_quality_score is not None else None,
    }


@router.get("")
def list_sources(session: Session = Depends(get_session)) -> dict[str, Any]:
    sources = session.execute(select(Source).order_by(Source.id)).scalars().all()

    counts = dict(
        session.execute(
            select(Sighting.source_id, func.count(func.distinct(Sighting.indicator_id))).group_by(
                Sighting.source_id
            )
        ).all()
    )
    avg_scores = dict(
        session.execute(
            select(Sighting.source_id, func.avg(Indicator.quality_score))
            .join(Indicator, Sighting.indicator_id == Indicator.id)
            .group_by(Sighting.source_id)
        ).all()
    )

    return {
        "items": [
            _serialise(source, counts.get(source.id, 0), avg_scores.get(source.id))
            for source in sources
        ]
    }


@router.get("/{source_id}")
def get_source(source_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    source = session.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")

    raw_document = (
        session.execute(select(RawDocument).where(RawDocument.source_id == source_id))
        .scalars()
        .first()
    )

    rows = session.execute(
        select(Indicator, Sighting.excerpt, func.count(QualityFlag.id))
        .join(Sighting, Sighting.indicator_id == Indicator.id)
        .outerjoin(QualityFlag, QualityFlag.indicator_id == Indicator.id)
        .where(Sighting.source_id == source_id)
        .group_by(Indicator.id)
    ).all()

    indicators: list[dict[str, Any]] = []
    for indicator, excerpt, flag_count in rows:
        components: dict[str, Any] = {}
        if indicator.score_components:
            try:
                components = json.loads(indicator.score_components)
            except (TypeError, ValueError):
                components = {}
        dimensions = components.get("dimensions") or {}

        indicators.append(
            {
                "id": indicator.id,
                "ioc_type": indicator.ioc_type,
                "value": indicator.value,
                "confidence": indicator.confidence,
                "quality_score": indicator.quality_score,
                "grade": components.get("grade"),
                "dimensions": {
                    "timeliness": dimensions.get("timeliness"),
                    "accuracy": dimensions.get("accuracy"),
                    "completeness": dimensions.get("completeness"),
                    "relevance": dimensions.get("relevance"),
                },
                "excerpt": excerpt,
                "flag_count": flag_count,
            }
        )

    # Best indicators first.
    indicators.sort(key=lambda row: (row["quality_score"] is None, -(row["quality_score"] or 0)))

    scores = [row["quality_score"] for row in indicators if row["quality_score"] is not None]
    avg_quality_score = sum(scores) / len(scores) if scores else None

    data = _serialise(source, len(indicators), avg_quality_score)
    data["raw_document"] = (
        {
            "content_type": raw_document.content_type,
            "file_path": raw_document.file_path,
            "sha256": raw_document.sha256,
            "size_bytes": raw_document.size_bytes,
            "archived_at": raw_document.archived_at,
        }
        if raw_document is not None
        else None
    )
    data["indicators"] = indicators
    return data


def _report_pdf_path(session: Session, source_id: int) -> Path:
    if session.get(Source, source_id) is None:
        raise HTTPException(status_code=404, detail="Source not found")
    file_path = session.execute(
        select(RawDocument.file_path).where(RawDocument.source_id == source_id)
    ).scalar()
    try:
        return pdf_view.resolve_pdf_path(file_path)
    except pdf_view.ReportPdfError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{source_id}/pdf")
def get_source_pdf(source_id: int, session: Session = Depends(get_session)) -> FileResponse:
    """The original report file, shown inline so it opens in the browser's own viewer."""
    path = _report_pdf_path(session, source_id)
    return FileResponse(
        path, media_type="application/pdf", filename=path.name, content_disposition_type="inline"
    )


@router.get("/{source_id}/pdf/highlights")
def get_source_pdf_highlights(
    source_id: int, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Page sizes plus where each of the report's indicators appears in its PDF."""
    path = _report_pdf_path(session, source_id)
    rows = session.execute(
        select(Indicator.id, Indicator.value, Indicator.normalised)
        .join(Sighting, Sighting.indicator_id == Indicator.id)
        .where(Sighting.source_id == source_id)
        .order_by(Indicator.id)
    ).all()
    needles = [pdf_view.Needle(row.id, (row.value, row.normalised)) for row in rows]
    try:
        return pdf_view.find_highlights(path, needles)
    except pdf_view.ReportPdfError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{source_id}/pdf/pages/{page_index}.png")
def get_source_pdf_page(
    source_id: int,
    page_index: int,
    scale: float = Query(
        pdf_view.DEFAULT_RENDER_ZOOM,
        ge=pdf_view.MIN_RENDER_ZOOM,
        le=pdf_view.MAX_RENDER_ZOOM,
        description="Render zoom; 1.0 is one pixel per PDF point (72 dpi)",
    ),
    session: Session = Depends(get_session),
) -> Response:
    path = _report_pdf_path(session, source_id)
    try:
        png = pdf_view.render_page_png(path, page_index, scale)
    except IndexError as exc:
        raise HTTPException(status_code=404, detail="Page not found") from exc
    except pdf_view.ReportPdfError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # Keyed on the source id, which a database switch can reuse for another
    # report, so let the browser revalidate rather than cache for long.
    return Response(png, media_type="image/png", headers={"Cache-Control": "private, max-age=60"})


@router.delete("/{source_id}")
def delete_source(source_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    source = session.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")

    # The report's indicators stay; their first/last seen dates are re-derived
    # from the reports still sighting them, so none keeps this report's date.
    affected = [sighting.indicator_id for sighting in source.sightings]
    session.delete(source)
    session.flush()
    refresh_seen_dates(session, affected)
    session.commit()
    return {"ok": True, "deleted": source_id}
