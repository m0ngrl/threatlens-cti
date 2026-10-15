"""ThreatLens dashboard - summary stats for the header cards."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatlens.dashboard.db import get_session
from threatlens.db.models import Indicator, QualityFlag, Source

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
def get_stats(session: Session = Depends(get_session)) -> dict[str, Any]:
    indicator_count = session.execute(select(func.count()).select_from(Indicator)).scalar_one()
    source_count = session.execute(select(func.count()).select_from(Source)).scalar_one()
    open_flags = session.execute(
        select(func.count()).select_from(QualityFlag).where(QualityFlag.status == "open")
    ).scalar_one()
    avg_score = session.execute(select(func.avg(Indicator.quality_score))).scalar_one()

    by_type = dict(
        session.execute(select(Indicator.ioc_type, func.count()).group_by(Indicator.ioc_type)).all()
    )

    return {
        "indicator_count": indicator_count,
        "source_count": source_count,
        "open_quality_flags": open_flags,
        "avg_quality_score": round(avg_score, 1) if avg_score is not None else None,
        "by_type": by_type,
    }
