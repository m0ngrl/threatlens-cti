"""ThreatLens dashboard - quality flag review routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatlens.dashboard.db import get_session
from threatlens.db.models import Indicator, QualityFlag

router = APIRouter(prefix="/api/quality-flags", tags=["quality-flags"])


class QualityFlagUpdate(BaseModel):
    status: str


def _serialise(flag: QualityFlag, indicator_value: str | None = None) -> dict[str, Any]:
    return {
        "id": flag.id,
        "indicator_id": flag.indicator_id,
        "indicator_value": indicator_value,
        "flag_type": flag.flag_type,
        "dimension": flag.dimension,
        "detail": flag.detail,
        "severity": flag.severity,
        "status": flag.status,
        "raised_at": flag.raised_at,
    }


@router.get("")
def list_quality_flags(
    status: str | None = None, session: Session = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(QualityFlag, Indicator.value).join(
        Indicator, QualityFlag.indicator_id == Indicator.id
    )
    if status:
        stmt = stmt.where(QualityFlag.status == status)

    rows = session.execute(stmt.order_by(QualityFlag.id.desc())).all()
    return {"items": [_serialise(flag, value) for flag, value in rows]}


@router.patch("/{flag_id}")
def update_quality_flag(
    flag_id: int, update: QualityFlagUpdate, session: Session = Depends(get_session)
) -> dict[str, Any]:
    flag = session.get(QualityFlag, flag_id)
    if flag is None:
        raise HTTPException(status_code=404, detail="Quality flag not found")

    flag.status = update.status
    session.commit()
    session.refresh(flag)
    return _serialise(flag)
