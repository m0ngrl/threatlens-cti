"""ThreatLens dashboard - switch which db/*.db file the dashboard reads/edits."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from threatlens.dashboard import db as db_module

router = APIRouter(prefix="/api/db", tags=["db"])


class DbSelection(BaseModel):
    filename: str


@router.get("/files")
def list_db_files() -> dict[str, Any]:
    return {
        "files": db_module.list_db_files(),
        "active": db_module.active_db_filename(),
    }


@router.post("/select")
def select_db_file(selection: DbSelection) -> dict[str, Any]:
    try:
        db_module.set_active_db(selection.filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"ok": True, "active": db_module.active_db_filename()}
