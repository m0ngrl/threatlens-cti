"""ThreatLens dashboard - view and edit threatlens.conf from the Configuration page.

Reads and writes the same file the CLI and ingest worker read (see
threatlens.config), so a saved change applies to the next ingest without a
restart. The database default only applies at dashboard startup; the header's
database dropdown still switches the live database.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from threatlens import config as conf
from threatlens import paths
from threatlens.dashboard import db as db_module
from threatlens.dashboard.db import get_session
from threatlens.dashboard.routes.ingest import ollama_models

router = APIRouter(prefix="/api/config", tags=["config"])


class OllamaSettings(BaseModel):
    url: str


class ModelSettings(BaseModel):
    verifier: str
    profiler: str = ""


class DatabaseSettings(BaseModel):
    default: str


class QualitySettings(BaseModel):
    weights: dict[str, float]
    agreement: dict[str, float]


class ConfigBody(BaseModel):
    ollama: OllamaSettings
    models: ModelSettings
    database: DatabaseSettings
    quality: QualitySettings


class OllamaProbe(BaseModel):
    url: str = Field(min_length=1)


def _payload(config: conf.ThreatLensConfig) -> dict[str, Any]:
    path = conf.config_path()
    return {
        "config": config.to_dict(),
        "path": str(path),
        "exists": path.is_file(),
        "databases": db_module.list_db_files(),
        "active_database": db_module.active_db_filename(),
        "dimensions": list(conf.DIMENSIONS),
        "agreement_grades": list(conf.AGREEMENT_GRADES),
        "setup": conf.setup_status().to_dict(),
        "locations": {
            "layout": "checkout" if paths.is_checkout() else "installed",
            "data": str(paths.data_dir()),
            "databases": str(paths.db_dir()),
            "reports": str(paths.reports_dir()),
        },
    }


@router.get("")
def read_config() -> dict[str, Any]:
    try:
        config = conf.load_config()
    except conf.ConfigError as exc:
        # Show the defaults so the page can still be used to repair the file.
        return {**_payload(conf.ThreatLensConfig()), "error": str(exc)}
    return _payload(config)


@router.put("")
def write_config(body: ConfigBody) -> dict[str, Any]:
    unknown = (set(body.quality.weights) - set(conf.DIMENSIONS)) | (
        set(body.quality.agreement) - set(conf.AGREEMENT_GRADES)
    )
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown keys: {', '.join(sorted(unknown))}")

    defaults = conf.ThreatLensConfig()
    # The page does not edit [llm], [calibration], [paths] or [dashboard];
    # carry them over so a save keeps them. An unreadable file has none to keep.
    try:
        current = conf.load_config()
    except conf.ConfigError:
        current = defaults
    config = conf.ThreatLensConfig(
        llm=current.llm,
        calibration=current.calibration,
        data_dir=current.data_dir,
        dashboard_host=current.dashboard_host,
        dashboard_port=current.dashboard_port,
        ollama_url=body.ollama.url.strip().rstrip("/"),
        verifier_model=body.models.verifier.strip(),
        profiler_model=body.models.profiler.strip(),
        database=body.database.default.strip(),
        weights={**defaults.weights, **body.quality.weights},
        agreement={**defaults.agreement, **body.quality.agreement},
    )
    errors = conf.validate(config)
    if config.database not in db_module.list_db_files():
        errors.append(f"database {config.database!r} is not a file in db/")
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    conf.save_config(config)
    return {**_payload(conf.load_config()), "saved": True}


@router.post("/ollama-models")
def probe_ollama(probe: OllamaProbe) -> dict[str, Any]:
    """Models installed on the Ollama server at `url`, for the model pickers."""
    try:
        models = sorted(m for m in ollama_models(probe.url) if m)
    except (OSError, ValueError) as exc:
        return {"reachable": False, "models": [], "detail": str(exc)}
    return {"reachable": True, "models": models}


@router.post("/rescore")
def rescore_active_db(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Re-score every indicator in the active database with the current weights."""
    from threatlens.quality.quality_checker import rescore_from_db

    try:
        count = rescore_from_db(session)
    except conf.ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    session.commit()
    return {"rescored": count, "database": db_module.active_db_filename()}
