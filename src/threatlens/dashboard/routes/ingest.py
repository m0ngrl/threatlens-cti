"""ThreatLens dashboard - run the ingest pipeline from the Ingest page.

Lists the report files in docs/database/CTI that are not yet in the active
database, queues the ones the user picks for ingest with the chosen engine
and verbosity, and reports each job's progress and log (see ingest_jobs.py
for the queue, ingest_worker.py for the pipeline itself).

Jobs are pinned to the database that was active when they were queued, so
switching the dashboard's database mid-run does not redirect a queued job.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from threatlens.dashboard import db as db_module
from threatlens.dashboard.db import get_session
from threatlens.dashboard.ingest_jobs import queue
from threatlens.dashboard.routes.report_files import (
    ingested_sources,
    report_paths,
    safe_report_path,
)
from threatlens.dashboard.url_downloads import DownloadError, downloads

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


class QueueRequest(BaseModel):
    files: list[str] = Field(min_length=1)
    engine: Literal["llm", "python"] = "llm"
    verbose: int = Field(default=2, ge=0, le=3)


@router.get("/pending")
def list_pending(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Report files not yet in the active database, flagging any already queued."""
    paths = report_paths()
    ingested = ingested_sources(session, paths)
    active = queue.active_paths(db_module.active_db_path())
    pending = [
        {"name": path.name, "size_bytes": path.stat().st_size, "queued": path in active}
        for path in paths
        if path.name not in ingested
    ]
    return {
        "database": db_module.active_db_filename(),
        "total_files": len(paths),
        "ingested": len(ingested),
        "pending": pending,
    }


@router.get("/engines")
def engine_status() -> dict[str, Any]:
    """Which LLM(s) the llm engine would use, and whether its Ollama server has them."""
    from threatlens.config import ConfigError, load_config, setup_status

    try:
        local = load_config()
    except ConfigError as exc:
        return {"llm": {"available": False, "detail": f"threatlens.conf: {exc}"}}

    wanted = [local.verifier_model]
    if local.profiler_model and local.profiler_model != local.verifier_model:
        wanted.append(local.profiler_model)

    llm: dict[str, Any] = {
        "model": local.verifier_model,
        "profiler_model": local.effective_profiler_model,
        "url": local.ollama_url,
        "setup_warnings": setup_status().warnings(),
    }
    try:
        installed = ollama_models(local.ollama_url)
    except (OSError, ValueError) as exc:
        llm.update(available=False, detail=f"Ollama is not reachable at {local.ollama_url} ({exc})")
    else:
        missing = [m for m in wanted if m not in installed and f"{m}:latest" not in installed]
        llm.update(
            available=not missing,
            detail=f"Not installed in Ollama: {', '.join(missing)}" if missing else None,
        )
    return {"llm": llm}


def ollama_models(url: str, timeout: float = 3) -> set[str]:
    """Names of the models installed on the Ollama server at `url`."""
    with urllib.request.urlopen(f"{url.rstrip('/')}/api/tags", timeout=timeout) as res:
        return {m.get("name") for m in json.load(res).get("models", [])}


@router.post("/queue")
def queue_files(request: QueueRequest) -> dict[str, Any]:
    paths = []
    for name in request.files:
        path = safe_report_path(name)
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"No such report file: {name}")
        paths.append(path)

    added = queue.enqueue(paths, db_module.active_db_path(), request.engine, request.verbose)
    return {
        "queued": [job.summary() for job in added],
        "skipped": len(paths) - len(added),  # already queued or running
    }


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    engine: Literal["llm", "python"] = "llm"
    verbose: int = Field(default=2, ge=0, le=3)


@router.post("/url")
def download_url(request: UrlRequest) -> dict[str, Any]:
    """Download a PDF into the report folder, then queue it for ingest."""
    try:
        download = downloads.start(request.url, db_module.active_db_path(), request.engine, request.verbose)
    except DownloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"download": download.summary()}


@router.get("/downloads")
def list_downloads() -> dict[str, Any]:
    return {"downloads": [d.summary() for d in downloads.downloads()]}


@router.post("/downloads/{download_id}/cancel")
def cancel_download(download_id: int) -> dict[str, Any]:
    download = downloads.cancel(download_id)
    if download is None:
        raise HTTPException(status_code=404, detail=f"No such download: {download_id}")
    return {"download": download.summary()}


@router.post("/downloads/clear")
def clear_downloads() -> dict[str, Any]:
    return {"cleared": downloads.clear_finished()}


@router.get("/jobs")
def list_jobs() -> dict[str, Any]:
    return {"jobs": [job.summary() for job in queue.jobs()]}


@router.get("/jobs/{job_id}/log")
def job_log(job_id: int, offset: int = Query(0, ge=0)) -> dict[str, Any]:
    job = queue.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"No such job: {job_id}")
    lines, next_offset = queue.log_since(job, offset)
    return {"job": job.summary(), "lines": lines, "offset": next_offset}


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int) -> dict[str, Any]:
    job = queue.cancel(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"No such job: {job_id}")
    return {"job": job.summary()}


@router.post("/cancel-all")
def cancel_all() -> dict[str, Any]:
    return {"cancelled": queue.cancel_all()}


@router.post("/clear")
def clear_finished() -> dict[str, Any]:
    return {"cleared": queue.clear_finished()}
