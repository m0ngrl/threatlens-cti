"""ThreatLens dashboard - upload, view and remove CTI report files.

Manages the PDFs in the report folder (paths.reports_dir(): docs/database/CTI
in a checkout, <data folder>/reports when installed), which the Ingest page
reads reports from. This
only touches files on disk: uploading a report does not ingest it, and
removing one does not delete its rows from the database - that is the
Reports tab's delete, which works on the database side.

The folder is kept flat, as the pipeline only globs its top level, so every
route takes a bare filename and refuses anything with a path in it.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from threatlens.dashboard import db as db_module
from threatlens.dashboard.db import get_session
from threatlens.dashboard.ingest_jobs import queue
from threatlens.db.models import RawDocument
from threatlens.paths import data_dir, reports_dir, resolve_stored

# The report folder, resolved once at startup (restart after moving it).
CTI_DIR = reports_dir()
ALLOWED_SUFFIXES = {".pdf"}

router = APIRouter(prefix="/api/report-files", tags=["report-files"])


def safe_report_path(filename: str) -> Path:
    """Path of a report file in CTI_DIR, refusing anything but a bare filename."""
    name = filename.strip()
    if not name or name != Path(name).name or "\\" in name or name.startswith("."):
        raise HTTPException(status_code=400, detail=f"Invalid filename: {filename!r}")
    if Path(name).suffix.lower() not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"Only PDF reports are accepted: {name}")
    return CTI_DIR / name


_SHA_CACHE: dict[tuple[str, int, int], str] = {}


def _file_sha256(path: Path) -> str:
    """SHA-256 of a report file, cached on (path, size, mtime) - the list is polled."""
    stat = path.stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    digest = _SHA_CACHE.get(key)
    if digest is None:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                hasher.update(chunk)
        digest = _SHA_CACHE[key] = hasher.hexdigest()
    return digest


def report_paths() -> list[Path]:
    """Every report file in CTI_DIR, sorted by name."""
    CTI_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(
        (
            path for path in CTI_DIR.iterdir()
            if path.is_file()
            and not path.name.startswith(".")
            and path.suffix.lower() in ALLOWED_SUFFIXES
        ),
        key=lambda p: p.name.lower(),
    )


def ingested_sources(session: Session, paths: list[Path]) -> dict[str, int]:
    """Report filename -> source id, for files in `paths` already in the active database.

    Matched by stored file path, or else by content hash - ingest identifies
    a document by its SHA-256, so a renamed copy of an ingested report would
    only be matched to the existing source again.
    """
    rows = session.execute(
        select(RawDocument.file_path, RawDocument.sha256, RawDocument.source_id)
    ).all()
    by_path: dict[Path, int] = {}
    by_sha = {sha256: source_id for _, sha256, source_id in rows}
    for file_path, _, source_id in rows:
        if file_path:
            by_path[resolve_stored(file_path).resolve()] = source_id

    found: dict[str, int] = {}
    for path in paths:
        source_id = by_path.get(path.resolve())
        if source_id is None:
            source_id = by_sha.get(_file_sha256(path))
        if source_id is not None:
            found[path.name] = source_id
    return found


@router.get("")
def list_report_files(session: Session = Depends(get_session)) -> dict[str, Any]:
    paths = report_paths()
    ingested = ingested_sources(session, paths)
    files = []
    for path in paths:
        stat = path.stat()
        files.append({
            "name": path.name,
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
            "source_id": ingested.get(path.name),
        })
    base = data_dir()
    directory = CTI_DIR.relative_to(base) if CTI_DIR.is_relative_to(base) else CTI_DIR
    return {"directory": str(directory), "files": files}


@router.post("")
async def upload_report_files(
    files: list[UploadFile] = File(...),
    overwrite: bool = Form(False),
) -> dict[str, Any]:
    CTI_DIR.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []
    skipped: list[dict[str, str]] = []

    for upload in files:
        # Browsers send just the basename, but strip any path a client adds anyway.
        name = Path((upload.filename or "").replace("\\", "/")).name
        try:
            target = safe_report_path(name)
        except HTTPException as exc:
            skipped.append({"name": name or "(unnamed)", "reason": str(exc.detail)})
            continue

        if target.exists() and not overwrite:
            skipped.append({"name": name, "reason": "already exists"})
            continue

        if (await upload.read(5)) != b"%PDF-":
            skipped.append({"name": name, "reason": "not a PDF file"})
            continue
        await upload.seek(0)

        # Write to a temp name and rename, so a failed upload never leaves a
        # half-written PDF where the pipeline would pick it up.
        partial = target.with_name(f".{name}.part")
        try:
            with partial.open("wb") as out_file:
                shutil.copyfileobj(upload.file, out_file)
            partial.replace(target)
        finally:
            partial.unlink(missing_ok=True)
        saved.append(name)

    return {"ok": True, "saved": saved, "skipped": skipped}


@router.get("/{filename}")
def get_report_file(filename: str) -> FileResponse:
    """The report file, shown inline so it opens in the browser's own viewer."""
    path = safe_report_path(filename)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"No such report file: {filename}")
    return FileResponse(
        path, media_type="application/pdf", filename=path.name, content_disposition_type="inline"
    )


@router.delete("/{filename}")
def delete_report_file(filename: str) -> dict[str, Any]:
    path = safe_report_path(filename)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"No such report file: {filename}")
    if path in queue.active_paths(db_module.active_db_path()):
        raise HTTPException(status_code=409, detail=f"{filename} is queued for ingest - cancel it first")
    path.unlink()
    return {"ok": True, "deleted": path.name}
