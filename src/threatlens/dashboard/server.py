"""ThreatLens - web dashboard.
ZEIT3118 Capstone Project

Serves the indicator/source/quality-flag browser and its static frontend.
Runs against the same SQLAlchemy models the extraction pipeline writes to
(see threatlens.db.models / threatlens.db.ingest), so what you see and edit
here is the live database, not a copy.

Run (with the project's virtual environment active):
    threatlens-dashboard
    threatlens-dashboard --host 0.0.0.0 --port 8000 --reload

The default address is threatlens.conf [dashboard] host / port
(127.0.0.1:8000 unless set; `threatlens init` asks).

or directly:
    uvicorn threatlens.dashboard.server:app --reload
"""

from __future__ import annotations

import argparse
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from threatlens.dashboard.routes import (
    config,
    db_admin,
    indicators,
    ingest,
    quality_flags,
    report_files,
    sources,
    stats,
)

BASE_DIR = Path(__file__).resolve().parent
# Project documentation, shipped inside the package (threatlens/docs).
DOCS_DIR = BASE_DIR.parent / "docs"

# FastAPI's own auto-generated API docs default to /docs, which is where we
# want the project documentation site instead - move Swagger/ReDoc out of the
# way rather than fight over the path.
app = FastAPI(title="ThreatLens Dashboard", docs_url="/api/docs", redoc_url="/api/redoc")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def revalidate_frontend(request: Request, call_next):
    """Make browsers check the page and its JS/CSS for changes on every load.

    Without a Cache-Control header, browsers cache static files heuristically
    and can keep running an old script after the dashboard is updated. With
    no-cache they still keep the copy, but ask first, and an unchanged file
    comes back as a cheap 304.
    """
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/") or not path.startswith(("/api/", "/docs", "/db-browser")):
        response.headers.setdefault("Cache-Control", "no-cache")
    return response

# Project documentation (threatlens/docs/index.html and friends), package
# data like the pages and static files above.
app.mount("/docs", StaticFiles(directory=DOCS_DIR, html=True), name="docs")

# Raw database browser (Datasette) - see db_browser.py. Optional dependency:
# only installed via the "dashboard" extra, so degrade gracefully rather than
# fail to start the whole dashboard if it's missing (e.g. an env not yet
# reinstalled after this was added).
try:
    from threatlens.dashboard.db_browser import MOUNT_PATH, DatasetteProxy
except ImportError:
    print("Note: datasette is not installed, so /db-browser is unavailable.")
    print('Install it with: pip install -e ".[dashboard]"')
else:
    app.mount(MOUNT_PATH, DatasetteProxy(), name="db-browser")

app.include_router(indicators.router)
app.include_router(sources.router)
app.include_router(quality_flags.router)
app.include_router(stats.router)
app.include_router(db_admin.router)
app.include_router(report_files.router)
app.include_router(ingest.router)
app.include_router(config.router)


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(BASE_DIR / "dashboard.html")


@app.get("/uploads")
async def uploads_page() -> FileResponse:
    return FileResponse(BASE_DIR / "uploads.html")


@app.get("/ingest")
async def ingest_page() -> FileResponse:
    return FileResponse(BASE_DIR / "ingest.html")


@app.get("/config")
async def config_page() -> FileResponse:
    return FileResponse(BASE_DIR / "config.html")


@app.get("/reports/{source_id}")
async def report_detail_page(source_id: int) -> FileResponse:
    return FileResponse(BASE_DIR / "report_detail.html")


@app.get("/indicators/{indicator_id}")
async def indicator_detail_page(indicator_id: int) -> FileResponse:
    return FileResponse(BASE_DIR / "indicator_detail.html")


def _lan_ip() -> str | None:
    """Best-effort guess at this machine's LAN-facing IP, for the startup banner."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def main(argv: list[str] | None = None) -> int:
    import uvicorn

    from threatlens.config import (
        ConfigError,
        ThreatLensConfig,
        load_config,
        setup_status,
    )
    from threatlens.setup_wizard import offer_setup

    parser = argparse.ArgumentParser(description="Run the ThreatLens dashboard.")
    parser.add_argument(
        "--host",
        default=None,
        help="default: threatlens.conf [dashboard] host, else 127.0.0.1 (this machine only); "
        "0.0.0.0 makes it reachable from the local network",
    )
    parser.add_argument("--port", type=int, default=None, help="default: threatlens.conf [dashboard] port, else 8000")
    parser.add_argument("--reload", action="store_true", help="auto-restart on code changes")
    args = parser.parse_args(argv)

    offer_setup()
    try:
        local = load_config()
    except ConfigError:
        local = ThreatLensConfig()  # reported below by setup_status()
    args.host = args.host or local.dashboard_host
    args.port = args.port or local.dashboard_port

    if args.host in ("0.0.0.0", "::"):
        lan_ip = _lan_ip()
        print(f"Local:   http://127.0.0.1:{args.port}/")
        if lan_ip:
            print(f"Network: http://{lan_ip}:{args.port}/")
        print(
            "WARNING: this dashboard can edit and delete database rows and has no "
            "authentication - anyone on the local network who reaches this URL can "
            "modify the database. Use --host 127.0.0.1 to restrict it to this machine."
        )

    for warning in setup_status().warnings():
        print(f"SETUP: {warning}")

    uvicorn.run(
        "threatlens.dashboard.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
