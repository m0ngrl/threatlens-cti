"""ThreatLens dashboard - database session wiring.

Points at a SQLite file in the database folder (paths.db_dir(): db/ in a
checkout, <data folder>/db when installed). Defaults to threatlens.conf's [database] default (else
db/threatlens.db), overridable at startup with THREATLENS_DB_URL or
THREATLENS_DB_FILE, and switchable at runtime via the
dashboard's own database dropdown (see routes/db_admin.py) - no restart
needed, since the engine/session factory here are swapped out in place.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from threatlens.config import ConfigError, load_config
from threatlens.db.models import (
    Base,  # noqa: F401  (registers the sqlite pragma listener)
)
from threatlens.paths import db_dir

# Resolved once at startup; a moved data folder needs a dashboard restart.
DB_DIR = db_dir()
DEFAULT_DB_FILENAME = "threatlens.db"


def list_db_files() -> list[str]:
    """Names of every .db file in db/, for the dashboard's selector."""
    if not DB_DIR.is_dir():
        return []
    return sorted(path.name for path in DB_DIR.glob("*.db"))


def _initial_db_path() -> Path:
    env_url = os.environ.get("THREATLENS_DB_URL")
    if env_url:
        return Path(env_url.removeprefix("sqlite:///"))

    env_file = os.environ.get("THREATLENS_DB_FILE")
    if env_file:
        return DB_DIR / env_file

    return DB_DIR / configured_db_filename()


def configured_db_filename() -> str:
    """threatlens.conf's [database] default, or threatlens.db if unset/unreadable."""
    try:
        return load_config().database
    except ConfigError as exc:
        print(f"Warning: {exc}; falling back to {DEFAULT_DB_FILENAME}")
        return DEFAULT_DB_FILENAME


def _make_session_factory(db_path: Path) -> sessionmaker[Session]:
    global engine
    engine = create_engine(f"sqlite:///{db_path}")
    return sessionmaker(bind=engine, expire_on_commit=False)


_active_path: Path = _initial_db_path()
engine: Engine
SessionLocal = _make_session_factory(_active_path)


def active_db_filename() -> str:
    return _active_path.name


def active_db_path() -> Path:
    return _active_path


def set_active_db(filename: str) -> None:
    """Switch the dashboard to a different .db file in db/.

    Only a bare filename is accepted (no path separators), so this can't
    be used to open an arbitrary file elsewhere on disk.
    """
    global _active_path, SessionLocal

    if filename != Path(filename).name:
        raise ValueError("filename must not contain a path")

    candidate = DB_DIR / filename
    if not candidate.is_file():
        raise FileNotFoundError(f"no such database: {filename}")

    engine.dispose()
    _active_path = candidate
    SessionLocal = _make_session_factory(candidate)


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
