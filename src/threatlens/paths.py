"""
ThreatLens - where files live.
ZEIT3118 Capstone Project

Every location ThreatLens reads or writes is resolved here, so the same code
works from a repo checkout and from a pip-installed package.

Two layouts, picked automatically:

    checkout   A git checkout (pyproject.toml beside src/threatlens/), which
               includes an editable install. Everything stays in the repo:
                   config    threatlens.conf
                   databases db/
                   reports   docs/database/CTI/
    installed  A pip-installed package. Per-user folders (platformdirs):
                   config    <user config dir>/threatlens.conf
                   data      <user data dir>/  holding db/ and reports/
               e.g. Linux ~/.config/threatlens and ~/.local/share/threatlens;
               Windows %LOCALAPPDATA%\\threatlens and macOS
               ~/Library/Application Support/threatlens, for both (platformdirs
               puts the config beside the data there when roaming is off).

Overrides, highest first:

    config file   THREATLENS_CONF
    data folder   THREATLENS_HOME > threatlens.conf [paths] data_dir > layout default

A data folder from THREATLENS_HOME or [paths] holds db/ and reports/ in
either layout. (The dashboard can also be pointed at one database with
THREATLENS_DB_URL / THREATLENS_DB_FILE - see dashboard/db.py.)

Report paths recorded in raw_documents.file_path are relative to the data
folder when the file is inside it, absolute otherwise. In a checkout the data
folder is the repo root, so existing "docs/database/CTI/..." rows still
resolve.

Everything is resolved on each call, never cached; a long-running process
(the dashboard) picks up a moved data folder on restart.
"""

from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

APP_NAME = "threatlens"
CONF_FILENAME = "threatlens.conf"

PACKAGE_DIR = Path(__file__).resolve().parent
# Only meaningful in a checkout: src/threatlens -> src -> repo root.
REPO_ROOT = PACKAGE_DIR.parents[1]


def is_checkout() -> bool:
    """True when running from a repo checkout (or an editable install of one)."""
    return (REPO_ROOT / "pyproject.toml").is_file() and (REPO_ROOT / "src" / APP_NAME).is_dir()


def config_file() -> Path:
    """The threatlens.conf every tool reads and writes."""
    env = os.environ.get("THREATLENS_CONF")
    if env:
        return Path(env).expanduser()
    if is_checkout():
        return REPO_ROOT / CONF_FILENAME
    return Path(user_config_dir(APP_NAME, appauthor=False)) / CONF_FILENAME


def _custom_data_dir() -> Path | None:
    """THREATLENS_HOME, else threatlens.conf [paths] data_dir, else None."""
    env = os.environ.get("THREATLENS_HOME")
    if env:
        return Path(env).expanduser()
    # Imported here: config imports this module for config_file().
    from threatlens.config import ConfigError, load_config

    try:
        configured = load_config().data_dir
    except ConfigError:
        # An unreadable file is reported by the setup check; fall back to
        # the default location rather than failing every path lookup.
        return None
    return Path(configured).expanduser() if configured else None


def default_data_dir() -> Path:
    """The data folder when nothing overrides it: the repo, or the per-user data folder."""
    return REPO_ROOT if is_checkout() else Path(user_data_dir(APP_NAME, appauthor=False))


def _folders(custom: Path | None) -> tuple[Path, Path, Path]:
    """(data folder, databases, reports) for a given custom data folder (None = default)."""
    if custom is not None:
        return custom, custom / "db", custom / "reports"
    data = default_data_dir()
    reports = REPO_ROOT / "docs" / "database" / "CTI" if is_checkout() else data / "reports"
    return data, data / "db", reports


def planned_folders(data_dir_setting: str) -> tuple[Path, Path, Path]:
    """(data folder, databases, reports) if [paths] data_dir were `data_dir_setting`.

    THREATLENS_HOME still wins, as it would at run time. For previews such as
    threatlens init's summary, before the setting is saved.
    """
    env = os.environ.get("THREATLENS_HOME")
    if env:
        return _folders(Path(env).expanduser())
    return _folders(Path(data_dir_setting).expanduser() if data_dir_setting else None)


def data_dir() -> Path:
    """Folder holding db/ and the report files."""
    return _folders(_custom_data_dir())[0]


def db_dir() -> Path:
    """Folder of SQLite databases, listed by the dashboard's database selector."""
    return _folders(_custom_data_dir())[1]


def reports_dir() -> Path:
    """Folder of report PDFs: uploads and URL downloads land here, ingest reads it."""
    return _folders(_custom_data_dir())[2]


def stored_path(path: Path) -> str:
    """How to record `path` in raw_documents.file_path: data-folder-relative when inside it."""
    resolved = path.resolve()
    base = data_dir().resolve()
    return str(resolved.relative_to(base)) if resolved.is_relative_to(base) else str(resolved)


def resolve_stored(stored: str | Path) -> Path:
    """Inverse of stored_path(): an absolute path for a recorded file_path."""
    path = Path(stored)
    return path if path.is_absolute() else data_dir() / path
