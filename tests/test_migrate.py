"""The Alembic chain shipped in threatlens/migrations, run via threatlens.db.migrate."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic.script import ScriptDirectory

from threatlens.db.migrate import MIGRATIONS_DIR, alembic_config, upgrade


def test_upgrade_creates_schema_at_head(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "new.db"
    upgrade(db_path)

    head = ScriptDirectory.from_config(alembic_config(db_path)).get_current_head()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (head,)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"sources", "indicators", "scoring_config", "allowlist"} <= tables


def test_upgrade_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "again.db"
    upgrade(db_path)
    upgrade(db_path)


def test_migrations_ship_inside_the_package() -> None:
    assert (MIGRATIONS_DIR / "env.py").is_file()
    assert (MIGRATIONS_DIR / "script.py.mako").is_file()
    assert list((MIGRATIONS_DIR / "versions").glob("*.py"))
