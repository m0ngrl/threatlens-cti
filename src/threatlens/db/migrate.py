"""
ThreatLens - schema migrations for an installed or checked-out package.
ZEIT3118 Capstone Project

Runs the Alembic chain shipped in threatlens/migrations against any SQLite
file, without an alembic.ini, so it works the same from a repo checkout and
from a pip-installed package. Always create and change the schema this way,
never with create_all().

    python -m threatlens.db.migrate                  # threatlens.conf's default database
    python -m threatlens.db.migrate db/ex_threatlens.db

Seeding the reference tables is separate: python -m threatlens.db.seed.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def alembic_config(db_path: Path) -> Config:
    """An Alembic Config pointing the shipped migrations at `db_path`."""
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return config


def upgrade(db_path: Path, revision: str = "head") -> None:
    """Create or upgrade `db_path`'s schema to `revision` (creating parent dirs)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(db_path), revision)


def main(argv: list[str] | None = None) -> int:
    from threatlens.db.seed import db_url

    parser = argparse.ArgumentParser(description="Create or upgrade a ThreatLens database's schema.")
    parser.add_argument(
        "db_path",
        nargs="?",
        type=Path,
        help="SQLite file (default: threatlens.conf [database] default, in db/)",
    )
    parser.add_argument("--revision", default="head", help="target revision (default: head)")
    args = parser.parse_args(argv)

    db_path = args.db_path or Path(db_url().removeprefix("sqlite:///"))
    upgrade(db_path, args.revision)
    print(f"{db_path}: schema at {args.revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
