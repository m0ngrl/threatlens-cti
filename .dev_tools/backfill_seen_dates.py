#!/usr/bin/env python3
"""Backfill indicators.first_seen / last_seen from report publish dates.

Databases built before the fix in db/ingest.py have first_seen NULL on every
indicator, and last_seen set to the publish date of whichever report happened
to be ingested last. This sets both from the publish dates of every report
that sighted each indicator (earliest and latest - see
db.ingest.refresh_seen_dates()), then rescores, since timeliness reads
last_seen.

The rescore runs as of each database's original scoring time by default, so
the dates are the only thing that changes and an evaluation run stays
comparable with its reports. --now rescores as of today instead. Either way
the weights are the database's scoring_config overlaid by threatlens.conf, as
for any rescore - check that file first.

Usage:
    python .dev_tools/backfill_seen_dates.py db/ex4_threatlens.db [db/... ...]
    python .dev_tools/backfill_seen_dates.py db/threatlens.db --now
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from threatlens.db.ingest import refresh_seen_dates
from threatlens.db.models import Indicator
from threatlens.quality.quality_checker import rescore_from_db


def backfill(db_path: Path, *, as_of_now: bool) -> None:
    session = Session(create_engine(f"sqlite:///{db_path}"))
    try:
        scored_at = session.execute(select(func.max(Indicator.scored_at))).scalar_one()
        now = None if as_of_now or not scored_at else datetime.fromisoformat(scored_at)
        changed = refresh_seen_dates(session)
        session.flush()
        rescored = rescore_from_db(session, now=now)
        session.commit()
        unknown = session.execute(
            select(func.count()).select_from(Indicator).where(Indicator.last_seen.is_(None))
        ).scalar_one()
        print(
            f"{db_path}: dates changed on {changed} indicators, {rescored} rescored "
            f"as of {'now' if now is None else scored_at}; {unknown} with no dated report"
        )
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("databases", nargs="+", type=Path, help="SQLite database files")
    parser.add_argument(
        "--now", action="store_true",
        help="rescore as of today rather than the database's original scoring time",
    )
    args = parser.parse_args(argv)

    for db_path in args.databases:
        if not db_path.is_file():
            print(f"error: no such database: {db_path}", file=sys.stderr)
            return 1
    for db_path in args.databases:
        backfill(db_path, as_of_now=args.now)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
