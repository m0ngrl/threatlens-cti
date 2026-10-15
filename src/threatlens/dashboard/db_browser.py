"""ThreatLens dashboard - embedded raw database browser.

Mounts Datasette (https://datasette.io/) as an ASGI sub-application under
/db-browser, so the header's "db" link shows every table's actual rows and
columns - unlike the Indicators/Reports/Quality Flags tabs, which are
curated, filtered views over the same data. Embedding it means there is
nothing separate to start, and the link always works.

Read-only in effect: Datasette's stock UI has no row edit/delete, so this
can't be used to change the database (unlike the dashboard's own
indicator/source editing).

DatasetteProxy rebuilds its Datasette instance whenever the dashboard's own
database selector (see db.py / routes/db_admin.py) points at a different
file, so /db-browser always reflects whatever the header dropdown currently
has selected - no dashboard restart needed. Rebuilding only happens when the
active file actually changes, so normal requests are cheap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from datasette.app import Datasette

from threatlens.dashboard import db as dashboard_db

MOUNT_PATH = "/db-browser"


class DatasetteProxy:
    """ASGI app wrapping whichever Datasette instance matches the
    dashboard's currently active database file."""

    def __init__(self) -> None:
        self._path: Path | None = None
        self._asgi: Any = None

    def _current_asgi(self) -> Any:
        active_path = dashboard_db.active_db_path()
        if active_path != self._path:
            self._asgi = Datasette(
                files=[str(active_path)],
                settings={"base_url": f"{MOUNT_PATH}/"},
            ).app()
            self._path = active_path
        return self._asgi

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        await self._current_asgi()(scope, receive, send)
