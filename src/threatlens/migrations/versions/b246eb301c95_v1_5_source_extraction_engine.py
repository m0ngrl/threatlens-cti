"""v1.5 source extraction engine

Records which verifier judged each report: sources.extraction_engine
('python', 'llm' or 'llm+python') and sources.verification_model.

Both columns are added with plain ALTER TABLE rather than a batch rebuild.
models.py turns PRAGMA foreign_keys on for every connection, this one
included, and a batch rebuild drops the old sources table - which would
cascade-delete every raw_documents and sightings row. ADD COLUMN and
DROP COLUMN (SQLite 3.35+) never rebuild the table, so nothing cascades.

Existing reports are left NULL ("unknown"): nothing stored says which
engine verified them.

Revision ID: b246eb301c95
Revises: 7797ff2fc9e2
Create Date: 2026-10-11 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b246eb301c95'
down_revision: Union[str, Sequence[str], None] = '7797ff2fc9e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        "ALTER TABLE sources ADD COLUMN extraction_engine TEXT "
        "CONSTRAINT ck_sources_extraction_engine CHECK ("
        "extraction_engine IS NULL OR extraction_engine IN ('python', 'llm', 'llm+python'))"
    )
    op.execute("ALTER TABLE sources ADD COLUMN verification_model TEXT")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("ALTER TABLE sources DROP COLUMN verification_model")
    op.execute("ALTER TABLE sources DROP COLUMN extraction_engine")
