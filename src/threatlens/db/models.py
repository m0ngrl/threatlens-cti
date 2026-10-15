"""
ThreatLens - SQLAlchemy ORM models
Database schema v1.5 (SQLite target)
ZEIT3118 Capstone Project

Defines the seven-table indicator repository:
  sources, raw_documents, indicators, sightings,
  quality_flags, allowlist, scoring_config

JSON columns are stored as TEXT and validated with json_valid() CHECK
constraints (SQLite has no native JSONB). Timestamps are ISO-8601 UTC text.
Foreign keys require PRAGMA foreign_keys = ON on every connection - the
event listener at the bottom of this file enforces that.
"""

from sqlalchemy import (
    create_engine, event, text, ForeignKey, CheckConstraint, UniqueConstraint,
    Integer, Text as TextType, REAL, Computed,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship,
)
from sqlalchemy.engine import Engine


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(TextType, nullable=False)
    source_type: Mapped[str] = mapped_column(TextType, nullable=False)
    url: Mapped[str | None] = mapped_column(TextType)
    ingested_at: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("(datetime('now'))")
    )
    raw_metadata: Mapped[str | None] = mapped_column(TextType)
    reliability: Mapped[int | None] = mapped_column(Integer)
    # Which verifier judged this report's candidates: 'python' (heuristics),
    # 'llm', or 'llm+python' when both ran. NULL for reports ingested before
    # this was recorded. Indicators inherit it through their sightings.
    extraction_engine: Mapped[str | None] = mapped_column(TextType)
    # The verifier's model name(s), e.g. an Ollama tag or python-heuristics.
    verification_model: Mapped[str | None] = mapped_column(TextType)

    raw_document: Mapped["RawDocument"] = relationship(
        back_populates="source", uselist=False, cascade="all, delete-orphan"
    )
    sightings: Mapped[list["Sighting"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "reliability IS NULL OR (reliability BETWEEN 0 AND 100)",
            name="ck_sources_reliability_range",
        ),
        CheckConstraint(
            "raw_metadata IS NULL OR json_valid(raw_metadata)",
            name="ck_sources_metadata_json",
        ),
        CheckConstraint(
            "extraction_engine IS NULL OR extraction_engine IN ('python', 'llm', 'llm+python')",
            name="ck_sources_extraction_engine",
        ),
    )


class RawDocument(Base):
    __tablename__ = "raw_documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"),
        nullable=False, unique=True,
    )
    content_type: Mapped[str] = mapped_column(TextType, nullable=False)
    raw_text: Mapped[str | None] = mapped_column(TextType)
    file_path: Mapped[str | None] = mapped_column(TextType)
    sha256: Mapped[str] = mapped_column(TextType, nullable=False, unique=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    archived_at: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("(datetime('now'))")
    )

    source: Mapped["Source"] = relationship(back_populates="raw_document")

    __table_args__ = (
        CheckConstraint(
            "raw_text IS NOT NULL OR file_path IS NOT NULL",
            name="ck_rawdoc_has_content",
        ),
        CheckConstraint(
            "length(sha256) = 64", name="ck_rawdoc_sha256_len"
        ),
    )


class Indicator(Base):
    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[str] = mapped_column(TextType, nullable=False)
    value: Mapped[str] = mapped_column(TextType, nullable=False)
    normalised: Mapped[str] = mapped_column(TextType, nullable=False)
    first_seen: Mapped[str | None] = mapped_column(TextType)
    last_seen: Mapped[str | None] = mapped_column(TextType)
    confidence: Mapped[int | None] = mapped_column(Integer)
    context: Mapped[str | None] = mapped_column(TextType)
    quality_score: Mapped[int | None] = mapped_column(Integer)
    score_components: Mapped[str | None] = mapped_column(TextType)
    scored_at: Mapped[str | None] = mapped_column(TextType)
    ctx_malware: Mapped[str | None] = mapped_column(
        TextType, Computed("json_extract(context, '$.malware_family')", persisted=False)
    )

    sightings: Mapped[list["Sighting"]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan"
    )
    quality_flags: Mapped[list["QualityFlag"]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("ioc_type", "normalised", name="uq_indicator_type_norm"),
        CheckConstraint(
            "confidence IS NULL OR (confidence BETWEEN 0 AND 100)",
            name="ck_indicator_confidence_range",
        ),
        CheckConstraint(
            "quality_score IS NULL OR (quality_score BETWEEN 0 AND 100)",
            name="ck_indicator_qscore_range",
        ),
        CheckConstraint(
            "context IS NULL OR json_valid(context)",
            name="ck_indicator_context_json",
        ),
        CheckConstraint(
            "score_components IS NULL OR json_valid(score_components)",
            name="ck_indicator_scorecomp_json",
        ),
    )


class Sighting(Base):
    __tablename__ = "sightings"

    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"), primary_key=True
    )
    seen_at: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("(datetime('now'))")
    )
    excerpt_start: Mapped[int | None] = mapped_column(Integer)
    excerpt_end: Mapped[int | None] = mapped_column(Integer)
    excerpt: Mapped[str | None] = mapped_column(TextType)

    indicator: Mapped["Indicator"] = relationship(back_populates="sightings")
    source: Mapped["Source"] = relationship(back_populates="sightings")


class QualityFlag(Base):
    __tablename__ = "quality_flags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False
    )
    flag_type: Mapped[str] = mapped_column(TextType, nullable=False)
    dimension: Mapped[str | None] = mapped_column(TextType)
    detail: Mapped[str | None] = mapped_column(TextType)
    severity: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("'warning'")
    )
    raised_at: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("(datetime('now'))")
    )
    status: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("'open'")
    )

    indicator: Mapped["Indicator"] = relationship(back_populates="quality_flags")


class Allowlist(Base):
    __tablename__ = "allowlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[str] = mapped_column(TextType, nullable=False)
    pattern: Mapped[str] = mapped_column(TextType, nullable=False)
    reason: Mapped[str | None] = mapped_column(TextType)


class ScoringConfig(Base):
    __tablename__ = "scoring_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dimension: Mapped[str] = mapped_column(TextType, nullable=False)
    weight: Mapped[float] = mapped_column(REAL, nullable=False)
    parameters: Mapped[str | None] = mapped_column(TextType)
    effective_from: Mapped[str] = mapped_column(
        TextType, nullable=False, server_default=text("(datetime('now'))")
    )

    __table_args__ = (
        CheckConstraint(
            "parameters IS NULL OR json_valid(parameters)",
            name="ck_scoring_parameters_json",
        ),
    )


@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Enforce foreign keys and enable WAL on every SQLite connection.

    SQLite ignores FOREIGN KEY constraints unless foreign_keys is ON, and
    the setting resets per connection - so this must run on connect, not once.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("PRAGMA journal_mode = WAL")
    cursor.close()


if __name__ == "__main__":
    engine = create_engine("sqlite:///threatlens.db", echo=True)
    Base.metadata.create_all(engine)
    print("All tables created.")