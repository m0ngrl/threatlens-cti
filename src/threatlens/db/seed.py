"""
ThreatLens - reference data seed script
Database schema v1.5 (SQLite)
ZEIT3118 Capstone Project

Populates the two reference tables the quality engine depends on:
  - scoring_config : four quality-dimension weights + Table 7 band parameters
  - allowlist      : known-benign entries for false-positive detection

Safe to re-run: it clears and repopulates both reference tables each time,
so it never creates duplicates. That also discards any scoring_config history
(rows added since with a later effective_from). It does NOT touch indicators,
sources, or any operational data.

It seeds the database named by threatlens.conf [database] default. Weights
set in threatlens.conf [quality.weights] override the ones written here.

Run from anywhere with the virtual environment active:
    python -m threatlens.db.seed
"""

import json

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import Session

from threatlens.config import load_config
from threatlens.db.models import Allowlist, ScoringConfig
from threatlens.paths import db_dir


def db_url() -> str:
    """The default database named in threatlens.conf, in paths.db_dir() (threatlens.db if unset)."""
    return f"sqlite:///{db_dir() / load_config().database}"


# ---------------------------------------------------------------------------
# Scoring configuration - four dimensions, weights summing to 1.00.
# Consistency is deliberately not scored: the paper's band is antivirus
# detection rate, which needs enrichment APIs that are out of scope, and the
# cross-verifier stand-in duplicated a signal already carried by confidence.
# Band parameters follow the paper's Table 7 (0-5 severity rubric).
# ---------------------------------------------------------------------------
SCORING_CONFIG = [
    {
        "dimension": "timeliness",
        "weight": 0.25,
        "parameters": {
            "bands_days": {"5": 7, "4": 30, "3": 90, "2": 365},
            "note": "days since last_seen; older than 365 or unknown scores 1/0",
        },
    },
    {
        "dimension": "accuracy",
        "weight": 0.30,
        "parameters": {
            "bands_reliability_pct": {"5": 90, "4": 80, "3": 70, "2": 55},
            "min_candidates": 10,
            "note": "percent of the source's candidates that survived "
                    "assessment. Corroboration counts are retained in "
                    "sightings for when external enrichment is available, "
                    "but measured over 105 reports only 3.3% of observables "
                    "appear twice and no file hash does, so corroboration "
                    "needs a feed rather than a corpus",
        },
    },
    {
        "dimension": "completeness",
        "weight": 0.25,
        "parameters": {
            "expected_keys": ["threat_actor", "campaign", "vulnerability", "tool"],
            "bands_pct": {"5": 80, "4": 60, "3": 40, "2": 20},
            "note": "percent of expected context keys populated; keys are the "
                    "SDO entity types the extractor emits, so all are reachable",
        },
    },
    {
        "dimension": "relevance",
        "weight": 0.20,
        "parameters": {
            "bands_match_pct": {"5": 80, "4": 60, "3": 40, "2": 20},
            "note": "percent match between the document's strategic..tactical "
                    "audience profile and the reader's selected role; a "
                    "strategic report scores 5 for a CISO and 1 for an analyst",
        },
    },
]


# ---------------------------------------------------------------------------
# Allowlist - starter known-benign entries (MISP warninglist pattern).
# Expand in Sprint 3, optionally by importing MISP's public warninglists.
# ---------------------------------------------------------------------------
ALLOWLIST = [
    ("ipv4", "8.8.8.8", "Google Public DNS"),
    ("ipv4", "8.8.4.4", "Google Public DNS (secondary)"),
    ("ipv4", "1.1.1.1", "Cloudflare Public DNS"),
    ("ipv4", "1.0.0.1", "Cloudflare Public DNS (secondary)"),
    ("ipv4", "9.9.9.9", "Quad9 Public DNS"),
    ("ipv4", "10.0.0.0/8", "RFC1918 private range"),
    ("ipv4", "172.16.0.0/12", "RFC1918 private range"),
    ("ipv4", "192.168.0.0/16", "RFC1918 private range"),
    ("ipv4", "127.0.0.0/8", "Loopback range"),
    ("domain", "google.com", "Top-ranked benign domain"),
    ("domain", "*.google.com", "Google subdomains"),
    ("domain", "microsoft.com", "Top-ranked benign domain"),
    ("domain", "*.microsoft.com", "Microsoft subdomains"),
    ("domain", "cloudflare.com", "Top-ranked benign domain"),
    ("domain", "amazonaws.com", "Common cloud infrastructure"),
    ("domain", "*.amazonaws.com", "AWS subdomains"),
]


def seed_missing(session: Session) -> list[str]:
    """Fill whichever reference table is still empty, leaving filled ones alone.

    Unlike seed(), this never discards edits or scoring_config history, so it
    is safe on an existing database (threatlens init, run_ex_pipeline.py).
    Commits, and returns one message per table it filled.
    """
    filled: list[str] = []
    if not session.execute(select(func.count()).select_from(ScoringConfig)).scalar_one():
        for row in SCORING_CONFIG:
            session.add(ScoringConfig(
                dimension=row["dimension"],
                weight=row["weight"],
                parameters=json.dumps(row["parameters"]),
            ))
        filled.append(f"Seeded scoring_config ({len(SCORING_CONFIG)} rows)")
    if not session.execute(select(func.count()).select_from(Allowlist)).scalar_one():
        for ioc_type, pattern, reason in ALLOWLIST:
            session.add(Allowlist(ioc_type=ioc_type, pattern=pattern, reason=reason))
        filled.append(f"Seeded allowlist ({len(ALLOWLIST)} rows)")
    session.commit()
    return filled


def seed():
    engine = create_engine(db_url())
    with Session(engine) as session:
        # Clear both reference tables so re-running never duplicates rows.
        session.execute(delete(ScoringConfig))
        session.execute(delete(Allowlist))

        for row in SCORING_CONFIG:
            session.add(ScoringConfig(
                dimension=row["dimension"],
                weight=row["weight"],
                parameters=json.dumps(row["parameters"]),
            ))

        for ioc_type, pattern, reason in ALLOWLIST:
            session.add(Allowlist(
                ioc_type=ioc_type,
                pattern=pattern,
                reason=reason,
            ))

        session.commit()

        n_cfg = session.query(ScoringConfig).count()
        n_allow = session.query(Allowlist).count()

    total_weight = round(sum(r["weight"] for r in SCORING_CONFIG), 2)
    print(f"Seeded scoring_config: {n_cfg} rows (weights sum to {total_weight}).")
    print(f"Seeded allowlist:      {n_allow} rows.")
    print("Done.")


if __name__ == "__main__":
    seed()