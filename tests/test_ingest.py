"""Tests for the ingest layer and allowlist matching.

These run against a real SQLite database built from the ORM metadata, so the
CHECK and UNIQUE constraints are exercised rather than mocked.
"""

import hashlib
import json

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from threatlens.db import conformance
from threatlens.db.ingest import (
    combine_engines,
    count_sightings,
    engine_for_model,
    ingest_extraction_file,
    ingest_extractions,
    refresh_seen_dates,
    resolve_sha256,
)
from threatlens.db.models import (
    Allowlist,
    Base,
    Indicator,
    QualityFlag,
    RawDocument,
    Sighting,
    Source,
)
from threatlens.quality import quality_checker as checker
from threatlens.quality.allowlist import (
    flag_allowlisted_indicators,
    load_allowlist,
    match_allowlist,
)

SEED_ALLOWLIST = [
    ("ipv4", "8.8.8.8", "Google Public DNS"),
    ("ipv4", "10.0.0.0/8", "RFC1918 private range"),
    ("ipv4", "192.168.0.0/16", "RFC1918 private range"),
    ("domain", "google.com", "Top-ranked benign domain"),
    ("domain", "*.google.com", "Google subdomains"),
    ("domain", "microsoft.com", "Top-ranked benign domain"),
    ("domain", "*.microsoft.com", "Microsoft subdomains"),
]


def _extraction(indicator_type, value, **overrides):
    record = {
        "indicator_type": indicator_type,
        "value": value,
        "normalized_value": value,
        "context": "surrounding text",
        "method": "regex:test",
        "start": 10,
        "end": 20,
        "attributes": {},
    }
    if indicator_type == "ip":
        record["attributes"] = {"ip_version": 4}
    record.update(overrides)
    return record


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        for ioc_type, pattern, reason in SEED_ALLOWLIST:
            db.add(Allowlist(ioc_type=ioc_type, pattern=pattern, reason=reason))
        db.commit()
        yield db


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------

def test_ingest_populates_all_four_tables(session):
    result = ingest_extractions(
        session,
        [_extraction("ip", "45.76.42.205"), _extraction("domain", "evil.com")],
        source_name="report.pdf",
        raw_text="a report",
    )
    session.commit()

    assert result.source_created is True
    assert result.indicators_created == 2
    assert result.sightings_created == 2
    assert session.execute(select(func.count()).select_from(Source)).scalar() == 1
    assert session.execute(select(func.count()).select_from(RawDocument)).scalar() == 1


def test_intelligence_entities_are_skipped(session):
    result = ingest_extractions(
        session,
        [_extraction("malware", "Emotet"), _extraction("ip", "45.76.42.205")],
        source_name="report.pdf",
        raw_text="a report",
    )
    session.commit()

    assert result.skipped_context_only == 1
    assert result.indicators_created == 1


def test_ingest_is_idempotent(session):
    records = [_extraction("ip", "45.76.42.205")]

    first = ingest_extractions(
        session, records, source_name="report.pdf", raw_text="identical"
    )
    session.commit()
    second = ingest_extractions(
        session, records, source_name="report.pdf", raw_text="identical"
    )
    session.commit()

    assert first.source_created is True
    assert second.source_created is False
    assert second.indicators_created == 0
    assert second.sightings_created == 0
    assert session.execute(select(func.count()).select_from(Source)).scalar() == 1
    assert session.execute(select(func.count()).select_from(Sighting)).scalar() == 1


def test_same_indicator_in_two_reports_yields_two_sightings(session):
    """The accuracy dimension counts corroborating sources, so this must not
    collapse into one sighting or split into two indicators."""
    records = [_extraction("ip", "45.76.42.205")]

    ingest_extractions(session, records, source_name="a.pdf", raw_text="alpha")
    ingest_extractions(session, records, source_name="b.pdf", raw_text="beta")
    session.commit()

    indicator = session.execute(select(Indicator)).scalars().one()
    assert count_sightings(session, indicator.id) == 2
    assert session.execute(select(func.count()).select_from(Source)).scalar() == 2


def test_repeated_occurrences_in_one_report_are_one_sighting(session):
    ingest_extractions(
        session,
        [_extraction("ip", "45.76.42.205"), _extraction("ip", "45.76.42.205")],
        source_name="report.pdf",
        raw_text="a report",
    )
    session.commit()

    assert session.execute(select(func.count()).select_from(Sighting)).scalar() == 1


def test_ingest_records_conformance_errors_without_aborting(session):
    result = ingest_extractions(
        session,
        [_extraction("ip", "1.2.3.4", attributes={}), _extraction("domain", "evil.com")],
        source_name="report.pdf",
        raw_text="a report",
    )
    session.commit()

    assert len(result.errors) == 1          # ip with no ip_version
    assert result.indicators_created == 1   # the domain still landed


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ioc_type, value, expected",
    [
        ("ipv4", "8.8.8.8", True),
        ("ipv4", "8.8.4.4", False),
        ("ipv4", "10.255.1.1", True),        # CIDR containment
        ("ipv4", "192.168.50.7", True),
        ("ipv4", "11.0.0.1", False),
        ("domain", "google.com", True),
        ("domain", "mail.google.com", True),  # wildcard
        ("domain", "notgoogle.com", False),   # must not match by bare suffix
        ("domain", "evil.com", False),
        ("url", "https://www.microsoft.com/advisory", True),
        ("url", "https://evil.com/payload", False),
    ],
)
def test_allowlist_matching(session, ioc_type, value, expected):
    entries = load_allowlist(session)
    assert (match_allowlist(ioc_type, value, entries) is not None) is expected


def test_wildcard_does_not_cover_the_apex(session):
    """seed.py lists google.com and *.google.com separately, which only makes
    sense if the wildcard excludes the apex domain."""
    entries = [e for e in load_allowlist(session) if e.pattern == "*.google.com"]
    assert match_allowlist("domain", "mail.google.com", entries) is not None
    assert match_allowlist("domain", "google.com", entries) is None


def test_flagging_is_not_duplicated(session):
    ingest_extractions(
        session,
        [_extraction("ip", "8.8.8.8"), _extraction("ip", "45.76.42.205")],
        source_name="report.pdf",
        raw_text="a report",
    )
    session.commit()

    first = flag_allowlisted_indicators(session)
    session.commit()
    second = flag_allowlisted_indicators(session)
    session.commit()

    assert len(first) == 1
    assert len(second) == 0
    assert session.execute(select(func.count()).select_from(QualityFlag)).scalar() == 1


def test_allowlisted_indicator_is_flagged_not_deleted(session):
    """The sighting is evidence about the report and must survive."""
    ingest_extractions(
        session, [_extraction("ip", "8.8.8.8")],
        source_name="report.pdf", raw_text="a report",
    )
    session.commit()
    flag_allowlisted_indicators(session)
    session.commit()

    assert session.execute(select(func.count()).select_from(Indicator)).scalar() == 1
    assert session.execute(select(func.count()).select_from(Sighting)).scalar() == 1


# ---------------------------------------------------------------------------
# Scoring against persisted data
# ---------------------------------------------------------------------------

def test_rescore_still_records_corroboration_without_scoring_it(session):
    """Sighting counts are kept for when external enrichment arrives.

    Accuracy no longer reads them - measured over 105 reports, corroboration
    sits at 3.3% and correlates with benign-ness - but the count must survive
    a rescore so the measure is there when a feed is.
    """
    records = [_extraction("ip", "45.76.42.205")]
    ingest_extractions(session, records, source_name="a.pdf", raw_text="alpha")
    ingest_extractions(session, records, source_name="b.pdf", raw_text="beta")
    session.commit()

    checker.rescore_from_db(session, policy=checker.ScoringPolicy.default())
    session.commit()

    indicator = session.execute(
        select(Indicator).where(Indicator.normalised == "45.76.42.205")
    ).scalars().one()
    components = json.loads(indicator.score_components or "{}")

    assert components["sightings"] == 2
    assert 0 <= indicator.quality_score <= 100


# ---------------------------------------------------------------------------
# Document identity
# ---------------------------------------------------------------------------

PDF_BYTES = b"%PDF-1.7 pretend report bytes"
PDF_SHA256 = hashlib.sha256(PDF_BYTES).hexdigest()


def test_supplied_sha256_wins_over_hashing_whatever_text_is_available():
    assert resolve_sha256(PDF_SHA256, None, "unrelated text") == PDF_SHA256


def test_supplied_sha256_is_normalised_to_lower_case():
    """An upper-case digest would compare unequal and duplicate the document."""
    assert resolve_sha256(PDF_SHA256.upper(), None, None) == PDF_SHA256


def test_malformed_sha256_is_rejected_with_the_column_named():
    with pytest.raises(conformance.ConformanceError, match="64 hexadecimal"):
        resolve_sha256("not-a-digest", None, None)


def test_sha256_falls_back_to_hashing_when_not_supplied():
    assert resolve_sha256(None, None, "alpha") == hashlib.sha256(b"alpha").hexdigest()


def test_one_report_two_ingest_routes_is_one_source(session, tmp_path):
    """The duplication the sha256 UNIQUE constraint exists to prevent.

    A report ingested from its PDF, then again from extractor JSON that names
    the same file_sha256, must be recognised as the same document. Hashing the
    JSON text instead would mint a second identity and double every sighting
    count - silently, and in the dimension weighted most heavily.
    """
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(PDF_BYTES)
    records = [_extraction("ip", "45.76.42.205")]

    # Route 1: the original document.
    ingest_extractions(session, records, source_name="report.pdf", file_path=pdf)
    session.commit()

    # Route 2: extractor JSON only, with no PDF to hand.
    ingest_extractions(
        session, records,
        source_name="report.pdf",
        raw_text='{"metadata": {"file_sha256": "..."}}',
        sha256=PDF_SHA256,
    )
    session.commit()

    assert session.execute(select(func.count()).select_from(Source)).scalar() == 1
    assert session.execute(
        select(func.count()).select_from(RawDocument)
    ).scalar() == 1

    indicator = session.execute(select(Indicator)).scalars().one()
    assert count_sightings(session, indicator.id) == 1


def test_ingest_extraction_file_uses_the_extractor_digest(session, tmp_path):
    """The JSON route must not identify a document by the JSON's own text."""
    payload = {
        "metadata": {"filename": "report.pdf", "file_sha256": PDF_SHA256},
        "verification_model": "qwen3.5:4b",
        "summary": {},
        "indicators": [_extraction("ip", "45.76.42.205")],
        "accepted_by_category": {"network": [_extraction("ip", "45.76.42.205")]},
    }
    json_path = tmp_path / "llm.json"
    json_path.write_text(json.dumps(payload), encoding="utf-8")

    ingest_extraction_file(session, json_path)
    session.commit()

    document = session.execute(select(RawDocument)).scalars().one()
    assert document.sha256 == PDF_SHA256

    # accepted_by_category repeats the indicators; counting both would inflate
    # the candidate set. One indicator in, one indicator out.
    assert session.execute(select(func.count()).select_from(Indicator)).scalar() == 1


# ---------------------------------------------------------------------------
# Extraction engine
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "model, expected",
    [
        ("python-heuristics", "python"),
        ("qwen3.5:4b", "llm"),
        ("unknown", None),
        ("", None),
        (None, None),
    ],
)
def test_engine_for_model(model, expected):
    assert engine_for_model(model) == expected


def test_combine_engines_unions_and_rejects_unknown_labels():
    assert combine_engines("llm", "python") == "llm+python"
    assert combine_engines("llm+python", "llm") == "llm+python"
    assert combine_engines(None, "python") == "python"
    assert combine_engines() is None
    with pytest.raises(conformance.ConformanceError):
        combine_engines("regex")


def _verified_run(model):
    record = _extraction(
        "ip",
        "45.76.42.205",
        candidate_id="0",
        category="network",
        verification={"status": "confirmed_ioc", "confidence": 0.9, "reason": "c2"},
    )
    return checker.run_from_payload(
        {
            "metadata": {"filename": "report.pdf", "file_sha256": PDF_SHA256},
            "verification_model": model,
            "summary": {},
            "indicators": [record],
        }
    )


@pytest.mark.parametrize(
    "models, engine",
    [
        (["python-heuristics"], "python"),
        (["qwen3.5:4b"], "llm"),
        (["qwen3.5:4b", "python-heuristics"], "llm+python"),
    ],
)
def test_persist_report_records_the_extraction_engine(session, models, engine):
    report = checker.check_report([_verified_run(m) for m in models])
    checker.persist_report(session, report, source_name="report.pdf")
    session.commit()

    source = session.execute(select(Source)).scalars().one()
    assert source.extraction_engine == engine
    assert source.verification_model == ", ".join(models)


def test_reingesting_with_the_other_engine_widens_rather_than_overwrites(session):
    for model in ("qwen3.5:4b", "python-heuristics"):
        report = checker.check_report([_verified_run(model)])
        checker.persist_report(session, report, source_name="report.pdf")
        session.commit()

    source = session.execute(select(Source)).scalars().one()
    assert source.extraction_engine == "llm+python"
    assert source.verification_model == "qwen3.5:4b, python-heuristics"


def test_ingest_without_an_engine_leaves_it_unknown(session):
    ingest_extractions(session, [_extraction("ip", "45.76.42.205")], source_name="a.pdf", raw_text="a")
    session.commit()
    source = session.execute(select(Source)).scalars().one()
    assert source.extraction_engine is None
    assert source.verification_model is None


def test_ingest_extraction_file_records_the_engine(session, tmp_path):
    payload = {
        "metadata": {"filename": "report.pdf", "file_sha256": PDF_SHA256},
        "verification_model": "python-heuristics",
        "indicators": [_extraction("ip", "45.76.42.205")],
    }
    json_path = tmp_path / "python.json"
    json_path.write_text(json.dumps(payload), encoding="utf-8")

    ingest_extraction_file(session, json_path)
    session.commit()

    source = session.execute(select(Source)).scalars().one()
    assert source.extraction_engine == "python"
    assert source.verification_model == "python-heuristics"


# ---------------------------------------------------------------------------
# first_seen / last_seen come from report publish dates
# ---------------------------------------------------------------------------

def _dated_report(sha_seed, publish_date, value="45.76.42.205"):
    record = _extraction(
        "ip",
        value,
        candidate_id="0",
        category="network",
        verification={"status": "confirmed_ioc", "confidence": 0.9, "reason": "c2"},
    )
    metadata = {
        "filename": f"{sha_seed}.pdf",
        "file_sha256": hashlib.sha256(sha_seed.encode()).hexdigest(),
    }
    if publish_date is not None:
        metadata["publish_date"] = publish_date
    return checker.check_report([
        checker.run_from_payload({
            "metadata": metadata,
            "verification_model": "qwen3.5:9b",
            "summary": {},
            "indicators": [record],
        })
    ])


def _persist(session, report):
    checker.persist_report(session, report, source_name=report.metadata["filename"])
    session.commit()


def test_seen_dates_are_report_dates_not_ingest_time(session):
    _persist(session, _dated_report("a", "2025-03-01"))
    indicator = session.execute(select(Indicator)).scalars().one()
    assert indicator.first_seen == "2025-03-01T00:00:00Z"
    assert indicator.last_seen == "2025-03-01T00:00:00Z"


def test_seen_dates_span_reports_whatever_the_ingest_order(session):
    # Newest first, then oldest, then one in between: ingest order must not matter.
    for seed, published in (("new", "2025-09-10"), ("old", "2024-01-05"), ("mid", "2025-02-01")):
        _persist(session, _dated_report(seed, published))

    indicator = session.execute(select(Indicator)).scalars().one()
    assert indicator.first_seen == "2024-01-05T00:00:00Z"
    assert indicator.last_seen == "2025-09-10T00:00:00Z"


def test_undated_report_leaves_seen_dates_unknown(session):
    _persist(session, _dated_report("undated", None))
    indicator = session.execute(select(Indicator)).scalars().one()
    assert indicator.first_seen is None
    assert indicator.last_seen is None


def test_undated_report_does_not_displace_known_dates(session):
    _persist(session, _dated_report("dated", "2025-03-01"))
    _persist(session, _dated_report("undated", None))
    indicator = session.execute(select(Indicator)).scalars().one()
    assert (indicator.first_seen, indicator.last_seen) == (
        "2025-03-01T00:00:00Z", "2025-03-01T00:00:00Z",
    )


def test_refresh_seen_dates_after_a_report_is_removed(session):
    _persist(session, _dated_report("old", "2024-01-05"))
    _persist(session, _dated_report("new", "2025-09-10"))

    newest = session.execute(
        select(Source).where(Source.name == "new.pdf")
    ).scalars().one()
    affected = [s.indicator_id for s in newest.sightings]
    session.delete(newest)
    session.flush()
    assert refresh_seen_dates(session, affected) == 1
    session.commit()

    indicator = session.execute(select(Indicator)).scalars().one()
    assert indicator.last_seen == "2024-01-05T00:00:00Z"
