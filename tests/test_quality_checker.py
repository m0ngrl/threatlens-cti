"""Tests for the quality checker.

Most cases reproduce a defect seen in real extractor output, built inline as
small payloads, so a regression means the checker has stopped catching
something it has been shown to catch.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threatlens.quality.quality_checker import (
    MALFORMED_FLAGS,
    SCREENED_FLAGS,
    Agreement,
    Candidate,
    ExtractionRun,
    ScoringPolicy,
    StixKind,
    Verdict,
    check_report,
    classify_stix,
    compare_verifiers,
    composite_score,
    find_filename_collisions,
    find_nested_values,
    find_span_overlaps,
    format_valid,
    grade_agreement,
    grade_quality_score,
    has_trailing_punctuation,
    is_non_routable,
    is_self_reference,
    is_sentence_fragment,
    is_technique_idiom,
    is_truncated_span,
    maliciousness_from_verdict,
    score_accuracy,
    score_completeness,
    score_timeliness,
)

POLICY = ScoringPolicy.default()
NOW = datetime(2026, 8, 11, tzinfo=UTC)


def make_candidate(
    candidate_id: str = "c1",
    indicator_type: str = "domain",
    value: str = "example.com",
    *,
    start: int | None = 0,
    end: int | None = 11,
    status: str | None = "confirmed_ioc",
    confidence: float | None = 0.9,
    attributes: dict | None = None,
) -> Candidate:
    return Candidate.from_record({
        "id": candidate_id,
        "category": "network",
        "indicator_type": indicator_type,
        "value": value,
        "normalized_value": value.lower(),
        "start": start,
        "end": end,
        "context": "excerpt",
        "method": "regex:test",
        "attributes": attributes or {"was_defanged": False},
        "verification": {
            "status": status,
            "confidence": confidence,
            "reason": "test",
        },
        "accepted": status in {"confirmed_ioc", "context_entity"},
    })


# ---------------------------------------------------------------------------
# Layer 1 - structural rejection
# ---------------------------------------------------------------------------


def test_span_overlap_keeps_the_wider_candidate():
    """/actions/mail/get.php.php beats the get.php.php carved from its tail."""
    filepath = make_candidate("a", "filepath", "/actions/mail/get.php.php",
                              start=6318, end=6343)
    domain = make_candidate("b", "domain", "get.php.php", start=6332, end=6343)

    losers = find_span_overlaps([filepath, domain])

    assert "b" in losers
    assert "a" not in losers


def test_nested_value_keeps_the_shortest_form():
    """'RoundPress' beats 'RoundPress -' and the sentence around it."""
    clean = make_candidate("a", "campaign", "RoundPress", start=727, end=737)
    dashed = make_candidate("b", "campaign", "RoundPress -", start=2233, end=2245)
    prose = make_candidate("c", "campaign", "RoundPress blog in May 2025",
                           start=2386, end=2425)

    losers = find_nested_values([clean, dashed, prose])

    assert set(losers) == {"b", "c"}


def test_nested_value_defers_to_span_overlap_when_spans_collide():
    """The two rules tie-break oppositely; span overlap is right about these.

    Without this, /actions/mail/get.php.php would lose to the get.php.php
    nested inside it and the real filepath would be discarded.
    """
    filepath = make_candidate("a", "filepath", "/actions/mail/get.php.php",
                              start=6318, end=6343)
    tail = make_candidate("b", "filepath", "get.php.php", start=6332, end=6343)

    assert find_nested_values([filepath, tail]) == {}


@pytest.mark.parametrize("value", [
    "RoundPress blog in May 2025. Proofpoint",
    "from April 2025. Proofpoint tracks TA458 as distinct from Operation",
    "directed by the Russian GRU. At the",
    "persistence mechanisms with that exploit, which is likely built as",
    "s as jump boxes to send the emails onward. Proofpoint has",
])
def test_sentence_fragments_are_detected(value):
    """The five fragments observed in the reference sample."""
    assert is_sentence_fragment(value, StixKind.SDO) is not None


@pytest.mark.parametrize("value", ["Fancy Bear", "APT28", "RoundPress", "TA458"])
def test_real_entity_names_are_not_fragments(value):
    assert is_sentence_fragment(value, StixKind.SDO) is None


def test_hash_is_not_a_fragment_despite_its_length():
    digest = "625e4c166c7a1d5a1becf56b27d4f76a2f95935cbd8d556c30a493263d10dbf8"
    assert is_sentence_fragment(digest, StixKind.SCO) is None


def test_trailing_punctuation_detected():
    assert has_trailing_punctuation("RoundPress -") is not None
    assert has_trailing_punctuation("RoundPress") is None


def test_technique_idiom_detected():
    assert is_technique_idiom("/dev/tcp") is not None
    assert is_technique_idiom("/js/list.js.php") is None


def test_self_reference_matches_the_publishing_domain():
    metadata = {
        "source_url": "https://www.proofpoint.com/us/blog/threat-insight/ta458",
        "cti_source": "https://www.proofpoint.com/us/blog/threat-insight/ta458",
    }
    assert is_self_reference(metadata["source_url"], metadata) is not None
    assert is_self_reference("evil.example.com", metadata) is None


# ---------------------------------------------------------------------------
# Layer 2 - STIX conformance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("indicator_type", "expected"), [
    ("hash", StixKind.SCO),
    ("domain", StixKind.SCO),
    ("url", StixKind.SCO),
    ("filepath", StixKind.SCO),
    ("threat_actor", StixKind.SDO),
    ("campaign", StixKind.SDO),
    ("vulnerability", StixKind.SDO),
    ("tool", StixKind.SDO),
    ("persistence", StixKind.SDO),
    ("service", StixKind.NONE),
])
def test_stix_classification_matches_the_documented_table(indicator_type, expected):
    kind, _ = classify_stix(indicator_type)
    assert kind is expected


def test_code_fragment_is_not_a_legal_domain():
    """requests.get parses as a hostname but '.get' is not a TLD."""
    ok, reason = format_valid("domain", "requests.get")
    assert not ok
    assert "TLD" in reason


def test_filename_collision_removes_php_pseudo_domains():
    """All four .php 'domains', including those whose spans never overlap."""
    filepaths = [
        make_candidate("f1", "filepath", "/js/list.js.php", start=6230, end=6245),
        make_candidate("f2", "filepath", "/resources/blank.gif.php",
                       start=6253, end=6277),
    ]
    domains = [
        make_candidate("d1", "domain", "list.js.php", start=9235, end=9246),
        make_candidate("d2", "domain", "blank.gif.php", start=9315, end=9328),
    ]

    losers = find_filename_collisions([*filepaths, *domains])

    assert set(losers) == {"d1", "d2"}
    assert all(losers[k][1] == "filename_as_domain" for k in losers)


def test_bare_filename_duplicating_a_filepath_is_flagged_as_duplication():
    filepath = make_candidate("f1", "filepath", "/js/list.js.php",
                              start=6230, end=6245)
    filename = make_candidate("n1", "filename", "list.js.php",
                              start=9235, end=9246)

    losers = find_filename_collisions([filepath, filename])

    assert losers["n1"][1] == "duplicate_observable"


def test_a_filepath_does_not_reject_itself():
    lone = make_candidate("f1", "filepath", "list.js.php", start=0, end=11)
    assert find_filename_collisions([lone]) == {}


def test_valid_ip_is_well_formed_even_when_not_routable():
    """Routability is a false-positive question, not a format question."""
    ok, _ = format_valid("ip", "10.0.0.1")
    assert ok
    assert is_non_routable("ip", "10.0.0.1") is not None
    assert is_non_routable("ip", "203.0.113.9") is not None  # RFC 5737 docs
    assert is_non_routable("ip", "45.155.204.10") is None


# ---------------------------------------------------------------------------
# Verifier agreement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("python_status", "llm_status", "expected"), [
    (Verdict.CONTEXT, Verdict.CONTEXT, Agreement.AGREE),
    (Verdict.UNCERTAIN, Verdict.CONFIRMED, Agreement.WEAK),
    (Verdict.CONTEXT, Verdict.REJECTED, Agreement.MODERATE),
    (Verdict.CONTEXT, Verdict.CONFIRMED, Agreement.MODERATE),
    (Verdict.CONFIRMED, Verdict.REJECTED, Agreement.STRONG),
    (None, Verdict.CONFIRMED, Agreement.SINGLE),
])
def test_agreement_grades(python_status, llm_status, expected):
    assert grade_agreement(python_status, llm_status) is expected


def test_verdict_confidence_is_not_maliciousness():
    """The python verifier rejects at 0.98; that is 0.0 maliciousness, not 0.98."""
    assert maliciousness_from_verdict(Verdict.REJECTED, 0.98) == 0.0
    assert maliciousness_from_verdict(Verdict.CONFIRMED, 0.95) == 0.95
    # A context entity makes no claim about maliciousness at all.
    assert maliciousness_from_verdict(Verdict.CONTEXT, 0.9) is None


def test_agreement_discounts_confidence():
    confirmed = make_candidate("x", status="confirmed_ioc", confidence=0.9)
    hedged = make_candidate("x", status="uncertain", confidence=0.5)
    rejected = make_candidate("x", status="rejected", confidence=0.98)

    agreed = compare_verifiers(confirmed, confirmed, POLICY.agreement_multipliers)
    weak = compare_verifiers(hedged, confirmed, POLICY.agreement_multipliers)
    strong = compare_verifiers(rejected, confirmed, POLICY.agreement_multipliers)

    assert agreed.confidence > weak.confidence > strong.confidence


def test_llm_wins_where_both_verifiers_are_present():
    python_side = make_candidate("x", status="confirmed_ioc", confidence=0.92)
    llm_side = make_candidate("x", status="rejected", confidence=0.0)

    comparison = compare_verifiers(python_side, llm_side, POLICY.agreement_multipliers)

    assert comparison.winner == "llm"
    assert comparison.winning_status is Verdict.REJECTED


# ---------------------------------------------------------------------------
# Layer 4 - dimension scoring
# ---------------------------------------------------------------------------


def test_timeliness_bands():
    bands = POLICY.timeliness_bands_days
    assert score_timeliness("2026-08-08", bands, NOW) == 5   # 3 days
    assert score_timeliness("2026-07-25", bands, NOW) == 4   # 17 days
    assert score_timeliness("2026-06-01", bands, NOW) == 3   # 71 days
    assert score_timeliness("2026-01-01", bands, NOW) == 2   # 222 days
    assert score_timeliness("2020-01-01", bands, NOW) == 1   # indefinite
    assert score_timeliness(None, bands, NOW) == 0           # unknown


def test_timeliness_accepts_aware_datetimes_and_iso_text():
    """Carried over from Timeliness_metric: the DB returns ISO-8601 text, but
    a caller holding an aware datetime must not trip a naive/aware TypeError.
    """
    from datetime import timedelta

    from threatlens.db import conformance

    recent = NOW - timedelta(days=3)
    bands = POLICY.timeliness_bands_days
    assert score_timeliness(recent, bands, NOW) == 5
    assert score_timeliness(conformance.to_iso8601(recent), bands, NOW) == 5
    assert score_timeliness("not a date", bands, NOW) == 0


@pytest.mark.parametrize(("reliability", "expected"), [
    (100.0, 5), (90.0, 5), (85.0, 4), (80.0, 4),
    (72.0, 3), (70.0, 3), (60.0, 2), (55.0, 2), (40.0, 1), (0.0, 1),
])
def test_accuracy_bands_source_reliability(reliability, expected):
    """Accuracy reads the share of a source's candidates that survived."""
    assert score_accuracy(
        reliability, POLICY.accuracy_bands_reliability_pct,
        candidate_count=50, min_candidates=POLICY.accuracy_min_candidates,
    ) == expected


def test_accuracy_is_zero_when_reliability_is_unknown():
    assert score_accuracy(None, POLICY.accuracy_bands_reliability_pct) == 0


def test_a_tiny_sample_cannot_claim_the_top_bands():
    """A report offering two candidates can hit 100% by luck."""
    bands = POLICY.accuracy_bands_reliability_pct
    floor = POLICY.accuracy_min_candidates

    assert score_accuracy(100.0, bands, candidate_count=2, min_candidates=floor) == 3
    assert score_accuracy(100.0, bands, candidate_count=50, min_candidates=floor) == 5


def test_malformed_ip_fails_format_validation():
    """Carried over from IP_checker."""
    assert format_valid("ip", "8.8.8.8")[0]
    assert not format_valid("ip", "999.1.1.1")[0]


def test_extractor_float_confidence_is_not_read_as_a_percentage():
    """Carried over from Confidence_metric: 0.96 must become 96, never 0.

    int(0.96) == 0 commits a valid-looking zero into a CHECK-constrained
    column, so the failure is invisible until someone reads the scores back.
    """
    confirmed = make_candidate("x", status="confirmed_ioc", confidence=0.96)
    comparison = compare_verifiers(confirmed, confirmed, POLICY.agreement_multipliers)
    assert comparison.confidence == 96


def test_completeness_measures_populated_expected_keys():
    keys = POLICY.completeness_expected_keys
    bands = POLICY.completeness_bands_pct
    assert score_completeness({}, keys, bands) == 0
    assert score_completeness({"campaign": ["RoundPress"]}, keys, bands) == 2
    full = dict.fromkeys(keys, "x")
    assert score_completeness(full, keys, bands) == 5


def test_truncated_span_catches_the_dropped_path_prefix():
    """The filepath rule needs a leading '/', so it began matching inside
    'program/js/list.js.php' and stored a path the report never published.
    """
    excerpt = "webshell to the following paths: program/js/list.js.php and"
    detail = is_truncated_span("/js/list.js.php", excerpt)

    assert detail is not None
    assert "program" in detail


def test_truncated_span_ignores_a_clean_capture():
    excerpt = "beaconing to /js/list.js.php over TCP"
    assert is_truncated_span("/js/list.js.php", excerpt) is None


def test_truncated_span_needs_every_occurrence_to_be_mid_token():
    """A value that also appears cleanly in the window was captured correctly."""
    excerpt = "program/js/list.js.php and later just /js/list.js.php alone"
    assert is_truncated_span("/js/list.js.php", excerpt) is None


@pytest.mark.parametrize("value, excerpt", [
    ("/js/list.js.php", ""),          # no excerpt to judge against
    ("ab", "xab"),                    # below the minimum value length
    ("evil.com", "unrelated text"),   # value absent from the excerpt
])
def test_truncated_span_stays_quiet_without_evidence(value, excerpt):
    assert is_truncated_span(value, excerpt) is None


def test_composite_score_normalises_by_applied_weight():
    """A dimension the policy does not weight must not distort the scale."""
    dimensions = {"timeliness": 5, "accuracy": 5, "completeness": 5,
                  "relevance": 5}
    assert composite_score(dimensions, POLICY.weights) == 100

    rebalanced = {**POLICY.weights, "relevance": 0.5}
    assert composite_score(dimensions, rebalanced) == 100


# ---------------------------------------------------------------------------
# Flag declarations, relevance and dimension rules
# ---------------------------------------------------------------------------


def test_every_flag_type_declares_its_dimension():
    """A flag with no declared dimension would silently default to consistency.

    The dimension is the traceability link from the research framework to the
    data, so a false positive filed under consistency is a real defect, not
    bookkeeping.
    """
    from threatlens.quality.quality_checker import FLAG_DIMENSIONS

    for flag_type in MALFORMED_FLAGS | SCREENED_FLAGS:
        assert flag_type in FLAG_DIMENSIONS, f"{flag_type} has no dimension"

    dimensions = {"timeliness", "accuracy", "completeness", "relevance",
                  "consistency"}
    for flag_type, (dimension, severity) in FLAG_DIMENSIONS.items():
        assert dimension in dimensions, f"{flag_type} -> unknown {dimension}"
        assert severity in {"error", "warning", "info"}


def test_severity_agrees_with_what_the_checker_did():
    """error means discarded, warning means stored and screened.

    A finding that keeps an indicator must not be recorded as an error.
    """
    from threatlens.quality.quality_checker import FLAG_DIMENSIONS, make_issue

    for flag_type in MALFORMED_FLAGS:
        assert FLAG_DIMENSIONS[flag_type][1] == "error"

    for flag_type in SCREENED_FLAGS:
        assert FLAG_DIMENSIONS[flag_type][1] == "warning"
        # Screening answers the client's false-positive issue.
        assert make_issue(flag_type, "x").dimension == "accuracy"


def test_relevance_matches_the_reader_to_the_report():
    """A naming-convention document is for a CISO; a hash list is for an analyst."""
    from threatlens.quality.quality_checker import ViewerRole, score_relevance

    bands = POLICY.relevance_bands_match_pct
    strategic_doc, tactical_doc = 0.01, 0.99

    assert score_relevance(strategic_doc, ViewerRole.STRATEGIC, bands) == 5
    assert score_relevance(strategic_doc, ViewerRole.TACTICAL, bands) == 1
    assert score_relevance(tactical_doc, ViewerRole.TACTICAL, bands) == 5
    assert score_relevance(tactical_doc, ViewerRole.STRATEGIC, bands) == 1


def test_a_mixed_report_half_serves_both_roles():
    from threatlens.quality.quality_checker import ViewerRole, score_relevance

    bands = POLICY.relevance_bands_match_pct
    assert score_relevance(0.5, ViewerRole.STRATEGIC, bands) == 3
    assert score_relevance(0.5, ViewerRole.TACTICAL, bands) == 3


def test_relevance_is_neutral_until_a_role_is_chosen():
    """The stored score cannot assume a reader; the dashboard recomputes it."""
    from threatlens.quality.quality_checker import ViewerRole, score_relevance

    bands = POLICY.relevance_bands_match_pct
    for profile in (0.0, 0.5, 1.0):
        assert score_relevance(profile, ViewerRole.ANY, bands) == 3


def test_consistency_is_no_longer_scored():
    assert "consistency" not in POLICY.weights
    assert abs(sum(POLICY.weights.values()) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Quality bracket - verbal grade for a 0-100 quality_score
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected",
    [
        (100, "Actionable"),
        (85, "Actionable"),
        (84, "Reliable"),
        (75, "Reliable"),
        (74, "Usable"),
        (65, "Usable"),
        (64, "Marginal"),
        (50, "Marginal"),
        (49, "Unreliable"),
        (0, "Unreliable"),
    ],
)
def test_grade_quality_score_bands(score, expected):
    assert grade_quality_score(score, POLICY.quality_bands) == expected


def test_grade_quality_score_of_none_is_none():
    """An unscored candidate (rejected or context) has no bracket to report."""
    assert grade_quality_score(None, POLICY.quality_bands) is None


def test_grade_quality_score_uses_whatever_bands_the_policy_carries():
    custom_bands = {90: "Excellent", 0: "Needs work"}
    assert grade_quality_score(95, custom_bands) == "Excellent"
    assert grade_quality_score(10, custom_bands) == "Needs work"


def test_empty_run_is_rejected():
    with pytest.raises(ValueError, match="at least one"):
        check_report([])


def test_run_with_no_candidates_produces_an_empty_report():
    empty = ExtractionRun(
        verification_model="qwen3.5:4b",
        metadata={"publish_date": "2026-08-01"},
        summary={},
        candidates=(),
    )
    report = check_report([empty], policy=POLICY, now=NOW)
    assert report.assessments == []
    assert report.scored_rows() == []
    assert report.summary()["mean_quality_score"] is None
