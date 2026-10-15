"""Tests for the database conformance layer.

The confidence tests exist because int(0.96 * 100) commits a valid-looking 0
into a CHECK-constrained column. That failure is invisible at insert time, so
it is pinned here instead.

The quality-checker regressions that used to live at the bottom of this file
moved to test_quality_checker.py when Qualtiy_Checker.py was replaced. Their
intent is preserved there against the new API.
"""

import json

import pytest

from threatlens.db import conformance

# ---------------------------------------------------------------------------
# Confidence conversion
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "unit_value, expected",
    [(0.0, 0), (0.29, 29), (0.62, 62), (0.96, 96), (0.99, 99), (1.0, 100)],
)
def test_confidence_from_unit_interval(unit_value, expected):
    assert conformance.confidence_from_unit_interval(unit_value) == expected


def test_confidence_rounds_rather_than_truncates():
    """0.29 * 100 is 28.999999999999996 in binary floating point."""
    assert int(0.29 * 100) == 28
    assert conformance.confidence_from_unit_interval(0.29) == 29


@pytest.mark.parametrize("bad", [96, 1.5, -0.1, True, "0.9", None, float("nan")])
def test_confidence_refuses_ambiguous_input(bad):
    with pytest.raises(conformance.ConformanceError):
        conformance.confidence_from_unit_interval(bad)


def test_confidence_result_is_int_not_float():
    """SQLite is loosely typed; a float here would store 96.0 in an INTEGER."""
    result = conformance.confidence_from_unit_interval(0.96)
    assert isinstance(result, int) and not isinstance(result, bool)


# ---------------------------------------------------------------------------
# Indicator type vocabulary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "indicator_type, attributes, expected",
    [
        ("ip", {"ip_version": 4}, "ipv4"),
        ("ip", {"ip_version": 6}, "ipv6"),
        ("hash", {"algorithm": "sha256"}, "sha256"),
        ("hash", {"algorithm": "md5"}, "md5"),
        ("domain", {}, "domain"),
        ("registry", {}, "registry_key"),
    ],
)
def test_to_ioc_type(indicator_type, attributes, expected):
    assert conformance.to_ioc_type(indicator_type, attributes) == expected


def test_ip_without_version_is_refused():
    """'ip' would never match the allowlist, which is seeded under 'ipv4'."""
    with pytest.raises(conformance.ConformanceError):
        conformance.to_ioc_type("ip", {})


def test_intelligence_entities_are_context_only():
    assert conformance.is_context_only("malware")
    with pytest.raises(conformance.ConformanceError):
        conformance.to_ioc_type("campaign", {})


# ---------------------------------------------------------------------------
# Row building and validation
# ---------------------------------------------------------------------------

SAMPLE_EXTRACTION = {
    "category": "network",
    "indicator_type": "ip",
    "value": "45.76.42[.]205",
    "normalized_value": "45.76.42.205",
    "context": "Network activity shows contact with 45.76.42.205",
    "method": "regex:ipv4",
    "attributes": {"ip_version": 4, "is_private": False},
}


def test_from_extraction_produces_valid_row():
    row = conformance.from_extraction(SAMPLE_EXTRACTION)

    assert row["ioc_type"] == "ipv4"
    assert row["normalised"] == "45.76.42.205"
    assert row["confidence"] is None  # extractor no longer supplies this
    json.loads(row["context"])  # must satisfy the json_valid() CHECK
    conformance.validate_indicator_row(row)


def test_validate_rejects_out_of_range_score():
    row = conformance.from_extraction(SAMPLE_EXTRACTION)
    row["quality_score"] = 150
    with pytest.raises(conformance.ConformanceError):
        conformance.validate_indicator_row(row)


def test_validate_rejects_unserialised_context():
    row = conformance.from_extraction(SAMPLE_EXTRACTION)
    row["context"] = {"not": "json text"}
    with pytest.raises(conformance.ConformanceError):
        conformance.validate_indicator_row(row)


def test_to_json_text_does_not_double_encode():
    encoded = conformance.to_json_text('{"a": 1}')
    assert json.loads(encoded) == {"a": 1}


def test_to_iso8601_is_utc():
    assert conformance.to_iso8601("2026-07-24T10:35:54").endswith("Z")


# ---------------------------------------------------------------------------
# Document identity
# ---------------------------------------------------------------------------

VALID_SHA256 = "defdca07fba39225ce3df8dff7ce82d04f222f6145f2ec0f506eb41272f149df"


def test_document_sha256_normalises_case_and_whitespace():
    """Two spellings of one digest would otherwise store the report twice."""
    assert conformance.document_sha256(f"  {VALID_SHA256.upper()}  ") == VALID_SHA256


@pytest.mark.parametrize("bad", [
    "",
    "abc123",
    VALID_SHA256[:-1],
    VALID_SHA256 + "0",
    "g" * 64,
])
def test_document_sha256_rejects_malformed_digests(bad):
    with pytest.raises(conformance.ConformanceError):
        conformance.document_sha256(bad)


def test_document_sha256_rejects_non_strings():
    with pytest.raises(conformance.ConformanceError, match="must be a string"):
        conformance.document_sha256(None)


