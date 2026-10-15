"""The Python-only engine shares the LLM engine's front end and must not crash on odd values."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.extractors import ioc_extract_llm_fs as llm
from threatlens.extractors import ioc_extract_python as py

# A synthetic report, so the PDF path is covered without shipping third-party
# CTI reports. Covers each common indicator type, defanged forms, a hash and
# benign values the extractors must still see as candidates.
SYNTHETIC_PDF_PAGES = [
    """Operation Example: Technical Analysis
Published 2026-10-01 by the ThreatLens test team

Executive summary
The actor delivered a loader by phishing email from billing@invoices-example[.]com.
The loader beacons to hxxps://update-check[.]example-c2[.]net/api/v2/ping and to
198.51.100.23 on port 8443.
""",
    """Indicators of Compromise

Domains: example-c2[.]net, cdn.files-example[.]org
IP addresses: 198.51.100.23, 203.0.113.77
SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
MD5: 098f6bcd4621d373cade4e832627b4f6
File: C:\\Users\\Public\\updater.exe
CVE-2021-44228 was exploited for initial access.

References: https://www.example.com/blog/operation-example
""",
]


@pytest.fixture(scope="module")
def synthetic_pdf(tmp_path_factory: pytest.TempPathFactory) -> Path:
    pymupdf = pytest.importorskip("pymupdf")
    path = tmp_path_factory.mktemp("pdf") / "synthetic_report.pdf"
    document = pymupdf.open()
    for text in SYNTHETIC_PDF_PAGES:
        document.new_page().insert_text((50, 72), text, fontsize=9)
    document.save(path)
    document.close()
    return path

# Markdown-escaped defang, as seen in report cc5d8d13...: an unrefanged
# "\[.\]" used to reach urlparse and raise "Invalid IPv6 URL".
ESCAPED_DEFANG_REPORT = """\
Indicators of Compromise

The loader downloads its payload from
https://chubrik\\[.\\]sbs/files/xK7mR9pL2nQw5tY8/ygvfuyze.dll
and beacons to momasites\\[.\\]lol.
"""


def test_engines_share_one_domain_model() -> None:
    # The verifier compares with `is IndicatorType.X`; a second copy of the
    # enums would make every comparison silently false.
    assert py.IndicatorType is llm.IndicatorType
    assert py.Extraction is llm.Extraction
    assert py.CTIExtractor is llm.CTIExtractor


def test_engines_extract_identical_candidates(synthetic_pdf: Path) -> None:
    llm_result = llm.analyse_document(synthetic_pdf, verify=False)
    py_result = py.analyse_document(synthetic_pdf)
    assert llm_result.items, "the synthetic report should yield candidates"
    assert [i.extraction.stable_id for i in py_result.items] == [
        i.extraction.stable_id for i in llm_result.items
    ]


def test_escaped_defang_is_refanged_and_does_not_crash(tmp_path: Path) -> None:
    report = tmp_path / "report.txt"
    report.write_text(ESCAPED_DEFANG_REPORT, encoding="utf-8")

    result = py.analyse_document(report)

    values = {(i.extraction.indicator_type.value, i.extraction.normalized_value) for i in result.items}
    assert ("url", "https://chubrik.sbs/files/xK7mR9pL2nQw5tY8/ygvfuyze.dll") in values
    assert ("domain", "momasites.lol") in values


def test_url_host_tolerates_malformed_urls() -> None:
    assert py._url_host("https://chubrik\\[.\\]sbs/x.dll") == ""
    assert py._url_host("https://Example.COM./path") == "example.com"
