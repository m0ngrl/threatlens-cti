"""
ThreatLens - indicator quality checker.
Database schema v1.5 (SQLite)
ZEIT3118 Capstone Project

Consumes the output of the extraction engine (ioc_extract_python.py and
ioc_extract_llm_fs.py) - in memory via run_from_payload(), or as JSON via
load_run() - answers the three quality issues named in the client's
brief - duplication, missing context, and likely false positives - and scores
what survives against the five-dimension framework from the research paper's
Table 7.

Four layers, run in order:

    Layer 1  structural rejection   span overlap, nested values, sentence
                                    fragments, trailing punctuation, length
                                    bounds, technique idioms, self-reference
    Layer 2  STIX 2.1 conformance   is this candidate an SCO (an observable,
                                    and so an indicator) or an SDO (context)?
    Layer 3  false-positive screen  allowlist matching, via allowlist.py
    Layer 4  dimension scoring      timeliness, accuracy, completeness,
                                    relevance -> quality_score (consistency
                                    is not scored; see the divergences below)

Layers 1-3 answer the client's three named issues directly; Layer 4 turns what
survives into the research-grounded score.

Verifier reconciliation
-----------------------
The extraction engine has two engines over the *same* regex candidate set:
python heuristics and a Qwen LLM. Neither extracts, so both see identical
candidates with identical offsets; only the verification verdict differs.
An ingest runs one engine, so its runs are graded single_verifier; the two
verdicts are only compared when this module's CLI is given both (--compare).

On the reference sample the two agree on 12 of 39 candidates, and *no candidate
at all is confirmed by both* - intersecting them would empty the repository.
The policy implemented here is therefore structure-first:

    1. Layers 1-2 reject on structural and STIX grounds regardless of what
       either verifier said. On the reference sample this removes all five
       strong contradictions without consulting a verifier at all.
    2. Among what survives, the LLM verdict wins.
    3. The *grade* of the disagreement discounts the verdict's
       maliciousness (ScoringPolicy.agreement_multipliers), and the result
       becomes indicators.confidence.

Well-formed observables are flagged, never discarded: a report genuinely
mentioning a value is a fact about that report, so a screened candidate is
stored with its flag. A candidate rejected as malformed or non-STIX is not an
observable at all; it gets no row and no stored flag, and appears only in
QualityReport (and so in the CLI's JSON output).

Two scores, two meanings
------------------------
    indicators.confidence     certainty the indicator is malicious (STIX)
    indicators.quality_score  fitness of the indicator as data

Both are 0-100 and they are not interchangeable.

A caution on the extractor's own confidence
-------------------------------------------
`verification.confidence` is confidence *in the verdict*, not in maliciousness.
The python verifier rejects at 0.98 (very sure it is not an IoC); the LLM
emits 0.0 for every rejection. Feeding either straight into
indicators.confidence would be wrong, so verdict confidence is translated
through maliciousness_from_verdict() first.

Naming collision
----------------
The extractor's per-candidate "context" is a free-text excerpt; the schema's
indicators.context is a structured JSON dict. They are not the same thing. The
excerpt goes to sightings.excerpt; the structured dict is built here from the
document's surviving SDO entities - see build_document_context().

Divergences from the paper, which must stay documented
------------------------------------------------------
    completeness  the paper measures the % of the STIX construction graph
                  completed. ThreatLens does not build that graph, so it
                  measures the proportion of expected context fields
                  populated instead.
    consistency   the paper measures antivirus detection rate, which needs
                  enrichment APIs (out of scope). ThreatLens does not score
                  it; consistency-type findings are still recorded as flags,
                  and agreement still discounts confidence. To be added once
                  a feed such as MISP or VirusTotal supplies data.
    accuracy      the paper counts corroborating sources; ThreatLens reads
                  source reliability instead - see score_accuracy().

Deliberately not built
----------------------
No STIX graph, no enrichment lookups, no inter-indicator relationships, no
threat-actor modelling. Alias handling is limited to a configurable lookup
used for entity *counting* only (see ScoringPolicy.alias_groups); resolving
actors properly is OpenCTI territory and stays out of scope.

Usage
-----
    python -m threatlens.quality.quality_checker llm.json --compare python.json
    python -m threatlens.quality.quality_checker llm.json -o report.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threatlens.db import conformance
from threatlens.quality.allowlist import AllowlistEntry, match_allowlist

# ===========================================================================
# Vocabularies
# ===========================================================================


class Verdict(str, Enum):
    """The four verification statuses the extraction engine emits.

    threatlens.md documents only confirmed/rejected/uncertain; context_entity
    is the fourth and, on the reference sample, the most common verdict the
    python verifier returns.
    """

    CONFIRMED = "confirmed_ioc"
    CONTEXT = "context_entity"
    UNCERTAIN = "uncertain"
    REJECTED = "rejected"


class Agreement(str, Enum):
    """How badly the two verifiers disagree about one candidate.

    Grading matters. On the reference sample every valid SHA-256 sits in a
    weak disagreement (python hedges "uncertain", the LLM confirms), so
    penalising a weak disagreement as heavily as a strong one would flag every
    good hash in the data.
    """

    AGREE = "agree"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    SINGLE = "single_verifier"


class StixKind(str, Enum):
    """STIX 2.1 classification of an extractor candidate.

    SCO   a Cyber-observable Object - becomes a row in indicators
    SDO   a Domain Object - describes indicators, becomes context
    NONE  not a legal STIX type as extracted - rejected
    """

    SCO = "sco"
    SDO = "sdo"
    NONE = "none"


class ViewerRole(str, Enum):
    """Who is reading the intelligence, which is what relevance is scored against.

    A CTI report is written for an audience. A threat-actor naming convention
    is for a CISO deciding policy; a list of ninety file hashes is for the
    analyst hunting them. Neither is "better" - relevance asks how well this
    report matches the person in front of it, so the same report is highly
    relevant to one role and nearly useless to the other.

    ANY is the stored default: no role has been chosen yet, so relevance sits
    at the neutral band and the dashboard recomputes it once the reader picks.
    """

    STRATEGIC = "strategic"      # CISO, CEO, executive
    TACTICAL = "tactical"        # security analyst, DFIR examiner
    ANY = "any"                  # no role selected


class Decision(str, Enum):
    """What the checker concluded about a candidate.

    SCREENED and REJECTED are both "not a malicious indicator", but they are
    not the same outcome and must not be collapsed:

        REJECTED  the text is not a well-formed observable at all - a sentence
                  fragment, a filename the regex read as a domain, a span
                  already covered by a better candidate. An extraction
                  artefact. Reported, but never written to indicators, because
                  storing it would pollute the repository with text that is
                  not an IoC in any sense.

        SCREENED  a well-formed observable that should not be treated as
                  malicious - a public DNS resolver, the report's own URL.
                  These *are* stored and flagged. A report genuinely
                  mentioning 8.8.8.8 is a fact about that report, and dropping
                  it would lose the sighting.
    """

    INDICATOR = "indicator"
    CONTEXT = "context"
    SCREENED = "screened"
    REJECTED = "rejected"


# Findings that mean the candidate is not a well-formed observable.
MALFORMED_FLAGS: frozenset[str] = frozenset({
    "span_overlap",
    "nested_value",
    "sentence_fragment",
    "trailing_punctuation",
    "length_bounds",
    "filename_as_domain",
    "duplicate_observable",
    "invalid_format",
    "not_stix_conformant",
    "unmapped_ioc_type",
})

# Findings that mean a well-formed observable is not malicious.
SCREENED_FLAGS: frozenset[str] = frozenset({
    "known_benign",
    "self_reference",
    "technique_idiom",
    "non_routable",
    "verifier_rejected",
    "benign_observable",
})


# The quality dimension each finding belongs to, and how serious it is.
#
# Every flag carries its dimension - that is the traceability link from the
# research framework back to the data - so this mapping is not bookkeeping.
# A false positive filed under consistency would be attributed to the wrong
# dimension in the report, and severity must agree with what the checker
# actually did: "error" means the candidate was discarded as malformed,
# "warning" means it was kept and screened, "info" means it was kept as an
# indicator with a caveat attached.
FLAG_DIMENSIONS: dict[str, tuple[str, str]] = {
    # Malformed: not a well-formed observable, so not stored.
    "span_overlap": ("consistency", "error"),
    "nested_value": ("consistency", "error"),
    "sentence_fragment": ("consistency", "error"),
    "trailing_punctuation": ("consistency", "error"),
    "length_bounds": ("consistency", "error"),
    "filename_as_domain": ("consistency", "error"),
    "duplicate_observable": ("consistency", "error"),
    "invalid_format": ("consistency", "error"),
    "not_stix_conformant": ("consistency", "error"),
    "unmapped_ioc_type": ("consistency", "error"),
    # Screened: well-formed, stored, but not malicious. These answer the
    # client's false-positive issue, which is an accuracy question - the same
    # dimension allowlist.py files known_benign under.
    "known_benign": ("accuracy", "warning"),
    "self_reference": ("accuracy", "warning"),
    "technique_idiom": ("accuracy", "warning"),
    "non_routable": ("accuracy", "warning"),
    "verifier_rejected": ("accuracy", "warning"),
    "benign_observable": ("accuracy", "warning"),
    # Kept, with a caveat recorded against it.
    "verifier_uncertain": ("consistency", "info"),
    # The value is real but transcribed short. Not "error": discarding it would
    # lose a genuine indicator over an extractor defect. Not "warning" either,
    # since that means screened-as-benign, which a truncated C2 path is not.
    "truncated_span": ("consistency", "info"),
}


def make_issue(flag_type: str, detail: str) -> QualityIssue:
    """Build a finding with the dimension and severity its type implies.

    Centralised so a new check cannot quietly file itself under the wrong
    dimension, and so severity always agrees with the decision the flag drives.
    """
    dimension, severity = FLAG_DIMENSIONS.get(flag_type, ("consistency", "warning"))
    return QualityIssue(
        flag_type=flag_type,
        dimension=dimension,
        detail=detail,
        severity=severity,
    )


# Extractor indicator_type -> the STIX 2.1 object it would become.
# Mirrors the Layer 2 table in threatlens.md. Types absent from both maps are
# flagged rather than silently accepted, so a new extractor type surfaces as a
# decision to make instead of passing through unexamined.
STIX_OBSERVABLES: dict[str, str] = {
    "hash": "file:hashes",
    "domain": "domain-name",
    "hostname": "domain-name",
    "email_domain": "domain-name",
    "url": "url",
    "ip": "ipv4-addr | ipv6-addr",
    "filepath": "file:name | directory:path",
    "filename": "file:name",
    "attachment": "file:name",
    "email_address": "email-addr",
    "email_subject": "email-message:subject",
    "email_header": "email-message:additional_header_fields",
    "registry": "windows-registry-key",
    "mutex": "mutex:name",
    "process": "process",
    "user_agent": "network-traffic:extensions.http-request-ext",
    "port": "network-traffic:dst_port",
    "certificate": "x509-certificate",
}

STIX_DOMAIN_OBJECTS: dict[str, str] = {
    "threat_actor": "threat-actor",
    "campaign": "campaign",
    "vulnerability": "vulnerability",
    "tool": "tool",
    "malware": "malware",
    "ttp": "attack-pattern",
    # Behaviour types describe a technique, not something observable.
    "persistence": "attack-pattern",
    "beaconing": "attack-pattern",
    "process_chain": "attack-pattern",
    "lateral_movement": "attack-pattern",
    "exfiltration": "attack-pattern",
}

# Extractor types with no legal STIX representation as extracted. "service" is
# emitted as a free-text span rather than a port/protocol pair, so it cannot
# form a pattern and is rejected outright.
STIX_UNMAPPED: frozenset[str] = frozenset({"service"})


# ===========================================================================
# Structural heuristics
# ===========================================================================

# Suffixes that look like a TLD but are not one. This is the backstop for the
# handful of code fragments the domain regex catches; the primary defence
# against ".php domains" is filename containment (see _filename_of_filepath),
# which needs no list at all.
NON_TLD_SUFFIXES: frozenset[str] = frozenset({
    "php", "js", "gif", "png", "jpg", "jpeg", "html", "htm", "asp", "aspx",
    "jsp", "css", "json", "xml", "txt", "exe", "dll", "bin", "dat", "log",
    "py", "sh", "bat", "ps1", "vbs", "jar", "zip", "rar", "doc", "docx",
    "xls", "xlsx", "pdf", "tmp", "bak", "conf", "ini", "yml", "yaml",
    # Attribute/method names the domain regex mistakes for hostnames, as in
    # "requests.get" from a code sample.
    "get", "post", "put", "head", "delete", "run", "read", "write", "open",
    "close", "append", "join", "split", "format", "encode", "decode",
})

# Words that betray a sentence fragment rather than an entity name.
FRAGMENT_STOPWORDS: frozenset[str] = frozenset({
    "the", "a", "an", "and", "or", "but", "as", "at", "by", "for", "from",
    "in", "into", "of", "on", "to", "with", "which", "that", "this", "these",
    "those", "is", "are", "was", "were", "be", "been", "being", "has", "have",
    "had", "it", "its", "their", "them", "they", "he", "she", "we", "you",
    "likely", "built", "send", "onward", "jump", "boxes", "distinct", "over",
})

# Shell and OS idioms that name a technique rather than an artefact.
TECHNIQUE_IDIOMS: frozenset[str] = frozenset({
    "/dev/tcp", "/dev/udp", "/dev/null", "/bin/sh", "/bin/bash", "cmd.exe",
    "powershell.exe", "/etc/passwd", "/etc/shadow",
})

# Longest a legitimate multi-word entity name runs, per STIX object kind.
# "Fancy Bear" is two words; "Operation RoundPress" is two. Anything longer is
# almost always a span the regex over-ran.
MAX_WORDS_SDO = 4
MAX_WORDS_SCO = 1

# Length bounds, chosen to keep a single character or a paragraph out of the
# indicators table without excluding any real IoC form.
MIN_VALUE_LENGTH = 3
MAX_VALUE_LENGTH = 512

_SENTENCE_BREAK = re.compile(r"[.,;:!?]\s")
_TRAILING_JUNK = re.compile(r"[\s\-–—_,;:!?'\"()\[\]{}]+$")
_WORD = re.compile(r"[A-Za-z0-9]+")
# Characters that continue a token, so finding one immediately before a value
# means the extractor's span started partway through it.
_TOKEN_CONTINUATION = re.compile(r"[A-Za-z0-9_.~@+-]")
_HEX = re.compile(r"^[a-f0-9]+$")
_EMAIL = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

HASH_LENGTHS: dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


# ===========================================================================
# Extractor output
# ===========================================================================


@dataclass(frozen=True, slots=True)
class Candidate:
    """One record from the extractor's `indicators` array.

    Kept as a thin view over the original mapping: `raw` is handed back to the
    ingest layer so the sighting can still record the excerpt and offsets that
    the derived indicator row does not carry.
    """

    candidate_id: str
    category: str
    indicator_type: str
    value: str
    normalized_value: str
    start: int | None
    end: int | None
    excerpt: str
    method: str
    attributes: Mapping[str, Any]
    status: Verdict | None
    verdict_confidence: float | None
    reason: str
    accepted: bool
    raw: Mapping[str, Any]

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> Candidate:
        verification = record.get("verification") or {}

        # corrected_indicator_type is the verifier's re-typing of a candidate
        # it thinks the regex mislabelled. The LLM uses it on the reference
        # sample; honour it, since it is the verifier's considered view.
        indicator_type = str(
            verification.get("corrected_indicator_type")
            or record.get("indicator_type")
            or ""
        ).strip().lower()
        category = str(
            verification.get("corrected_category") or record.get("category") or ""
        ).strip().lower()

        return cls(
            candidate_id=str(record.get("id") or ""),
            category=category,
            indicator_type=indicator_type,
            value=str(record.get("value") or ""),
            normalized_value=str(
                record.get("normalized_value") or record.get("value") or ""
            ),
            start=_as_optional_int(record.get("start")),
            end=_as_optional_int(record.get("end")),
            excerpt=str(record.get("context") or ""),
            method=str(record.get("method") or ""),
            attributes=dict(record.get("attributes") or {}),
            status=_as_verdict(verification.get("status")),
            verdict_confidence=_as_optional_float(verification.get("confidence")),
            reason=str(verification.get("reason") or ""),
            accepted=bool(record.get("accepted")),
            raw=record,
        )


@dataclass(frozen=True, slots=True)
class ExtractionRun:
    """One extractor JSON file: the metadata block plus its candidates."""

    verification_model: str
    metadata: Mapping[str, Any]
    summary: Mapping[str, Any]
    candidates: tuple[Candidate, ...]
    path: Path | None = None

    @property
    def is_llm(self) -> bool:
        """Whether this run was verified by the LLM rather than by heuristics."""
        return self.verification_model.strip().lower() != "python-heuristics"

    @property
    def label(self) -> str:
        return "llm" if self.is_llm else "python"


def run_from_payload(
    payload: Any,
    *,
    source: str = "<memory>",
    path: Path | None = None,
) -> ExtractionRun:
    """Build an ExtractionRun from extractor output already held in memory.

    This is the in-process handover the extraction engine is built for. An
    IoCExtractionResult can be passed straight in - no file written, no JSON
    round trip:

        result = analyse_document(pdf)          # IoCExtractionResult
        report = check_report([run_from_payload(result)])

    dashboard/ingest_worker.py does exactly this.

    Accepts, in order:

        * any object exposing .to_dict(), which is how IoCExtractionResult and
          the rest of the extractor's dataclasses expose themselves. Duck-typed
          on purpose - importing the extractor here would couple the quality
          checker to an engine that is still changing, and the checker only
          ever needs the mapping.
        * the current mapping shape
          {metadata, verification_model, summary, indicators[], ...}
        * the two older shapes the archived extractors produced (a flat list of
          records, or records grouped by category), so a teammate's older
          output still runs through the checker.

    `source` names the payload in error messages, since an in-memory run has no
    path to point at.
    """
    # to_dict() first: an extractor result object is not a Mapping, and calling
    # it here means callers never have to remember to.
    to_dict = getattr(payload, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()

    if isinstance(payload, list):
        records: list[Mapping[str, Any]] = [
            r for r in payload if isinstance(r, Mapping)
        ]
        return ExtractionRun(
            verification_model="unknown",
            metadata={},
            summary={},
            candidates=tuple(Candidate.from_record(r) for r in records),
            path=path,
        )

    if not isinstance(payload, Mapping):
        # ValueError, not TypeError: this is malformed input, and main()
        # catches ValueError to turn it into a clean exit code.
        raise ValueError(  # noqa: TRY004
            f"unexpected extractor payload in {source}: {type(payload).__name__}"
        )

    raw_indicators = payload.get("indicators")
    if isinstance(raw_indicators, list):
        records = [r for r in raw_indicators if isinstance(r, Mapping)]
    else:
        # Grouped-by-category form. accepted_by_category is skipped when
        # indicators[] is present, so a candidate is never counted twice.
        records = []
        for key, group in payload.items():
            if key == "accepted_by_category" or not isinstance(group, list):
                continue
            records.extend(r for r in group if isinstance(r, Mapping))

    return ExtractionRun(
        verification_model=str(payload.get("verification_model") or "unknown"),
        metadata=dict(payload.get("metadata") or {}),
        summary=dict(payload.get("summary") or {}),
        candidates=tuple(Candidate.from_record(r) for r in records),
        path=path,
    )


def load_run(path: Path | str) -> ExtractionRun:
    """Load one extractor JSON file.

    A thin wrapper over run_from_payload(), so the file and in-memory paths
    parse through the same code and cannot drift apart.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load extractor JSON {path}: {exc}") from exc

    return run_from_payload(data, source=str(path), path=path)


# ===========================================================================
# Quality issues
# ===========================================================================


@dataclass(frozen=True, slots=True)
class QualityIssue:
    """One finding, shaped so it can be written straight to quality_flags.

    Every issue carries its `dimension`. That is the traceability link from
    the research framework back to the data, and the reason quality_flags has
    the column at all.
    """

    flag_type: str
    dimension: str
    detail: str
    severity: str = "warning"

    def to_dict(self) -> dict[str, str]:
        return {
            "flag_type": self.flag_type,
            "dimension": self.dimension,
            "detail": self.detail,
            "severity": self.severity,
        }


# ===========================================================================
# Layer 1 - structural rejection
# ===========================================================================


def find_span_overlaps(
    candidates: Sequence[Candidate],
) -> dict[str, tuple[str, str]]:
    """Identify candidates whose character span is covered by a better one.

    Mechanical, and it needs no external data, which is why threatlens.md puts
    it first. Where two candidates overlap, the one covering more of the
    document wins: on the reference sample the filepath
    /actions/mail/get.php.php [6318:6343] beats the domain get.php.php
    [6332:6343] carved out of its tail.

    Returns {losing candidate_id: (winning candidate_id, detail)}.
    """
    spanned = [c for c in candidates if c.start is not None and c.end is not None]
    spanned.sort(key=lambda c: (c.start or 0, -(c.end or 0)))

    losers: dict[str, tuple[str, str]] = {}

    for i, first in enumerate(spanned):
        for second in spanned[i + 1:]:
            # Sorted by start, so once a candidate begins at or after this
            # one's end, nothing later can overlap it either.
            if (second.start or 0) >= (first.end or 0):
                break

            longer, shorter = _wider_span(first, second)
            if shorter.candidate_id in losers:
                continue
            losers[shorter.candidate_id] = (
                longer.candidate_id,
                (
                    f"span [{shorter.start}:{shorter.end}] "
                    f"{shorter.indicator_type} {shorter.value!r} overlaps "
                    f"[{longer.start}:{longer.end}] {longer.indicator_type} "
                    f"{longer.value!r}"
                ),
            )

    return losers


def _wider_span(a: Candidate, b: Candidate) -> tuple[Candidate, Candidate]:
    width_a = (a.end or 0) - (a.start or 0)
    width_b = (b.end or 0) - (b.start or 0)
    return (a, b) if width_a >= width_b else (b, a)


def _spans_overlap(a: Candidate, b: Candidate) -> bool:
    if None in (a.start, a.end, b.start, b.end):
        return False
    return (a.start or 0) < (b.end or 0) and (b.start or 0) < (a.end or 0)


def find_nested_values(
    candidates: Sequence[Candidate],
) -> dict[str, tuple[str, str]]:
    """Identify candidates whose value strictly contains a cleaner sibling.

    The opposite tie-break to span overlap, and deliberately so. Overlapping
    *spans* mean two readings of the same text, where the fuller reading is
    usually right. A nested *value* means the same entity was captured once
    cleanly and once with the sentence around it: "RoundPress" versus
    "RoundPress -" versus "RoundPress blog in May 2025. Proofpoint". There the
    shortest form is the entity and the rest is over-run.

    Candidates whose spans overlap are left alone, because the two rules
    disagree by design and span overlap is the one that is right about them:
    /actions/mail/get.php.php and the get.php.php carved out of its tail are
    nested by value but overlapping by span, and letting the shorter win there
    would discard the real filepath and keep the fragment.

    Returns {losing candidate_id: (winning candidate_id, detail)}.
    """
    losers: dict[str, tuple[str, str]] = {}

    by_type: dict[str, list[Candidate]] = {}
    for candidate in candidates:
        by_type.setdefault(candidate.indicator_type, []).append(candidate)

    for siblings in by_type.values():
        # Shortest first, so the cleanest form is always the winner recorded.
        ordered = sorted(siblings, key=lambda c: len(c.normalized_value))
        for i, short in enumerate(ordered):
            if not short.normalized_value:
                continue
            for long in ordered[i + 1:]:
                if long.candidate_id in losers or _spans_overlap(short, long):
                    continue
                if short.normalized_value in long.normalized_value:
                    losers[long.candidate_id] = (
                        short.candidate_id,
                        (
                            f"{long.value!r} contains the shorter candidate "
                            f"{short.value!r} of the same type"
                        ),
                    )

    return losers


def is_sentence_fragment(value: str, stix_kind: StixKind) -> str | None:
    """Return why this value reads as prose, or None if it looks like a name.

    Three signals, any of which is enough:

      * an internal sentence break - "GRU. At the"
      * more words than an entity name carries
      * a stopword, which no IoC and no actor name contains

    The word bound is looser for SDOs because "Fancy Bear" and "Operation
    RoundPress" are legitimate two-word names, while an observable is a single
    token.
    """
    text = value.strip()
    if not text:
        return "value is empty"

    if _SENTENCE_BREAK.search(text):
        return "contains a sentence break, so the span over-ran the entity"

    words = _WORD.findall(text)
    limit = MAX_WORDS_SDO if stix_kind is StixKind.SDO else MAX_WORDS_SCO

    # Observables that legitimately contain separators are counted as one token.
    if stix_kind is StixKind.SCO and _looks_like_single_token(text):
        return None

    if len(words) > limit:
        return f"{len(words)} words exceeds the {limit}-word bound for a name"

    lowered = {w.lower() for w in words}
    intruder = lowered & FRAGMENT_STOPWORDS
    if intruder and len(words) > 1:
        return f"contains prose word(s) {sorted(intruder)!r}"

    return None


def _looks_like_single_token(text: str) -> bool:
    """Whether this is one unbroken observable rather than several words."""
    return " " not in text.strip()


def has_trailing_punctuation(value: str) -> str | None:
    """Return why the value ends in junk, or None. Catches 'RoundPress -'."""
    stripped = _TRAILING_JUNK.sub("", value)
    if stripped != value.rstrip():
        return f"trailing punctuation; {value!r} should be {stripped!r}"
    return None


def is_truncated_span(value: str, excerpt: str) -> str | None:
    """Return what the extractor's span lost off the front of the value, or None.

    A regex anchored on a leading character can start matching partway through
    a token. The filepath rule requires a leading '/', so on the reference
    sample it captured '/js/list.js.php' out of 'program/js/list.js.php' - a
    different path from the one the report published, and one a defender
    searching for it would never hit.

    The extractor's own excerpt is the evidence: if every occurrence of the
    value inside it is preceded by a character that continues the token, the
    span began mid-token. Requiring *every* occurrence keeps a value that also
    appears cleanly elsewhere in the window from being flagged.

    Reports rather than repairs. The extracted value belongs to the extraction
    engine, so this records the discrepancy and the likely full value for a
    human, instead of silently rewriting evidence.
    """
    value = value.strip()
    if len(value) < MIN_VALUE_LENGTH or not excerpt:
        return None

    lost_prefixes: list[str] = []
    index = excerpt.find(value)

    while index != -1:
        if index == 0 or not _TOKEN_CONTINUATION.match(excerpt[index - 1]):
            return None  # at least one clean occurrence, so the span is fine

        start = index
        while start > 0 and _TOKEN_CONTINUATION.match(excerpt[start - 1]):
            start -= 1
        lost_prefixes.append(excerpt[start:index])

        index = excerpt.find(value, index + 1)

    if not lost_prefixes:
        return None

    lost = lost_prefixes[0]
    return (
        f"span started mid-token: {lost!r} was dropped, so the value is "
        f"{value!r} where the report says {lost + value!r}"
    )


def is_out_of_bounds(value: str) -> str | None:
    """Return why the value's length disqualifies it, or None."""
    length = len(value.strip())
    if length < MIN_VALUE_LENGTH:
        return f"length {length} is below the {MIN_VALUE_LENGTH}-character floor"
    if length > MAX_VALUE_LENGTH:
        return f"length {length} exceeds the {MAX_VALUE_LENGTH}-character ceiling"
    return None


def is_technique_idiom(value: str) -> str | None:
    """Return why this value names a technique rather than an artefact.

    /dev/tcp is a bash redirection idiom, not a file an analyst should block.
    """
    if value.strip().lower() in TECHNIQUE_IDIOMS:
        return f"{value!r} is a technique idiom, not an observable artefact"
    return None


def is_self_reference(value: str, metadata: Mapping[str, Any]) -> str | None:
    """Return why this value is the report describing itself, or None.

    A report's own URL is not intelligence it is reporting, and neither is the
    vendor domain it was published on. Both appear as extracted "IoCs" in the
    reference sample.
    """
    candidate = value.strip().lower()
    if not candidate:
        return None

    own_urls = [
        str(metadata.get(key) or "").strip().lower()
        for key in ("source_url", "cti_source")
    ]
    own_hosts = {_host_of(u) for u in own_urls if u}
    own_hosts.discard("")

    if candidate in {u for u in own_urls if u}:
        return "value is the report's own source URL"

    candidate_host = _host_of(candidate) or candidate
    for host in own_hosts:
        if candidate_host == host or candidate_host.endswith("." + host):
            return f"value resolves to the publishing domain {host!r}"

    return None


def _host_of(url: str) -> str:
    try:
        parsed = urlparse(url if "//" in url else f"//{url}")
    except ValueError:
        return ""
    return (parsed.hostname or "").lower()


# ===========================================================================
# Layer 2 - STIX 2.1 conformance
# ===========================================================================


def classify_stix(indicator_type: str) -> tuple[StixKind, str]:
    """Classify an extractor type as an SCO, an SDO, or neither.

    This is the principled resolution of the type-vocabulary problem: rather
    than arguing about which extractor types "count", ask whether the value
    could form a legal STIX pattern. Something that cannot is not an
    observable, whatever the regex named it.
    """
    key = indicator_type.strip().lower()

    if key in STIX_OBSERVABLES:
        return StixKind.SCO, STIX_OBSERVABLES[key]
    if key in STIX_DOMAIN_OBJECTS:
        return StixKind.SDO, STIX_DOMAIN_OBJECTS[key]
    if key in STIX_UNMAPPED:
        return StixKind.NONE, ""

    return StixKind.NONE, ""


def format_valid(indicator_type: str, value: str) -> tuple[bool, str]:
    """Whether a value can populate its STIX observable property.

    Raises the consistency-dimension invalid_format flag (the dimension
    itself is not scored), and is the second Layer 2 gate: a type that maps to an SCO still has to produce a
    legal value for it.

    Returns (ok, reason). reason is empty when ok.
    """
    key = indicator_type.strip().lower()
    candidate = value.strip()

    if key == "hash":
        digest = candidate.replace(":", "").lower()
        if not _HEX.fullmatch(digest):
            return False, "hash is not hexadecimal"
        if len(digest) not in HASH_LENGTHS:
            return False, f"length {len(digest)} is not a known digest size"
        return True, ""

    if key == "ip":
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return False, "not a valid IP address"
        # Routability is deliberately *not* checked here. 10.0.0.1 is a
        # perfectly well-formed ipv4-addr; that it cannot be a public C2 is a
        # false-positive question, answered by is_non_routable() at Layer 3.
        return True, ""

    if key == "url":
        try:
            parsed = urlparse(candidate)
        except ValueError:
            return False, "malformed URL"
        if parsed.scheme not in {"http", "https"}:
            return False, f"scheme {parsed.scheme!r} is not http/https"
        if not parsed.netloc:
            return False, "URL has no host"
        return True, ""

    if key in {"domain", "hostname", "email_domain"}:
        return _domain_valid(candidate)

    if key == "email_address":
        if not _EMAIL.fullmatch(candidate):
            return False, "not a valid email address"
        return True, ""

    if key in {"filepath", "filename", "attachment"}:
        if not candidate or candidate.isspace():
            return False, "empty path"
        return True, ""

    # No agreed syntax for the remaining types yet, so they are not failed on
    # format. Absence of a rule is not evidence of a defect.
    return True, ""


def _domain_valid(value: str) -> tuple[bool, str]:
    """Whether a value is a legal STIX domain-name.

    RFC 1123 label syntax, plus a plausible top-level label. The TLD test is
    what removes "requests.get"; the ".php filenames" are caught earlier and
    more cheaply by filename containment.
    """
    candidate = value.strip().lower().rstrip(".")
    if not candidate or len(candidate) > 253:
        return False, "domain is empty or over 253 characters"

    labels = candidate.split(".")
    if len(labels) < 2:
        return False, "domain has no top-level label"

    for label in labels:
        if not _DOMAIN_LABEL.fullmatch(label):
            return False, f"label {label!r} is not a legal DNS label"

    tld = labels[-1]
    if tld.isdigit():
        return False, "top-level label is numeric"
    if tld in NON_TLD_SUFFIXES:
        return False, f"{tld!r} is a file or method suffix, not a TLD"

    return True, ""


def find_filename_collisions(
    candidates: Sequence[Candidate],
) -> dict[str, tuple[str, str, str]]:
    """Identify candidates that are really the basename of a sibling filepath.

    Two defects share one mechanism, and both are visible on the reference
    sample:

    * The domain regex treats .php as a TLD, so program/js/list.js.php yields
      a filepath *and* a domain "list.js.php". Comparing against the filepath
      candidates in the same document settles it with no TLD list at all: if
      the value is exactly the last component of a filepath the extractor also
      found, it is a filename, not a host. This catches all four .php
      pseudo-domains, including the three whose spans never overlap their
      filepath and so escape find_span_overlaps().

    * The same basename extracted separately as a bare filename is the same
      underlying observable stored twice - duplication, the first of the three
      quality issues the client named. The filepath is the more complete
      record, so it wins.

    Returns {losing candidate_id: (winning candidate_id, flag_type, detail)}.
    """
    owners: dict[str, Candidate] = {}
    for candidate in candidates:
        if candidate.indicator_type != "filepath":
            continue
        name = _filename_of_filepath(candidate.normalized_value)
        # A bare filename extracted as a filepath owns nothing; it *is* the
        # basename, so treating it as an owner would reject its own twin.
        if name and name != candidate.normalized_value.strip().lower():
            owners.setdefault(name, candidate)

    losers: dict[str, tuple[str, str, str]] = {}
    for candidate in candidates:
        owner = owners.get(candidate.normalized_value.strip().lower())
        if owner is None or owner.candidate_id == candidate.candidate_id:
            continue

        if candidate.indicator_type in {"domain", "hostname"}:
            losers[candidate.candidate_id] = (
                owner.candidate_id,
                "filename_as_domain",
                (
                    f"{candidate.value!r} is the filename of the filepath "
                    f"{owner.value!r}, not a domain"
                ),
            )
        elif candidate.indicator_type in {"filename", "attachment", "filepath"}:
            losers[candidate.candidate_id] = (
                owner.candidate_id,
                "duplicate_observable",
                (
                    f"{candidate.value!r} is the basename of the filepath "
                    f"{owner.value!r} already extracted from this report"
                ),
            )

    return losers


def _filename_of_filepath(path: str) -> str:
    return path.strip().lower().replace("\\", "/").rstrip("/").rpartition("/")[2]


# ===========================================================================
# Layer 3 - false-positive screening
# ===========================================================================


def is_non_routable(indicator_type: str, value: str) -> str | None:
    """Return why an address cannot be attacker infrastructure, or None.

    The complement to the allowlist: rather than a list of known-benign
    values, this is the set that cannot be malicious by construction -
    RFC 1918 private space, loopback, link-local, and the RFC 5737
    documentation ranges that appear in write-ups as example addresses.

    A false positive, not a malformed value, so the indicator is stored and
    flagged rather than discarded.
    """
    if indicator_type.strip().lower() != "ip":
        return None

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None  # malformed, which format_valid() already reported

    if address.is_loopback:
        return f"{value} is a loopback address"
    if address.is_link_local:
        return f"{value} is link-local"
    if address.is_private:
        # is_private covers RFC 1918 and, in Python 3.12+, the RFC 5737
        # documentation ranges used for examples in reports.
        return f"{value} is private, reserved or documentation-range space"
    if address.is_multicast:
        return f"{value} is multicast"

    return None


# ===========================================================================
# Verifier agreement
# ===========================================================================

# How far apart two verdicts are. Keyed by the unordered pair, so the table is
# read the same way regardless of which verifier said what.
_AGREEMENT_GRADES: dict[frozenset[Verdict], Agreement] = {
    # A hedge against a commitment. The weakest form of disagreement, and the
    # most common: on the reference sample it covers every valid SHA-256.
    frozenset({Verdict.UNCERTAIN, Verdict.CONFIRMED}): Agreement.WEAK,
    frozenset({Verdict.UNCERTAIN, Verdict.CONTEXT}): Agreement.WEAK,
    frozenset({Verdict.UNCERTAIN, Verdict.REJECTED}): Agreement.WEAK,
    # Both verifiers agree the value is not an observable; they differ on
    # whether it is worth keeping as context.
    frozenset({Verdict.CONTEXT, Verdict.REJECTED}): Agreement.MODERATE,
    # A typing conflict: observable or descriptive? Both still accept it.
    frozenset({Verdict.CONTEXT, Verdict.CONFIRMED}): Agreement.MODERATE,
    # A flat contradiction: an indicator, or noise?
    frozenset({Verdict.CONFIRMED, Verdict.REJECTED}): Agreement.STRONG,
}


@dataclass(frozen=True, slots=True)
class VerifierComparison:
    """How the two verifiers judged one candidate, and what that implies."""

    candidate_id: str
    python_status: Verdict | None
    llm_status: Verdict | None
    python_confidence: float | None
    llm_confidence: float | None
    agreement: Agreement
    winner: str
    winning_status: Verdict | None
    confidence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "python_status": _verdict_name(self.python_status),
            "llm_status": _verdict_name(self.llm_status),
            "python_confidence": self.python_confidence,
            "llm_confidence": self.llm_confidence,
            "agreement": self.agreement.value,
            "winner": self.winner,
            "winning_status": _verdict_name(self.winning_status),
            "confidence": self.confidence,
        }


def grade_agreement(
    python_status: Verdict | None,
    llm_status: Verdict | None,
) -> Agreement:
    """Grade how far apart two verdicts are."""
    if python_status is None or llm_status is None:
        return Agreement.SINGLE
    if python_status is llm_status:
        return Agreement.AGREE
    return _AGREEMENT_GRADES.get(
        frozenset({python_status, llm_status}), Agreement.MODERATE
    )


def maliciousness_from_verdict(
    status: Verdict | None,
    verdict_confidence: float | None,
) -> float | None:
    """Translate a verdict plus its confidence into 0.0-1.0 maliciousness.

    The extractor's confidence is confidence *in the verdict*, so it cannot be
    used directly. The python verifier rejects at 0.98 - very sure the value is
    *not* an IoC - while the LLM emits 0.0 for every rejection. Reading either
    as "how malicious is this" would invert the first and discard the second.

    Returns None when the verdict makes no claim about maliciousness at all,
    which is the honest answer for a context entity.
    """
    if status is None:
        return None

    if status is Verdict.CONFIRMED:
        # Confidence in "this is an IoC" is confidence it is malicious.
        return verdict_confidence if verdict_confidence is not None else 0.5

    if status is Verdict.REJECTED:
        # Not an indicator at all. A confident rejection and a hesitant one
        # both land at zero; the hesitancy shows up in the agreement grade.
        return 0.0

    if status is Verdict.UNCERTAIN:
        # A hedge. High confidence in a hedge is still a hedge, so the verdict
        # confidence says nothing about maliciousness - the midpoint does.
        return 0.5

    return None  # Verdict.CONTEXT - a description, not a maliciousness claim


def compare_verifiers(
    python_candidate: Candidate | None,
    llm_candidate: Candidate | None,
    multipliers: Mapping[Agreement, float],
) -> VerifierComparison:
    """Reconcile the two verifiers for one candidate.

    The LLM verdict wins where both are present, per the reconciliation policy
    in the module docstring. The confidence returned is what
    indicators.confidence receives: the winning verdict's maliciousness,
    discounted by how much the two verifiers disagreed. Corroboration is
    rewarded - when they agree the two readings are averaged rather than one
    being thrown away.
    """
    python_status = python_candidate.status if python_candidate else None
    llm_status = llm_candidate.status if llm_candidate else None
    python_conf = python_candidate.verdict_confidence if python_candidate else None
    llm_conf = llm_candidate.verdict_confidence if llm_candidate else None

    agreement = grade_agreement(python_status, llm_status)

    if llm_candidate is not None:
        winner, winning_status = "llm", llm_status
    elif python_candidate is not None:
        winner, winning_status = "python", python_status
    else:
        winner, winning_status = "none", None

    python_malice = maliciousness_from_verdict(python_status, python_conf)
    llm_malice = maliciousness_from_verdict(llm_status, llm_conf)

    if agreement is Agreement.AGREE:
        readings = [m for m in (python_malice, llm_malice) if m is not None]
        base = sum(readings) / len(readings) if readings else None
    else:
        base = llm_malice if winner == "llm" else python_malice

    if base is None:
        confidence = 0
    else:
        scaled = base * multipliers.get(agreement, 1.0)
        confidence = conformance.confidence_from_unit_interval(
            min(max(scaled, 0.0), 1.0)
        )

    candidate = llm_candidate or python_candidate
    return VerifierComparison(
        candidate_id=candidate.candidate_id if candidate else "",
        python_status=python_status,
        llm_status=llm_status,
        python_confidence=python_conf,
        llm_confidence=llm_conf,
        agreement=agreement,
        winner=winner,
        winning_status=winning_status,
        confidence=confidence,
    )


# ===========================================================================
# Layer 4 - dimension scoring
# ===========================================================================


@dataclass(frozen=True)
class ScoringPolicy:
    """Weights and band thresholds for the four scored dimensions.

    Weights and agreement multipliers come from threatlens.conf when it sets
    them (see threatlens.config), so they can be tuned per machine or from the
    dashboard without editing this file. Band thresholds are read from
    scoring_config wherever a database is available. Every score records the
    weights it was computed with in score_components, so a score computed in
    Week 8 stays explainable in Week 12. default() mirrors the rows seed.py
    writes and is the fallback when neither source supplies a value.
    """

    weights: Mapping[str, float]
    timeliness_bands_days: Mapping[int, int]
    accuracy_bands_reliability_pct: Mapping[int, int]
    accuracy_min_candidates: int
    completeness_expected_keys: tuple[str, ...]
    completeness_bands_pct: Mapping[int, int]
    relevance_bands_match_pct: Mapping[int, int]
    agreement_multipliers: Mapping[Agreement, float]
    alias_groups: tuple[frozenset[str], ...]
    # The verbal bracket a 0-100 quality_score falls into, e.g. for a client
    # dashboard that should not force a reader to interpret a bare integer.
    # Keyed by the band's floor, same >=-threshold convention as every other
    # band table here. Not sourced from scoring_config: it grades the composite
    # output rather than a rubric dimension, so it does not participate in the
    # weights-sum-to-1.0 invariant scoring_config enforces.
    quality_bands: Mapping[int, str]

    @classmethod
    def default(cls) -> ScoringPolicy:
        return cls(
            weights={
                "timeliness": 0.25,
                "accuracy": 0.30,
                "completeness": 0.25,
                "relevance": 0.20,
            },
            timeliness_bands_days={5: 7, 4: 30, 3: 90, 2: 365},
            # Accuracy is the share of a source's candidates that survived
            # assessment, not a count of corroborating sources. Measured over
            # 105 reports, cross-report corroboration sits at 3.3% and what
            # does repeat is LOLBins, generic paths and publisher domains -
            # zero file hashes appear in two reports. Corroboration needs a
            # feed, not a corpus, so it is retained in sightings for when
            # external enrichment arrives but is not what accuracy reads.
            accuracy_bands_reliability_pct={5: 90, 4: 80, 3: 70, 2: 55},
            # A report offering two candidates can hit 100% by luck, so a
            # small sample cannot claim the top bands.
            accuracy_min_candidates=10,
            completeness_expected_keys=conformance.EXPECTED_CONTEXT_KEYS,
            completeness_bands_pct={5: 80, 4: 60, 3: 40, 2: 20},
            relevance_bands_match_pct={5: 80, 4: 60, 3: 40, 2: 20},
            # How much a disagreement discounts confidence. Not in
            # scoring_config today; a dimension='agreement' row would be the
            # place for it if the team wants these tunable from the database.
            agreement_multipliers={
                Agreement.AGREE: 1.00,
                Agreement.WEAK: 0.90,
                Agreement.SINGLE: 0.85,
                Agreement.MODERATE: 0.75,
                Agreement.STRONG: 0.50,
            },
            # Counted as one entity each for relevance, so an actor named
            # three ways does not inflate the score. This is deliberately a
            # lookup and not actor modelling, which is out of scope; a
            # reference table is the proper home for it later.
            alias_groups=(
                frozenset({"ta422", "apt28", "fancy bear"}),
            ),
            # Verbal bracket for quality_score's own meaning - "fitness of the
            # indicator as data" - not maliciousness, which is what
            # indicators.confidence already answers. Deliberately avoids
            # Verdict/Decision/Agreement's vocabulary (confirmed, agree, ...)
            # so a reader never confuses this bracket with those. 0 is the
            # floor, so every score lands in some band.
            quality_bands={
                85: "Actionable",
                75: "Reliable",
                65: "Usable",
                50: "Marginal",
                0: "Unreliable",
            },
        )

    @classmethod
    def configured(cls) -> ScoringPolicy:
        """default() with threatlens.conf's weights and multipliers applied."""
        return cls.default().with_local_config()

    def with_local_config(self) -> ScoringPolicy:
        """This policy with any weights/multipliers threatlens.conf sets.

        Only sections present in the file override, so a policy built from
        scoring_config keeps its database weights on a machine with no
        [quality.weights] section.
        """
        from threatlens.config import load_config

        config = load_config()
        changes: dict[str, Any] = {}
        if "quality.weights" in config.present:
            changes["weights"] = dict(config.weights)
        if "quality.agreement" in config.present:
            changes["agreement_multipliers"] = {
                Agreement[grade.upper()]: value for grade, value in config.agreement.items()
            }
        return replace(self, **changes) if changes else self

    @classmethod
    def from_session(cls, session: Any) -> ScoringPolicy:
        """Build a policy from the live scoring_config rows.

        scoring_config is insert-only with effective_from, so the latest row
        *per dimension* is the one in force - not simply every row, which
        would leave the winner depending on insertion order.
        """
        from sqlalchemy import select

        from threatlens.db.models import ScoringConfig

        rows = session.execute(
            select(ScoringConfig).order_by(
                ScoringConfig.dimension,
                ScoringConfig.effective_from,
                ScoringConfig.id,
            )
        ).scalars().all()

        latest: dict[str, Any] = {}
        for row in rows:
            latest[row.dimension] = row  # later rows supersede earlier ones

        if not latest:
            return cls.configured()

        base = cls.default()
        weights = {d: float(r.weight) for d, r in latest.items()}
        parameters = {
            d: json.loads(r.parameters) if r.parameters else {}
            for d, r in latest.items()
        }

        return cls(
            weights=weights or base.weights,
            timeliness_bands_days=_int_bands(
                parameters.get("timeliness", {}).get("bands_days"),
                base.timeliness_bands_days,
            ),
            accuracy_bands_reliability_pct=_int_bands(
                parameters.get("accuracy", {}).get("bands_reliability_pct"),
                base.accuracy_bands_reliability_pct,
            ),
            accuracy_min_candidates=int(
                parameters.get("accuracy", {}).get("min_candidates")
                or base.accuracy_min_candidates
            ),
            completeness_expected_keys=tuple(
                parameters.get("completeness", {}).get("expected_keys")
                or base.completeness_expected_keys
            ),
            completeness_bands_pct=_int_bands(
                parameters.get("completeness", {}).get("bands_pct"),
                base.completeness_bands_pct,
            ),
            relevance_bands_match_pct=_int_bands(
                parameters.get("relevance", {}).get("bands_match_pct"),
                base.relevance_bands_match_pct,
            ),
            agreement_multipliers=base.agreement_multipliers,
            alias_groups=base.alias_groups,
            quality_bands=base.quality_bands,
        ).with_local_config()


def _int_bands(
    raw: Any,
    fallback: Mapping[int, int],
) -> Mapping[int, int]:
    """Coerce a scoring_config band map (JSON string keys) to int keys."""
    if not isinstance(raw, Mapping):
        return fallback
    try:
        return {int(k): int(v) for k, v in raw.items()}
    except (TypeError, ValueError):
        return fallback


def score_timeliness(
    reference: str | datetime | None,
    bands_days: Mapping[int, int],
    now: datetime | None = None,
) -> int:
    """Score how recently the intelligence was reported.

    Bands come from scoring_config: 5 inside a week, down to 2 inside a year.
    Anything older is indefinite and scores 1; an unknown or unparseable date
    scores 0, because not knowing is worse than knowing it is old.
    """
    if reference is None:
        return 0

    if isinstance(reference, str):
        try:
            moment = datetime.fromisoformat(reference)
        except ValueError:
            return 0
    else:
        moment = reference

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)

    # A future publish date is not fresher than today.
    age = max((now or datetime.now(UTC)) - moment, timedelta(0))

    for band in sorted(bands_days, reverse=True):
        if age < timedelta(days=bands_days[band]):
            return band

    return 1


def score_accuracy(
    reliability_pct: float | None,
    bands_reliability_pct: Mapping[int, int],
    candidate_count: int = 0,
    min_candidates: int = 0,
) -> int:
    """Score how much of what this source asserted survived assessment.

    Documented divergence #3. The paper - and this project until now - defined
    accuracy as the count of distinct sources corroborating an indicator. That
    is measurable only against a feed. Across 105 reports this repository
    produced 7,058 observables of which 3.3% appeared twice, no file hash
    appeared twice at all, and the values that did repeat were cmd.exe,
    powershell.exe, generic Windows paths and the publishers' own domains
    corroboration was not merely absent, it correlated with benign-ness.

    Accuracy therefore reads source reliability instead: the proportion of a
    document's candidates that were not rejected as malformed or non-STIX.
    This is the classical data-quality reading of accuracy - how much of what
    a source asserted turned out to be correct - and it is knowable from
    static data alone.

    Caveat worth carrying: it measures the extraction of a source as much as
    the source itself. A report scoring low may be well written and badly
    parsed. The number improves as the extraction engine improves.
    """
    if reliability_pct is None:
        return 0

    ceiling = 5 if candidate_count >= min_candidates else 3

    for band in sorted(bands_reliability_pct, reverse=True):
        if reliability_pct >= bands_reliability_pct[band]:
            return min(band, ceiling)
    return 1


def score_completeness(
    context: Mapping[str, Any] | str | None,
    expected_keys: Sequence[str],
    bands_pct: Mapping[int, int],
) -> int:
    """Score the proportion of expected context fields that carry a value.

    Documented divergence #1. The paper measures how much of the STIX
    construction graph was completed; ThreatLens does not build that graph, so
    it measures populated context fields instead.
    """
    if not context or not expected_keys:
        return 0

    if isinstance(context, str):
        try:
            parsed = json.loads(context)
        except json.JSONDecodeError:
            return 0
        context = parsed if isinstance(parsed, Mapping) else None

    if not isinstance(context, Mapping):
        return 0

    populated = sum(1 for key in expected_keys if _is_populated(context.get(key)))
    percent = populated / len(expected_keys) * 100

    for band in sorted(bands_pct, reverse=True):
        if percent >= bands_pct[band]:
            return band

    return 1 if percent > 0 else 0


def _is_populated(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return bool(str(value).strip())


def audience_profile(assessments: Sequence[CandidateAssessment]) -> float:
    """Return where the document sits on the strategic..tactical axis, 0.0-1.0.

    0.0 is purely strategic, 1.0 purely tactical. The measure is the share of
    the document's surviving content that is a cyber-observable rather than a
    domain object: hashes, addresses and paths are what an analyst actions,
    while actors, campaigns and techniques are what an executive reads.

    On the 30-report corpus this separates cleanly and with good face validity
    - a threat-actor naming convention lands at 0.01 and a playbook viewer
    carrying ninety-four observables lands at 0.99.

    A document with nothing stored and nothing in context has no audience to
    speak of and returns 0.0.
    """
    tactical = sum(1 for a in assessments if a.is_stored)
    strategic = sum(1 for a in assessments if a.decision is Decision.CONTEXT)
    total = tactical + strategic
    return tactical / total if total else 0.0


def score_relevance(
    profile: float,
    role: ViewerRole,
    bands_match_pct: Mapping[int, int],
) -> int:
    """Score how well the document's audience matches the reader's role.

    `profile` is audience_profile() above. A tactical reader is served by a
    tactical document, so the match is the profile itself; a strategic reader
    is served by its complement. A mixed report scores moderately for both,
    which is the honest answer - it half-serves each.

    ANY returns the middle band: relevance is not knowable until someone picks
    a role, and the dashboard recomputes it per reader from the stored profile.
    """
    if role is ViewerRole.ANY:
        return 3

    match = profile if role is ViewerRole.TACTICAL else 1.0 - profile
    match_pct = match * 100

    for band in sorted(bands_match_pct, reverse=True):
        if match_pct >= bands_match_pct[band]:
            return band
    return 1


# ===========================================================================
# Assessment and report
# ===========================================================================


@dataclass
class CandidateAssessment:
    """The checker's complete finding for one candidate."""

    candidate: Candidate
    decision: Decision
    stix_kind: StixKind
    stix_type: str
    ioc_type: str | None
    issues: list[QualityIssue] = field(default_factory=list)
    comparison: VerifierComparison | None = None
    dimensions: dict[str, int] = field(default_factory=dict)
    quality_score: int | None = None
    grade: str | None = None
    confidence: int | None = None

    @property
    def is_indicator(self) -> bool:
        return self.decision is Decision.INDICATOR

    @property
    def is_stored(self) -> bool:
        """Whether this candidate gets a row in the indicators table.

        Screened indicators are stored too: they are real observables the
        report mentioned, and their flag records that they are not malicious.
        """
        return self.decision in {Decision.INDICATOR, Decision.SCREENED}

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate.candidate_id,
            "indicator_type": self.candidate.indicator_type,
            "ioc_type": self.ioc_type,
            "value": self.candidate.value,
            "normalised": self.candidate.normalized_value,
            "decision": self.decision.value,
            "stix": {"kind": self.stix_kind.value, "type": self.stix_type},
            "dimensions": self.dimensions,
            "quality_score": self.quality_score,
            "grade": self.grade,
            "confidence": self.confidence,
            "agreement": (
                self.comparison.to_dict() if self.comparison is not None else None
            ),
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass
class QualityReport:
    """Everything the checker concluded about one document."""

    metadata: Mapping[str, Any]
    policy: ScoringPolicy
    assessments: list[CandidateAssessment]
    document_context: dict[str, Any]
    verifiers: list[str]
    unpopulatable_context_keys: list[str]
    scored_at: str
    # Where the document sits on the strategic..tactical axis, and the role it
    # was scored for. The profile is the durable fact worth storing; the role
    # is whoever asked. The dashboard recomputes relevance per reader from the
    # profile rather than the checker storing a score per role.
    audience_profile: float = 0.0
    role: ViewerRole = ViewerRole.ANY
    # Each run's verification_model, in the order of `verifiers`. What
    # persist_report() records as the source's extraction engine and model.
    verification_models: list[str] = field(default_factory=list)

    @property
    def source_reliability(self) -> float:
        """Percent of this document's candidates that survived assessment.

        What accuracy scores against, and what sources.reliability stores. A
        candidate is counted as surviving unless it was rejected outright as
        malformed or non-STIX-conformant; screened observables count, because
        being benign is a correct reading of the source, not a defect in it.
        """
        total = len(self.assessments)
        if not total:
            return 0.0
        rejected = sum(1 for a in self.assessments if a.decision is Decision.REJECTED)
        return (total - rejected) / total * 100

    @property
    def audience(self) -> str:
        """Plain label for the profile, for display."""
        if self.audience_profile >= 0.8:
            return "tactical"
        if self.audience_profile <= 0.2:
            return "strategic"
        return "mixed"

    @property
    def indicators(self) -> list[CandidateAssessment]:
        return [a for a in self.assessments if a.is_indicator]

    @property
    def stored(self) -> list[CandidateAssessment]:
        """Indicators plus screened observables - everything that gets a row."""
        return [a for a in self.assessments if a.is_stored]

    @property
    def context_entities(self) -> list[CandidateAssessment]:
        return [a for a in self.assessments if a.decision is Decision.CONTEXT]

    @property
    def screened(self) -> list[CandidateAssessment]:
        return [a for a in self.assessments if a.decision is Decision.SCREENED]

    @property
    def rejected(self) -> list[CandidateAssessment]:
        return [a for a in self.assessments if a.decision is Decision.REJECTED]

    def agreement_matrix(self) -> dict[str, int]:
        """Count candidates by agreement grade, for the demo and the report."""
        counts: dict[str, int] = {}
        for assessment in self.assessments:
            if assessment.comparison is None:
                continue
            grade = assessment.comparison.agreement.value
            counts[grade] = counts.get(grade, 0) + 1
        return counts

    def issue_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for assessment in self.assessments:
            for issue in assessment.issues:
                counts[issue.flag_type] = counts.get(issue.flag_type, 0) + 1
        return counts

    def summary(self) -> dict[str, Any]:
        # Averaged over `stored`, not `indicators`: a screened observable is
        # scored and does get a row, so reporting None for a document whose
        # candidates were all screened contradicted scored_rows(), which was
        # happily returning those same rows.
        scores = [
            a.quality_score for a in self.stored if a.quality_score is not None
        ]
        mean_quality_score = round(sum(scores) / len(scores), 1) if scores else None
        return {
            "candidates": len(self.assessments),
            "indicators": len(self.indicators),
            "screened": len(self.screened),
            "context_entities": len(self.context_entities),
            "rejected": len(self.rejected),
            "verifiers": self.verifiers,
            "mean_quality_score": mean_quality_score,
            "grade": grade_quality_score(mean_quality_score, self.policy.quality_bands),
            "agreement": self.agreement_matrix(),
            "issues": self.issue_counts(),
            "unpopulatable_context_keys": self.unpopulatable_context_keys,
            "source_reliability": round(self.source_reliability, 1),
            "audience_profile": round(self.audience_profile, 3),
            "audience": self.audience,
            "role": self.role.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": dict(self.metadata),
            "scored_at": self.scored_at,
            "summary": self.summary(),
            "document_context": self.document_context,
            "assessments": [a.to_dict() for a in self.assessments],
        }

    def scored_rows(self) -> list[tuple[dict[str, Any], Mapping[str, Any]]]:
        """Build (indicator row, original extraction) pairs for the ingest layer.

        Every row has been through conformance.validate_indicator_row(), so a
        bad value raises here with the column named rather than committing
        silently or surfacing as an unattributed SQLite CHECK failure.
        """
        rows: list[tuple[dict[str, Any], Mapping[str, Any]]] = []

        for assessment in self.stored:
            row = conformance.from_extraction(assessment.candidate.raw)

            # Merge the document's structured context in beside the extractor's
            # excerpt. This is the naming collision resolved: the excerpt stays
            # namespaced, the structured dict sits at the top level where the
            # ctx_malware computed column can reach $.malware_family.
            existing = json.loads(row["context"]) if row.get("context") else {}
            merged = {**self.document_context, **existing}
            row["context"] = conformance.to_json_text(merged)

            row["confidence"] = assessment.confidence
            row["quality_score"] = assessment.quality_score
            row["score_components"] = conformance.to_json_text(
                {
                    "dimensions": assessment.dimensions,
                    "weights": {
                        k: v
                        for k, v in self.policy.weights.items()
                        if k in assessment.dimensions
                    },
                    "grade": assessment.grade,
                    "agreement": (
                        assessment.comparison.to_dict()
                        if assessment.comparison is not None
                        else None
                    ),
                    "stix": {
                        "kind": assessment.stix_kind.value,
                        "type": assessment.stix_type,
                    },
                }
            )
            row["scored_at"] = self.scored_at

            published = self.metadata.get("publish_date")
            if published:
                row["last_seen"] = conformance.to_iso8601(str(published))

            rows.append((conformance.validate_indicator_row(row), assessment.candidate.raw))

        return rows


# ===========================================================================
# Orchestration
# ===========================================================================


def default_allowlist_entries() -> tuple[AllowlistEntry, ...]:
    """Pre-parsed allowlist entries from seed.py, for running without a database.

    Uses the same rows seed.py writes, so an offline run screens against
    exactly what a seeded database would. load_allowlist(session) is the
    preferred source whenever a session is available.
    """
    from threatlens.db.models import Allowlist
    from threatlens.db.seed import ALLOWLIST

    return tuple(
        AllowlistEntry.from_row(
            Allowlist(ioc_type=ioc_type, pattern=pattern, reason=reason)
        )
        for ioc_type, pattern, reason in ALLOWLIST
    )


def build_document_context(
    assessments: Sequence[CandidateAssessment],
    expected_keys: Sequence[str],
) -> tuple[dict[str, Any], list[str]]:
    """Assemble indicators.context from the document's surviving SDO entities.

    This is the structured dict the schema means by "context", as opposed to
    the extractor's free-text excerpt. Entities that survived Layers 1-2 are
    grouped by their extractor type, and the keys scoring_config expects are
    filled from them where they correspond.

    Also returns the expected keys (threat_actor, campaign, vulnerability,
    tool by default) that no surviving entity in this report supplies. Each
    one caps completeness for every indicator from the report. Surfacing them
    is the point - a gap is either the report's or the extractor's, and it
    should be visible rather than a silent low score.
    """
    grouped: dict[str, list[str]] = {}
    for assessment in assessments:
        if assessment.decision is not Decision.CONTEXT:
            continue
        # Only SDOs describe indicators, per StixKind: an SDO becomes context,
        # an SCO becomes a row. The verifier does sometimes label a filepath or
        # a domain a context entity, and without this guard those became keys in
        # the context dict that indicators.context carries - "filepath",
        # "domain", "filename" are observables, not descriptions of one.
        if assessment.stix_kind is not StixKind.SDO:
            continue
        grouped.setdefault(assessment.candidate.indicator_type, []).append(
            assessment.candidate.value.strip()
        )

    context: dict[str, Any] = {
        key: sorted(set(values)) for key, values in grouped.items() if values
    }

    # malware_family is not an expected key, but the ctx_malware computed
    # column reads it, so the malware entities are copied there too.
    if grouped.get("malware"):
        context["malware_family"] = sorted(set(grouped["malware"]))

    unpopulatable = [
        key for key in expected_keys if not _is_populated(context.get(key))
    ]

    return context, unpopulatable


def count_relevant_entities(
    assessments: Sequence[CandidateAssessment],
    alias_groups: Sequence[frozenset[str]],
) -> int:
    """Count distinct recognised entities, collapsing known aliases.

    TA422, APT28 and Fancy Bear are one actor, and counting them as three
    would inflate relevance for a document that named the same group
    repeatedly.
    """
    seen: set[str] = set()

    for assessment in assessments:
        if assessment.decision is not Decision.CONTEXT:
            continue
        # Same SDO restriction as build_document_context. Relevance asks how
        # richly the document describes the world around its indicators, so
        # counting an observable here would credit the document for naming a
        # file path rather than an actor, campaign or technique.
        if assessment.stix_kind is not StixKind.SDO:
            continue
        value = assessment.candidate.normalized_value.strip().lower()
        if not value:
            continue
        canonical = next(
            (min(group) for group in alias_groups if value in group), value
        )
        seen.add(f"{assessment.candidate.indicator_type}:{canonical}")

    return len(seen)


def check_report(
    runs: Sequence[ExtractionRun],
    *,
    policy: ScoringPolicy | None = None,
    allowlist_entries: Sequence[AllowlistEntry] | None = None,
    role: ViewerRole = ViewerRole.ANY,
    now: datetime | None = None,
) -> QualityReport:
    """Run all four layers over one document's extractor output.

    `runs` is one or both verifier runs of the same report. They are matched
    by candidate id, which is stable across verifiers because both verify the
    same regex candidate set - the LLM classifies, it does not extract, so
    hallucinated indicators are not a risk and the offsets are trustworthy.

    Pure: no database session, no network, no filesystem beyond what the
    caller already loaded. persist_report() is the adapter that writes the
    result to SQLite.
    """
    if not runs:
        raise ValueError("check_report() needs at least one extraction run")

    policy = policy or ScoringPolicy.configured()
    entries = (
        allowlist_entries
        if allowlist_entries is not None
        else default_allowlist_entries()
    )
    now = now or datetime.now(UTC)

    llm_run = next((r for r in runs if r.is_llm), None)
    python_run = next((r for r in runs if not r.is_llm), None)
    primary = llm_run or python_run
    assert primary is not None  # guaranteed: runs is non-empty

    metadata = primary.metadata
    by_id_python = {c.candidate_id: c for c in (python_run.candidates if python_run else ())}
    by_id_llm = {c.candidate_id: c for c in (llm_run.candidates if llm_run else ())}

    # The union, so a candidate present in only one run is still assessed.
    ordered_ids: list[str] = []
    for run in (primary, *(r for r in runs if r is not primary)):
        for candidate in run.candidates:
            if candidate.candidate_id not in ordered_ids:
                ordered_ids.append(candidate.candidate_id)

    merged: list[Candidate] = [
        by_id_llm.get(cid) or by_id_python[cid] for cid in ordered_ids
    ]

    # ---- Layer 1: document-wide structural checks -------------------------
    span_losers = find_span_overlaps(merged)
    nested_losers = find_nested_values(merged)
    filename_losers = find_filename_collisions(merged)

    assessments: list[CandidateAssessment] = []

    for candidate in merged:
        stix_kind, stix_type = classify_stix(candidate.indicator_type)
        issues: list[QualityIssue] = []

        comparison = compare_verifiers(
            by_id_python.get(candidate.candidate_id),
            by_id_llm.get(candidate.candidate_id),
            policy.agreement_multipliers,
        )

        # ---- Layer 1: per-candidate structural checks --------------------
        issues.extend(
            make_issue(flag_type, detail)
            for flag_type, detail in _structural_issues(
                candidate, stix_kind, metadata,
                span_losers, nested_losers, filename_losers,
            )
        )

        # ---- Layer 2: STIX conformance -----------------------------------
        if stix_kind is StixKind.NONE:
            issues.append(
                make_issue(
                    "not_stix_conformant",
                    f"{candidate.indicator_type!r} has no STIX 2.1 "
                    "representation as extracted",
                )
            )

        is_valid, format_reason = format_valid(
            candidate.indicator_type, candidate.normalized_value
        )
        if stix_kind is StixKind.SCO and not is_valid:
            issues.append(
                make_issue(
                    "invalid_format",
                    f"cannot populate STIX {stix_type}: {format_reason}",
                )
            )

        # ---- Layer 3: false-positive screening ---------------------------
        # Resolved before the decision, not after, so an allowlist hit is
        # weighed alongside the structural findings instead of overriding a
        # decision that has already been taken.
        ioc_type: str | None = None
        if stix_kind is StixKind.SCO:
            try:
                ioc_type = conformance.to_ioc_type(
                    candidate.indicator_type, candidate.attributes
                )
            except conformance.ConformanceError as exc:
                issues.append(make_issue("unmapped_ioc_type", str(exc)))

        if ioc_type is not None:
            entry = match_allowlist(ioc_type, candidate.normalized_value, entries)
            if entry is not None:
                issues.append(
                    make_issue(
                        "known_benign",
                        f"matches allowlist pattern {entry.pattern!r}"
                        + (f" ({entry.reason})" if entry.reason else ""),
                    )
                )

            non_routable = is_non_routable(
                candidate.indicator_type, candidate.normalized_value
            )
            if non_routable:
                issues.append(make_issue("non_routable", non_routable))

        decision, decision_issues = _decide(candidate, stix_kind, issues, comparison)
        issues.extend(decision_issues)

        assessments.append(
            CandidateAssessment(
                candidate=candidate,
                decision=decision,
                stix_kind=stix_kind,
                stix_type=stix_type,
                # Screened indicators keep their ioc_type: they are stored, so
                # they need one, and their flags attach to the stored row.
                ioc_type=(
                    ioc_type
                    if decision in {Decision.INDICATOR, Decision.SCREENED}
                    else None
                ),
                issues=issues,
                comparison=comparison,
            )
        )

    # ---- Layer 4: scoring, once the document's context is known -----------
    document_context, unpopulatable = build_document_context(
        assessments, policy.completeness_expected_keys
    )
    profile = audience_profile(assessments)
    rejected = sum(1 for a in assessments if a.decision is Decision.REJECTED)
    reliability_pct = (
        (len(assessments) - rejected) / len(assessments) * 100 if assessments else 0.0
    )
    published = metadata.get("publish_date")

    for assessment in assessments:
        if not assessment.is_stored:
            continue
        _score_assessment(
            assessment,
            policy=policy,
            document_context=document_context,
            profile=profile,
            role=role,
            published=str(published) if published else None,
            reliability_pct=reliability_pct,
            candidate_count=len(assessments),
            now=now,
        )

    return QualityReport(
        metadata=metadata,
        policy=policy,
        assessments=assessments,
        document_context=document_context,
        verifiers=[r.label for r in runs],
        unpopulatable_context_keys=unpopulatable,
        scored_at=conformance.to_iso8601(now),
        audience_profile=profile,
        role=role,
        verification_models=[r.verification_model for r in runs],
    )


def _structural_issues(
    candidate: Candidate,
    stix_kind: StixKind,
    metadata: Mapping[str, Any],
    span_losers: Mapping[str, tuple[str, str]],
    nested_losers: Mapping[str, tuple[str, str]],
    filename_losers: Mapping[str, tuple[str, str, str]],
) -> list[tuple[str, str]]:
    """Collect every Layer 1 finding for one candidate as (flag_type, detail)."""
    found: list[tuple[str, str]] = []

    if candidate.candidate_id in span_losers:
        found.append(("span_overlap", span_losers[candidate.candidate_id][1]))
    if candidate.candidate_id in nested_losers:
        found.append(("nested_value", nested_losers[candidate.candidate_id][1]))
    if candidate.candidate_id in filename_losers:
        _, flag_type, detail = filename_losers[candidate.candidate_id]
        found.append((flag_type, detail))

    fragment = is_sentence_fragment(candidate.value, stix_kind)
    if fragment:
        found.append(("sentence_fragment", fragment))

    trailing = has_trailing_punctuation(candidate.value)
    if trailing:
        found.append(("trailing_punctuation", trailing))

    bounds = is_out_of_bounds(candidate.value)
    if bounds:
        found.append(("length_bounds", bounds))

    truncated = is_truncated_span(candidate.value, candidate.excerpt)
    if truncated:
        found.append(("truncated_span", truncated))

    idiom = is_technique_idiom(candidate.normalized_value)
    if idiom:
        found.append(("technique_idiom", idiom))

    self_ref = is_self_reference(candidate.normalized_value, metadata)
    if self_ref:
        found.append(("self_reference", self_ref))

    return found


def _decide(
    candidate: Candidate,
    stix_kind: StixKind,
    issues: Sequence[QualityIssue],
    comparison: VerifierComparison,
) -> tuple[Decision, list[QualityIssue]]:
    """Apply the reconciliation policy: structure first, then the LLM verdict.

    Any error-severity issue is fatal regardless of what either verifier said.
    That ordering is what removes all five strong contradictions on the
    reference sample without needing to pick a verifier at all.

    Returns the decision plus any issue raised in reaching it, so a candidate
    is never dropped without a flag recording why. A rejection with no
    explanation is not traceable, and traceability is the whole point of
    quality_flags carrying a dimension.
    """
    found = {issue.flag_type for issue in issues}

    # Malformed beats everything: text that is not an observable cannot be
    # screened, scored or stored, whatever either verifier concluded.
    if found & MALFORMED_FLAGS:
        return Decision.REJECTED, []

    if stix_kind is StixKind.SDO:
        return Decision.CONTEXT, []
    if stix_kind is StixKind.NONE:
        return Decision.REJECTED, []

    if found & SCREENED_FLAGS:
        return Decision.SCREENED, []

    status = comparison.winning_status
    reason = candidate.reason or "no reason given"

    if status is Verdict.REJECTED:
        # Well-formed and STIX-conformant, but the verifier judged it not an
        # indicator. Stored and flagged rather than discarded, so the sighting
        # survives and a human can review the call.
        return Decision.SCREENED, [
            make_issue(
                "verifier_rejected",
                f"{comparison.winner} verifier rejected this candidate "
                f"({comparison.agreement.value} agreement): {reason}",
            )
        ]

    if status is Verdict.CONTEXT:
        # Only SCOs reach here - SDOs returned CONTEXT above - and an
        # observable cannot be context, it can only be an observable that is
        # not malicious: a victim organisation's domain from a leak-site
        # table, a legitimate binary the malware abused, a standard system
        # path. Screened rather than stored as an indicator, because putting a
        # victim's domain into a malicious-IOC feed would have a defender
        # blocking the people who were attacked. Screening keeps the row, the
        # sighting and the verifier's reasoning, at confidence 0.
        return Decision.SCREENED, [
            make_issue(
                "benign_observable",
                f"{comparison.winner} verifier judged this a real observable "
                f"that is not attacker infrastructure: {reason}",
            )
        ]

    # CONFIRMED, UNCERTAIN, or no verdict at all. An uncertain observable that
    # survived Layers 1-2 is kept and scored: its hesitancy is already priced
    # into its confidence (agreement multiplier) and recorded as a flag.
    extra: list[QualityIssue] = []
    if status is Verdict.UNCERTAIN:
        extra.append(
            make_issue(
                "verifier_uncertain",
                f"{comparison.winner} verifier was uncertain "
                f"({comparison.agreement.value} agreement): {reason}",
            )
        )
    return Decision.INDICATOR, extra


def _score_assessment(
    assessment: CandidateAssessment,
    *,
    policy: ScoringPolicy,
    document_context: Mapping[str, Any],
    profile: float,
    role: ViewerRole,
    published: str | None,
    reliability_pct: float,
    candidate_count: int,
    now: datetime,
) -> None:
    """Fill in the four dimensions, the composite score, and the confidence."""
    assessment.dimensions = {
        "timeliness": score_timeliness(published, policy.timeliness_bands_days, now),
        "accuracy": score_accuracy(
            reliability_pct,
            policy.accuracy_bands_reliability_pct,
            candidate_count,
            policy.accuracy_min_candidates,
        ),
        "completeness": score_completeness(
            document_context,
            policy.completeness_expected_keys,
            policy.completeness_bands_pct,
        ),
        "relevance": score_relevance(
            profile, role, policy.relevance_bands_match_pct
        ),
    }

    assessment.quality_score = composite_score(assessment.dimensions, policy.weights)
    assessment.grade = grade_quality_score(assessment.quality_score, policy.quality_bands)

    if assessment.decision is Decision.SCREENED:
        # A screened observable is well-formed data - it keeps its quality
        # score - but it is not malicious, and the allowlist is more
        # authoritative about 8.8.8.8 than either verifier's verdict.
        assessment.confidence = 0
    else:
        assessment.confidence = (
            assessment.comparison.confidence if assessment.comparison else 0
        )


def composite_score(
    dimensions: Mapping[str, int],
    weights: Mapping[str, float],
) -> int:
    """Combine the 0-5 dimension scores into the database's 0-100 integer.

    Normalised by the weight actually applied rather than assuming the weights
    sum to 1.0. The defaults do, but weights set in threatlens.conf or
    scoring_config may not, and an unnormalised total past 5 would fail the
    conformance check. A dimension weighted 0 is left out entirely.
    """
    applied = {
        name: weights.get(name, 0.0)
        for name in dimensions
        if weights.get(name, 0.0) > 0
    }
    total_weight = sum(applied.values())
    if total_weight <= 0:
        return 0

    weighted = sum(weight * dimensions[name] for name, weight in applied.items())
    return conformance.quality_score_from_rubric(weighted / total_weight)


def grade_quality_score(
    score: float | None,
    bands: Mapping[int, str],
) -> str | None:
    """Translate a 0-100 quality_score into a verbal bracket, e.g. "Reliable".

    Same >=-threshold convention as every rubric band above: the highest band
    whose floor the score meets or exceeds wins. A candidate with no score
    (rejected or context - never scored at all) has no grade either, so None
    passes straight through rather than being coerced into a false "Fail".
    """
    if score is None:
        return None
    for floor in sorted(bands, reverse=True):
        if score >= floor:
            return bands[floor]
    return None


# ===========================================================================
# Database adapter
# ===========================================================================


def persist_report(
    session: Any,
    report: QualityReport,
    *,
    source_name: str | None = None,
    source_type: str = "report",
    file_path: Path | str | None = None,
    reliability: int | None = None,
) -> Any:
    """Write a report's indicators, sightings and quality flags to the database.

    The thin adapter over the pure core. Scoring already happened, so this
    hands ingest the finished rows rather than letting it re-derive them, then
    raises the quality flags against the indicator ids ingest assigned.

    Document identity comes from the extractor's metadata.file_sha256, which is
    the digest of the report itself. Without it, ingesting from JSON would hash
    whatever text was to hand and mint a second identity for a report already
    stored under its PDF - two sources for one document, and every sighting
    counted twice in the dimension weighted most heavily.

    The caller commits, so a failed run rolls back as a unit.
    """
    from threatlens.db.ingest import combine_engines, engine_for_model, ingest_scored_rows

    metadata = report.metadata
    document_sha256 = str(metadata.get("file_sha256") or "").strip() or None
    # Which verifier(s) judged these candidates - 'llm+python' when compared.
    known_models = [
        model for model in report.verification_models if engine_for_model(model)
    ]

    result = ingest_scored_rows(
        session,
        report.scored_rows(),
        source_name=source_name or str(metadata.get("filename") or "unknown"),
        source_type=source_type,
        url=str(metadata.get("source_url") or "") or None,
        file_path=file_path,
        # raw_documents requires content: the report when the caller has it,
        # otherwise the metadata block as the archived record of what was read.
        raw_text=(
            None
            if file_path
            else json.dumps(dict(metadata), sort_keys=True, ensure_ascii=False)
        ),
        sha256=document_sha256,
        # The source's own measured reliability, unless the caller overrides.
        # This is what accuracy scores against, so it is stored with the source
        # rather than recomputed per indicator.
        reliability=(
            reliability if reliability is not None
            else round(report.source_reliability)
        ),
        # candidate_count travels with it: the sample the rate rests on, which
        # score_accuracy needs to decide whether the top bands are claimable.
        metadata={**dict(metadata), "candidate_count": len(report.assessments)},
        extraction_engine=combine_engines(*map(engine_for_model, known_models)),
        verification_model=", ".join(known_models) or None,
    )

    raise_flags(session, report)
    return result


def raise_flags(session: Any, report: QualityReport) -> int:
    """Record every finding against the indicator it concerns.

    Indicators are flagged, never deleted. A candidate the checker rejected
    still has a sighting if it reached the database, and a report genuinely
    mentioning a value is a fact about that report.

    Re-running does not duplicate a flag already open for the same indicator
    and flag_type. The caller commits.
    """
    from sqlalchemy import select

    from threatlens.db.models import Indicator, QualityFlag

    raised_at = report.scored_at
    raised = 0

    existing = {
        (indicator_id, flag_type)
        for indicator_id, flag_type in session.execute(
            select(QualityFlag.indicator_id, QualityFlag.flag_type)
        ).all()
    }

    for assessment in report.assessments:
        if not assessment.issues or assessment.ioc_type is None:
            continue

        indicator = session.execute(
            select(Indicator).where(
                Indicator.ioc_type == assessment.ioc_type,
                Indicator.normalised == assessment.candidate.normalized_value,
            )
        ).scalars().first()

        if indicator is None:
            continue

        for issue in assessment.issues:
            if (indicator.id, issue.flag_type) in existing:
                continue
            session.add(
                QualityFlag(
                    indicator_id=indicator.id,
                    flag_type=issue.flag_type,
                    dimension=issue.dimension,
                    detail=issue.detail,
                    severity=issue.severity,
                    raised_at=raised_at,
                    status="open",
                )
            )
            existing.add((indicator.id, issue.flag_type))
            raised += 1

    return raised


def rescore_from_db(
    session: Any,
    *,
    policy: ScoringPolicy | None = None,
    now: datetime | None = None,
) -> int:
    """Recompute every stored indicator's timeliness and accuracy.

    Worth running after each ingest. Accuracy reads the reliability of the
    source that supplied the indicator, which is only knowable once a whole
    document has been assessed, and timeliness moves with the calendar.

    The corroboration count is still read and recorded in score_components -
    it is the measure accuracy will use once external enrichment arrives -
    but it does not drive the score today. See score_accuracy() for why.

    The structural, STIX and agreement findings belong to the extraction that
    produced them and are read back rather than guessed at. The caller commits.
    """
    from sqlalchemy import select

    from threatlens.db.ingest import sighting_counts
    from threatlens.db.models import Indicator, Sighting, Source

    policy = policy or ScoringPolicy.from_session(session)
    counts = sighting_counts(session)
    now = now or datetime.now(UTC)
    rescored = 0

    # Best reliability among the sources that reported each indicator, plus
    # how many candidates that source offered - the sample the rate rests on.
    reliability: dict[int, tuple[float, int]] = {}
    for sighting in session.execute(select(Sighting)).scalars():
        source = session.get(Source, sighting.source_id)
        if source is None or source.reliability is None:
            continue
        meta = json.loads(source.raw_metadata or "{}") if source.raw_metadata else {}
        sample = int(meta.get("candidate_count") or 0)
        best = reliability.get(sighting.indicator_id)
        if best is None or source.reliability > best[0]:
            reliability[sighting.indicator_id] = (float(source.reliability), sample)

    for indicator in session.execute(select(Indicator)).scalars():
        try:
            components = json.loads(indicator.score_components or "{}")
        except json.JSONDecodeError:
            components = {}

        dimensions = dict(components.get("dimensions") or {})
        dimensions["timeliness"] = score_timeliness(
            indicator.last_seen, policy.timeliness_bands_days, now
        )
        rel, sample = reliability.get(indicator.id, (None, 0))
        dimensions["accuracy"] = score_accuracy(
            rel,
            policy.accuracy_bands_reliability_pct,
            sample,
            policy.accuracy_min_candidates,
        )
        dimensions.setdefault("completeness", score_completeness(
            indicator.context,
            policy.completeness_expected_keys,
            policy.completeness_bands_pct,
        ))
        dimensions.setdefault("relevance", 0)

        components["dimensions"] = dimensions
        components["weights"] = {
            k: v for k, v in policy.weights.items() if k in dimensions
        }
        # Recorded, not scored: the corroboration measure accuracy will use
        # once an external feed is available.
        components["sightings"] = counts.get(indicator.id, 0)
        components["source_reliability"] = rel

        indicator.quality_score = composite_score(dimensions, policy.weights)
        components["grade"] = grade_quality_score(
            indicator.quality_score, policy.quality_bands
        )
        indicator.score_components = conformance.to_json_text(components)
        indicator.scored_at = conformance.to_iso8601(now)
        rescored += 1

    return rescored


# ===========================================================================
# Helpers
# ===========================================================================


def _as_optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_optional_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_verdict(value: Any) -> Verdict | None:
    if value is None:
        return None
    try:
        return Verdict(str(value).strip().lower())
    except ValueError:
        return None


def _verdict_name(verdict: Verdict | None) -> str | None:
    return verdict.value if verdict is not None else None


# ===========================================================================
# CLI
# ===========================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens-quality",
        description=(
            "Assess extractor output for duplication, missing context and "
            "likely false positives, then score what survives on timeliness, "
            "accuracy, completeness and relevance."
        ),
    )
    parser.add_argument(
        "extraction",
        type=Path,
        help="Extractor JSON to assess (llm.json or python.json)",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        help=(
            "Second verifier's JSON for the same report. Enables the "
            "cross-verifier agreement assessment; without it, every "
            "candidate is graded single_verifier."
        ),
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Write the full quality report as JSON to this path",
    )
    parser.add_argument(
        "--show",
        choices=("summary", "indicators", "screened", "rejected", "all"),
        default="summary",
        help="How much per-candidate detail to print (default: summary)",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    runs = [load_run(args.extraction)]
    if args.compare:
        runs.append(load_run(args.compare))

    report = check_report(runs)
    summary = report.summary()

    print(
        f"report:    {report.metadata.get('title') or 'untitled'} "
        f"({report.metadata.get('publish_date') or 'date unknown'})"
    )
    print(f"verifiers: {', '.join(summary['verifiers'])}")
    print(
        f"verdict:   {summary['indicators']} indicators, "
        f"{summary['screened']} screened, "
        f"{summary['context_entities']} context entities, "
        f"{summary['rejected']} rejected "
        f"(from {summary['candidates']} candidates)"
    )
    if summary["mean_quality_score"] is not None:
        grade_suffix = f" ({summary['grade']})" if summary["grade"] else ""
        print(f"quality:   mean score {summary['mean_quality_score']}/100{grade_suffix}")

    if summary["agreement"]:
        grades = ", ".join(
            f"{grade}={count}" for grade, count in sorted(summary["agreement"].items())
        )
        print(f"agreement: {grades}")

    if summary["issues"]:
        print("issues:")
        for flag_type, count in sorted(
            summary["issues"].items(), key=lambda kv: (-kv[1], kv[0])
        ):
            print(f"             {count:>3}  {flag_type}")

    if summary["unpopulatable_context_keys"]:
        print(
            "note:      no extractor field supplies "
            f"{summary['unpopulatable_context_keys']}, so completeness is "
            "capped for every indicator"
        )

    _print_detail(report, args.show)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"output:    {args.output}")

    return 0


def _print_detail(report: QualityReport, show: str) -> None:
    if show == "summary":
        return

    groups: list[tuple[str, Iterable[CandidateAssessment]]] = []
    if show in {"indicators", "all"}:
        groups.append(("indicators", report.indicators))
    if show in {"screened", "all"}:
        groups.append(("screened", report.screened))
    if show in {"rejected", "all"}:
        groups.append(("rejected", report.rejected))
    if show == "all":
        groups.append(("context", report.context_entities))

    for title, assessments in groups:
        listed = list(assessments)
        print(f"\n{title} ({len(listed)}):")
        for assessment in listed:
            score = assessment.quality_score
            confidence = assessment.confidence
            grade_suffix = f" ({assessment.grade})" if assessment.grade else ""
            print(
                f"  {assessment.candidate.indicator_type:<14}"
                f" {_truncate(assessment.candidate.value, 44):<46}"
                f" q={score if score is not None else '-':>4}{grade_suffix}"
                f" c={confidence if confidence is not None else '-':>4}"
            )
            for issue in assessment.issues:
                print(f"      - {issue.flag_type}: {_truncate(issue.detail, 90)}")


def _truncate(text: str, width: int) -> str:
    # Plain ASCII: the Windows console this runs on defaults to cp1252, which
    # renders a proper ellipsis as a question mark.
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 3] + "..."


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, conformance.ConformanceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
