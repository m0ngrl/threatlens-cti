#!/usr/bin/env python3
"""ThreatLens CTI extraction using Python-only heuristic verification.

Pipeline
--------
1. Read a CTI document (text directly; PDF when PyMuPDF is installed).
2. Extract broad IoC candidates using deterministic rules.
3. Extract document metadata using conservative heuristics.
4. Apply deterministic Python heuristics to verify candidates against report context.
5. Return the same typed Python object used by the LLM-enhanced extractor and optionally write JSON.

Steps 1-3 and the domain model are imported from ioc_extract_llm_fs.py, so
both engines extract an identical candidate set; only step 4 lives here.
Candidate ids (Extraction.stable_id) are therefore the same in both engines'
output for the same report, which is what lets the quality checker line the
two verdicts up when it is given both runs.

This is the "python" engine wherever a caller offers a choice: cli.py
(`threatlens --engine python`) and dashboard/ingest_worker.py (the Ingest
page, `threatlens-ingest`, .dev_tools/run_ex_pipeline.py). Both call
analyse_document() below. Nothing is read from threatlens.conf, and no
network is used.

The deterministic stage is intentionally recall-oriented. A Python-only heuristic
verification stage then uses report structure and nearby language to distinguish
likely IoCs from references, benign examples, source metadata, and ambiguous values.
This fallback is less capable than the LLM-enhanced extractor but preserves the
same output objects and JSON shape.

Python 3.10+
Optional dependency for PDFs: pymupdf (imported as fitz)
No Ollama or external LLM is required.
"""

from __future__ import annotations

import argparse
import time
import json
import re
import sys
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Shared front end - reading, metadata and candidate extraction.
#
# Everything up to verification is the LLM engine's, so both engines see the
# same candidates (same ids, same refanging, same types) and differ only in
# how those candidates are verified. Improve extraction in
# ioc_extract_llm_fs.py; this module picks it up automatically.
# ---------------------------------------------------------------------------


from threatlens.extractors.ioc_extract_llm_fs import (
    Category,
    CTIExtractor,
    DocumentMetadata,
    DocumentReader,
    Extraction,
    ExtractorConfig,
    IndicatorType,
    IoCExtractionResult,
    MetadataExtractor,
    Verification,
    VerificationStatus,
    VerifiedExtraction,
)


# ---------------------------------------------------------------------------
# Python-only heuristic verification
# ---------------------------------------------------------------------------


class HeuristicVerifier:
    """Verify extracted CTI candidates using deterministic report-context rules.

    The verifier is deliberately conservative:
    - strong report evidence -> confirmed_ioc
    - obvious report/source/reference material -> rejected
    - intelligence concepts and behaviour descriptions -> context_entity
    - everything else -> uncertain

    This preserves the same Verification/VerifiedExtraction/IoCExtractionResult
    interface as the LLM-enhanced extractor.
    """

    IOC_SECTION_RE = re.compile(
        r"\b(?:indicators?\s+of\s+compromise|"
        r"indicators?\s+of\s+compromises?|"
        r"\biocs?\b|"
        r"technical\s+indicators?|"
        r"network\s+indicators?|"
        r"host\s+indicators?)\b",
        re.IGNORECASE,
    )

    MALICIOUS_CONTEXT_RE = re.compile(
        r"\b(?:malware|ransomware|trojan|backdoor|loader|stealer|implant|"
        r"payload|dropper|downloader|phish(?:ing)?|malicious|adversar(?:y|ial)|"
        r"threat\s+actor|attacker|intrusion|compromise|infect(?:ed|ion)?|"
        r"command[- ]and[- ]control|c2|beacon(?:ed|ing)?|exfiltrat(?:e|ed|ion)|"
        r"persistence|lateral\s+movement|credential\s+theft)\b",
        re.IGNORECASE,
    )

    MALICIOUS_ACTION_RE = re.compile(
        r"\b(?:create(?:d|s)?|drop(?:ped|s)?|download(?:ed|s)?|execute(?:d|s)?|"
        r"launch(?:ed|es)?|install(?:ed|s)?|decode(?:d|s)?|write(?:s|ten)?|"
        r"connect(?:ed|s)?|communicat(?:e|ed|es|ing)|contact(?:ed|s)?|"
        r"beacon(?:ed|s|ing)?|resolve(?:d|s)?|host(?:ed|s)?|deliver(?:ed|s)?|"
        r"send(?:s|ing)?|receive(?:d|s)?|upload(?:ed|s)?|exfiltrat(?:e|ed|es|ing))\b",
        re.IGNORECASE,
    )

    REFERENCE_CONTEXT_RE = re.compile(
        r"\b(?:reference(?:s)?|citation|bibliograph(?:y|ic)|source\s+link|"
        r"report\s+source|published\s+at|published\s+on|available\s+at|"
        r"read\s+more|documentation|official\s+website|website\s+of|"
        r"copyright|privacy\s+policy|terms\s+of\s+use|author\s+contact|"
        r"contact\s+us|report\s+download)\b",
        re.IGNORECASE,
    )

    BENIGN_CONTEXT_RE = re.compile(
        r"\b(?:benign|legitimate|not\s+malicious|not\s+an?\s+(?:ioc|indicator)|"
        r"false\s+positive|example\s+only|test\s+data|sample\s+value)\b",
        re.IGNORECASE,
    )

    EMAIL_THREAT_RE = re.compile(
        r"\b(?:phish(?:ing)?|sender|from\s+address|reply[- ]to|return[- ]path|"
        r"spoof(?:ed|ing)?|malicious\s+email|campaign\s+email)\b",
        re.IGNORECASE,
    )

    AUTHOR_EMAIL_RE = re.compile(
        r"\b(?:author|researcher|analyst|contact|questions|feedback|copyright)\b",
        re.IGNORECASE,
    )

    PAREN_LABEL_RE = re.compile(
        r"\((?P<label>[A-Za-z][A-Za-z0-9_.+ -]{2,80})\)"
    )

    HASH_RE = re.compile(
        r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|"
        r"[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})(?![A-Fa-f0-9])"
    )

    def __init__(self, *, verbose: int = 0) -> None:
        self.verbose = max(0, verbose)

    def verify(
        self,
        candidates: Sequence[Extraction],
        metadata: DocumentMetadata,
    ) -> list[Verification]:
        results: list[Verification] = []

        for number, candidate in enumerate(candidates, start=1):
            verification = self._verify_one(candidate, metadata)
            results.append(verification)

            if self.verbose >= 2:
                print(
                    f"[PY] {number}/{len(candidates)} "
                    f"{candidate.indicator_type.value}: {candidate.value[:100]} "
                    f"-> {verification.status.value} "
                    f"({verification.confidence:.2f})",
                    file=sys.stderr,
                    flush=True,
                )
            if self.verbose >= 3:
                print(
                    f"     reason: {verification.reason}",
                    file=sys.stderr,
                    flush=True,
                )

        return results

    @staticmethod
    def _local_context(item: Extraction, radius: int = 140) -> str:
        """Return context immediately surrounding the candidate value.

        This avoids allowing an IoC heading or malicious sentence several hundred
        characters away to incorrectly influence a citation/reference candidate.
        """
        context = item.context or ""
        index = context.casefold().find(item.value.casefold())
        if index < 0:
            index = context.casefold().find(item.normalized_value.casefold())
        if index < 0:
            return context[: radius * 2]

        left = max(0, index - radius)
        right = min(len(context), index + len(item.value) + radius)
        return context[left:right]

    @staticmethod
    def _candidate_prefix(item: Extraction, radius: int = 100) -> str:
        """Return text immediately preceding the candidate within stored context."""
        context = item.context or ""
        index = context.casefold().find(item.value.casefold())
        if index < 0:
            index = context.casefold().find(item.normalized_value.casefold())
        if index < 0:
            return ""
        return context[max(0, index - radius):index]

    def _verify_one(
        self,
        item: Extraction,
        metadata: DocumentMetadata,
    ) -> Verification:
        context = item.context or ""
        local_context = self._local_context(item)
        candidate_prefix = self._candidate_prefix(item)
        attrs = dict(item.attributes)

        section_hint = str(attrs.get("document_section_hint", ""))
        in_ioc_section = bool(
            self.IOC_SECTION_RE.search(section_hint)
            or self.IOC_SECTION_RE.search(context)
        )
        malicious_context = bool(self.MALICIOUS_CONTEXT_RE.search(context))
        malicious_action = bool(self.MALICIOUS_ACTION_RE.search(context))
        local_malicious_context = bool(self.MALICIOUS_CONTEXT_RE.search(local_context))
        local_malicious_action = bool(self.MALICIOUS_ACTION_RE.search(local_context))
        reference_context = bool(self.REFERENCE_CONTEXT_RE.search(context))
        local_reference_context = bool(self.REFERENCE_CONTEXT_RE.search(local_context))
        reference_prefix = bool(self.REFERENCE_CONTEXT_RE.search(candidate_prefix))
        benign_context = bool(self.BENIGN_CONTEXT_RE.search(context))
        was_defanged = bool(attrs.get("was_defanged", False))
        nearby_hash = bool(self.HASH_RE.search(context))
        nearby_label = self._nearby_parenthesised_label(item)
        source_match = self._matches_document_source(item, metadata)

        evidence = self._compact_evidence(
            item,
            section=in_ioc_section,
            label=nearby_label,
        )

        # Intelligence entities are intentionally not treated as static IoCs.
        if item.category is Category.INTELLIGENCE:
            if reference_context and not malicious_context:
                return self._verification(
                    item,
                    VerificationStatus.REJECTED,
                    0.85,
                    "Intelligence-like value appears only in reference/documentation context.",
                    evidence,
                )
            return self._verification(
                item,
                VerificationStatus.CONTEXT_ENTITY,
                0.90 if malicious_context or in_ioc_section else 0.75,
                "Threat-intelligence concept retained as contextual intelligence rather than a static observable.",
                evidence,
            )

        # Behaviour descriptions are useful CTI context, not static observables.
        if item.category is Category.BEHAVIOUR:
            return self._verification(
                item,
                VerificationStatus.CONTEXT_ENTITY,
                0.90 if malicious_context else 0.75,
                "Behavioural CTI retained as contextual intelligence.",
                evidence,
            )

        # Explicit local reference/citation wording is stronger than a nearby IoC
        # heading. This prevents references placed after an IoC list from inheriting
        # the preceding malicious context.
        if reference_prefix:
            return self._verification(
                item,
                VerificationStatus.REJECTED,
                0.98,
                "Value is explicitly presented as a reference, citation, documentation, or report-source item.",
                evidence,
            )

        # Obvious report/source material should be filtered before broader rules.
        # For an exact source match, only direct malicious use without reference
        # wording is allowed to override the source interpretation.
        if source_match and not (local_malicious_context and local_malicious_action):
            return self._verification(
                item,
                VerificationStatus.REJECTED,
                0.98,
                "Value matches the report's own source or source URL.",
                evidence,
            )

        if reference_context and not (
            local_malicious_action
            or (local_malicious_context and item.indicator_type in {
                IndicatorType.HASH,
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.FILENAME,
                IndicatorType.FILEPATH,
            })
        ):
            return self._verification(
                item,
                VerificationStatus.REJECTED,
                0.92,
                "Value appears in citation, documentation, source, or report-reference context.",
                evidence,
            )

        # E-mail addresses need special handling because author addresses are common.
        if item.indicator_type in {
            IndicatorType.EMAIL_ADDRESS,
            IndicatorType.EMAIL_DOMAIN,
            IndicatorType.EMAIL_SUBJECT,
            IndicatorType.EMAIL_HEADER,
            IndicatorType.ATTACHMENT,
        }:
            if self.AUTHOR_EMAIL_RE.search(context) and not self.EMAIL_THREAT_RE.search(context):
                return self._verification(
                    item,
                    VerificationStatus.REJECTED,
                    0.90,
                    "Email-related value appears to be author/contact/report metadata.",
                    evidence,
                )
            if self.EMAIL_THREAT_RE.search(context) or in_ioc_section or malicious_context:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.90 if in_ioc_section else 0.82,
                    "Email-related observable is associated with malicious or phishing activity in the report.",
                    evidence,
                )

        # Hashes are high-quality candidates, especially in IoC or malware context.
        if item.indicator_type is IndicatorType.HASH:
            if in_ioc_section:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.99,
                    "Hash is explicitly located in an Indicators of Compromise context.",
                    evidence,
                )
            if malicious_context or malicious_action:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.92,
                    "Hash is directly associated with malicious activity in nearby report text.",
                    evidence,
                )
            if benign_context:
                return self._verification(
                    item,
                    VerificationStatus.REJECTED,
                    0.85,
                    "Hash appears in explicitly benign/example context.",
                    evidence,
                )
            return self._verification(
                item,
                VerificationStatus.UNCERTAIN,
                0.55,
                "Hash is syntactically valid but the nearby text does not clearly establish malicious use.",
                evidence,
            )

        # Host artefacts can masquerade as legitimate software names.
        if item.indicator_type in {
            IndicatorType.FILENAME,
            IndicatorType.FILEPATH,
            IndicatorType.PROCESS,
            IndicatorType.SERVICE,
            IndicatorType.MUTEX,
            IndicatorType.SCHEDULED_TASK,
            IndicatorType.REGISTRY,
            IndicatorType.NAMED_PIPE,
        }:
            if in_ioc_section:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.97,
                    "Host observable is listed in an Indicators of Compromise context.",
                    evidence,
                )
            if nearby_label and (nearby_hash or malicious_context):
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.95,
                    f"Host observable is paired with the label {nearby_label!r} in malicious context.",
                    evidence,
                )
            if malicious_action and malicious_context:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.92,
                    "Report describes the host observable being created, executed, installed, or otherwise used by malware.",
                    evidence,
                )
            if nearby_hash and malicious_context:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.90,
                    "Host observable appears beside a cryptographic hash in malicious report context.",
                    evidence,
                )
            if benign_context and not malicious_context:
                return self._verification(
                    item,
                    VerificationStatus.REJECTED,
                    0.85,
                    "Host observable appears only in explicitly benign context.",
                    evidence,
                )

        # Network observables require threat association; merely appearing in a CTI
        # report is not enough.
        if item.indicator_type in {
            IndicatorType.IP,
            IndicatorType.DOMAIN,
            IndicatorType.HOSTNAME,
            IndicatorType.URL,
            IndicatorType.PORT,
            IndicatorType.CERTIFICATE,
            IndicatorType.USER_AGENT,
            IndicatorType.CRYPTO_ADDRESS,
            IndicatorType.CRYPTO_KEY,
            IndicatorType.TOX_ID,
        }:
            if in_ioc_section:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.97,
                    "Network observable is listed in an Indicators of Compromise context.",
                    evidence,
                )
            if local_malicious_context and local_malicious_action:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.92,
                    "Report directly associates the network observable with malicious communication or infrastructure.",
                    evidence,
                )
            if was_defanged and local_malicious_context:
                return self._verification(
                    item,
                    VerificationStatus.CONFIRMED,
                    0.88,
                    "Defanged network observable appears in malicious report context.",
                    evidence,
                )
            if source_match or reference_prefix:
                return self._verification(
                    item,
                    VerificationStatus.REJECTED,
                    0.95,
                    "Network value appears to be report/source/reference infrastructure rather than adversary infrastructure.",
                    evidence,
                )

        if benign_context and not malicious_context:
            return self._verification(
                item,
                VerificationStatus.REJECTED,
                0.82,
                "Nearby text explicitly describes the value as benign or non-malicious.",
                evidence,
            )

        if malicious_context:
            return self._verification(
                item,
                VerificationStatus.CONFIRMED,
                0.76,
                "Candidate appears in malicious CTI context but lacks stronger structural evidence.",
                evidence,
            )

        return self._verification(
            item,
            VerificationStatus.UNCERTAIN,
            0.40,
            "Python-only heuristics could not establish whether the report authors intended this value as an IoC.",
            evidence,
        )

    @staticmethod
    def _verification(
        item: Extraction,
        status: VerificationStatus,
        confidence: float,
        reason: str,
        evidence: str,
    ) -> Verification:
        return Verification(
            candidate_id=item.stable_id,
            status=status,
            confidence=max(0.0, min(1.0, confidence)),
            reason=reason,
            evidence=evidence,
            corrected_category=item.category,
            corrected_indicator_type=item.indicator_type,
        )

    def _nearby_parenthesised_label(self, item: Extraction) -> str | None:
        matches = list(self.PAREN_LABEL_RE.finditer(item.context or ""))
        if not matches:
            return None

        # Prefer a parenthesised label close to the candidate value.
        value_index = (item.context or "").casefold().find(item.value.casefold())
        if value_index < 0:
            return matches[0].group("label").strip()

        best = min(
            matches,
            key=lambda match: abs(match.start() - value_index),
        )
        label = best.group("label").strip()
        return label if 2 <= len(label) <= 80 else None

    @staticmethod
    def _matches_document_source(
        item: Extraction,
        metadata: DocumentMetadata,
    ) -> bool:
        value = item.normalized_value.casefold().rstrip(".")

        source_url = metadata.source_url
        if source_url:
            host = _url_host(source_url)
            if host:
                if item.indicator_type in {
                    IndicatorType.DOMAIN,
                    IndicatorType.HOSTNAME,
                    IndicatorType.EMAIL_DOMAIN,
                } and value == host:
                    return True
                if item.indicator_type is IndicatorType.URL:
                    if _url_host(item.normalized_value) == host:
                        return True

        source = (metadata.cti_source or "").casefold().strip()
        if source and source in (item.context or "").casefold():
            if item.indicator_type in {
                IndicatorType.DOMAIN,
                IndicatorType.HOSTNAME,
                IndicatorType.URL,
                IndicatorType.EMAIL_ADDRESS,
                IndicatorType.EMAIL_DOMAIN,
            }:
                return True

        return False

    @staticmethod
    def _compact_evidence(
        item: Extraction,
        *,
        section: bool,
        label: str | None,
    ) -> str:
        pieces: list[str] = []
        if section:
            hint = str(item.attributes.get("document_section_hint", "")).strip()
            pieces.append(
                f"section={hint or 'Indicators of Compromise context'}"
            )
        if label:
            pieces.append(f"nearby_label={label}")
        if item.context:
            compact = " ".join(item.context.split())
            if len(compact) > 220:
                compact = compact[:217] + "..."
            pieces.append(compact)
        return " | ".join(pieces)


def _url_host(url: str) -> str:
    """Lower-cased hostname of `url`, or "" when it does not parse.

    urlparse raises on some malformed values (e.g. an unbalanced "[" read as
    an IPv6 literal); one odd candidate must not fail the whole report.
    """
    try:
        return (urlparse(url).hostname or "").casefold().rstrip(".")
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Public application API
# ---------------------------------------------------------------------------


def analyse_document(
    path: Path,
    *,
    verbose: int = 0,
    config: ExtractorConfig | None = None,
) -> IoCExtractionResult:
    """Analyse one CTI document without an LLM.

    Returns the same IoCExtractionResult as ioc_extract_llm_fs.analyse_document(),
    with model="python-heuristics" and scope=None (there is no document
    profile without an LLM).
    """
    started = time.perf_counter()

    if verbose >= 1:
        print(f"[INFO] reading {path}", file=sys.stderr, flush=True)

    loaded = DocumentReader.load(path)

    if verbose >= 1:
        print(
            f"[INFO] extracted {len(loaded.text):,} characters",
            file=sys.stderr,
            flush=True,
        )

    metadata = MetadataExtractor().extract(loaded)
    candidates = CTIExtractor(config).extract(loaded.text)

    if verbose >= 1:
        print(
            f"[INFO] found {len(candidates)} candidates",
            file=sys.stderr,
            flush=True,
        )

    verifier = HeuristicVerifier(verbose=verbose)
    verifications = verifier.verify(candidates, metadata)

    result = IoCExtractionResult(
        metadata=metadata,
        items=tuple(
            VerifiedExtraction(candidate, verification)
            for candidate, verification in zip(
                candidates,
                verifications,
                strict=True,
            )
        ),
        # Keep the same field while making the verification source explicit.
        model="python-heuristics",
    )

    if verbose >= 1:
        elapsed = time.perf_counter() - started
        print(
            f"[INFO] completed in {elapsed:.2f}s: "
            f"{len(result.confirmed_iocs())} confirmed, "
            f"{len(result.context_entities())} context, "
            f"{len(result.rejected())} rejected, "
            f"{sum(i.verification.status is VerificationStatus.UNCERTAIN for i in result.items)} uncertain",
            file=sys.stderr,
            flush=True,
        )

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract and heuristically verify CTI indicators using Python only. "
            "No Ollama or LLM is required."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Input .txt/.md/.json/.csv or .pdf report",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write JSON to this path",
    )
    parser.add_argument(
        "--accepted-only",
        action="store_true",
        help="Omit rejected and uncertain candidates from JSON",
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="Do not deduplicate candidates",
    )
    parser.add_argument(
        "--exclude-private-ips",
        action="store_true",
        help="Do not retain private IP addresses",
    )
    parser.add_argument(
        "--context-chars",
        type=int,
        default=300,
        help="Characters of surrounding context on each side (default: 300)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase progress detail; use -vv or -vvv",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    config = ExtractorConfig(
        context_chars=max(100, args.context_chars),
        include_private_ips=not args.exclude_private_ips,
        deduplicate=not args.keep_duplicates,
    )

    try:
        result = analyse_document(
            args.input,
            verbose=args.verbose,
            config=config,
        )
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(
        result.to_dict(include_rejected=not args.accepted_only),
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(
                f"error: unable to write {args.output}: {exc}",
                file=sys.stderr,
            )
            return 2
    else:
        print(rendered, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
