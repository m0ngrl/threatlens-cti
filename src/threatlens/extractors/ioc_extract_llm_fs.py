#!/usr/bin/env python3
"""ThreatLens CTI candidate extraction with LLM/Ollama verification ("full send" engine).

The project's extraction engine: the "llm" engine everywhere a caller offers
a choice. Originally a fork of ioc_extract_llm.py (since removed),
adding one document-level LLM call (DocumentProfiler) per report before
verification.

This module also owns the shared front end. Steps 1-3 below (DocumentReader,
MetadataExtractor, CTIExtractor), the domain model and IoCExtractionResult are
imported by ioc_extract_python.py, so both engines produce the identical
candidate set and the same result object, and differ only in the verifier.
Changes to reading or candidate extraction belong here.

Callers (all go through analyse_document()):

    cli.py                      `threatlens` - inspect one report; prints a
                                summary or writes to_dict() as JSON.
    dashboard/ingest_worker.py  the ingest pipeline behind the dashboard's
                                Ingest page, `threatlens-ingest` and
                                .dev_tools/run_ex_pipeline.py. Hands the
                                IoCExtractionResult in memory to
                                quality_checker.run_from_payload().

Both callers take the Ollama URL, models and [llm] tuning from
threatlens.conf (config.load_config). This module's own __main__ reads the
same file, overridden by its command-line flags.

Pipeline
--------
1. Read a CTI document (text directly; PDF when PyMuPDF is installed).
2. Extract broad IoC candidates using deterministic rules.
3. Extract document metadata using conservative heuristics.
4. Profile the document once: a short structure summary (for disambiguating
   candidate context, e.g. victim tables vs attacker infrastructure) plus a
   strategic/operational/tactical scope classification.
5. Ask the configured Ollama LLM to verify candidates against report context,
   informed by the structure summary from step 4.
6. Derive tactical/operational content flags from the verified candidates and
   combine them with the scope classification into a ScopeAssessment.
7. Return a typed Python object and optionally write JSON.

The deterministic stage is intentionally recall-oriented. The LLM stage decides
whether a candidate is an IoC actually presented by the report authors rather
than a citation, vendor website, social link, bibliography entry, benign example,
or unrelated infrastructure.

Python 3.10+
Optional dependency for PDFs: pymupdf (imported as fitz)
Ollama: settings come from threatlens.conf ([ollama], [models], [llm]); built-in fallbacks when absent
"""

from __future__ import annotations

import argparse
import time
import hashlib
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Domain model — preserves the original category and subtype classification.
# ---------------------------------------------------------------------------


class Category(str, Enum):
    NETWORK = "network"
    HOST = "host"
    EMAIL = "email"
    BEHAVIOUR = "behaviour"
    INTELLIGENCE = "intelligence"


class IndicatorType(str, Enum):
    # Network
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HOSTNAME = "hostname"
    PORT = "port"
    CERTIFICATE = "certificate"
    USER_AGENT = "user_agent"
    CRYPTO_ADDRESS = "crypto_address"
    CRYPTO_KEY = "crypto_key"
    TOX_ID = "tox_id"

    # Host
    HASH = "hash"
    FILENAME = "filename"
    FILEPATH = "filepath"
    REGISTRY = "registry"
    MUTEX = "mutex"
    PROCESS = "process"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"
    NAMED_PIPE = "named_pipe"

    # Email
    EMAIL_ADDRESS = "email_address"
    EMAIL_DOMAIN = "email_domain"
    EMAIL_SUBJECT = "email_subject"
    ATTACHMENT = "attachment"
    EMAIL_HEADER = "email_header"

    # Behaviour
    BEACONING = "beaconing"
    PROCESS_CHAIN = "process_chain"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"

    # Intelligence
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"
    TTP = "ttp"


class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed_ioc"
    REJECTED = "rejected"
    CONTEXT_ENTITY = "context_entity"
    UNCERTAIN = "uncertain"
    NOT_VERIFIED = "not_verified"


class Scope(str, Enum):
    """A CTI report's primary intended audience.

    - TACTICAL: short-term, immediate mechanisms; aimed at operators and
      software tools.
    - OPERATIONAL: aimed at analysts and security teams; discusses tactics
      and campaign patterns currently seen.
    - STRATEGIC: aimed at strategic decision makers; discusses long-term and
      current trends.
    """
    STRATEGIC = "strategic"
    OPERATIONAL = "operational"
    TACTICAL = "tactical"


'''Candidate topics

| Topic                             | What the report is primarily about                        | Typical information / IoCs                                                 |
| --------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Malware Analysis**              | Analysis of a malware family or sample                    | Hashes, filenames, domains, IPs, mutexes, registry keys, processes         |
| **Threat Actor / APT**            | Activity attributed to a particular group                 | Infrastructure, malware, tools, TTPs, targeted organisations               |
| **Campaign / Operation**          | A coordinated malicious campaign                          | Domains, URLs, phishing infrastructure, malware, victims, timeline         |
| **Phishing / Social Engineering** | Phishing or credential-theft activity                     | Sender addresses, subjects, URLs, domains, attachments                     |
| **Ransomware**                    | A ransomware family or intrusion campaign                 | Hashes, extensions, ransom notes, C2, initial-access methods               |
| **Vulnerability Exploitation**    | Exploitation of a particular vulnerability                | CVEs, affected products, exploit behaviour, scanning IPs                   |
| **Exploit / Zero-Day Analysis**   | Technical investigation of an exploit                     | CVEs, payloads, vulnerable versions, exploitation techniques               |
| **Botnet**                        | Botnet infrastructure and activity                        | C2 IPs/domains, ports, malware hashes, protocols                           |
| **Command-and-Control (C2)**      | Attacker communication infrastructure                     | Domains, IPs, URLs, certificates, ports, user agents                       |
| **Infrastructure Analysis**       | Malicious infrastructure operated by an actor             | IPs, domains, hosting providers, certificates, ASN information             |
| **Initial Access**                | How attackers gain entry                                  | Phishing, exposed services, exploits, stolen credentials                   |
| **Credential Theft**              | Credential-stealing malware or operations                 | Phishing domains, credential-stealer malware, exfiltration endpoints       |
| **Data Theft / Exfiltration**     | Theft or transfer of information                          | Exfiltration domains/IPs, protocols, cloud services, tools                 |
| **Persistence**                   | How attackers maintain access                             | Services, scheduled tasks, registry keys, accounts, startup mechanisms     |
| **Lateral Movement**              | Movement between systems after compromise                 | Accounts, SMB/RDP activity, tools, processes, remote services              |
| **Privilege Escalation**          | Gaining elevated privileges                               | Exploits, CVEs, tools, processes, configuration weaknesses                 |
| **Living-off-the-Land (LOLBins)** | Abuse of legitimate system utilities                      | PowerShell, rundll32, certutil, WMI, command lines                         |
| **Web Attack / Web Shell**        | Compromise of web-facing systems                          | Web-shell filenames, URLs, IPs, commands, hashes                           |
| **Supply-Chain Attack**           | Compromise through software/vendor dependencies           | Packages, hashes, domains, affected software, certificates                 |
| **DDoS**                          | Distributed denial-of-service activity                    | Botnet nodes, IPs, ports, protocols, attack methods                        |
| **Cryptojacking / Cryptomining**  | Unauthorised cryptocurrency mining                        | Wallet addresses, mining pools, domains, binaries, processes               |
| **Mobile Threats**                | Android/iOS malware or malicious applications             | App/package names, hashes, C2 domains, certificates                        |
| **Cloud Threats**                 | Attacks targeting cloud infrastructure                    | Cloud accounts, IAM behaviour, API calls, IPs, tools                       |
| **ICS / OT Threats**              | Threats against industrial systems                        | Protocols, devices, malware, PLC activity, infrastructure                  |
| **Sector-Specific Threats**       | Threats targeting a particular industry                   | Actors, campaigns, malware and TTPs affecting that sector                  |
| **Geographic Threat Activity**    | Threats targeting a country or region                     | Actors, campaigns, infrastructure, targeted organisations                  |
| **TTP / Behaviour Analysis**      | Attacker techniques rather than a specific malware family | MITRE ATT&CK techniques, processes, commands, behavioural patterns         |
| **Threat Landscape / Trends**     | Broad overview of activity over a period                  | Statistics, actors, malware families, vulnerabilities, campaigns           |
| **Incident / Breach Analysis**    | Investigation of a particular compromise                  | Timeline, entry point, lateral movement, malware, infrastructure           |
| **Detection / Hunting**           | How to identify particular malicious activity             | YARA/Sigma rules, hashes, domains, processes, behavioural indicators       |
| **Emerging Threat**               | Newly observed malicious activity                         | New malware, infrastructure, vulnerabilities, techniques                   |
| **Dark Web / Criminal Ecosystem** | Underground marketplaces or criminal groups               | Actor aliases, services, malware, infrastructure, cryptocurrency addresses |






'''





@dataclass(frozen=True, slots=True)             #Adding new metadata type for CTI report overall category
class DocumentMetadata:
    filename: str
    title: str | None = None
    #topic: str | None = None
    authors: tuple[str, ...] = ()
    cti_source: str | None = None
    source_url: str | None = None
    publish_date: str | None = None
    file_sha256: str | None = None
    extraction_method: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["authors"] = list(self.authors)
        return data


@dataclass(frozen=True, slots=True)
class Extraction:
    category: Category
    indicator_type: IndicatorType
    value: str
    normalized_value: str
    start: int
    end: int
    context: str
    method: str
    attributes: Mapping[str, str | int | float | bool] = field(default_factory=dict)

    @property
    def stable_id(self) -> str:
        material = (
            f"{self.category.value}|{self.indicator_type.value}|"
            f"{self.normalized_value}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.stable_id,
            "category": self.category.value,
            "indicator_type": self.indicator_type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "start": self.start,
            "end": self.end,
            "context": self.context,
            "method": self.method,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class Verification:
    candidate_id: str
    status: VerificationStatus
    confidence: float
    reason: str
    evidence: str = ""
    corrected_category: Category | None = None
    corrected_indicator_type: IndicatorType | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence": self.evidence,
            "corrected_category": (
                self.corrected_category.value if self.corrected_category else None
            ),
            "corrected_indicator_type": (
                self.corrected_indicator_type.value
                if self.corrected_indicator_type
                else None
            ),
        }


@dataclass(frozen=True, slots=True)
class VerifiedExtraction:
    extraction: Extraction
    verification: Verification

    @property
    def accepted(self) -> bool:
        return self.verification.status in {
            VerificationStatus.CONFIRMED,
            VerificationStatus.CONTEXT_ENTITY,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.extraction.to_dict()
        data["verification"] = self.verification.to_dict()
        data["accepted"] = self.accepted
        return data


@dataclass(frozen=True, slots=True)
class DocumentProfile:
    """One-shot, document-level read: structure notes plus a scope judgement.

    Produced before candidate verification runs (it only needs headings/an
    excerpt, not confirmed-IoC counts), so structure_summary can be threaded
    into every verification batch as disambiguating context - one document
    read serving both purposes instead of two overlapping LLM calls.
    """
    structure_summary: str
    scope: Scope
    scope_reason: str


@dataclass(frozen=True, slots=True)
class ScopeAssessment:
    primary_scope: Scope
    reason: str
    structure_summary: str
    has_tactical_content: bool
    has_operational_content: bool
    has_strategic_content: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_scope": self.primary_scope.value,
            "reason": self.reason,
            "structure_summary": self.structure_summary,
            "has_tactical_content": self.has_tactical_content,
            "has_operational_content": self.has_operational_content,
            "has_strategic_content": self.has_strategic_content,
        }


@dataclass(frozen=True, slots=True)
class IoCExtractionResult:
    metadata: DocumentMetadata
    items: tuple[VerifiedExtraction, ...]
    model: str | None = None
    scope: ScopeAssessment | None = None

    def confirmed_iocs(self) -> list[VerifiedExtraction]:
        return [
            item
            for item in self.items
            if item.verification.status is VerificationStatus.CONFIRMED
        ]

    def context_entities(self) -> list[VerifiedExtraction]:
        return [
            item
            for item in self.items
            if item.verification.status is VerificationStatus.CONTEXT_ENTITY
        ]

    def rejected(self) -> list[VerifiedExtraction]:
        return [
            item
            for item in self.items
            if item.verification.status is VerificationStatus.REJECTED
        ]

    def by_category(self, *, accepted_only: bool = True) -> dict[str, list[dict[str, Any]]]:
        grouped = {category.value: [] for category in Category}
        for item in self.items:
            if accepted_only and not item.accepted:
                continue
            category = (
                item.verification.corrected_category
                or item.extraction.category
            )
            grouped[category.value].append(item.to_dict())
        return grouped

    def to_dict(self, *, include_rejected: bool = True) -> dict[str, Any]:
        selected = self.items if include_rejected else tuple(i for i in self.items if i.accepted)
        return {
            "metadata": self.metadata.to_dict(),
            "verification_model": self.model,
            "scope": self.scope.to_dict() if self.scope else None,
            "summary": {
                "candidate_count": len(self.items),
                "confirmed_ioc_count": len(self.confirmed_iocs()),
                "context_entity_count": len(self.context_entities()),
                "rejected_count": len(self.rejected()),
                "uncertain_count": sum(
                    i.verification.status is VerificationStatus.UNCERTAIN
                    for i in self.items
                ),
            },
            "indicators": [item.to_dict() for item in selected],
            "accepted_by_category": self.by_category(accepted_only=True),
        }


# ---------------------------------------------------------------------------
# Document reading and metadata extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoadedDocument:
    path: Path
    text: str
    file_sha256: str
    embedded_metadata: Mapping[str, str] = field(default_factory=dict)


class DocumentReader:
    TEXT_SUFFIXES = {".txt", ".md", ".log", ".csv", ".json"}

    # Markdown source rendered to PDF commonly leaves its own escape
    # backslashes (\[, \], \(, \), \{, \}) in the extracted text layer, and
    # the renderer sometimes wraps the line right after that backslash. That
    # splits a defanged indicator such as "example\[.\]com" into
    # "example\" + "\n" + "[.\]com", which no longer looks like a domain to
    # any downstream regex. Dropping the backslash (and any whitespace before
    # the bracket it was escaping) reassembles it as "example[.]com".
    #
    # "_" is included alongside the brackets for the same reason: Markdown
    # escapes a literal underscore as "\_" so it isn't misread as an
    # emphasis marker (e.g. a mutex name "cfgmgr_mtx" written as
    # "cfgmgr\_mtx" in the source), and a naive markdown-to-PDF renderer
    # that doesn't itself process the escape leaves that backslash sitting
    # in the extracted text right in the middle of the real artifact name.
    _ESCAPED_BRACKET_RE = re.compile(r"\\\s*(?=[\[\]\(\)\{\}_])")

    # The same Markdown source can also escape a literal backslash itself as
    # "\\", which a renderer that doesn't collapse the escape leaves as a
    # literal doubled backslash in the PDF text - turning a real Windows
    # path like "%AppData%\Local\DCFG\..." into "%AppData%\\Local\\DCFG\\...".
    # Every downstream path regex expects a single separator, so a doubled
    # one silently breaks the match (typically losing the %ENVVAR% root
    # entirely). Collapsed only when a word character (or the "%" that
    # closes an env-var reference) precedes the pair, so a genuine UNC path
    # opener ("\\server\share", preceded by whitespace/quote/start-of-line)
    # is left alone.
    _DOUBLED_BACKSLASH_RE = re.compile(r"(?<=[\w%])\\\\(?!\\)")

    # Obfuscated PowerShell/JS commonly builds a string piecemeal, e.g.
    # $h='memsho'+'wblob[.]forum', specifically to keep the real value out of
    # any single string literal. Regex extraction over the raw text only ever
    # sees the literals as written, so it picks up a meaningless substring of
    # one piece ("wblob[.]forum") instead of the value the script actually
    # builds and uses ("memshowblob[.]forum"). Collapsing adjacent
    # same-quote literal concatenation before extraction runs makes that
    # value appear as the single token it decodes to.
    _CONCAT_LITERAL_RES = (
        re.compile(r"'([^'\r\n]{0,200})'\s*\+\s*'([^'\r\n]{0,200})'"),
        re.compile(r'"([^"\r\n]{0,200})"\s*\+\s*"([^"\r\n]{0,200})"'),
    )

    # A PDF page/column can wrap a hyphenated technical token right at the
    # hyphen (e.g. a query-string value "scheduler-once" rendered as
    # "scheduler-\nonce"), silently truncating it for every downstream regex
    # since none of them span a line break. Removing just the newline (and
    # keeping the hyphen) reassembles the original token without having to
    # guess whether the hyphen was "real" - it's kept either way.
    #
    # The lookahead accepts any letter *or digit* after the break, not just
    # lowercase: a hyphenated domain wrapped as "remax-\n1stchoice.com" loses
    # its "remax-" prefix entirely if digits aren't allowed, and an
    # ALL-CAPS/mixed-case forum-thread slug wrapped as "DEFENSE-DRONE-\nDEAL"
    # or "Regulatory-\nAuthority-..." is just as real a continuation as a
    # lowercase one - prose that happens to end a sentence on a literal
    # trailing hyphen right at a line break is rare enough that the recall
    # gained here outweighs it.
    _LINE_WRAP_HYPHEN_RE = re.compile(r"-\n(?=[A-Za-z0-9])")

    @classmethod
    def _normalise_text(cls, text: str) -> str:
        text = cls._LINE_WRAP_HYPHEN_RE.sub("-", text)
        text = cls._ESCAPED_BRACKET_RE.sub("", text)
        text = cls._DOUBLED_BACKSLASH_RE.sub(lambda m: "\\", text)
        for pattern in cls._CONCAT_LITERAL_RES:
            quote = pattern.pattern[0]
            for _ in range(6):
                new_text, count = pattern.subn(
                    lambda m: quote + m.group(1) + m.group(2) + quote, text
                )
                if count == 0:
                    break
                text = new_text
        return text

    @staticmethod
    def load(path: Path) -> LoadedDocument:
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        suffix = path.suffix.lower()

        if suffix == ".pdf":
            try:
                import fitz  # type: ignore
            except ImportError as exc:
                raise RuntimeError(
                    "PDF input requires PyMuPDF: python -m pip install pymupdf"
                ) from exc

            document = fitz.open(stream=raw, filetype="pdf")
            text = "\n\n".join(page.get_text("text") for page in document)
            text = DocumentReader._normalise_text(text)
            metadata = {
                str(k): str(v).strip()
                for k, v in (document.metadata or {}).items()
                if v
            }
            return LoadedDocument(path, text, digest, metadata)

        if suffix in DocumentReader.TEXT_SUFFIXES or not suffix:
            text = DocumentReader._normalise_text(raw.decode("utf-8"))
            return LoadedDocument(path, text, digest, {})

        raise ValueError(f"Unsupported input type: {suffix or '<none>'}")


class MetadataExtractor:
    URL_RE = re.compile(
        r"\b(?:https?://)?"
        r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
        r"[A-Z]{2,63}"
        r"(?:/[^\s<>\"')]+)?",
        re.IGNORECASE,
    )

    # Filenames like "certutil.exe", "gojoke.png", or "readme.txt" match
    # URL_RE's label(.label)+TLD shape (the "TLD" being the file extension),
    # so a candidate ending in a known non-domain extension is rejected
    # rather than treated as a hostname. This check happens inside
    # _source_url below against the module-level NON_DOMAIN_EXTENSIONS set
    # (defined later in this file, alongside the RULES/FILENAME machinery
    # that needs the identical distinction) rather than a separate list
    # here - a prior, narrower local copy of this list didn't include plain
    # document/text extensions like "txt"/"js", so a stray filename such as
    # "r3adm3.txt" or "database.js" mentioned in body text could win the
    # "first public URL" scan and get reported as the document's source_url.
    # "com" is deliberately excluded from that shared set too: it is also
    # the single most common TLD, so treating it as a non-domain extension
    # would reject nearly every ".com" domain.


    DATE_PATTERNS = (
        re.compile(r"\b(20\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01]))\b"),
        re.compile(
            r"\b((?:0?[1-9]|[12]\d|3[01])\s+"
            r"(?:January|February|March|April|May|June|July|August|September|October|November|December)"
            r"\s+20\d{2})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b((?:January|February|March|April|May|June|July|August|September|October|November|December)"
            r"\s+(?:0?[1-9]|[12]\d|3[01]),?\s+20\d{2})\b",
            re.IGNORECASE,
        ),
    )
    # Archived/scraped CTI pages (e.g. "Published: 2026-08-02 · Archived:
    # 2026-08-07 02:00:24 UTC") commonly sit right next to an "Archived"
    # timestamp, and the PDF's own embedded creationDate is usually that same
    # archival/render time rather than the article's real publish date. An
    # explicit "Published:" label is a stronger signal than either, so it is
    # searched for separately and given priority.
    PUBLISHED_LABEL_RE = re.compile(r"\bpublished\b\s*(?:on|date)?\s*[:\-]?\s*(.{0,40})", re.IGNORECASE)

    AUTHOR_RE = re.compile(
        r"^(?:authors?|written by|prepared by|researchers?)\s*[:\-]\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    )
    # No leading-capital requirement on the name itself: some CTI sources
    # byline a lowercase handle/pseudonym (e.g. "By ameer"), and the
    # terminator below (blank line, or a Published/Posted/Archived/Updated
    # label) already keeps this from running on into unrelated prose.
    BYLINE_RE = re.compile(
        r"^By\s+(.{1,250}?)(?:\n\s*\n|\n(?:Published|Posted|Archived|Updated)\b)",
        re.MULTILINE | re.DOTALL,
    )
    SOURCE_RE = re.compile(
        r"^(?:source|published by|publisher|organisation|organization)\s*[:\-]\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    )
    TITLE_LABEL_RE = re.compile(r"^title\s*[:\-]\s*(.+)$", re.IGNORECASE | re.MULTILINE)

    def extract(self, doc: LoadedDocument) -> DocumentMetadata:
        text = doc.text
        # Title inference is positional (a title is one of the first few
        # headings of the document), so it alone stays scoped to the start.
        # Every other heuristic scans the full document: CTI reports commonly
        # place their citation/source line, or a "First Seen"-style date, on
        # a closing page far past any fixed prefix.
        lead_lines = [" ".join(line.split()) for line in text[:12000].splitlines()]
        useful_lines = [line for line in lead_lines if 4 <= len(line) <= 240]
        embedded = doc.embedded_metadata

        title = self._first_nonempty(
            embedded.get("title"),
            self._group(self.TITLE_LABEL_RE, text),
            self._infer_title(useful_lines),
        )
        authors = self._authors(
            embedded.get("author"),
            self._group(self.AUTHOR_RE, text),
            self._byline(text),
        )
        source_url = self._source_url(text)
        source = self._first_nonempty(
            self._source_label(text),
            embedded.get("producer"),
            embedded.get("creator"),
            self._organisation_from_url(source_url),
        )
        publish_date = self._first_nonempty(
            self._published_label_date(text),
            self._normalise_date(embedded.get("creationDate")),
            self._find_date(text),
        )

        methods = {
            "title": "embedded/label/first-heading heuristic",
            "authors": "embedded/label heuristic",
            "cti_source": "label/embedded/source-domain heuristic",
            "source_url": "first public URL heuristic",
            "publish_date": "embedded/date-pattern heuristic",
        }
        return DocumentMetadata(
            filename=doc.path.name,
            title=title,
            authors=authors,
            cti_source=source,
            source_url=source_url,
            publish_date=publish_date,
            file_sha256=doc.file_sha256,
            extraction_method=methods,
        )

    @staticmethod
    def _group(pattern: re.Pattern[str], text: str) -> str | None:
        match = pattern.search(text)
        return match.group(1).strip() if match else None

    def _source_label(self, text: str) -> str | None:
        """Find a "Source:"-style label whose value looks like a publisher, not an IoC.

        CTI reports often reuse the word "Source" inside IoC tables (e.g.
        "Source: C:\\Users\\...\\payload.exe" describing a file-copy operation),
        which the generic SOURCE_RE would otherwise mistake for the document's
        own publisher/organisation line.
        """
        for match in self.SOURCE_RE.finditer(text):
            value = match.group(1).strip()
            if value and not self._looks_like_path(value):
                return value
        return None

    @staticmethod
    def _looks_like_path(value: str) -> bool:
        return bool(
            re.match(r"^[A-Za-z]:\\", value)
            or value.startswith("\\\\")
            or value.startswith("/")
            or "\\" in value
        )

    def _byline(self, text: str) -> str | None:
        match = self.BYLINE_RE.search(text)
        if not match:
            return None
        joined = " ".join(match.group(1).split())
        joined = re.sub(r"^(?:by\s+)+", "", joined, flags=re.IGNORECASE)
        return joined or None

    @staticmethod
    def _first_nonempty(*values: str | None) -> str | None:
        for value in values:
            if value and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _infer_title(lines: Sequence[str]) -> str | None:
        blocked = ("http://", "https://", "copyright", "table of contents")
        for line in lines[:40]:
            lowered = line.lower()
            if any(token in lowered for token in blocked):
                continue
            # A bare byline date ("February 16, 2022") satisfies the
            # length/word-count check below just as well as a real title
            # does, and commonly sits on its own line right above the
            # actual headline - skip it explicitly rather than returning it.
            if any(p.fullmatch(line) for p in MetadataExtractor.DATE_PATTERNS):
                continue
            if 8 <= len(line) <= 180 and len(line.split()) >= 3:
                return line
        return None

    @staticmethod
    def _authors(*values: str | None) -> tuple[str, ...]:
        merged = next((v for v in values if v and v.strip()), None)
        if not merged:
            return ()
        parts = re.split(r"\s*(?:,|;|\band\b|\&)\s*", merged)
        return tuple(dict.fromkeys(p.strip() for p in parts if 2 <= len(p.strip()) <= 100))

    def _source_url(self, text: str) -> str | None:
        # A schemeless match ("word.word", the shape URL_RE also accepts) is
        # far weaker evidence of being a real URL than one with an explicit
        # http(s):// prefix - it's the same shape as a detection-signature
        # name ("ACM.Untrst-RunSys!g1" contains "ACM.Untrst") or any other
        # dotted non-domain token whose final segment isn't on the
        # NON_DOMAIN_EXTENSIONS blacklist. Scheme-bearing matches are
        # returned first (in document order); a schemeless one is only used
        # as a fallback if no scheme-bearing match exists at all, rather
        # than letting document order alone decide.
        schemeless_fallback: str | None = None
        for match in self.URL_RE.finditer(text):
            value = match.group(0).rstrip(".,;:")
            has_scheme = bool(re.match(r"^https?://", value, re.IGNORECASE))

            parse_value = value if has_scheme else "https://" + value
            host = (urlparse(parse_value).hostname or "").lower()
            tld = host.rsplit(".", 1)[-1] if host else ""

            if (
                host
                and host not in {"localhost", "127.0.0.1"}
                and tld not in NON_DOMAIN_EXTENSIONS
            ):
                if has_scheme:
                    return value
                if schemeless_fallback is None:
                    schemeless_fallback = value

        return schemeless_fallback

    @staticmethod
    def _organisation_from_url(url: str | None) -> str | None:
        if not url:
            return None
        host = (urlparse(url).hostname or "").lower().removeprefix("www.")
        if not host:
            return None
        label = host.split(".")[0].replace("-", " ")
        return label.title() if label else None

    def _published_label_date(self, text: str) -> str | None:
        match = self.PUBLISHED_LABEL_RE.search(text)
        if not match:
            return None
        snippet = match.group(1)
        for pattern in self.DATE_PATTERNS:
            date_match = pattern.search(snippet)
            if date_match:
                return self._normalise_date(date_match.group(1)) or date_match.group(1)
        return None

    def _find_date(self, text: str) -> str | None:
        for pattern in self.DATE_PATTERNS:
            match = pattern.search(text)
            if match:
                return self._normalise_date(match.group(1)) or match.group(1)
        return None

    @staticmethod
    def _normalise_date(value: str | None) -> str | None:
        if not value:
            return None
        cleaned = value.strip()
        if cleaned.startswith("D:") and len(cleaned) >= 10:
            cleaned = cleaned[2:10]
            try:
                return datetime.strptime(cleaned, "%Y%m%d").date().isoformat()
            except ValueError:
                return None
        formats = (
            "%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d",
            "%d %B %Y", "%B %d, %Y", "%B %d %Y",
        )
        for fmt in formats:
            try:
                parsed = datetime.strptime(cleaned, fmt).date()
                if date(1990, 1, 1) <= parsed <= datetime.now(UTC).date():
                    return parsed.isoformat()
            except ValueError:
                continue
        return None


# ---------------------------------------------------------------------------
# Candidate extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RegexRule:
    category: Category
    indicator_type: IndicatorType
    pattern: re.Pattern[str]
    method: str
    group: str | int = "value"


def _compile(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Shared defanging tokens. Moved above RULES (rather than declared once near
# DOMAIN_RE, as originally) because both the URL and email rules need them
# too: reports defang a scheme's colon ("http[:]//") independently of - and
# not always consistently with - how they defang the dots in the rest of the
# same document.
DEFANGED_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\})"
DEFANGED_COLON = r"(?::|\[:\]|\(:\)|\{:\})"
DEFANGED_AT = r"(?:@|\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\})"

# Extensions FILENAME recognises as "this token is a file". Also used by
# _extract_domains to reject a domain-shaped match whose final label is
# actually a file extension (e.g. "msci.Cng", "Setup.Dat") rather than a TLD -
# kept as one set so the two can't drift out of sync the way they previously
# did (the old domain-side blacklist only knew a handful of extensions the
# filename side already recognised, so anything past that handful - .dat,
# .hwp, .cng, .lock, ... - was extracted as a bogus network/domain candidate
# instead of, or as well as, a host/filename one).
FILE_EXTENSIONS: frozenset[str] = frozenset({
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse",
    "hta", "msi", "lnk", "docm", "xlsm", "pptm", "jar", "elf", "bin",
    "dat", "tmp", "zip", "rar", "7z", "hwp", "cng", "lock",
    # "txt" is the one plain-document extension included here rather than
    # only in the broader NON_DOMAIN_EXTENSIONS set below: ransomware notes
    # are overwhelmingly named "<something>.txt" ("r3adm3.txt", "readme.txt",
    # "DECRYPT_INSTRUCTIONS.txt"), and that filename is routinely the
    # report's own stated host artifact - unlike a bare ".doc"/".pdf"/".csv"
    # mention, which is essentially always a citation or generic reference
    # rather than the artifact itself.
    "txt",
})
# Document/office formats a report cites (source PDFs, attached documents)
# that FILENAME doesn't itself need to recognise as a droppable payload, but
# that _extract_domains still needs to reject the same way.
NON_DOMAIN_EXTENSIONS: frozenset[str] = FILE_EXTENSIONS | {
    "doc", "docx", "pdf", "json", "csv", "xml",
}
# Deliberately NOT extended with .php/.aspx/.ashx despite those also causing
# domain false positives (e.g. a URL path segment like ".../get.php" getting
# re-matched by DOMAIN_RE as a bare "domain"): all three are exactly the
# extensions real webshells use, and CTI reports routinely name a dropped
# webshell by its bare filename (e.g. "list.js.php", "password.js.php" listed
# as dropped-webshell artifacts in an ET rule name) - excluding the extension
# outright would stop that genuine artifact from ever becoming a candidate at
# all, trading a real recall loss for a modest cut in an already
# LLM-verifier-caught false-positive rate.
# A file's stem is normally letters/digits/punctuation with no dot (a dot
# starts the extension). The one deliberate exception is a version-style
# fragment such as "26.4.4" or "v1.0" - a dot flanked by digits on both
# sides - which decoy/report filenames commonly contain; allowing "." in the
# stem unconditionally would instead let it run on across real sentence
# breaks (e.g. turning "...C2 server. Then it drops payload.exe" into one
# giant bogus filename).
#
# Parens are only allowed as a complete "(...)" unit, not as bare "(" / ")"
# characters, for the same reason: decoy filenames legitimately use a
# balanced parenthetical ("Policy Update (4).LNK", "(RESUME)_....LNK"), but
# a bare "(" with no match nearby is instead almost always a citation
# opening in the surrounding sentence (e.g. "Parameter 2: The address of
# Xctdoor (roaming.Dat) to be used..."), and letting the stem swallow it
# unconditionally lets it run backwards across the whole clause up to that
# "(" looking for the real filename that starts right after it.
#
# Space is deliberately NOT in this default stem: a report mentions the vast
# majority of filenames inline, mid-sentence ("...used the Regsvr32.Exe
# process to execute..."), and a stem that tolerates spaces there has no way
# to tell "a real multi-word name" apart from "ordinary words followed by a
# short real filename" - it just keeps extending backwards through the
# sentence until the {1,100} budget or a disallowed character stops it (e.g.
# "The binary is a 64-bit Windows PE driver named smuol.sys" was captured
# whole instead of just "smuol.sys"). FILENAME_RE below only allows spaces
# via _FILENAME_STEM_SPACED, and only for a candidate that occupies its own
# line - see there for why that's the actual, reliable signal a genuine
# multi-word decoy name gives that plain prose doesn't.
_FILENAME_STEM = r"(?:[\w@+~$*&'-]|\([^()\r\n]{0,60}\)|(?<=\d)\.(?=\d))"
# Same stem, but with an embedded space allowed - used only for the
# whole-line FILENAME_RE branch below. A decoy-filename list in a CTI report
# is written one name per line ("Refund Application 1.LNK",
# "Security Precautions for Using *** Due to the Rise in Phishing
# Sites.LNK", ...), so requiring the match to span the *entire* line (see
# FILENAME_RE's first alternative) is a cheap, reliable way to allow those
# long multi-word names in full without reopening the mid-sentence
# prose-swallowing bug the space caused when it was in the default stem.
_FILENAME_STEM_SPACED = r"(?:[\w@+~$*&' -]|\([^()\r\n]{0,60}\)|(?<=\d)\.(?=\d))"
# Double-extension masquerade (e.g. "Invoice.Docx.Lnk", "Report.Pdf.Scr") is a
# standard phishing-decoy technique: the real, droppable extension sits after
# a document-format extension that's meant to catch the victim's eye instead.
# Allowing exactly one such extension before the mandatory real one lets
# FILENAME_RE see the whole token rather than failing to match at all, since
# _FILENAME_STEM's dot-in-stem exception only covers digit-flanked dots.
_MASQUERADE_EXTENSIONS: tuple[str, ...] = tuple(sorted(NON_DOMAIN_EXTENSIONS - FILE_EXTENSIONS))
_FILE_EXT_ALT = "|".join(sorted(FILE_EXTENSIONS))

# Characters a Windows path segment excludes. Beyond the actual
# filesystem-reserved set (\/:*?"<>|), curly quotes are excluded too: CTI
# prose routinely wraps a quoted path in “smart quotes” rather than straight
# ones (e.g. "the path “%TEMP%\\foo.exe” to disguise itself"), and
# without this a path's negated trailing segment - which has no other reason
# to stop - runs straight through the closing quote and keeps consuming the
# sentence that follows. "&" is excluded too: it's a batch/cmd command
# separator ("cmd1 & cmd2"), never a legitimate path character, and a report
# quoting an obfuscated command line (e.g. "...\96fd1e29-...-2c7e2f78ae48 &
# r^undl^l32 gmwmvymdzgqgptwvbslq.dll") otherwise let the lazy
# extension-first branch below run straight past the first command's end
# looking for a ".dll"/".exe"/... that actually belongs to a second, separate
# command, merging both into one bogus path.
_PATH_CHAR = r"[^\\/:*?\"<>|\r\n“”‘’&]"
# Same exclusions as _PATH_CHAR, plus space. Used only for a path's
# *extensionless* fallback tail (below, the branch tried when the
# lazy-up-to-a-known-extension alternative finds none nearby): that branch
# has nothing else bounding it, since there's no extension for it to stop
# at, so with space allowed it ran straight through the end of the real
# path and kept consuming the rest of the sentence (e.g.
# "C:\Windows\SysWOW64\drivers to exploit this bug as a vaccine" was
# captured whole instead of stopping after "drivers"). The lazy
# extension-first branch is left alone - it already stops exactly at a
# recognised extension, so a space before it (e.g. a "Program Files"-style
# directory name) is fine there.
_PATH_CHAR_NOSPACE = r"[^\\/:*?\"<>|\r\n“”‘’ &]"

RULES: tuple[RegexRule, ...] = (
    RegexRule(Category.NETWORK, IndicatorType.URL,
              _compile(rf"(?P<value>\b(?:hxxps?|https?|ftp){DEFANGED_COLON}//[^\s<>'\"\)}}]+)"), "regex:url"),
    RegexRule(Category.NETWORK, IndicatorType.IP,
              _compile(rf"(?P<value>(?<![\w:])(?:\d{{1,3}}{DEFANGED_DOT}){{3}}\d{{1,3}}(?![\w:]))"), "regex:ipv4"),
    RegexRule(Category.NETWORK, IndicatorType.IP,
              _compile(r"(?P<value>(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![\w:]))"), "regex:ipv6"),
    RegexRule(Category.NETWORK, IndicatorType.PORT,
              _compile(r"\b(?:port|tcp|udp|destination port|source port)\s*(?:[:=/]|is|was|of)?\s*(?P<value>\d{1,5})\b"), "regex:labelled-port"),
    RegexRule(Category.NETWORK, IndicatorType.USER_AGENT,
              _compile(r"\b(?:user[- ]agent|ua string)\s*(?:[:=]|was|is)?\s*(?P<value>\"[^\"\r\n]{3,300}\"|'[^'\r\n]{3,300}'|[^\r\n]{3,300})"), "regex:user-agent"),
    RegexRule(Category.NETWORK, IndicatorType.CERTIFICATE,
              _compile(r"\b(?:certificate|cert|ja3s?|tls fingerprint|ssl fingerprint)\s*(?:fingerprint|hash)?\s*(?:[:=]|is|was)?\s*(?P<value>[a-f0-9:]{32,128})\b"), "regex:certificate-fingerprint"),
    # EVM-style (Ethereum/Polygon/BSC/...) contract or wallet addresses are
    # "0x" + 40 hex chars - the same length as a SHA-1 hash. Matched as its
    # own rule (rather than left to the generic sha1 rule below, which is
    # given a lookbehind that skips the "0x"-prefixed case) so blockchain C2
    # infrastructure is typed correctly instead of reported as a file hash.
    RegexRule(Category.NETWORK, IndicatorType.CRYPTO_ADDRESS,
              _compile(r"(?<![A-Za-z0-9])(?P<value>0x[a-f0-9]{40})(?![A-Za-z0-9])"), "regex:evm-address"),
    # A hex blob explicitly labelled as a key (AES/encryption/decryption/
    # hardcoded key, etc.) is key material, not a file hash, even though it
    # is frequently the same length as a SHA-256/512 hash.
    RegexRule(Category.NETWORK, IndicatorType.CRYPTO_KEY,
              _compile(r"\b(?:AES(?:-?\d{2,3})?(?:-CBC|-GCM|-ECB|-CTR)?|encryption|decryption|cipher|hardcoded)\b[^.\r\n]{0,30}?\bkey\b\s*(?:[:=]|is|was|of)?\s*[\"'“”]?\s*(?P<value>[a-f0-9]{32,128})\b"), "regex:labelled-crypto-key"),
    # A Tox ID (used by threat actors as a contact/negotiation identifier
    # on Data Leak Sites) is a fixed 76-character hex string - distinct
    # from every hash length the HASH rules below recognise (32/40/64/128).
    RegexRule(Category.NETWORK, IndicatorType.TOX_ID,
              _compile(r"\bTOX(?:\s+ID)?\s*(?:[:=]|is|was)?\s*(?P<value>[A-F0-9]{76})\b"), "regex:labelled-tox-id"),

    RegexRule(Category.HOST, IndicatorType.HASH, _compile(r"(?<![a-f0-9])(?P<value>[a-f0-9]{128})(?![a-f0-9])"), "regex:sha512"),
    RegexRule(Category.HOST, IndicatorType.HASH, _compile(r"(?<![a-f0-9])(?P<value>[a-f0-9]{64})(?![a-f0-9])"), "regex:sha256"),
    RegexRule(Category.HOST, IndicatorType.HASH, _compile(r"(?<![a-f0-9])(?<!0x)(?P<value>[a-f0-9]{40})(?![a-f0-9])"), "regex:sha1"),
    RegexRule(Category.HOST, IndicatorType.HASH, _compile(r"(?<![a-f0-9])(?P<value>[a-f0-9]{32})(?![a-f0-9])"), "regex:md5"),
    # The trailing segment of the two Unix-style alternatives additionally
    # allows "?=&$%" so a C2 request path keeps its query string (e.g.
    # "/Res/get-command.Php?Uid=$gUid") instead of being cut off at the "?".
    # Windows/UNC paths deliberately keep the stricter class - "?" etc. are
    # not valid in filesystem paths on that platform.
    #
    # The drive-letter/%VAR%/UNC final segment tries two branches in order: a
    # lazy run up to a recognised extension (".exe", ".cng", ...) first, so
    # a path that happens to end in one stops exactly there rather than
    # continuing into the sentence that follows (e.g. "...\msci.Cng file
    # (data used...)" stops at ".Cng", not at "(data"); only when no such
    # extension is found nearby does it fall back to the old
    # greedy-until-forbidden-char behaviour (e.g. a path ending in a bare
    # directory name with no extension). That fallback uses
    # _PATH_CHAR_NOSPACE rather than _PATH_CHAR - unlike the extension-first
    # branch, it has nothing to stop at, so with space allowed it ran
    # straight through the actual end of the path and swallowed the rest of
    # the sentence (e.g. "\device\czx9umpTReqbOOKF and a symbolic link with
    # the path \??" was captured as one filepath instead of stopping after
    # "czx9umpTReqbOOKF").
    RegexRule(Category.HOST, IndicatorType.FILEPATH,
              _compile(
                  rf"(?P<value>"
                  rf"(?:[A-Z]:\\(?:{_PATH_CHAR}+\\)*(?:{_PATH_CHAR}*?\.(?:{_FILE_EXT_ALT})|{_PATH_CHAR_NOSPACE}*))"
                  rf"|(?:%[A-Za-z_][A-Za-z0-9_]{{1,40}}%\\(?:{_PATH_CHAR}+\\)*(?:{_PATH_CHAR}*?\.(?:{_FILE_EXT_ALT})|{_PATH_CHAR_NOSPACE}*))"
                  rf"|(?:/(?:[\w.@+~-]+/)+[\w.@+~?=&$%-]+)"
                  rf"|(?:(?<![\w./\\-])(?:[\w.@+~-]+/){{2,}}[\w.@+~?=&$%-]+)"
                  rf"|(?:\\\\[^\\\s]+\\(?:[^\"'“”‘’:\r\n&]*?\.(?:{_FILE_EXT_ALT})|[^\"'“”‘’:\r\n &]+))"
                  rf")"
              ), "regex:filepath"),
    # Excludes straight/curly quotes as well as comma/semicolon/newline: a
    # registry path is routinely written quoted in prose (e.g. "...dump the
    # “HKLM\SYSTEM” registry by performing..."), and without excluding the
    # closing quote here too this ran straight through it and kept
    # consuming the sentence that followed, the same class of bug fixed
    # earlier for FILEPATH/MUTEX/SERVICE.
    #
    # The per-character negative lookahead additionally stops before a space
    # that's immediately followed by what looks like the start of a second,
    # unrelated path (a drive letter "C:\" or an "%ENVVAR%\") - a command
    # line such as "Reg save HKLM\SYSTEM C:\users\...\ys.Hiv" genuinely
    # contains a registry key and a destination file path back to back,
    # separated by nothing but a space, and without this the match merged
    # both into one nonsensical value instead of stopping at the key.
    RegexRule(Category.HOST, IndicatorType.REGISTRY,
              _compile(r"(?P<value>\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\(?:(?!\s+[A-Za-z]:\\|\s+%[A-Za-z_])[^\r\n,;\"'“”‘’])+)"), "regex:registry"),
    # The "\\.\" device-namespace prefix (as opposed to "\\server\share\...")
    # specifically marks a named pipe, not an arbitrary UNC path - typed
    # separately so it reads as the named pipe the report calls it, rather
    # than a generic host/filepath.
    RegexRule(Category.HOST, IndicatorType.NAMED_PIPE,
              _compile(r"(?P<value>\\\\\.\\[Pp]ipe\\[^\"'“”‘’:\\\r\n]+)"), "regex:named-pipe"),
    # Two alternatives sharing one "value" group (Python's re rejects the
    # same named group twice, so the alternation has to sit *inside* the
    # group rather than wrap two of them): a whole-line match using the
    # space-tolerant stem, for a decoy name that's the only thing on its
    # line; otherwise the space-free stem anywhere in the text, so a name
    # mentioned mid-sentence only ever captures the token itself. See
    # _FILENAME_STEM/_FILENAME_STEM_SPACED above for why the line boundary
    # is what gates the space, not just a length/count cap.
    RegexRule(Category.HOST, IndicatorType.FILENAME,
              _compile(
                  rf"(?P<value>"
                  rf"(?:^{_FILENAME_STEM_SPACED}{{1,100}}(?:\.(?:{'|'.join(_MASQUERADE_EXTENSIONS)})){{0,1}}\.(?:{'|'.join(sorted(FILE_EXTENSIONS))})(?=[ \t]*$))"
                  rf"|(?:(?<![\w.-]){_FILENAME_STEM}{{1,100}}(?:\.(?:{'|'.join(_MASQUERADE_EXTENSIONS)})){{0,1}}\.(?:{'|'.join(sorted(FILE_EXTENSIONS))})(?![\w-]))"
                  rf")"
              ), "regex:filename"),
    # Unlike SERVICE below, the separator here stays *optional*: CTI prose
    # routinely names a mutex with no separator word at all ("creates the
    # mutex cfgmgr_mtx", "using mutex X to ensure..."), and making it
    # mandatory (an earlier version of this rule did) silently lost every
    # one of those - a worse regression than the false positive it was
    # trying to fix. That false positive - a bare "mutex" mention with no
    # real name, e.g. a figure caption "Figure 14. CRAT's mutex name"
    # immediately followed by the next section's number "4.2." - is instead
    # excluded directly: a value that's just digits/dots (a section-number
    # shape no real mutex name takes) is rejected, and so is the bare word
    # "name" itself - without also excluding it, the optional "(?: name)?"
    # suffix backtracks to leaving "name" unconsumed so it can be captured
    # as the "value" instead of the digits, which is a smaller but still
    # wrong version of the same false positive.
    RegexRule(Category.HOST, IndicatorType.MUTEX,
              _compile(r"\bmutex\b(?: name\b)?\s*(?:[:=]|is|was|named)?\s*(?P<value>[\"'][^\"'\r\n]{1,200}[\"']|(?!\d+(?:\.\d+)*\b)(?!name\b)[A-Za-z0-9_.$\\:{}-]{3,200})"), "regex:labelled-mutex"),
    # "\bservice\b" (not just "\bservice") keeps this from matching mid-word
    # inside "services", and the separator is mandatory (not "?") so a plain
    # prose mention of "service" - "financial services", "service requests",
    # "Tor service as a permanent indicator" - isn't itself treated as
    # naming a value; only an actual "service: X"/"service named X" label is.
    RegexRule(Category.HOST, IndicatorType.SERVICE,
              _compile(r"\bservice\b(?: name)?\s*(?:[:=]|is|was|named|created)\s*(?P<value>[\"'][^\"'\r\n]{1,200}[\"']|[A-Za-z0-9_.$ -]{3,200})"), "regex:labelled-service"),
    # Same mandatory-separator fix as SERVICE/MUTEX above - the label alone
    # ("scheduled task") is common in prose with no name actually attached.
    RegexRule(Category.HOST, IndicatorType.SCHEDULED_TASK,
              _compile(r"\b(?:scheduled task|task name)\b\s*(?:[:=]|is|was|named|created)\s*(?P<value>[\"'][^\"'\r\n]{1,200}[\"']|[A-Za-z0-9_.$\\ -]{3,200})"), "regex:labelled-scheduled-task"),
    RegexRule(Category.HOST, IndicatorType.PROCESS,
              _compile(r"\b(?:process|process name|running as|executed as|launch(?:ed|es)?)\s*(?:[:=]|is|was|named)?\s*(?P<value>[A-Za-z0-9_.$@+~-]{1,100}\.(?:exe|dll|bin|elf))\b"), "regex:labelled-process"),

    # The domain part tolerates the same defanged-dot forms as DOMAIN_RE -
    # threat-actor contact addresses in particular are routinely defanged
    # (e.g. "actor@evil[.]com") to avoid leaving a clickable mailto: link.
    # The "@" itself is also commonly defanged as "[at]"/"(at)"/"{at}"
    # (e.g. "actor[at]evil[.]com"), not just the bracketed-@ forms.
    RegexRule(Category.EMAIL, IndicatorType.EMAIL_ADDRESS,
              _compile(rf"(?<![\w.+-])(?P<value>[A-Z0-9._%+-]+{DEFANGED_AT}(?:[A-Z0-9-]+{DEFANGED_DOT})+[A-Z]{{2,63}})(?![\w-])"), "regex:email"),
    RegexRule(Category.EMAIL, IndicatorType.EMAIL_SUBJECT,
              _compile(r"^(?:subject|email subject)\s*:\s*(?P<value>[^\r\n]{1,300})$"), "regex:email-subject"),
    RegexRule(Category.EMAIL, IndicatorType.EMAIL_HEADER,
              _compile(r"^(?P<value>(?:From|Reply-To|Return-Path|Received|Message-ID|Authentication-Results|DKIM-Signature|Received-SPF):[^\r\n]+)$"), "regex:email-header"),
    RegexRule(Category.EMAIL, IndicatorType.ATTACHMENT,
              _compile(r"\b(?:attachment|attached file)\s*(?:[:=]|is|was|named)?\s*(?P<value>[A-Za-z0-9_.$@+~() -]{1,150}\.[A-Za-z0-9]{1,10})\b"), "regex:labelled-attachment"),

    RegexRule(Category.BEHAVIOUR, IndicatorType.BEACONING,
              _compile(r"(?P<value>\b(?:beacon(?:ed|ing|s)?|callbacks?)(?:[^.\r\n]{0,100})(?:every|interval(?: of)?|period(?: of)?)\s+\d+(?:\.\d+)?\s*(?:ms|milliseconds?|s|sec(?:onds?)?|m|min(?:utes?)?|h|hours?)\b)"), "regex:beaconing-context"),
    RegexRule(Category.BEHAVIOUR, IndicatorType.PROCESS_CHAIN,
              _compile(r"(?P<value>\b[A-Za-z0-9_.$@+~-]+\.exe\s+(?:spawn(?:ed|s|ing)?|launch(?:ed|es|ing)?|creat(?:ed|es|ing)?|start(?:ed|s|ing)?)\s+[A-Za-z0-9_.$@+~-]+\.exe\b)"), "regex:process-chain"),
    RegexRule(Category.BEHAVIOUR, IndicatorType.LATERAL_MOVEMENT,
              _compile(r"(?P<value>\b(?:lateral movement|remote service|pass[- ]the[- ]hash|pass[- ]the[- ]ticket|SMB|RDP|WinRM|PsExec|WMI)[^.\r\n]{0,180}(?:host|machine|system|server|network|credential|share)[^.\r\n]{0,80})"), "regex:lateral-movement-context"),
    RegexRule(Category.BEHAVIOUR, IndicatorType.PERSISTENCE,
              _compile(r"(?P<value>\b(?:persistence|autorun|startup folder|run key|scheduled task|new service|logon script|DLL search order hijacking)[^.\r\n]{0,180})"), "regex:persistence-context"),
    RegexRule(Category.BEHAVIOUR, IndicatorType.EXFILTRATION,
              _compile(r"(?P<value>\b(?:exfiltrat(?:e|ed|es|ing|ion)|data theft|uploaded|transferred|staged)[^.\r\n]{0,180}(?:data|files?|documents?|archive|credentials?|records?|bytes?|MB|GB)[^.\r\n]{0,80})"), "regex:exfiltration-context"),

    RegexRule(Category.INTELLIGENCE, IndicatorType.VULNERABILITY,
              _compile(r"(?<![\w-])(?P<value>CVE-\d{4}-\d{4,7})(?![\w-])"), "regex:cve"),
    RegexRule(Category.INTELLIGENCE, IndicatorType.TTP,
              # Real ATT&CK technique IDs are always 4 digits, but some CTI
              # platforms render a truncated/malformed ID (e.g. "T811" for
              # what should be a 4-digit technique) inside their own TTP
              # table. Widening recall to 3-4 digits still lets the LLM
              # verifier reject anything that isn't presented as a technique;
              # it just stops the regex stage from silently dropping the
              # candidate before verification ever sees it.
              _compile(r"(?<![\w.])(?P<value>T\d{3,4}(?:\.\d{3})?)(?![\w])"), "regex:mitre-attack-id"),
    RegexRule(Category.INTELLIGENCE, IndicatorType.THREAT_ACTOR,
              _compile(r"\b(?P<value>(?:APT|FIN|UNC|TA)\s?-?\d{1,5}|TEMP\.[A-Z][A-Za-z]+|Lazarus Group|Turla(?:\s+Team)?|Sandworm|Mustang Panda|Charming Kitten|Cozy Bear|Fancy Bear)\b"), "regex:threat-actor"),
    # Vendor "cryptonym" naming systems (e.g. Google's <adjective> <noun> pairs,
    # Mandiant TEMP.<Name> clusters not covered by the fixed list above) look
    # like two or three consecutive ALL-CAPS words - a shape ordinary prose
    # essentially never produces. Deliberately not IGNORECASE: matching only
    # true uppercase keeps this from firing on every capitalized two-word
    # phrase. Recall-oriented on purpose, same as the rest of this stage -
    # the LLM verifier is what filters section headings/acronym runs back out.
    #
    # The trailing negative lookahead specifically excludes "MITRE ATT&CK":
    # the regex's own [ \t]+ word separator can't span the "&" in "ATT&CK",
    # so it was matching just "MITRE ATT" as a fake two-word cryptonym every
    # time that framework name appeared - a truncated, meaningless fragment
    # that showed up repeatedly across unrelated reports and was verified
    # inconsistently (rejected in some, wrongly accepted as a real
    # threat-actor name in others). Excluding any match immediately followed
    # by "&" + a capital letter blocks this one recurring false positive at
    # the source instead of relying on every future LLM call to catch it.
    RegexRule(Category.INTELLIGENCE, IndicatorType.THREAT_ACTOR,
              _compile(r"\b(?P<value>[A-Z]{3,}(?:[ \t]+[A-Z]{3,}){1,2})\b(?!&[A-Z])", flags=re.MULTILINE), "regex:threat-actor-cryptonym"),
)

DOMAIN_RE = _compile(
    rf"(?<![@\w.-])(?P<value>(?:[A-Z0-9](?:[A-Z0-9-]{{0,61}}[A-Z0-9])?{DEFANGED_DOT})+[A-Z]{{2,63}})(?![\w-])"
)
HOSTNAME_CONTEXT_RE = _compile(
    # The trailing \b on the keyword alternation matters: without it "server"
    # matches as a bare prefix of an unrelated word like "serverdock[.]online",
    # truncating the real domain to "dock[.]online" instead of skipping past
    # "server" because it wasn't actually the standalone keyword.
    r"\b(?:host(?:name)?|server|C2|command[- ]and[- ]control)\b\s*(?:[:=]|is|was)?\s*"
    rf"(?P<value>(?:[A-Z0-9](?:[A-Z0-9-]{{0,61}}[A-Z0-9])?{DEFANGED_DOT})+[A-Z]{{2,63}})"
)
# A domain immediately followed by a path but with no scheme (e.g. a
# Telegram/social-profile reference like "t.me/chanadarkpart") is not matched
# by URL_RE, which requires an explicit http(s)/ftp scheme, so it falls back
# to DOMAIN_RE and gets truncated to the bare domain - over-broad for a
# platform-wide domain like t.me when the report's actual indicator is one
# specific path on it. The leading lookbehinds keep this from re-matching the
# domain+path portion of a URL that URL_RE already captured in full - one per
# defanged-colon spelling of the scheme delimiter, since a Python lookbehind
# must be fixed-width and can't itself alternate between them.
SCHEMELESS_URL_RE = _compile(
    r"(?<!://)(?<!\[:\]//)(?<!\(:\)//)(?<!\{:\}//)"
    rf"(?<![@\w.-])(?P<value>(?:[A-Z0-9](?:[A-Z0-9-]{{0,61}}[A-Z0-9])?{DEFANGED_DOT})+"
    r"[A-Z]{2,63}/[^\s<>'\"\)}]+)"
)
# A naming verb is very often followed by the name in quotes ("named it
# 'HeptaX'"). Skipping one optional leading quote character (straight or
# curly) matters more than it looks: without it, the value pattern can't
# start on the quoted name at all, so the *whole* alternative at that
# position fails, and backtracking falls back to an earlier, looser
# alternative that "succeeds" on the wrong text instead (e.g. capturing the
# pronoun "it" rather than ever reaching the actual name) - regex commits to
# the first successful parse, not the best one, so preventing the failure
# in the first place is what fixes it, not merely widening the char class.
_QUOTE_SKIP = "[\"'“”‘’]?"

# Up to two filler words are allowed between the trigger noun and the
# naming verb (e.g. "backdoor account named X", not just "backdoor named
# X") - real CTI prose routinely qualifies the noun before naming it. The
# value's leading character class additionally allows a digit/underscore
# start (e.g. "_BootUEFI_"), not just a capital letter.
MALWARE_CONTEXT_RE = _compile(
    r"\b(?:malware|ransomware|trojan|loader|backdoor|stealer|implant|worm|rootkit)"
    r"(?:[ \t]+\w+){0,2}?[ \t]+(?:named|called|known as|identified as|dubbed|such as|including)[ \t]+"
    rf"{_QUOTE_SKIP}(?P<value>[A-Za-z0-9_][A-Za-z0-9_.-]{{2,80}})"
)
# The naming verb is now mandatory (previously optional, which let a bare
# "campaign <anything>" match swallow unrelated prose as a fake campaign
# name whenever the immediately-following text didn't happen to be a real
# name - e.g. "identified this same attack campaign and named it 'HeptaX'"
# matched as value="and named it"). A small filler-word gap plus "dubbed"/
# "and named it" as connectors keeps that same sentence matching correctly,
# landing on the actual quoted name instead. "identified as"/"tracked as"/
# "referred to as" widen the verb list further - common report phrasings
# ("an attack campaign identified as HeptaX", "which Sonatype is tracking
# as X") that the original list left uncovered.
CAMPAIGN_CONTEXT_RE = _compile(
    r"\b(?:campaign|operation)\b(?:[ \t]+\w+){0,3}?[ \t]+"
    r"(?:named|called|known as|identified as|dubbed|tracked as|referred to as|"
    r"and named it|and called it)[ \t]+"
    rf"{_QUOTE_SKIP}(?P<value>[A-Za-z][A-Za-z0-9_. -]{{2,100}})"
)
# CAMPAIGN_CONTEXT_RE only catches a campaign name introduced by an explicit
# naming verb, but a report commonly establishes the name once (often in a
# title or key-findings summary) and then just reuses it as a bare proper
# noun throughout - e.g. "the group behind Operation RoundPress" - with no
# "named"/"called" phrasing anywhere. "Operation"/"Campaign" is capitalised
# specifically to mean "this is the report's own name for it" here, as
# opposed to ordinary lowercase prose ("this operation was conducted...");
# compiled without IGNORECASE for the same reason the cryptonym/threat-actor
# label rules below are - the module default would let a lowercase qualifier
# satisfy the [A-Z] "proper noun" gate and defeat the distinction entirely.
CAMPAIGN_LABEL_RE = _compile(
    r"\b(?:Operation|Campaign)[ \t]+"
    r"(?P<value>[A-Z][\w'-]*(?:[ \t]+[A-Z][\w'-]*){0,2})\b",
    flags=re.MULTILINE,
)
# Profile-style CTI reports (e.g. "<Name> is a newly emerged ransomware
# extortion group...") introduce the group's own name as the subject of the
# report's opening sentence rather than via a "named/called X" phrase, so
# neither THREAT_ACTOR_RE's fixed name list nor MALWARE_CONTEXT_RE's
# "named/called" pattern catches it. The lookbehind anchors the name to the
# start of a sentence (line start or after ". ") so the match doesn't run
# backwards across unrelated capitalized words earlier in the paragraph.
THREAT_ACTOR_INTRO_RE = _compile(
    r"(?:(?<=^)|(?<=\n)|(?<=\. ))"
    r"(?P<value>[A-Z][\w'-]*(?:[ \t]+[A-Z][\w'-]*){0,2})[ \t]+is[ \t]+an?[ \t]+"
    # Filler words allow an internal hyphen (e.g. "data-extortion") since
    # that compound is one token, not two space-separated words.
    r"(?:[a-z-]+[ \t]+){0,4}?(?:[a-z]+-)?(?:ransomware|extortion|threat actor|hacking)"
    r"[ \t]+(?:group|gang|operation|collective|actor)\b"
)
# Complements THREAT_ACTOR_INTRO_RE's "<Name> is a ... group" template for
# reports that instead label the actor inline as "<Name> threat actor"
# without ever using "is a/an" (e.g. "The Larva-24009 threat actor has been
# active since..."). Compiled without IGNORECASE, same reasoning as the
# cryptonym rule above: under the module default, [A-Z] matches any case, so
# an ordinary lowercase qualifier right before "threat actor" (e.g. "a
# well-known threat actor") would otherwise be captured as a bogus name.
THREAT_ACTOR_LABEL_RE = _compile(
    r"\b(?P<value>(?!(?:The|A|An)\b)[A-Z][\w'-]*(?:[ \t]+[A-Z][\w'-]*){0,2})"
    r"[ \t]+threat[ \t]+actor\b",
    flags=re.MULTILINE,
)
# "s?" matters: the singular-only original never matched "tools" at all, so
# a very common list phrasing ("remote control tools such as X and Y") was
# invisible to this rule regardless of the connector-word issue below.
# "such as"/"including" cover list intros; "named/called/known as" remain for
# the single-tool-introduction phrasing.
TOOL_CONTEXT_RE = _compile(
    r"\b(?:tool|utility|framework|software)s?[ \t]+(?:named|called|known as|such as|including)[ \t]+"
    rf"{_QUOTE_SKIP}(?P<value>[A-Z][A-Za-z0-9_.+-]{{2,80}})"
)
# Infrastructure the report describes an actor's site/service as built on
# (e.g. "a Tor-hosted DLS ... running on nginx") - context, not a named
# tool the actor introduced, but still relevant intelligence. "\s+" (not
# "[ \t]+") since a PDF column wrap routinely puts the linked word on the
# next line right after "running on".
SOFTWARE_CONTEXT_RE = _compile(
    r"\b(?:running on|hosted on|powered by|built on)\s+"
    r"(?P<value>[A-Za-z][A-Za-z0-9_.+-]{1,40})"
)

DEFANG_REPLACEMENTS = (
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]|\(:\)|\{:\}"), ":"),
    (re.compile(r"\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\}", re.IGNORECASE), "@"),
)
STRIP_CHARS = "\"'`.,;:"
# Bracket pairs are stripped from the edges separately from STRIP_CHARS (see
# _clean) - unlike a quote or trailing period, a leading/trailing bracket
# character is only ever incidental prose-wrapping when it's the *unmatched*
# half of its pair. A value like "x{random}" or "(RESUME)_..." has both
# halves and the bracket is part of the actual artifact name, so it must be
# left alone; a value like "(malware.exe" (stray open, sentence-wrapped)
# has only one and should still be trimmed.
BRACKET_PAIRS: tuple[tuple[str, str], ...] = (("(", ")"), ("[", "]"), ("{", "}"), ("<", ">"))



@dataclass(frozen=True, slots=True)
class ExtractorConfig:
    context_chars: int = 300
    include_private_ips: bool = True
    include_loopback_ips: bool = False
    deduplicate: bool = True


class CTIExtractor:
    def __init__(self, config: ExtractorConfig | None = None) -> None:
        self.config = config or ExtractorConfig()

    def extract(self, text: str) -> list[Extraction]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        candidates: list[Extraction] = []
        for rule in RULES:
            for match in rule.pattern.finditer(text):
                item = self._from_match(text, match, rule)
                if item is not None:
                    candidates.append(item)

        candidates.extend(self._extract_domains(text))
        candidates.extend(self._extract_hostnames(text))
        candidates.extend(self._extract_schemeless_urls(text))
        candidates.extend(self._extract_email_domains(candidates))
        candidates.extend(self._extract_context_entities(text))
        candidates = self._remove_nested(candidates)
        if self.config.deduplicate:
            candidates = self._deduplicate(candidates)
        return sorted(candidates, key=lambda x: (x.start, x.end, x.indicator_type.value))

    def _from_match(self, text: str, match: re.Match[str], rule: RegexRule) -> Extraction | None:
        value = self._clean(match.group(rule.group))
        if rule.indicator_type in {IndicatorType.FILENAME, IndicatorType.ATTACHMENT}:
            value = self._strip_leading_hash_token(value)
        start, end = match.span(rule.group)
        normalized, attrs = self._normalize(rule.indicator_type, value)
        if normalized is None:
            return None
        attrs = dict(attrs)
        attrs["was_defanged"] = self._refang(value) != value
        attrs["document_section_hint"] = self._section_hint(text, start)
        return Extraction(
            rule.category, rule.indicator_type, value, normalized,
            start, end, self._context(text, start, end), rule.method, attrs,
        )

    # Mandiant-style "TEMP.<Name>" threat-actor cluster codenames (e.g.
    # "TEMP.Hex", "TEMP.Zagros") are already recognised as threat_actor
    # entities by the dedicated THREAT_ACTOR_RE rule above, but their shape -
    # one label, a dot, another label - also satisfies DOMAIN_RE, so the
    # same string was additionally, wrongly extracted a second time as a
    # network/domain candidate (and sometimes verified/accepted as one).
    _TEMP_CLUSTER_RE = re.compile(r"^temp\.[a-z]", re.IGNORECASE)

    # AV vendors name detections as "<Category>.<Platform>.<Family>[.<Variant>]"
    # (e.g. "Trojan.Downloader.DOC.Gen", "Backdoor.Win64.PhantomCore.dt",
    # Symantec's "SONAR.Ransom") - the same TitleCase-dotted shape DOMAIN_RE
    # matches, so a detection-verdict string quoted from an AV scan result
    # table was additionally, wrongly extracted as a network/domain candidate
    # every time (and occasionally verified/accepted as one, since the
    # category word alone gives no hint to a reviewer skimming quickly that
    # it's a signature name rather than a domain label). No real domain's
    # registrable label collides with one of these category words followed by
    # a dot, so this is a safe, unambiguous exclusion unlike a file-extension
    # blacklist.
    _AV_SIGNATURE_PREFIX_RE = re.compile(
        r"^(?:Trojan|Backdoor|Worm|Virus|Ransom|Downloader|Exploit|Heur|PWS|"
        r"HackTool|RiskWare|Adware|SONAR|Rootkit|Spyware|Dropper|Keylogger|"
        r"Generic)\.",
    )

    def _extract_domains(self, text: str) -> Iterator[Extraction]:
        for match in DOMAIN_RE.finditer(text):
            start, end = match.span("value")
            value = self._clean(match.group("value"))
            if start > 0 and text[start - 1] == "@":
                continue
            if self._TEMP_CLUSTER_RE.match(value):
                continue
            if self._AV_SIGNATURE_PREFIX_RE.match(value):
                continue
            refanged_tail = self._refang(value).lower().rsplit(".", 1)[-1]
            if refanged_tail in NON_DOMAIN_EXTENSIONS:
                continue
            yield Extraction(
                Category.NETWORK, IndicatorType.DOMAIN, value,
                self._refang(value).lower().rstrip("."), start, end,
                self._context(text, start, end), "regex:domain",
                {"was_defanged": self._refang(value) != value,
                 "document_section_hint": self._section_hint(text, start)},
            )

    def _extract_hostnames(self, text: str) -> Iterator[Extraction]:
        for match in HOSTNAME_CONTEXT_RE.finditer(text):
            start, end = match.span("value")
            value = self._clean(match.group("value"))
            yield Extraction(
                Category.NETWORK, IndicatorType.HOSTNAME, value,
                self._refang(value).lower().rstrip("."), start, end,
                self._context(text, start, end), "regex:labelled-hostname",
                {"was_defanged": self._refang(value) != value,
                 "document_section_hint": self._section_hint(text, start)},
            )

    def _extract_schemeless_urls(self, text: str) -> Iterator[Extraction]:
        for match in SCHEMELESS_URL_RE.finditer(text):
            start, end = match.span("value")
            value = self._clean(match.group("value"))
            yield Extraction(
                Category.NETWORK, IndicatorType.URL, value,
                self._refang(value).rstrip(".,;"), start, end,
                self._context(text, start, end), "regex:schemeless-url",
                {"was_defanged": self._refang(value) != value,
                 "document_section_hint": self._section_hint(text, start)},
            )

    _AT_TOKEN_RE = re.compile(DEFANGED_AT, re.IGNORECASE)

    def _extract_email_domains(self, items: Sequence[Extraction]) -> Iterator[Extraction]:
        for item in items:
            if item.indicator_type is not IndicatorType.EMAIL_ADDRESS:
                continue
            domain = item.normalized_value.rsplit("@", 1)[-1]
            # The "@" separator itself may be defanged as "[at]"/"(at)"/
            # "{at}" rather than a literal "@", so locate it with the same
            # token pattern the EMAIL_ADDRESS rule matched against, instead
            # of a literal rfind("@") that would miss those forms.
            at_match = self._AT_TOKEN_RE.search(item.value)
            domain_offset = at_match.end() if at_match else len(item.value)
            yield Extraction(
                Category.EMAIL, IndicatorType.EMAIL_DOMAIN, domain, domain.lower(),
                item.start + domain_offset, item.end, item.context,
                "derived:email-domain", {"source_email": item.normalized_value},
            )

    def _extract_context_entities(self, text: str) -> Iterator[Extraction]:
        specs = (
            (IndicatorType.MALWARE, MALWARE_CONTEXT_RE, "regex:malware-context"),
            (IndicatorType.CAMPAIGN, CAMPAIGN_CONTEXT_RE, "regex:campaign-context"),
            (IndicatorType.CAMPAIGN, CAMPAIGN_LABEL_RE, "regex:campaign-label"),
            (IndicatorType.TOOL, TOOL_CONTEXT_RE, "regex:tool-context"),
            (IndicatorType.TOOL, SOFTWARE_CONTEXT_RE, "regex:software-context"),
            (IndicatorType.THREAT_ACTOR, THREAT_ACTOR_INTRO_RE, "regex:threat-actor-intro"),
            (IndicatorType.THREAT_ACTOR, THREAT_ACTOR_LABEL_RE, "regex:threat-actor-label"),
        )
        for indicator_type, pattern, method in specs:
            for match in pattern.finditer(text):
                start, end = match.span("value")
                value = self._clean(match.group("value"))
                yield Extraction(
                    Category.INTELLIGENCE, indicator_type, value, value.casefold(),
                    start, end, self._context(text, start, end), method,
                    {"requires_validation": True,
                     "document_section_hint": self._section_hint(text, start)},
                )

    def _normalize(self, indicator_type: IndicatorType, value: str) -> tuple[str | None, dict[str, Any]]:
        refanged = self._refang(value).strip()
        attrs: dict[str, Any] = {}
        if indicator_type is IndicatorType.IP:
            try:
                ip = ipaddress.ip_address(refanged)
            except ValueError:
                return None, {}
            if ip.is_loopback and not self.config.include_loopback_ips:
                return None, {}
            if ip.is_private and not self.config.include_private_ips:
                return None, {}
            attrs.update(ip_version=ip.version, is_private=ip.is_private,
                         is_global=ip.is_global, is_loopback=ip.is_loopback,
                         is_multicast=ip.is_multicast)
            return ip.compressed.lower(), attrs
        if indicator_type is IndicatorType.PORT:
            try:
                port = int(refanged)
            except ValueError:
                return None, {}
            return (str(port), {"port": port}) if 1 <= port <= 65535 else (None, {})
        if indicator_type is IndicatorType.HASH:
            normalized = refanged.replace(":", "").lower()
            algorithm = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(normalized))
            if not algorithm or not re.fullmatch(r"[a-f0-9]+", normalized):
                return None, {}
            return normalized, {"algorithm": algorithm}
        if indicator_type is IndicatorType.CERTIFICATE:
            normalized = refanged.replace(":", "").lower()
            return normalized, {"fingerprint_length": len(normalized)}
        if indicator_type is IndicatorType.CRYPTO_ADDRESS:
            return refanged.lower(), {}
        if indicator_type is IndicatorType.TOX_ID:
            return refanged.upper(), {}
        if indicator_type is IndicatorType.CRYPTO_KEY:
            normalized = refanged.replace(":", "").lower()
            return normalized, {"key_length_hex": len(normalized)}
        if indicator_type is IndicatorType.URL:
            return refanged.rstrip(".,;"), {}
        if indicator_type in {IndicatorType.DOMAIN, IndicatorType.HOSTNAME, IndicatorType.EMAIL_DOMAIN}:
            return refanged.lower().rstrip("."), {}
        if indicator_type is IndicatorType.EMAIL_ADDRESS:
            return refanged.lower(), {}
        if indicator_type is IndicatorType.VULNERABILITY:
            return refanged.upper(), {}
        if indicator_type is IndicatorType.TTP:
            return refanged.upper(), {"framework": "MITRE ATT&CK"}
        if indicator_type is IndicatorType.FILEPATH:
            return (refanged.replace("/", "\\") if re.match(r"^[A-Za-z]:", refanged) else refanged), {}
        if indicator_type in {IndicatorType.FILENAME, IndicatorType.PROCESS, IndicatorType.ATTACHMENT}:
            return refanged.lower(), {}
        return refanged.casefold(), {}

    def _remove_nested(self, items: list[Extraction]) -> list[Extraction]:
        suppressions = {
            IndicatorType.URL: {IndicatorType.DOMAIN, IndicatorType.HOSTNAME, IndicatorType.FILEPATH, IndicatorType.FILENAME},
            IndicatorType.EMAIL_ADDRESS: {IndicatorType.DOMAIN},
            IndicatorType.FILEPATH: {IndicatorType.FILENAME},
            # A Windows registry path (HKLM\...\Services\Foo) also matches the
            # generic UNC-style filepath alternative from within its own tail
            # (\...\Services\Foo), and the generic hash rule matches the same
            # hex run inside a labelled certificate/key value - keep only the
            # more specific type for both cases.
            IndicatorType.REGISTRY: {IndicatorType.FILEPATH, IndicatorType.FILENAME},
            IndicatorType.NAMED_PIPE: {IndicatorType.FILEPATH, IndicatorType.FILENAME},
            IndicatorType.CERTIFICATE: {IndicatorType.HASH},
            IndicatorType.CRYPTO_KEY: {IndicatorType.HASH},
        }
        output: list[Extraction] = []
        for item in items:
            nested = any(
                outer.indicator_type in suppressions
                and item.indicator_type in suppressions[outer.indicator_type]
                and outer.start <= item.start and item.end <= outer.end
                for outer in items
                if outer is not item
            )
            if not nested:
                output.append(item)
        return output

    @staticmethod
    def _deduplicate(items: Iterable[Extraction]) -> list[Extraction]:
        best: dict[tuple[str, str, str], Extraction] = {}
        for item in items:
            key = (item.category.value, item.indicator_type.value, item.normalized_value)
            current = best.get(key)
            if current is None or len(item.context) > len(current.context):
                best[key] = item
        return list(best.values())

    def _context(self, text: str, start: int, end: int) -> str:
        left = max(0, start - self.config.context_chars)
        right = min(len(text), end + self.config.context_chars)
        return " ".join(text[left:right].split())

    @staticmethod
    def _section_hint(text: str, start: int) -> str:
        prefix = text[max(0, start - 2500):start]
        lines = [" ".join(line.split()) for line in prefix.splitlines() if line.strip()]
        for line in reversed(lines[-25:]):
            if len(line) <= 100 and (
                line.isupper()
                or re.match(r"^(?:\d+(?:\.\d+)*\s+)?[A-Z][A-Za-z /&-]{2,80}$", line)
            ):
                return line
        return ""

    @staticmethod
    def _clean(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        value = value.strip(STRIP_CHARS + " ")
        changed = True
        while changed and value:
            changed = False
            for open_ch, close_ch in BRACKET_PAIRS:
                if value and value[0] == open_ch and value.count(open_ch) > value.count(close_ch):
                    value = value[1:].strip()
                    changed = True
                if value and value[-1] == close_ch and value.count(close_ch) > value.count(open_ch):
                    value = value[:-1].strip()
                    changed = True
        return value

    _HASH_LIKE_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$", re.IGNORECASE)

    @staticmethod
    def _strip_leading_hash_token(value: str) -> str:
        """Drop an accidentally-captured hash prefix from a space-tolerant match.

        FILENAME/ATTACHMENT allow an embedded space so real multi-word decoy
        filenames (e.g. "Account Statement.LNK") match in full, but that also
        lets them swallow a preceding, unrelated hash when a report lists
        "<hash> <filename>" on one table row/line - there is nothing else in
        the character class to stop the match at the space between them.
        """
        head, sep, rest = value.partition(" ")
        if sep and rest and CTIExtractor._HASH_LIKE_RE.match(head):
            return rest
        return value

    @staticmethod
    def _refang(value: str) -> str:
        result = value
        for pattern, replacement in DEFANG_REPLACEMENTS:
            result = pattern.sub(replacement, result)
        return result


# ---------------------------------------------------------------------------
# Ollama / LLM verification
# ---------------------------------------------------------------------------


class OllamaError(RuntimeError):
    def __init__(self, message: str, *, prompt_tokens: int | None = None) -> None:
        super().__init__(message)
        self.prompt_tokens = prompt_tokens


class OllamaClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        timeout: int = 180,
        *,
        verbose: int = 0,
        num_predict: int = 384,
        num_ctx: int = 4096,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = max(1, timeout)
        self.verbose = max(0, verbose)
        self.num_predict = max(64, num_predict)
        self.num_ctx = max(1024, num_ctx)

    def chat_json(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Send a chat request to Ollama and return a parsed JSON object.

        The supplied schema is passed to Ollama as the structured-output format.
        This is more reliable than using only ``"format": "json"`` because it
        tells the model exactly which fields and value types it must return.
        """

        payload = {
            "model": model,
            "stream": False,
            "think": False,
            "keep_alive": "10m",

            # Use the supplied JSON schema rather than the generic "json" mode.
            "format": dict(schema),

            "options": {
                "temperature": 0,
                "num_predict": self.num_predict,
                "num_ctx": self.num_ctx,
            },
            "messages": [
                {
                    "role": "system",
                    "content": (
                        f"{system}\n\n"
                        "Return only a valid JSON object matching this exact schema:\n"
                        f"{json.dumps(dict(schema), ensure_ascii=False)}\n\n"
                        "Do not repeat full candidate objects. Return only compact "
                        "decision records. Do not use Markdown, code fences, bullet "
                        "points, or explanatory text outside the JSON object."
                    ),
                },
                {
                    "role": "user",
                    "content": user,
                },
            ],
        }

        encoded_payload = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=encoded_payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        started = time.perf_counter()

        if self.verbose >= 3:
            print(
                "[DEBUG] POST "
                f"{self.base_url}/api/chat "
                f"model={model} "
                f"timeout={self.timeout}s "
                f"num_predict={self.num_predict} "
                f"num_ctx={self.num_ctx}",
                file=sys.stderr,
                flush=True,
            )
            print(
                f"[DEBUG] request bytes={len(encoded_payload)}",
                file=sys.stderr,
                flush=True,
            )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                raw_body = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )
            raise OllamaError(
                f"Ollama HTTP {exc.code}: {detail}"
            ) from exc

        except urllib.error.URLError as exc:
            # A timeout may be wrapped inside URLError.
            if isinstance(exc.reason, TimeoutError):
                raise OllamaError(
                    f"Ollama request timed out after {self.timeout}s"
                ) from exc

            raise OllamaError(
                f"Cannot connect to Ollama at "
                f"{self.base_url}: {exc.reason}"
            ) from exc

        except TimeoutError as exc:
            raise OllamaError(
                f"Ollama request timed out after {self.timeout}s"
            ) from exc

        elapsed = time.perf_counter() - started

        if self.verbose >= 2:
            print(
                f"[LLM] response received in {elapsed:.1f}s",
                file=sys.stderr,
                flush=True,
            )

        if self.verbose >= 3:
            print(
                f"[DEBUG] response bytes="
                f"{len(raw_body.encode('utf-8'))}",
                file=sys.stderr,
                flush=True,
            )

        try:
            outer = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise OllamaError(
                "Ollama returned an invalid outer JSON response: "
                f"{raw_body[:500]}"
            ) from exc

        if self.verbose >= 3:
            print(
                "[DEBUG] Ollama stats: "
                f"done={outer.get('done')} "
                f"done_reason={outer.get('done_reason')} "
                f"prompt_tokens={outer.get('prompt_eval_count')} "
                f"generated_tokens={outer.get('eval_count')}",
                file=sys.stderr,
                flush=True,
            )

        if outer.get("done_reason") == "length":
            prompt_tokens = outer.get("prompt_eval_count")
            # done_reason "length" fires both when generation hits num_predict
            # and when prompt + generation together fill num_ctx - the two
            # look identical here, so report the prompt size too: if it's
            # already most of num_ctx, raising num_predict alone cannot help.
            raise OllamaError(
                "Model output was truncated. Current num_predict="
                f"{self.num_predict}, num_ctx={self.num_ctx}"
                + (f", prompt_tokens={prompt_tokens}" if prompt_tokens is not None else "")
                + ". Increase num_predict/num_ctx or reduce the batch size.",
                prompt_tokens=prompt_tokens,
            )

        message = outer.get("message")

        if not isinstance(message, dict):
            raise OllamaError(
                f"Unexpected Ollama response: {outer}"
            )

        content = message.get("content")

        if not isinstance(content, str):
            raise OllamaError(
                f"Ollama response did not contain text content: {outer}"
            )

        if self.verbose >= 3:
            print(
                "[DEBUG] raw model content:\n"
                f"{content[:2000]}",
                file=sys.stderr,
                flush=True,
            )

        parsed = self._parse_json_object(content)

        if self.verbose >= 3:
            print(
                "[DEBUG] parsed model JSON:\n"
                f"{json.dumps(parsed, indent=2, ensure_ascii=False)}",
                file=sys.stderr,
                flush=True,
            )

        return parsed

    @staticmethod
    def _parse_json_object(content: str) -> dict[str, Any]:
        """
        Parse a JSON object returned by the model.

        Structured output should normally produce clean JSON. The fallback
        handling below also tolerates Markdown fences or accidental surrounding
        text so one malformed response does not immediately stop a full report.
        """

        cleaned = content.strip()

        if not cleaned:
            raise OllamaError(
                "Model returned an empty response"
            )

        # Remove a Markdown code fence if the model ignored instructions.
        if cleaned.startswith("```"):
            cleaned = re.sub(
                r"^```(?:json)?\s*",
                "",
                cleaned,
                flags=re.IGNORECASE,
            )
            cleaned = re.sub(
                r"\s*```$",
                "",
                cleaned,
            )
            cleaned = cleaned.strip()

        try:
            parsed = json.loads(cleaned)

        except json.JSONDecodeError as first_error:
            # Try extracting an object surrounded by accidental prose.
            object_start = cleaned.find("{")
            object_end = cleaned.rfind("}")

            if object_start == -1 or object_end <= object_start:
                raise OllamaError(
                    "Model returned invalid JSON and no JSON object "
                    f"could be located:\n{cleaned[:1000]}"
                ) from first_error

            possible_json = cleaned[
                object_start : object_end + 1
            ]

            try:
                parsed = json.loads(possible_json)
            except json.JSONDecodeError as second_error:
                raise OllamaError(
                    "Model returned invalid or truncated JSON:\n"
                    f"{cleaned[:1000]}"
                ) from second_error

        if not isinstance(parsed, dict):
            raise OllamaError(
                "Model JSON response must be an object, "
                f"not {type(parsed).__name__}"
            )

        return parsed



class LLMVerifier:
    SYSTEM_PROMPT = """You are a conservative cyber-threat-intelligence IoC verifier.
Judge only what the report authors are presenting in the supplied context.

Definitions:
- confirmed_ioc: a concrete observable the authors associate with malicious,
  suspicious, adversary, campaign, malware, intrusion, phishing, C2, payload,
  persistence, exfiltration, or detection activity.
- context_entity: malware names, threat actors, campaigns, tools, CVEs and ATT&CK
  techniques that provide intelligence context but are not static observables.
- rejected: citations, bibliography links, vendor/home pages, social links,
  documentation, report download URLs, benign examples, generic technology,
  author contact details, copyright/legal text, or values merely mentioned with
  no threat association.
- uncertain: context is genuinely insufficient.

A defanged value is evidence of author intent but is not conclusive by itself.
A URL must not be accepted merely because it appears in a CTI report.
Never invent facts outside the supplied candidate and context.

When the request includes a document_structure field, treat it as verified
notes about this specific report's own section/table structure - in
particular for distinguishing a victims/targets table from an
attacker-infrastructure table when the candidate's own local context does not
make this clear on its own. It never overrides an explicit contradiction in
the candidate's own context; use it only to resolve genuine ambiguity.

document_structure can only narrow which of two structural roles a candidate
belongs to (e.g. victims table vs. infrastructure table). It is never grounds
by itself to downgrade or reject a candidate that otherwise meets the
confirmed_ioc/context_entity criteria above - in particular, it never
overrides the IOC-table rule two paragraphs above, even if document_structure
uses hedging language ("contextual," "illustrative," "not standalone
verified") about the report's own indicators/IOC section. Judge every
candidate strictly on its own definition above and its own supplied context.

Many CTI reports include an indicators/artifacts table, in either of two
common shapes: (a) short lines pairing a bare value with a one- or two-word
type label (e.g. "registry", "install", "persistence", "hash", "mutex",
"domain"), or (b) a short section heading such as "URL", "FQDN", "MD5", or
"SHA256" followed by a bare list of values with no label on each line. A
candidate that appears in either format is a confirmed_ioc presented by the
report's own IOC section - do not reject it for lacking a narrative sentence,
and do not let an unrelated caveat about a *different* value nearby (e.g. "no
record found for X") transfer onto this one.

A legitimate, signed vendor binary or built-in OS component (e.g.
wkspbroker.exe, rundll32.exe, explorer.exe) that the report says is abused for
side-loading or process injection, with no indication the binary itself was
modified, is context_entity, not confirmed_ioc - the actionable artifact is
the malicious file dropped alongside it or injected into it, not the abused
legitimate binary itself. This applies the same way when the report names
several such processes together as candidate injection targets (e.g.
"may inject into ApplicationFrameHost.exe, RuntimeBroker.exe, Sihost.exe,
Taskhostw.exe, or Explorer.exe") - every process in that kind of list is
context_entity, not confirmed_ioc, because the list names *where* injected
code might run, not an artifact the actor introduced. The renamed/disguised
copy of a malicious payload (e.g. a legitimate installer's filename reused
for a dropped malicious file) remains confirmed_ioc.

These two "renamed" cases go in opposite directions and are easy to
conflate - check which direction the report describes before deciding:
a genuine, unmodified legitimate tool that has merely been renamed to look
relevant or trustworthy (e.g. a copy of Sysinternals ShellRunAs renamed to
"veraport-q3.exe" to mimic an installer, or a copy of the legitimate
wkspbroker.exe renamed to "SCWSSPSetup.exe") is context_entity - the file's
own bytes are not malicious, only its filename is a lure, and the same
side-loading rule above applies: the actionable artifact is whatever
malicious DLL/payload it loads or drops, not the renamed legitimate tool.
That is distinct from a malicious payload given a legitimate-sounding name
(e.g. a dropped backdoor saved as "svchost.exe"), which remains
confirmed_ioc because the file itself, not just its name, is malicious.

Mechanical check for this exact sentence shape - "<renamed legitimate tool>
uses/performs side-loading (or DLL side-loading) to load/execute <payload>":
the grammatical subject (the renamed tool doing the loading) is
context_entity; only the object it loads/executes (the payload named after
"load"/"execute"/"load and execute") is confirmed_ioc. Do not let the
subject's own verb phrase ("uses side-loading to load a malicious X") make
the subject itself confirmed_ioc - performing the load is not the same as
being the payload.

Never mark a threat-actor or APT group name (e.g. "Lazarus group") as
confirmed_ioc; that is always context_entity, never a static observable.

A victims/targets table (columns such as Company, Domain, Country, Industry,
Status, Discovered, or a ransomware leak-site's "Claimed" listing) names
organizations the adversary claims to have breached - the domain in that row
identifies the *victim*, not attacker-controlled infrastructure. Such a
domain is context_entity, not confirmed_ioc, even though the row's status
says "Claimed" or "victim" - being listed as a target is not evidence the
domain itself is malicious or attacker-operated. Only mark a victim-table
domain confirmed_ioc if the report separately states that domain now hosts
attacker content (e.g. it was repurposed for a leak page, phishing kit, or
C2). Do not reject a victim-table domain outright either - the victim's
identity is still threat-relevant context the report is presenting, so
rejected is for citations/vendor links/unrelated mentions, not for victims.

If you set corrected_category or corrected_indicator_type, the new type must
be one you can point to specific evidence for in the supplied context. Never
substitute a different, unrelated type within the same category (e.g. do not
turn a "persistence" candidate into "beaconing") unless the context explicitly
describes that other behaviour. Do not set corrected_category to intelligence
or corrected_indicator_type to malware/threat_actor/campaign/tool for a value
your own reasoning identifies as legitimate, benign, or a standard system
component - leave its category/type unchanged in that case. A generic
tactic/section label with no specific technique ID attached (e.g. the bare
word "Persistence" used as a table heading) is not itself a TTP; leave its
indicator_type unchanged rather than setting corrected_indicator_type to ttp.

Return one decision for every candidate ID and no extra candidates.

Return only valid JSON.

Do not use Markdown.
Do not use code fences.
Do not use bullet points.
Do not include text before or after the JSON object.

"""

    RESPONSE_SCHEMA: dict[str, Any] = {
        "type": "object",
        "properties": {
            "decisions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "candidate_id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": [
                                "confirmed_ioc",
                                "rejected",
                                "context_entity",
                                "uncertain",
                            ],
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "reason": {"type": "string", "maxLength": 300},
                        "evidence": {"type": "string", "maxLength": 300},
                        "corrected_category": {
                            "anyOf": [
                                {
                                    "type": "string",
                                    "enum": [item.value for item in Category],
                                },
                                {"type": "null"},
                            ]
                        },
                        "corrected_indicator_type": {
                            "anyOf": [
                                {
                                    "type": "string",
                                    "enum": [item.value for item in IndicatorType],
                                },
                                {"type": "null"},
                            ]
                        },
                    },
                    "required": [
                        "candidate_id",
                        "status",
                        "confidence",
                        "reason",
                        "evidence",
                        "corrected_category",
                        "corrected_indicator_type",
                    ],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["decisions"],
        "additionalProperties": False,
    }


    def __init__(
        self,
        client: OllamaClient,
        model: str = "qwen3.5:4b",
        batch_size: int = 20,
        verbose: int = 0,
        max_retries: int = 3,
    ) -> None:
        self.client = client
        self.model = model
        self.batch_size = max(1, batch_size)
        self.verbose = verbose
        self.max_retries = max(1, max_retries)

    def verify(
        self,
        candidates: Sequence[Extraction],
        metadata: DocumentMetadata,
        document_profile: DocumentProfile | None = None,
    ) -> list[Verification]:
        decisions: dict[str, Verification] = {}
        total_batches = (len(candidates) + self.batch_size - 1) // self.batch_size

        for offset in range(0, len(candidates), self.batch_size):
            batch = candidates[offset: offset + self.batch_size]
            batch_number = offset // self.batch_size + 1

            if self.verbose >= 1:
                print(
                    f"[LLM] batch {batch_number}/{total_batches}: {len(batch)} candidates",
                    file=sys.stderr,
                    flush=True,
                )
            if self.verbose >= 2:
                for item in batch:
                    print(
                        f"      {item.indicator_type.value}: {item.value[:120]}",
                        file=sys.stderr,
                        flush=True,
                    )

            decisions.update(
                self._verify_batch(batch, metadata, document_profile, batch_number, total_batches)
            )

        return [decisions[candidate.stable_id] for candidate in candidates]

    def _verify_batch(
        self,
        batch: Sequence[Extraction],
        metadata: DocumentMetadata,
        document_profile: DocumentProfile | None,
        batch_number: int,
        total_batches: int,
    ) -> dict[str, Verification]:
        batch_id_map = {
            str(index): item
            for index, item in enumerate(batch)
        }
        expected_ids = set(batch_id_map.keys())
        request_data = {
            "document_metadata": {
                "filename": metadata.filename,
                "title": metadata.title,
                "authors": list(metadata.authors),
                "cti_source": metadata.cti_source,
                "source_url": metadata.source_url,
                "publish_date": metadata.publish_date,
            },
            **(
                {"document_structure": document_profile.structure_summary}
                if document_profile and document_profile.structure_summary
                else {}
            ),
            "candidates": [
                {
                    "candidate_id": str(index),
                    "category": item.category.value,
                    "indicator_type": item.indicator_type.value,
                    "value": item.value,
                    "normalized_value": item.normalized_value,
                    "method": item.method,
                    "attributes": dict(item.attributes),
                    "context": item.context,
                }
                for index, item in enumerate(batch)
            ],
        }

        try:
            return self._request_with_retry(
                request_data, batch_id_map, expected_ids, batch_number, total_batches
            )
        except OllamaError:
            if len(batch) == 1:
                raise
            # A response that's incomplete for this exact group of candidates
            # can reproduce identically across every retry at temperature 0 -
            # not sampling variance, but something about this specific
            # combination/ordering the model's structured-output generation
            # struggles with. Repeating the identical request cannot fix a
            # deterministic failure; splitting the batch changes what the
            # model is actually asked to produce, which routes around it far
            # more often than another identical retry would. Each half gets
            # its own full retry budget and can split further if needed.
            if self.verbose >= 1:
                print(
                    f"[WARN] batch {batch_number}/{total_batches} still failing "
                    f"after {self.max_retries} attempts - splitting "
                    f"{len(batch)} candidates and retrying independently",
                    file=sys.stderr,
                    flush=True,
                )
            mid = len(batch) // 2
            left = self._verify_batch(
                batch[:mid], metadata, document_profile, batch_number, total_batches
            )
            right = self._verify_batch(
                batch[mid:], metadata, document_profile, batch_number, total_batches
            )
            return {**left, **right}

    def _request_with_retry(
        self,
        request_data: Mapping[str, Any],
        batch_id_map: Mapping[str, Extraction],
        expected_ids: set[str],
        batch_number: int,
        total_batches: int,
    ) -> dict[str, Verification]:
        """Request and validate one verification batch, retrying transient
        failures and structurally incomplete responses alike.

        A response that is syntactically valid JSON but simply omits a
        candidate_id (or duplicates/misnames one) is exactly as retryable as
        a truncated one - it's sampling variance on that one batch, not a
        reasoning failure, so a fresh attempt commonly succeeds. Hard-failing
        the entire report over one batch dropping one decision was losing
        otherwise-complete reports for no benefit (a genuine reasoning
        problem in an individual decision surfaces as an uncertain/incorrect
        verdict, not a missing one).
        """
        last_error: OllamaError | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat_json(
                    model=self.model,
                    system=self.SYSTEM_PROMPT,
                    user=json.dumps(request_data, ensure_ascii=False),
                    schema=self.RESPONSE_SCHEMA,
                )
                return self._validate_batch(response, batch_id_map, expected_ids)
            except OllamaError as exc:
                last_error = exc
                if self.verbose >= 1:
                    print(
                        f"[WARN] batch {batch_number}/{total_batches} "
                        f"attempt {attempt}/{self.max_retries} failed: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )

                if "truncated" in str(exc).lower():
                    self.client.num_predict = min(
                        max(self.client.num_predict + 128, self.client.num_predict * 2),
                        8192,
                    )
                    # num_ctx bounds prompt + generation together. If the
                    # prompt alone already fills most of it (a dense IOC
                    # table with long candidate contexts can do this even
                    # for a short document), growing num_predict is a no-op:
                    # the model has no room left regardless of the target.
                    # Size num_ctx to the known prompt plus a safety margin
                    # so the retry can actually succeed.
                    margin = 512
                    if exc.prompt_tokens is not None:
                        required_ctx = exc.prompt_tokens + self.client.num_predict + margin
                        self.client.num_ctx = max(self.client.num_ctx, min(required_ctx, 32768))
                    else:
                        self.client.num_ctx = max(
                            self.client.num_ctx,
                            min(self.client.num_predict * 2, 32768),
                        )
                    if self.verbose >= 1:
                        print(
                            f"[WARN] increasing num_predict to {self.client.num_predict} "
                            f"and num_ctx to {self.client.num_ctx} for retry",
                            file=sys.stderr,
                            flush=True,
                        )

                if attempt < self.max_retries:
                    time.sleep(1)

        raise OllamaError(
            f"LLM verification failed after {self.max_retries} attempts: {last_error}"
        )

    @staticmethod
    def _validate_batch(
        response: Mapping[str, Any],
        batch_id_map: Mapping[str, Extraction],
        expected_ids: set[str],
    ) -> dict[str, Verification]:
        raw_decisions = response.get("decisions")
        if not isinstance(raw_decisions, list):
            raise OllamaError(
                "Model response did not match the required schema: "
                "missing 'decisions' array."
            )

        seen_ids: set[str] = set()
        batch_decisions: dict[str, Verification] = {}

        for raw in raw_decisions:
            parsed = LLMVerifier._parse_decision(raw)

            if parsed is None:
                raise OllamaError(
                    f"Model returned an invalid decision object: {raw!r}"
                )

            if parsed.candidate_id not in expected_ids:
                raise OllamaError(
                    "Model returned an unknown candidate_id: "
                    f"{parsed.candidate_id}"
                )

            if parsed.candidate_id in seen_ids:
                raise OllamaError(
                    "Model returned a duplicate decision for candidate_id: "
                    f"{parsed.candidate_id}"
                )

            seen_ids.add(parsed.candidate_id)

            original_candidate = batch_id_map[parsed.candidate_id]

            batch_decisions[original_candidate.stable_id] = Verification(
                candidate_id=original_candidate.stable_id,
                status=parsed.status,
                confidence=parsed.confidence,
                reason=parsed.reason,
                evidence=parsed.evidence,
                corrected_category=parsed.corrected_category,
                corrected_indicator_type=parsed.corrected_indicator_type,
            )

        missing_ids = expected_ids - seen_ids
        if missing_ids:
            raise OllamaError(
                "Model omitted decisions for candidate IDs: "
                + ", ".join(sorted(missing_ids))
            )

        return batch_decisions

    @staticmethod
    def _parse_decision(raw: Any) -> Verification | None:
        if not isinstance(raw, dict) or not isinstance(raw.get("candidate_id"), str):
            return None
        try:
            status = VerificationStatus(raw.get("status"))
        except ValueError:
            status = VerificationStatus.UNCERTAIN
        try:
            confidence = min(1.0, max(0.0, float(raw.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0.0
        try:
            category = Category(raw["corrected_category"]) if raw.get("corrected_category") else None
        except ValueError:
            category = None
        try:
            indicator_type = IndicatorType(raw["corrected_indicator_type"]) if raw.get("corrected_indicator_type") else None
        except ValueError:
            indicator_type = None
        return Verification(
            candidate_id=raw["candidate_id"],
            status=status,
            confidence=confidence,
            reason=str(raw.get("reason", "")).strip(),
            evidence=str(raw.get("evidence", "")).strip(),
            corrected_category=category,
            corrected_indicator_type=indicator_type,
        )


class DocumentProfiler:
    """One cheap call per document, run before verification.

    Reads only the title, section headings, and an opening excerpt - not the
    full document text - and returns a structure summary (threaded into every
    LLMVerifier batch as disambiguating context) plus a scope classification.
    Scope is judged from framing/audience, not indicator density: the
    confirmed-IoC counts needed to tell "the report contains a technical
    appendix" from "the report IS a technical appendix" only exist after
    verification runs, which is too late for this call. See
    _assess_scope, which folds those counts back in afterwards via the
    has_tactical_content/has_operational_content flags.
    """

    SYSTEM_PROMPT = """You are profiling a cyber-threat-intelligence report before its
indicators are extracted and verified.

Produce two things from the supplied title, section headings, and opening excerpt:

1. structure_summary: a short, factual note on the report's structure that
   would help a separate reviewer correctly classify individual candidate
   indicators. In particular, name any section/table whose role could be
   mistaken for another - e.g. "Section 4 lists victim/target organisations,
   not attacker-controlled infrastructure" or "the appendix IOC table
   contains confirmed indicators, distinct from the vendor names cited in
   the references section." Leave it as an empty string if the report has no
   such ambiguous structure.

   This note is read alongside every candidate in the document, not just
   ones drawn from the section it describes, so never characterise a
   report's own indicators/IOC table as unverified, contextual, or merely
   illustrative - doing so would bias judgement of unrelated candidates
   elsewhere in the same document. Confirming that a value belongs to the
   report's own IOC table is a job for the separate verification step, not
   for this summary; restrict this note to *what a section's role is*
   (which table is victims vs. infrastructure, which named library is a
   side-loading target vs. a payload), never a verdict on whether its
   contents are legitimate indicators.

2. scope: the report's primary intended audience, exactly one of:
   - tactical: short-term, immediate mechanisms; aimed at operators and
     software tools (raw indicators, detection signatures, immediate
     technical mechanics).
   - operational: aimed at analysts and security teams; discusses tactics
     and campaign patterns currently being observed (TTPs, campaign
     narrative, actor behaviour).
   - strategic: aimed at strategic decision makers; discusses long-term and
     current trends (business risk, threat landscape, sector/geopolitical
     framing).

   Judge scope from framing and audience, not indicator density alone: a
   report can contain a technical IOC appendix and still be primarily
   strategic if its narrative frames those IOCs as supporting evidence for a
   trend/decision-maker audience rather than being written for operators.

Return only valid JSON. Do not use Markdown, code fences, or bullet points.
Do not include text before or after the JSON object.
"""

    RESPONSE_SCHEMA: dict[str, Any] = {
        "type": "object",
        "properties": {
            "structure_summary": {"type": "string", "maxLength": 1500},
            "scope": {"type": "string", "enum": [item.value for item in Scope]},
            "scope_reason": {"type": "string", "maxLength": 300},
        },
        "required": ["structure_summary", "scope", "scope_reason"],
        "additionalProperties": False,
    }

    # Deliberately looser than CTIExtractor._section_hint's version (which
    # only needs the single nearest heading above one candidate): this scans
    # the whole document to build a heading list for the LLM, so recall
    # matters more than precision - the model, not this regex, is what
    # ultimately judges which headings are structurally meaningful.
    _HEADING_RE = re.compile(r"^(?:\d+(?:\.\d+)*\s+)?[A-Z][A-Za-z0-9 /&'-]{2,80}$")

    def __init__(
        self,
        client: OllamaClient,
        model: str = "qwen3.5:4b",
        verbose: int = 0,
        max_retries: int = 3,
    ) -> None:
        self.client = client
        self.model = model
        self.verbose = verbose
        self.max_retries = max(1, max_retries)

    def profile(self, text: str, metadata: DocumentMetadata) -> DocumentProfile:
        request_data = {
            "document_metadata": {
                "filename": metadata.filename,
                "title": metadata.title,
                "cti_source": metadata.cti_source,
                "publish_date": metadata.publish_date,
            },
            "headings": self._extract_headings(text),
            "excerpt": " ".join(text[:2000].split()),
        }

        last_error: OllamaError | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat_json(
                    model=self.model,
                    system=self.SYSTEM_PROMPT,
                    user=json.dumps(request_data, ensure_ascii=False),
                    schema=self.RESPONSE_SCHEMA,
                )
                return self._parse(response)
            except OllamaError as exc:
                last_error = exc
                if self.verbose >= 1:
                    print(
                        f"[WARN] document profiling attempt {attempt}/{self.max_retries} failed: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )
                if attempt < self.max_retries:
                    time.sleep(1)

        raise OllamaError(
            f"Document profiling failed after {self.max_retries} attempts: {last_error}"
        )

    @staticmethod
    def _parse(response: Mapping[str, Any]) -> DocumentProfile:
        try:
            scope = Scope(response.get("scope"))
        except ValueError:
            raise OllamaError(f"Model returned an unknown scope: {response.get('scope')!r}")
        return DocumentProfile(
            structure_summary=str(response.get("structure_summary", "")).strip(),
            scope=scope,
            scope_reason=str(response.get("scope_reason", "")).strip(),
        )

    @classmethod
    def _extract_headings(cls, text: str, limit: int = 40) -> list[str]:
        headings: list[str] = []
        seen: set[str] = set()
        for raw_line in text.splitlines():
            line = " ".join(raw_line.split())
            if not line or len(line) > 100:
                continue
            if line.isupper() or cls._HEADING_RE.match(line):
                if line not in seen:
                    seen.add(line)
                    headings.append(line)
            if len(headings) >= limit:
                break
        return headings


# ---------------------------------------------------------------------------
# Public application API
# ---------------------------------------------------------------------------


_TACTICAL_CATEGORIES = {Category.NETWORK, Category.HOST, Category.EMAIL}


def _assess_scope(
    profile: DocumentProfile,
    items: Sequence[VerifiedExtraction],
) -> ScopeAssessment:
    # accepted (CONFIRMED + CONTEXT_ENTITY), not CONFIRMED alone: the
    # verifier's own SYSTEM_PROMPT taxonomy classifies ATT&CK techniques and
    # behavioural narrative as context_entity ("provide intelligence context
    # but are not static observables"), never confirmed_ioc - filtering to
    # CONFIRMED only would make has_operational_content structurally unable
    # to ever be True, since the exact indicator_type/category it's meant to
    # detect (TTP, BEHAVIOUR) is defined to land in the other bucket.
    accepted = [item for item in items if item.accepted]
    has_tactical = any(
        (item.verification.corrected_category or item.extraction.category) in _TACTICAL_CATEGORIES
        for item in accepted
    )
    has_operational = any(
        (item.verification.corrected_category or item.extraction.category) is Category.BEHAVIOUR
        or (item.verification.corrected_indicator_type or item.extraction.indicator_type) is IndicatorType.TTP
        for item in accepted
    )
    return ScopeAssessment(
        primary_scope=profile.scope,
        reason=profile.scope_reason,
        structure_summary=profile.structure_summary,
        has_tactical_content=has_tactical,
        has_operational_content=has_operational,
        has_strategic_content=profile.scope is Scope.STRATEGIC,
    )


def analyse_document(
    path: Path,
    *,
    model: str = "qwen3.5:4b",
    profiler_model: str | None = None,
    ollama_url: str = "http://127.0.0.1:11434",
    batch_size: int = 5,
    timeout: int = 600,
    verify: bool = True,
    verbose: int = 0,
    num_predict: int = 384,
    num_ctx: int = 4096,
    max_retries: int = 3,
    config: ExtractorConfig | None = None,
) -> IoCExtractionResult:
    """Analyse one CTI document and return a reusable Python object.

    `model` verifies candidates; `profiler_model` classifies document scope
    and defaults to `model` when not given.
    """
    started = time.perf_counter()
    if verbose >= 1:
        print(f"[INFO] reading {path}", file=sys.stderr, flush=True)
    loaded = DocumentReader.load(path)
    if verbose >= 1:
        print(f"[INFO] extracted {len(loaded.text):,} characters", file=sys.stderr, flush=True)
    metadata = MetadataExtractor().extract(loaded)
    candidates = CTIExtractor(config).extract(loaded.text)
    if verbose >= 1:
        print(f"[INFO] found {len(candidates)} candidates", file=sys.stderr, flush=True)

    profile: DocumentProfile | None = None
    if verify:
        client = OllamaClient(
            ollama_url, timeout=timeout, verbose=verbose,
            num_predict=num_predict, num_ctx=num_ctx,
        )
        profiler = DocumentProfiler(client, model=profiler_model or model, verbose=verbose, max_retries=max_retries)
        profile = profiler.profile(loaded.text, metadata)
        if verbose >= 1:
            print(
                f"[INFO] scope={profile.scope.value}: {profile.scope_reason}",
                file=sys.stderr, flush=True,
            )

    if verify and candidates:
        verifier = LLMVerifier(
            client,
            model=model,
            batch_size=batch_size,
            verbose=verbose,
            max_retries=max_retries,
        )
        verifications = verifier.verify(candidates, metadata, document_profile=profile)
        used_model: str | None = model
    else:
        verifications = [
            Verification(
                item.stable_id,
                VerificationStatus.NOT_VERIFIED,
                0.0,
                "LLM verification was disabled.",
            )
            for item in candidates
        ]
        used_model = None

    items = tuple(
        VerifiedExtraction(candidate, verification)
        for candidate, verification in zip(candidates, verifications, strict=True)
    )

    return IoCExtractionResult(
        metadata=metadata,
        items=items,
        model=used_model,
        scope=_assess_scope(profile, items) if profile is not None else None,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract CTI candidates and verify them with an Ollama-hosted LLM."
    )
    parser.add_argument("input", type=Path, help="Input .txt/.md/.json/.csv or .pdf report")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON to this path")
    parser.add_argument(
        "--config",
        type=Path,
        help="threatlens.conf to read settings from (default: THREATLENS_CONF, else the checkout's or per-user one)",
    )
    parser.add_argument(
        "--ignore-calibration",
        action="store_true",
        help="Use built-in [llm] tuning instead of threatlens.conf's (its Ollama URL and models still apply)",
    )
    parser.add_argument("--model", default=None, help="Ollama model name; overrides threatlens.conf")
    parser.add_argument("--ollama-url", default=None, help="Ollama base URL; overrides threatlens.conf")
    parser.add_argument("--batch-size", type=int, default=None, help="Candidates per LLM request; overrides threatlens.conf")
    parser.add_argument("--timeout", type=int, default=None, help="Seconds allowed per Ollama request; overrides threatlens.conf")
    parser.add_argument("--no-llm", action="store_true", help="Extract candidates without LLM verification")
    parser.add_argument("--accepted-only", action="store_true", help="Omit rejected candidates from JSON")
    parser.add_argument("--keep-duplicates", action="store_true")
    parser.add_argument("--exclude-private-ips", action="store_true")
    parser.add_argument("--context-chars", type=int, default=None, help="Context radius; overrides threatlens.conf")
    parser.add_argument("--num-predict", type=int, default=None, help="Maximum output tokens; overrides threatlens.conf")
    parser.add_argument("--num-ctx", type=int, default=None, help="Ollama context size; overrides threatlens.conf")
    parser.add_argument("--max-retries", type=int, default=None, help="LLM attempts per batch; overrides threatlens.conf")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase progress detail; use -vv or -vvv")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    # Prepend the input CTI report filename to the output filename
    if args.output:
        args.output = args.output.with_name(
            f"{args.input.stem}_{args.output.name}"
        )

    from threatlens.config import ConfigError, LLMSettings, config_path, load_config

    selected = args.config or config_path()
    if args.config is not None and not args.config.is_file():
        print(f"error: config file does not exist: {args.config}", file=sys.stderr)
        return 2
    try:
        local = load_config(selected)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    llm = LLMSettings() if args.ignore_calibration else local.llm

    model = args.model or local.verifier_model
    ollama_url = args.ollama_url or local.ollama_url
    batch_size = max(1, args.batch_size if args.batch_size is not None else llm.batch_size)
    timeout = max(30, args.timeout if args.timeout is not None else llm.timeout)
    context_chars = max(100, args.context_chars if args.context_chars is not None else llm.context_chars)
    num_predict = max(64, args.num_predict if args.num_predict is not None else llm.num_predict)
    num_ctx = max(1024, args.num_ctx if args.num_ctx is not None else llm.num_ctx)
    max_retries = max(1, args.max_retries if args.max_retries is not None else llm.max_retries)

    if args.verbose >= 1:
        source = str(selected) if selected.is_file() else "built-in defaults"
        print(
            f"[CONFIG] source={source} profile={llm.profile} model={model} "
            f"batch_size={batch_size} num_ctx={num_ctx} num_predict={num_predict} "
            f"context_chars={context_chars} timeout={timeout}s max_retries={max_retries}",
            file=sys.stderr,
            flush=True,
        )

    config = ExtractorConfig(
        context_chars=context_chars,
        include_private_ips=not args.exclude_private_ips,
        deduplicate=not args.keep_duplicates,
    )
    try:
        result = analyse_document(
            args.input,
            model=model,
            profiler_model=local.profiler_model or None,
            ollama_url=ollama_url,
            batch_size=batch_size,
            timeout=timeout,
            verify=not args.no_llm,
            config=config,
            verbose=args.verbose,
            num_predict=num_predict,
            num_ctx=num_ctx,
            max_retries=max_retries,
        )
    except (OSError, UnicodeError, ValueError, RuntimeError, OllamaError) as exc:
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
            print(f"error: unable to write {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())