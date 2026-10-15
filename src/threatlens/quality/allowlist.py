"""
ThreatLens - allowlist / false-positive detection.
ZEIT3118 Capstone Project

Checks indicators against allowlist entries in the MISP warninglist pattern:
values that are known-benign and therefore likely false positives when a
report mentions them. load_allowlist(session) reads the allowlist table, and
flag_allowlisted_indicators() uses it, but only the tests call that. The
pipeline screens in quality_checker.check_report(), and no current caller
passes it the table's entries, so it falls back to seed.py's ALLOWLIST
(default_allowlist_entries). Edits to the table do not affect ingest yet.

Matching semantics
------------------
Three pattern forms are supported, chosen to fit the seeded data:

    8.8.8.8         exact match, case-insensitive
    10.0.0.0/8      CIDR containment, for ipv4 and ipv6 only
    *.google.com    subdomain match, NOT the apex domain

The last one is a real decision, and the seed data settles it: seed.py lists
"google.com" and "*.google.com" as two separate entries. If the wildcard
already covered the apex, the second entry would be redundant. So "*.google.com"
matches mail.google.com but not google.com itself.

URL indicators are matched on their host, so a report linking to
https://www.microsoft.com/advisory is recognised as benign rather than being
scored as a malicious URL. This is the other judgement call in the module and
is easy to disable if the team decides a URL should only match a url pattern.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from threatlens.db.conformance import to_iso8601
from threatlens.db.models import Allowlist, Indicator, QualityFlag

# ioc_types that carry an IP address, and so support CIDR patterns.
_IP_TYPES = frozenset({"ipv4", "ipv6"})

# ioc_types that carry a hostname, and so are matched against domain patterns.
_HOST_TYPES = frozenset({"domain", "hostname", "email_domain"})


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    """One allowlist row, pre-parsed so matching does not re-parse per lookup."""

    ioc_type: str
    pattern: str
    reason: str | None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    wildcard_suffix: str | None = None

    @classmethod
    def from_row(cls, row: Allowlist) -> AllowlistEntry:
        ioc_type = (row.ioc_type or "").strip().lower()
        pattern = (row.pattern or "").strip().lower()

        network = None
        wildcard_suffix = None

        if "/" in pattern and ioc_type in _IP_TYPES:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                network = None

        elif pattern.startswith("*."):
            # Store ".google.com" so a suffix test cannot match "notgoogle.com".
            wildcard_suffix = pattern[1:]

        return cls(
            ioc_type=ioc_type,
            pattern=pattern,
            reason=row.reason,
            network=network,
            wildcard_suffix=wildcard_suffix,
        )

    def matches(self, ioc_type: str, normalised: str) -> bool:
        candidate = (normalised or "").strip().lower()
        if not candidate:
            return False

        ioc_type = (ioc_type or "").strip().lower()

        if self.network is not None:
            if ioc_type not in _IP_TYPES:
                return False
            try:
                return ipaddress.ip_address(candidate) in self.network
            except ValueError:
                return False

        # A url is checked against domain patterns using its host.
        if ioc_type == "url" and self.ioc_type == "domain":
            candidate = _url_host(candidate)
            if not candidate:
                return False
        elif self.ioc_type != ioc_type and not (
            self.ioc_type == "domain" and ioc_type in _HOST_TYPES
        ):
            return False

        if self.wildcard_suffix is not None:
            return candidate.endswith(self.wildcard_suffix)

        return candidate == self.pattern


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def load_allowlist(session: Session) -> tuple[AllowlistEntry, ...]:
    """Load and pre-parse every allowlist row."""
    rows = session.execute(select(Allowlist)).scalars().all()
    return tuple(AllowlistEntry.from_row(row) for row in rows)


def match_allowlist(
    ioc_type: str,
    normalised: str,
    entries: Iterable[AllowlistEntry],
) -> AllowlistEntry | None:
    """Return the first allowlist entry matching this indicator, or None."""
    for entry in entries:
        if entry.matches(ioc_type, normalised):
            return entry
    return None


def is_allowlisted(
    ioc_type: str,
    normalised: str,
    entries: Iterable[AllowlistEntry],
) -> bool:
    return match_allowlist(ioc_type, normalised, entries) is not None


# ---------------------------------------------------------------------------
# Flagging
# ---------------------------------------------------------------------------

FLAG_TYPE = "known_benign"
FLAG_DIMENSION = "accuracy"
FLAG_SEVERITY = "warning"


def flag_allowlisted_indicators(
    session: Session,
    entries: Sequence[AllowlistEntry] | None = None,
) -> list[QualityFlag]:
    """Raise a quality flag against every indicator that is known-benign.

    Indicators are flagged rather than deleted. A report genuinely mentioning
    8.8.8.8 is a fact about the report, and discarding it would lose the
    sighting; the flag records that it should not be treated as malicious.

    Re-running does not duplicate flags for an indicator already flagged.
    The caller commits.
    """
    entries = entries if entries is not None else load_allowlist(session)

    already_flagged = set(
        session.execute(
            select(QualityFlag.indicator_id).where(QualityFlag.flag_type == FLAG_TYPE)
        ).scalars().all()
    )

    raised: list[QualityFlag] = []
    raised_at = to_iso8601()

    for indicator in session.execute(select(Indicator)).scalars():
        if indicator.id in already_flagged:
            continue

        entry = match_allowlist(indicator.ioc_type, indicator.normalised, entries)
        if entry is None:
            continue

        flag = QualityFlag(
            indicator_id=indicator.id,
            flag_type=FLAG_TYPE,
            dimension=FLAG_DIMENSION,
            detail=(
                f"matches allowlist pattern {entry.pattern!r}"
                + (f" ({entry.reason})" if entry.reason else "")
            ),
            severity=FLAG_SEVERITY,
            raised_at=raised_at,
            status="open",
        )
        session.add(flag)
        raised.append(flag)

    return raised
