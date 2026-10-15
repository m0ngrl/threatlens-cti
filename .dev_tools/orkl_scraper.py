#!/usr/bin/env python3
"""Download CTI reports from the ORKL archive that we don't already have.

Source: https://archive.orkl.eu/ (a plain file mirror of the ORKL threat
intel library). The mirror also publishes a single catalog file,
``library.json``, listing every report it holds (sha1 hash, title, dates,
file size, source PDF URL). That catalog is the only remote call this script
needs to make besides the actual PDF downloads themselves - the site's own
directory listing is enormous (tens of thousands of rows of HTML) and is not
used here.

Pipeline
--------
1. Fetch (or reuse a cached copy of) ``library.json``.
2. Hash every PDF already in the destination directory (content sha1, not
   filename - some local files predate this tool and aren't hash-named).
3. Diff against the catalog to get the set of reports we don't have yet.
4. Rank those by report date, newest first. A report's date is the leading
   ``YYYY-MM-DD`` in its title when present (ORKL's own convention), falling
   back to the archive's file_creation_date otherwise.
5. Download newest-first until the destination directory holds ``--target``
   reports, skipping over any individual download failures rather than
   stopping the run.

Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ARCHIVE_BASE = "https://archive.orkl.eu"
LIBRARY_URL = f"{ARCHIVE_BASE}/library.json"

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEST = REPO_ROOT / "docs" / "database" / "CTI"
CACHE_DIR = REPO_ROOT / ".dev_tools" / ".cache"
INDEX_CACHE = CACHE_DIR / "orkl_index.json"

TITLE_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
USER_AGENT = "ThreatLens-ORKL-Scraper/1.0 (dev tool; +https://github.com/m0ngrl/threatlens-cti)"

MIN_SANE_DATE = "1990-01-01"
MAX_SANE_DATE = "2099-12-31"


@dataclass
class ReportEntry:
    sha1: str
    title: str
    report_date: str  # "YYYY-MM-DD", best-effort; "0000-00-00" if unknown
    file_size: int
    pdf_url: str


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def http_head_etag(url: str, timeout: int = 30) -> str | None:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.headers.get("ETag")
    except urllib.error.URLError:
        return None


def extract_report_date(title: str, file_creation_date: str) -> str:
    m = TITLE_DATE_RE.match(title or "")
    if m and MIN_SANE_DATE <= m.group(1) <= MAX_SANE_DATE:
        return m.group(1)
    if file_creation_date:
        candidate = file_creation_date[:10]
        if MIN_SANE_DATE <= candidate <= MAX_SANE_DATE:
            return candidate
    return "0000-00-00"


def build_index_from_catalog(raw: bytes) -> list[ReportEntry]:
    entries = json.loads(raw)
    index: list[ReportEntry] = []
    for e in entries:
        sha1 = e.get("sha1_hash")
        if not sha1 or not SHA1_RE.match(sha1):
            continue
        files = e.get("files") or {}
        pdf_url = files.get("pdf") if isinstance(files, dict) else None
        if not pdf_url:
            pdf_url = f"{ARCHIVE_BASE}/{sha1}.pdf"
        title = e.get("title") or e.get("llm_title") or ""
        report_date = extract_report_date(title, e.get("file_creation_date") or "")
        index.append(
            ReportEntry(
                sha1=sha1,
                title=title,
                report_date=report_date,
                file_size=int(e.get("file_size") or 0),
                pdf_url=pdf_url,
            )
        )
    return index


def load_index(force_refresh: bool) -> list[ReportEntry]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not force_refresh and INDEX_CACHE.exists():
        cached = json.loads(INDEX_CACHE.read_text())
        etag = http_head_etag(LIBRARY_URL)
        if etag and etag == cached.get("etag"):
            log(f"Using cached ORKL index ({len(cached['entries'])} reports, unchanged since last run).")
            return [ReportEntry(**e) for e in cached["entries"]]
        if etag is None:
            log("Could not reach archive.orkl.eu to check for catalog updates; using cached index.")
            return [ReportEntry(**e) for e in cached["entries"]]

    log("Fetching ORKL catalog (library.json) - this is a one-time ~600MB download, cached afterwards...")
    req = urllib.request.Request(LIBRARY_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=300) as resp:
        etag = resp.headers.get("ETag")
        raw = resp.read()

    index = build_index_from_catalog(raw)
    INDEX_CACHE.write_text(
        json.dumps({"etag": etag, "entries": [e.__dict__ for e in index]})
    )
    log(f"Catalog fetched: {len(index)} reports known to the archive.")
    return index


def local_hashes(dest: Path) -> set[str]:
    hashes = set()
    for pdf in dest.glob("*.pdf"):
        data = pdf.read_bytes()
        hashes.add(hashlib.sha1(data).hexdigest())
    return hashes


def download_report(entry: ReportEntry, dest: Path, timeout: int = 120) -> bool:
    tmp_path = dest / f".{entry.sha1}.pdf.part"
    final_path = dest / f"{entry.sha1}.pdf"
    req = urllib.request.Request(entry.pdf_url, headers={"User-Agent": USER_AGENT})
    hasher = hashlib.sha1()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp_path, "wb") as f:
            while chunk := resp.read(1 << 16):
                hasher.update(chunk)
                f.write(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log(f"  FAILED: {entry.sha1}.pdf ({exc})")
        tmp_path.unlink(missing_ok=True)
        return False

    if hasher.hexdigest() != entry.sha1:
        log(f"  FAILED: {entry.sha1}.pdf (checksum mismatch after download, discarding)")
        tmp_path.unlink(missing_ok=True)
        return False

    tmp_path.replace(final_path)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-n", "--target", type=int, required=True,
        help="Total number of reports the CTI directory should hold once this run finishes.",
    )
    parser.add_argument(
        "--dest", type=Path, default=DEFAULT_DEST,
        help=f"CTI reports directory (default: {DEFAULT_DEST.relative_to(REPO_ROOT)})",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be downloaded, without downloading.")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between downloads (default: 0.5).")
    parser.add_argument(
        "--refresh-library", action="store_true",
        help="Force a fresh download of the ORKL catalog instead of reusing the cached one.",
    )
    args = parser.parse_args()

    if args.target < 0:
        parser.error("--target must be >= 0")

    dest: Path = args.dest
    dest.mkdir(parents=True, exist_ok=True)

    log(f"Scanning existing reports in {dest} ...")
    have = local_hashes(dest)
    log(f"Found {len(have)} report(s) already present.")

    needed = args.target - len(have)
    if needed <= 0:
        log(f"Target of {args.target} already met (have {len(have)}). Nothing to do.")
        return 0

    index = load_index(force_refresh=args.refresh_library)
    candidates = [e for e in index if e.sha1 not in have]
    candidates.sort(key=lambda e: e.report_date, reverse=True)

    if not candidates:
        log("No reports in the archive that we don't already have.")
        return 0

    log(f"Need {needed} more report(s) to reach target of {args.target}.")
    log(f"{len(candidates)} candidate report(s) available, newest first.")

    downloaded = 0
    failed = 0
    for i, entry in enumerate(candidates, start=1):
        if downloaded >= needed:
            break

        label = f"[{downloaded + 1}/{needed}]"
        date_label = entry.report_date if entry.report_date != "0000-00-00" else "unknown date"
        title = entry.title or "(untitled)"

        if args.dry_run:
            log(f"{label} WOULD DOWNLOAD {entry.sha1}.pdf  ({date_label})  {title}")
            downloaded += 1
            continue

        log(f"{label} Downloading {entry.sha1}.pdf  ({date_label})  {title}")
        if download_report(entry, dest):
            downloaded += 1
        else:
            failed += 1
        time.sleep(args.delay)

    log("")
    log("=" * 70)
    log(f"{'Would download' if args.dry_run else 'Downloaded'}: {downloaded}")
    if failed:
        log(f"Failed          : {failed} (skipped, next candidate used instead)")
    log(f"CTI directory now holds (target): {len(have) + downloaded}/{args.target}")
    if downloaded < needed:
        log("Note: ran out of new candidates before reaching target.")
    log("=" * 70)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
