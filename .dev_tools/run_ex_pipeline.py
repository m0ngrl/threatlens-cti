#!/usr/bin/env python3
"""Bulk-ingest the CTI corpus into a ThreatLens database, in resumable batches.

A thin wrapper around the dashboard's ingest worker: every report goes through
threatlens.dashboard.ingest_worker.run(), the exact pipeline the Ingest page
and threatlens-ingest use, so a database built here matches one built from
the web UI. Per report that is:

    1. Extract  - the "llm" (Ollama-verified, settings from threatlens.conf)
                  or "python" engine.
    2. QA       - quality_checker.check_report(), with the database's own
                  scoring policy.
    3. Persist  - quality_checker.persist_report(), committed per report,
                  recording sources.extraction_engine / verification_model.
    4. Rescore  - quality_checker.rescore_from_db(), so cross-report
                  accuracy is current after every report.

What this script adds is only what the dashboard cannot do:

* Creates the database if needed, via the real Alembic chain (never
  create_all()), and seeds scoring_config + allowlist with seed.py's
  reference data - but only while those tables are empty, so a re-run never
  overwrites weights edited since.
* Splits the corpus into batches (--batch K/N over the sorted file list), so
  a long LLM run can be done in sittings.
* Skips reports already stored (matched by file sha256, as ingest keys
  sources), so an interrupted batch can simply be re-run. Nothing is cached
  outside the database: a skipped report is one that finished, and anything
  not stored is re-extracted from scratch.

Usage:
    python .dev_tools/run_ex_pipeline.py --db-path db/ex3_threatlens.db --batch 1/3
    python .dev_tools/run_ex_pipeline.py --db-path db/ex3_threatlens.db --batch 2/3 -vv
    python .dev_tools/run_ex_pipeline.py --db-path db/scratch.db --limit 2      # smoke test
    python .dev_tools/run_ex_pipeline.py --db-path db/scratch.db --engine python
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from threatlens.dashboard import ingest_worker  # noqa: E402
from threatlens.db.ingest import compute_sha256  # noqa: E402
from threatlens.db.migrate import upgrade  # noqa: E402
from threatlens.db.models import RawDocument  # noqa: E402
from threatlens.db.seed import seed_missing  # noqa: E402

DEFAULT_DB_PATH = REPO_ROOT / "db" / "ex_threatlens.db"
DEFAULT_CTI_DIR = REPO_ROOT / "docs" / "database" / "CTI"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def seed_reference_data(session: Session) -> None:
    """seed.py's reference rows, for whichever of the two tables is still empty."""
    for message in seed_missing(session):
        log(message)


def parse_batch(value: str) -> tuple[int, int]:
    """'2/3' -> (2, 3)."""
    try:
        k, n = (int(part) for part in value.split("/"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected K/N, e.g. 1/3, got {value!r}")
    if not 1 <= k <= n:
        raise argparse.ArgumentTypeError(f"batch {k} is not in 1..{n}")
    return k, n


def batch_slice(pdfs: list[Path], k: int, n: int) -> list[Path]:
    """The k-th of n near-equal contiguous slices (103 / 3 -> 35, 34, 34)."""
    size, extra = divmod(len(pdfs), n)
    start = (k - 1) * size + min(k - 1, extra)
    return pdfs[start : start + size + (1 if k <= extra else 0)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--cti-dir", type=Path, default=DEFAULT_CTI_DIR)
    parser.add_argument("--batch", type=parse_batch, default=(1, 1), metavar="K/N",
                        help="Process the K-th of N slices of the sorted report list (default: all).")
    parser.add_argument("--engine", choices=("llm", "python"), default="llm")
    parser.add_argument("--limit", type=int, default=None, help="Process only the first N reports of the batch (smoke test).")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args()

    all_pdfs = sorted(args.cti_dir.glob("*.pdf"))
    k, n = args.batch
    pdfs = batch_slice(all_pdfs, k, n)
    if args.limit:
        pdfs = pdfs[: args.limit]
    if not pdfs:
        log(f"No PDFs found in {args.cti_dir}")
        return 1

    # Human-readable output only; the @@ lines are for the dashboard's queue.
    ingest_worker.MACHINE_OUTPUT = False

    log(f"Database: {args.db_path}")
    log("Applying Alembic migrations (head)...")
    upgrade(args.db_path)
    with Session(create_engine(f"sqlite:///{args.db_path}")) as session:
        seed_reference_data(session)
        stored = set(session.execute(select(RawDocument.sha256)).scalars())

    log(f"Batch {k}/{n}: {len(pdfs)} of {len(all_pdfs)} reports, engine={args.engine}")

    run_start = time.time()
    processed, skipped, failed = 0, 0, []

    for i, pdf in enumerate(pdfs, start=1):
        tag = f"[{i}/{len(pdfs)}] {pdf.name}"
        if compute_sha256(pdf) in stored:
            log(f"{tag}  already stored - skipped")
            skipped += 1
            continue

        t0 = time.time()
        try:
            ingest_worker.run(pdf, args.db_path, args.engine, args.verbose)
            log(f"{tag}  done in {time.time() - t0:.1f}s")
            processed += 1
        except Exception as exc:  # noqa: BLE001 - keep the batch going unattended
            log(f"{tag}  FAILED: {type(exc).__name__}: {exc}")
            log(traceback.format_exc(limit=3))
            failed.append((pdf.name, f"{type(exc).__name__}: {exc}"))

    elapsed_total = time.time() - run_start
    log("=" * 70)
    log(f"Batch {k}/{n}")
    log(f"Reports processed : {processed}/{len(pdfs)}  ({skipped} already stored)")
    log(f"Reports failed    : {len(failed)}")
    for name, reason in failed:
        log(f"  - {name}: {reason}")
    log(f"Total elapsed     : {elapsed_total / 60:.1f} min")
    log(f"Database          : {args.db_path}")
    log("=" * 70)

    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
