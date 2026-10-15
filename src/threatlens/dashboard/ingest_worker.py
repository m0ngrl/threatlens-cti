"""ThreatLens dashboard - ingest one report into a database (worker process).

The dashboard's Ingest page runs this once per queued report, as a separate
process (see ingest_jobs.py), so a slow or stuck LLM run can be cancelled by
killing it, and an extractor crash cannot take the dashboard down with it.

Same pipeline as .dev_tools/run_ex_pipeline.py, for a single report:

    1. Extract  - the "llm" (Ollama-verified, threatlens.conf) or
                  "python" (local heuristics only) engine, as in cli.py.
    2. QA       - quality_checker.check_report(), all four layers.
    3. Persist  - quality_checker.persist_report(), then commit.
    4. Rescore  - quality_checker.rescore_from_db(), as its docstring
                  recommends after each ingest.

Everything is written to stdout. Besides the extractors' own -v/-vv/-vvv
log lines, the worker prints machine-readable lines the dashboard parses:

    @@progress {"stage": "...", "percent": 0-100, "message": "..."}
    @@result   {"source_id": ..., ...}

The same pipeline is installed as the threatlens-ingest command (cli_main),
which drops the @@ lines and keeps only the human-readable output.

Usage:
    python -m threatlens.dashboard.ingest_worker report.pdf --db db/threatlens.db --engine llm -vv
    threatlens-ingest report.pdf --db db/threatlens.db --engine python
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any

PROGRESS_PREFIX = "@@progress "
RESULT_PREFIX = "@@result "

# False under threatlens-ingest, where nobody is parsing the @@ lines.
MACHINE_OUTPUT = True



def emit(prefix: str, payload: dict[str, Any]) -> None:
    if not MACHINE_OUTPUT:
        return
    print(prefix + json.dumps(payload), flush=True)


def progress(stage: str, percent: float, message: str) -> None:
    emit(PROGRESS_PREFIX, {"stage": stage, "percent": percent, "message": message})
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def stored_file_path(pdf: Path) -> str:
    """Path to record in raw_documents: data-folder-relative when possible (paths.stored_path)."""
    from threatlens.paths import stored_path

    return stored_path(pdf)


def extract(pdf: Path, engine: str, verbose: int):
    from threatlens.config import setup_status

    # Both engines persist with threatlens.conf's quality weights; only the
    # llm engine needs calibration.
    for warning in setup_status().warnings(llm=engine == "llm"):
        print(f"[WARN] {warning}", flush=True)

    if engine == "python":
        from threatlens.extractors.ioc_extract_python import analyse_document

        return analyse_document(pdf, verbose=verbose)

    from threatlens.config import load_config
    from threatlens.extractors.ioc_extract_llm_fs import (
        ExtractorConfig,
        analyse_document,
    )

    local = load_config()
    llm = local.llm
    print(
        f"[INFO] LLM model={local.verifier_model} "
        f"profiler={local.effective_profiler_model} url={local.ollama_url} "
        f"batch_size={llm.batch_size} timeout={llm.timeout}s",
        flush=True,
    )
    return analyse_document(
        pdf,
        model=local.verifier_model,
        profiler_model=local.profiler_model or None,
        ollama_url=local.ollama_url,
        batch_size=llm.batch_size,
        timeout=llm.timeout,
        num_predict=llm.num_predict,
        num_ctx=llm.num_ctx,
        max_retries=llm.max_retries,
        verbose=verbose,
        config=ExtractorConfig(context_chars=llm.context_chars),
    )


def run(pdf: Path, db_path: Path, engine: str, verbose: int) -> int:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from threatlens.quality import quality_checker as checker

    started = time.time()
    progress("extract", 2, f"Extracting {pdf.name} with the {engine} engine")
    result = extract(pdf, engine, verbose)
    progress(
        "qa",
        88,
        f"Extracted {len(result.items)} candidates: {len(result.confirmed_iocs())} confirmed, "
        f"{len(result.context_entities())} context, {len(result.rejected())} rejected - running quality checks",
    )

    # Hand-off from extraction to QA: the IoCExtractionResult goes over in
    # memory (run_from_payload calls its to_dict()), never via a JSON file.
    # One engine per run, so the agreement grade is always single_verifier.
    run_ = checker.run_from_payload(result, source=str(pdf))
    session = Session(create_engine(f"sqlite:///{db_path}"))
    try:
        report = checker.check_report([run_], policy=checker.ScoringPolicy.from_session(session))
        progress(
            "persist",
            93,
            f"Quality checks done: {len(report.indicators)} accepted of {len(report.assessments)} - "
            f"writing to {db_path.name}",
        )
        ingest = checker.persist_report(
            session, report, source_name=pdf.name, file_path=stored_file_path(pdf)
        )
        session.commit()
        print(f"[INFO] stored: {ingest}", flush=True)

        progress("rescore", 97, "Rescoring stored indicators (timeliness/accuracy)")
        rescored = checker.rescore_from_db(session)
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()

    elapsed = time.time() - started
    progress("done", 100, f"Done in {elapsed:.1f}s - source id {ingest.source_id}")
    emit(RESULT_PREFIX, {
        "source_id": ingest.source_id,
        "source_created": ingest.source_created,
        "candidates": len(report.assessments),
        "accepted": len(report.indicators),
        "indicators_created": ingest.indicators_created,
        "indicators_updated": ingest.indicators_updated,
        "sightings_created": ingest.sightings_created,
        "rescored": rescored,
        "model": result.model,
        "elapsed_seconds": round(elapsed, 1),
    })
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest one CTI report into a ThreatLens database.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--db", type=Path, required=True, help="SQLite database file to write to")
    parser.add_argument("--engine", choices=("llm", "python"), default="llm")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args(argv)

    if not args.source.is_file():
        print(f"error: source does not exist: {args.source}", flush=True)
        return 1
    if not args.db.is_file():
        print(f"error: database does not exist: {args.db}", flush=True)
        return 1

    try:
        return run(args.source, args.db, args.engine, args.verbose)
    except Exception as exc:  # noqa: BLE001 - report every failure to the dashboard
        print(f"error: {type(exc).__name__}: {exc}", flush=True)
        traceback.print_exc(file=sys.stdout)
        return 1


def cli_main(argv: list[str] | None = None) -> int:
    """threatlens-ingest entry point: the dashboard's ingest pipeline, run from a terminal."""
    global MACHINE_OUTPUT
    MACHINE_OUTPUT = False
    from threatlens.setup_wizard import offer_setup

    offer_setup()
    return main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
