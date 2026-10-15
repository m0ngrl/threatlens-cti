"""
ThreatLens - report extraction CLI (the `threatlens` command).
ZEIT3118 Capstone Project

An inspection tool: runs one report through extraction and verification and
shows what the extraction engine made of it, without touching a database.

    read (pdf or text) -> regex candidates + metadata
                       -> LLM or heuristic verification -> IoCExtractionResult

The extractor modules (ioc_extract_llm_fs / ioc_extract_python) do the actual
work; this is a thin wrapper that picks the verification backend, prints a
one-screen summary and, with -o, writes the full result as JSON - every
candidate with its offsets, context excerpt, verdict, reason and evidence,
plus document metadata and (llm engine) the scope assessment. That JSON is
also the input format of the quality checker's own CLI
(python -m threatlens.quality.quality_checker), so the two can be chained to
inspect each stage separately.

No database step, by design. Ingesting a report (extract -> quality checks ->
persist -> rescore) is threatlens-ingest / dashboard/ingest_worker.py, the
same pipeline the dashboard's Ingest page and .dev_tools/run_ex_pipeline.py
use.

Two extraction engines are available. The default, "llm", asks an
Ollama-hosted model to verify each regex candidate against its report context
and adds a document-level scope classification (see ioc_extract_llm_fs.py);
"python" runs the same deterministic extraction but verifies with local
heuristics only, for use where no LLM is available.

LLM settings (Ollama URL, models and [llm] performance tuning) all come from
threatlens.conf - unless --config names another file; paths.config_file()
finds it - with built-in defaults for anything it leaves out (see config.py).

`threatlens init` runs the setup wizard instead (threatlens/setup_wizard.py).

Usage:
    threatlens init
    threatlens report.pdf
    threatlens report.txt --engine python
    threatlens report.pdf -o result.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threatlens import __version__
from threatlens.config import ConfigError, LLMSettings, load_config, setup_status
from threatlens.extractors.ioc_extract_llm_fs import ExtractorConfig, OllamaError
from threatlens.extractors.ioc_extract_llm_fs import (
    analyse_document as analyse_with_llm,
)
from threatlens.extractors.ioc_extract_python import (
    analyse_document as analyse_with_python,
)


def build_parser() -> argparse.ArgumentParser:
    """Define the CLI's arguments: the report to analyse plus extraction/verification overrides."""
    parser = argparse.ArgumentParser(
        description="Extract and verify IoCs/metadata from a CTI report.",
        epilog="First time? Run `threatlens init` to set up threatlens.conf.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "source",
        type=Path,
        help="Report to analyse (.pdf, or text: .txt/.md/.log/.csv/.json)",
    )
    parser.add_argument(
        "--engine",
        choices=("llm", "python"),
        default="llm",
        help=(
            "Verification backend: 'llm' asks Ollama to verify candidates "
            "(tuned by threatlens.conf [llm]); 'python' uses local heuristics "
            "only, no LLM required (default: llm)"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="threatlens.conf to read instead of the default (THREATLENS_CONF, else the checkout's or per-user one)",
    )
    parser.add_argument(
        "--ignore-calibration",
        action="store_true",
        help=(
            "llm engine only: use built-in [llm] tuning instead of threatlens.conf's "
            "(its Ollama URL and models still apply)"
        ),
    )
    parser.add_argument(
        "--accepted-only",
        action="store_true",
        help=(
            "JSON output keeps only confirmed and context-entity candidates "
            "(drops rejected and uncertain); summary counts are unaffected"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Write the result as JSON to this path (default: print a summary only)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help=(
            "Progress detail on stderr: -v stages and LLM batches, -vv each "
            "candidate as it is verified, -vvv raw Ollama request/response debug"
        ),
    )
    return parser


def run(args: argparse.Namespace) -> int:
    """Run extraction + verification once and report the populated result."""
    source: Path = args.source
    if not source.is_file():
        raise SystemExit(f"source does not exist: {source}")

    # Extract + verify: both engines return the same IoCExtractionResult shape
    # (metadata plus per-candidate verification verdicts) - a plain object,
    # nothing written anywhere.
    if args.engine == "python":
        result = analyse_with_python(source, verbose=args.verbose)
    else:
        if args.config is not None and not args.config.is_file():
            raise SystemExit(f"error: config file does not exist: {args.config}")
        if args.config is None:
            from threatlens.setup_wizard import offer_setup

            offer_setup()
        try:
            local = load_config(args.config)
        except ConfigError as exc:
            raise SystemExit(f"error: {exc}")
        llm = LLMSettings() if args.ignore_calibration else local.llm
        for warning in setup_status(args.config).warnings(llm=not args.ignore_calibration):
            print(f"warning: {warning}", file=sys.stderr)
        result = analyse_with_llm(
            source,
            model=local.verifier_model,
            profiler_model=local.profiler_model or None,
            ollama_url=local.ollama_url,
            batch_size=llm.batch_size,
            timeout=llm.timeout,
            num_predict=llm.num_predict,
            num_ctx=llm.num_ctx,
            max_retries=llm.max_retries,
            verbose=args.verbose,
            config=ExtractorConfig(context_chars=llm.context_chars),
        )

    metadata = result.metadata

    print(
        f"metadata: {metadata.cti_source or 'unknown source'}, published "
        f"{metadata.publish_date or 'unknown'}, {len(metadata.authors)} author(s)"
    )
    print(
        f"extract:  {len(result.items)} candidates from {source.name} "
        f"({args.engine} engine, model={result.model or 'none'})"
    )
    print(
        f"verify:   {len(result.confirmed_iocs())} confirmed, "
        f"{len(result.context_entities())} context, {len(result.rejected())} rejected"
    )
    scope = getattr(result, "scope", None)
    if scope:
        print(
            f"scope:    {scope.primary_scope.value} "
            f"(tactical={scope.has_tactical_content}, "
            f"operational={scope.has_operational_content}, "
            f"strategic={scope.has_strategic_content})"
        )

    if args.output:
        rendered = json.dumps(
            result.to_dict(include_rejected=not args.accepted_only),
            indent=2,
            ensure_ascii=False,
        ) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"output:   {args.output}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse argv and run extraction, turning expected failures into a clean exit code."""
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["init"]:
        from threatlens.setup_wizard import main as init_main

        return init_main(argv[1:])
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, UnicodeError, ValueError, RuntimeError, OllamaError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
