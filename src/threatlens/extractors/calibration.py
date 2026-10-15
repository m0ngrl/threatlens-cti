#!/usr/bin/env python3
"""Calibrate Ollama settings for ThreatLens IoC verification.

Runs small structured-output benchmarks at several candidate batch sizes,
suggests performance settings and optionally saves them into threatlens.conf
(the same file every other ThreatLens tool reads - see config.py):

    [ollama] url        the server that was benchmarked
    [models] verifier   the model that was benchmarked
    [llm]               batch_size, num_ctx, num_predict, context_chars,
                        timeout, max_retries, profile
    [calibration]       what was measured (informational)

Every other section ([database], [quality.*], [models] profiler) is kept as
it was. Model and URL default to the file's current values, so a re-run
re-tunes the configured setup.

calibrate() and save_calibration() are the reusable pieces, for a setup step
that wants to run calibration without this command line.

Usage:
    python -m threatlens.extractors.calibration
    python -m threatlens.extractors.calibration --model qwen3.5:9b --save
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from threatlens.config import (
    ConfigError,
    LLMSettings,
    config_path,
    load_config,
    save_config,
)


def resolve_ollama_url(
    *,
    ollama_url: str | None,
    ollama_ip: str | None,
    ollama_port: int,
    configured_url: str,
) -> str:
    """Resolve the Ollama endpoint from a full URL, an IP/hostname, or the configured URL."""
    if ollama_url:
        return ollama_url.rstrip("/")

    host = (ollama_ip or "").strip()
    if not host:
        return configured_url.rstrip("/")

    if not 1 <= ollama_port <= 65535:
        raise ValueError("--ollama-port must be between 1 and 65535")

    # Allow users to pass a hostname, IPv4 address, or IPv6 literal.
    if ":" in host and not host.startswith("[") and host.count(":") > 1:
        host = f"[{host}]"

    return f"http://{host}:{ollama_port}"


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
                        "enum": ["confirmed_ioc", "rejected", "context_entity", "uncertain"],
                    },
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "required": ["candidate_id", "status", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["decisions"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are testing structured JSON output performance.

For every supplied candidate, return exactly one decision with the same
candidate_id.

Use these deterministic rules:
- candidate IDs ending in 1, 4, 7, or 9: status rejected
- candidate IDs ending in 6: status context_entity
- all other candidate IDs: status confirmed_ioc
- confidence must be 0.95

Do not omit, rename, combine, or invent candidate IDs.

The top-level JSON object MUST contain exactly one key named "decisions".

Correct format:
{
  "decisions": [
    {
      "candidate_id": "cal-001",
      "status": "rejected",
      "confidence": 0.95
    }
  ]
}

Do NOT return a key named "candidates".
Do NOT return a bare JSON array.
Do NOT repeat the input candidate data.
Return only the JSON object.
"""


SYNTHETIC_CANDIDATES = [
    {
        "candidate_id": "cal-001",
        "indicator_type": "domain",
        "value": "security-vendor.example",
        "context": "The report was published on the security vendor website. This is a citation, not attacker infrastructure.",
    },
    {
        "candidate_id": "cal-002",
        "indicator_type": "filename",
        "value": "microsoft-cortana.exe",
        "context": "Indicators of Compromise: microsoft-cortana.exe (GraphSteel). The malware drops and executes this file.",
    },
    {
        "candidate_id": "cal-003",
        "indicator_type": "hash",
        "value": "9e9fa8b3b0a59762b429853a36674608df1fa7d7f7140c8fccd7c1946070995a",
        "context": "Indicators of Compromise: SHA-256 hash associated with the GoDownloader payload.",
    },
    {
        "candidate_id": "cal-004",
        "indicator_type": "url",
        "value": "https://attack.mitre.org/techniques/T1059/",
        "context": "Reference: MITRE ATT&CK technique documentation. This is not adversary infrastructure.",
    },
    {
        "candidate_id": "cal-005",
        "indicator_type": "ip",
        "value": "194.31.98.124",
        "context": "The malware connected to the command-and-control server 194.31.98.124 over TCP 443.",
    },
    {
        "candidate_id": "cal-006",
        "indicator_type": "malware",
        "value": "GrimPlant",
        "context": "The report identifies the malware family as GrimPlant.",
    },
    {
        "candidate_id": "cal-007",
        "indicator_type": "filepath",
        "value": "/article/38374",
        "context": "CERT-UA article path used as the source citation for the report.",
    },
    {
        "candidate_id": "cal-008",
        "indicator_type": "filename",
        "value": "Base-Update.exe",
        "context": "The malicious macro creates Base-Update.exe and executes it as a downloader.",
    },
    {
        "candidate_id": "cal-009",
        "indicator_type": "email_address",
        "value": "analyst@example.org",
        "context": "Author contact address shown in the report footer.",
    },
    {
        "candidate_id": "cal-010",
        "indicator_type": "domain",
        "value": "evil.example",
        "context": "The report states the implant beaconed to evil.example every 60 seconds.",
    },
]


@dataclass(frozen=True)
class BenchmarkResult:
    batch_size: int
    elapsed_seconds: float
    candidates: int
    prompt_tokens: int
    generated_tokens: int
    load_seconds: float
    prompt_seconds: float
    generation_seconds: float
    valid: bool
    error: str = ""

    @property
    def seconds_per_candidate(self) -> float:
        return self.elapsed_seconds / max(1, self.candidates)

    @property
    def candidates_per_second(self) -> float:
        return self.candidates / max(0.001, self.elapsed_seconds)


class CalibrationError(RuntimeError):
    pass


def _post_json(url: str, payload: Mapping[str, Any], timeout: int) -> dict[str, Any]:
    encoded = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise CalibrationError(f"Ollama HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CalibrationError(f"Cannot connect to Ollama: {exc.reason}") from exc
    except TimeoutError as exc:
        raise CalibrationError(f"Ollama request timed out after {timeout}s") from exc

    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        raise CalibrationError(f"Ollama returned invalid JSON: {body[:300]}") from exc
    if not isinstance(result, dict):
        raise CalibrationError("Ollama response was not an object")
    return result


def get_model_names(base_url: str, timeout: int) -> list[str]:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/api/tags", timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception:
        return []
    models = body.get("models", []) if isinstance(body, dict) else []
    return [str(item.get("name")) for item in models if isinstance(item, dict) and item.get("name")]



def warm_up_model(
    *,
    base_url: str,
    model: str,
    num_ctx: int,
    timeout: int,
) -> float:
    """Load the model and verify basic Ollama chat connectivity.

    Warm-up deliberately does not use the CTI response schema. Schema adherence
    is measured separately by benchmark_batch().
    """
    payload = {
        "model": model,
        "stream": False,
        "think": False,
        "keep_alive": "10m",
        "options": {
            "temperature": 0,
            "seed": 42,
            "num_ctx": max(1024, num_ctx),
            "num_predict": 16,
        },
        "messages": [
            {
                "role": "user",
                "content": "Reply with exactly READY and nothing else.",
            }
        ],
    }

    started = time.perf_counter()
    outer = _post_json(
        f"{base_url.rstrip('/')}/api/chat",
        payload,
        timeout,
    )
    elapsed = time.perf_counter() - started

    content = outer.get("message", {}).get("content")
    if not isinstance(content, str):
        raise CalibrationError(
            f"warm-up returned no text content: {outer}"
        )

    cleaned = content.strip().strip("`").strip()
    if cleaned.upper() != "READY":
        raise CalibrationError(
            f"unexpected warm-up response: {content[:200]!r}"
        )

    return elapsed


def benchmark_batch(
    *,
    base_url: str,
    model: str,
    batch_size: int,
    num_ctx: int,
    num_predict: int,
    timeout: int,
) -> BenchmarkResult:
    candidates = SYNTHETIC_CANDIDATES[:batch_size]
    payload = {
        "model": model,
        "stream": False,
        "think": False,
        "keep_alive": "10m",
        "format": RESPONSE_SCHEMA,
        "options": {
            "temperature": 0,
            "seed": 42,
            "num_ctx": num_ctx,
            "num_predict": num_predict,
        },
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps({"candidates": candidates}, ensure_ascii=False)},
        ],
    }

    started = time.perf_counter()
    try:
        outer = _post_json(f"{base_url.rstrip('/')}/api/chat", payload, timeout)
        elapsed = time.perf_counter() - started
        if outer.get("done_reason") == "length":
            raise CalibrationError("output truncated at num_predict")
        content = outer.get("message", {}).get("content")

        if not isinstance(content, str) or not content.strip():
            raise CalibrationError("model returned empty content")

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise CalibrationError(
                f"model returned invalid JSON: {content[:500]!r}"
            ) from exc


        # Normal/expected schema:
        # {
        #     "decisions": [...]
        # }
        if isinstance(parsed, dict) and isinstance(parsed.get("decisions"), list):
            decisions = parsed["decisions"]

        # Qwen sometimes returns:
        # {
        #     "candidates": [...]
        # }
        elif isinstance(parsed, dict) and isinstance(parsed.get("candidates"), list):
            decisions = parsed["candidates"]

        # Qwen sometimes returns:
        # [
        #     {...},
        #     {...}
        # ]
        elif isinstance(parsed, list):
            decisions = parsed

        else:
            raise CalibrationError(
                "model response contained JSON but no usable decision list; "
                f"model content={content[:500]}"
            )

        returned_ids = [
            item.get("candidate_id")
            for item in decisions
            if isinstance(item, dict)
        ]
        expected_ids = [item["candidate_id"] for item in candidates]

        if len(returned_ids) != len(decisions):
            raise CalibrationError("one or more decisions were not JSON objects")

        if len(returned_ids) != len(expected_ids):
            raise CalibrationError(
                f"expected {len(expected_ids)} decisions, received "
                f"{len(returned_ids)}"
            )

        if len(set(returned_ids)) != len(returned_ids):
            raise CalibrationError("model returned duplicate candidate IDs")

        missing = sorted(set(expected_ids) - set(returned_ids))
        unknown = sorted(set(returned_ids) - set(expected_ids))
        if missing or unknown:
            raise CalibrationError(
                f"candidate ID mismatch; missing={missing}, unknown={unknown}"
            )

        ns = 1_000_000_000
        return BenchmarkResult(
            batch_size=batch_size,
            elapsed_seconds=elapsed,
            candidates=len(candidates),
            prompt_tokens=int(outer.get("prompt_eval_count") or 0),
            generated_tokens=int(outer.get("eval_count") or 0),
            load_seconds=float(outer.get("load_duration") or 0) / ns,
            prompt_seconds=float(outer.get("prompt_eval_duration") or 0) / ns,
            generation_seconds=float(outer.get("eval_duration") or 0) / ns,
            valid=True,
        )
    except (CalibrationError, json.JSONDecodeError) as exc:
        return BenchmarkResult(
            batch_size=batch_size,
            elapsed_seconds=time.perf_counter() - started,
            candidates=len(candidates),
            prompt_tokens=0,
            generated_tokens=0,
            load_seconds=0,
            prompt_seconds=0,
            generation_seconds=0,
            valid=False,
            error=str(exc),
        )


def memory_gib() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / 1024 / 1024
    except OSError:
        pass
    return None


def gpu_summary() -> str:
    commands = [
        ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
        ["rocm-smi", "--showproductname", "--showmeminfo", "vram"],
    ]
    for command in commands:
        try:
            output = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
            if output:
                return " | ".join(line.strip() for line in output.splitlines()[:4])
        except (OSError, subprocess.SubprocessError):
            continue
    return "not detected by calibration script"



def ollama_runtime_summary(base_url: str, timeout: int = 10) -> tuple[str, bool]:
    """Inspect the remote Ollama runtime after model warm-up.

    Returns a human-readable summary and whether Ollama appears to have loaded
    any model data into VRAM. This works for remote Ollama servers, unlike the
    local nvidia-smi/rocm-smi checks.
    """
    try:
        with urllib.request.urlopen(
            f"{base_url.rstrip('/')}/api/ps",
            timeout=timeout,
        ) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return f"unavailable ({exc})", False

    models = body.get("models", []) if isinstance(body, dict) else []
    if not isinstance(models, list) or not models:
        return "no loaded models reported", False

    summaries: list[str] = []
    gpu_active = False

    for item in models:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name") or item.get("model") or "unknown")
        size = int(item.get("size") or 0)
        size_vram = int(item.get("size_vram") or 0)

        if size_vram > 0:
            gpu_active = True

        if size > 0:
            percent_vram = (size_vram / size) * 100
            summaries.append(
                f"{name}: {percent_vram:.0f}% GPU "
                f"({size_vram / 1024**3:.2f}/{size / 1024**3:.2f} GiB VRAM)"
            )
        else:
            summaries.append(f"{name}: VRAM usage unknown")

    return " | ".join(summaries) or "runtime data unavailable", gpu_active


def hardware_profile(best: BenchmarkResult, ram: float | None, gpu_present: bool) -> str:
    if gpu_present and best.candidates_per_second >= 1.0:
        return "gpu-high"
    if gpu_present:
        return "gpu-balanced"
    if best.seconds_per_candidate <= 3:
        return "cpu-balanced"
    if best.seconds_per_candidate <= 12:
        return "cpu-low"
    return "cpu-minimal"


def choose_best(results: Sequence[BenchmarkResult]) -> BenchmarkResult:
    valid = [result for result in results if result.valid]
    if not valid:
        errors = "; ".join(f"batch {r.batch_size}: {r.error}" for r in results)
        raise CalibrationError(f"No benchmark completed successfully. {errors}")
    # Prefer throughput, but avoid a larger batch if improvement is negligible.
    fastest = max(valid, key=lambda item: item.candidates_per_second)
    near_best = [
        item for item in valid
        if item.candidates_per_second >= fastest.candidates_per_second * 0.92
    ]
    return min(near_best, key=lambda item: item.batch_size)


def suggested_settings(best: BenchmarkResult, profile: str) -> LLMSettings:
    batch = best.batch_size
    return LLMSettings(
        profile=profile,
        batch_size=batch,
        num_ctx=4096 if batch <= 5 else 8192,
        num_predict=max(384, min(4096, 160 * batch + 256)),
        context_chars=300 if profile in {"cpu-minimal", "cpu-low"} else 450,
        timeout=max(120, int(best.elapsed_seconds * 4 + 30)),
        max_retries=3,
        verification_policy="all",
    )


@dataclass(frozen=True)
class Calibration:
    """Outcome of one calibrate() run: what to write, and what it was based on."""

    model: str
    base_url: str
    settings: LLMSettings
    best: BenchmarkResult
    ram: float | None
    gpu: str
    ollama_runtime: str

    def record(self) -> dict[str, str]:
        """The [calibration] section: the machine and measurements behind `settings`."""
        best = self.best
        return {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "logical_cpus": str(os.cpu_count() or 0),
            "memory_gib": f"{self.ram:.2f}" if self.ram is not None else "unknown",
            "local_gpu": self.gpu,
            "ollama_runtime": self.ollama_runtime,
            "measured_batch_size": str(best.batch_size),
            "measured_seconds": f"{best.elapsed_seconds:.3f}",
            "measured_seconds_per_candidate": f"{best.seconds_per_candidate:.3f}",
            "measured_candidates_per_second": f"{best.candidates_per_second:.4f}",
            "prompt_tokens": str(best.prompt_tokens),
            "generated_tokens": str(best.generated_tokens),
        }


def save_calibration(result: Calibration, path: Path | None = None) -> Path:
    """Merge `result` into threatlens.conf, keeping every section it does not own.

    Raises ConfigError if the existing file is unreadable or invalid, rather
    than overwriting settings that could not be read.
    """
    current = load_config(path)
    updated = replace(
        current,
        ollama_url=result.base_url,
        verifier_model=result.model,
        llm=result.settings,
        calibration=result.record(),
    )
    return save_config(updated, path)


def calibrate(
    *,
    base_url: str,
    model: str,
    batch_sizes: Sequence[int] = (1, 3, 5, 8),
    repetitions: int = 1,
    attempts: int = 3,
    num_ctx: int = 4096,
    num_predict: int = 2048,
    timeout: int = 300,
) -> Calibration:
    """Benchmark `model` on `base_url` and suggest [llm] settings, printing progress.

    Raises CalibrationError if the model cannot be warmed up or no batch size
    completes.
    """
    ram = memory_gib()
    gpu = gpu_summary()
    print("ThreatLens LLM calibration")
    print("=" * 72)
    print(f"Model       : {model}")
    print(f"Ollama URL  : {base_url}")
    print(f"CPU threads : {os.cpu_count() or 'unknown'}")
    print(f"RAM         : {f'{ram:.1f} GiB' if ram is not None else 'unknown'}")
    print(f"GPU         : {gpu}")
    print()

    print("Warming model...")
    try:
        warm_seconds = warm_up_model(
            base_url=base_url,
            model=model,
            num_ctx=num_ctx,
            timeout=timeout,
        )
    except CalibrationError as exc:
        raise CalibrationError(f"warm-up failed: {exc}") from exc
    print(f"Warm-up complete in {warm_seconds:.2f}s")

    runtime_summary, remote_gpu_active = ollama_runtime_summary(
        base_url,
        min(timeout, 10),
    )
    print(f"Ollama runtime: {runtime_summary}")
    print()

    repetitions = max(1, repetitions)
    attempts = max(1, attempts)
    results: list[BenchmarkResult] = []
    for size in batch_sizes:
        runs: list[BenchmarkResult] = []
        for repetition in range(repetitions):
            print(f"Testing batch size {size} ({repetition + 1}/{repetitions})...", flush=True)
            result: BenchmarkResult | None = None
            for attempt in range(1, attempts + 1):
                result = benchmark_batch(
                    base_url=base_url,
                    model=model,
                    batch_size=size,
                    num_ctx=num_ctx,
                    num_predict=num_predict,
                    timeout=timeout,
                )
                if result.valid:
                    break

                print(f"  attempt {attempt}/{attempts} failed: {result.error}")
                if attempt < attempts:
                    time.sleep(1)

            assert result is not None
            runs.append(result)

            if result.valid:
                print(
                    f"  {result.elapsed_seconds:.2f}s total | "
                    f"{result.seconds_per_candidate:.2f}s/candidate | "
                    f"{result.candidates_per_second:.3f} candidates/s"
                )
            else:
                print(f"  failed after {attempts} attempts: {result.error}")
                break
        valid_runs = [run for run in runs if run.valid]
        if valid_runs:
            median_run = min(
                valid_runs,
                key=lambda run: abs(run.elapsed_seconds - statistics.median(r.elapsed_seconds for r in valid_runs)),
            )
            results.append(median_run)
        else:
            results.append(runs[-1])

    best = choose_best(results)
    profile = hardware_profile(best, ram, remote_gpu_active)
    return Calibration(
        model=model,
        base_url=base_url,
        settings=suggested_settings(best, profile),
        best=best,
        ram=ram,
        gpu=gpu,
        ollama_runtime=runtime_summary,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark Ollama and save ThreatLens LLM settings to threatlens.conf.")
    parser.add_argument("--model", default=None, help="Model to benchmark (default: threatlens.conf [models] verifier)")
    parser.add_argument(
        "--ollama-url",
        default=None,
        help="Full Ollama base URL, for example http://192.0.2.50:11434 (default: threatlens.conf [ollama] url)",
    )
    parser.add_argument(
        "--ollama-ip",
        default=None,
        help="Ollama server IP address or hostname",
    )
    parser.add_argument(
        "--ollama-port",
        type=int,
        default=11434,
        help="Ollama server port when using --ollama-ip (default: 11434)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="threatlens.conf to read and update (default: THREATLENS_CONF, else the checkout's or per-user one)",
    )
    parser.add_argument("--batch-sizes", default="1,3,5,8", help="Comma-separated batch sizes to test")
    parser.add_argument("--repetitions", type=int, default=1, help="Runs per batch size after warm-up")
    parser.add_argument("--attempts", type=int, default=3, help="Attempts allowed for each structured benchmark run")
    parser.add_argument("--num-ctx", type=int, default=4096)
    parser.add_argument("--num-predict", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--save", action="store_true", help="Save without prompting")
    parser.add_argument("--no-save", action="store_true", help="Do not prompt to save")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = args.config or config_path()
    try:
        # Read now so a broken file is reported before minutes of benchmarking.
        current = load_config(target)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Fix or remove the file, then re-run calibration.", file=sys.stderr)
        return 2

    model = args.model or current.verifier_model
    try:
        base_url = resolve_ollama_url(
            ollama_url=args.ollama_url,
            ollama_ip=args.ollama_ip,
            ollama_port=args.ollama_port,
            configured_url=current.ollama_url,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    model_names = get_model_names(base_url, min(args.timeout, 30))
    if model_names and model not in model_names:
        print(f"warning: model {model!r} was not found by Ollama", file=sys.stderr)
        print("available: " + ", ".join(model_names), file=sys.stderr)

    try:
        batch_sizes = sorted({int(value) for value in args.batch_sizes.split(",") if int(value) > 0})
    except ValueError:
        print("error: --batch-sizes must contain comma-separated positive integers", file=sys.stderr)
        return 2
    batch_sizes = [size for size in batch_sizes if size <= len(SYNTHETIC_CANDIDATES)]
    if not batch_sizes:
        print("error: no usable batch sizes", file=sys.stderr)
        return 2

    try:
        result = calibrate(
            base_url=base_url,
            model=model,
            batch_sizes=batch_sizes,
            repetitions=args.repetitions,
            attempts=args.attempts,
            num_ctx=args.num_ctx,
            num_predict=args.num_predict,
            timeout=args.timeout,
        )
    except CalibrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print()
    print("Suggested configuration")
    print("=" * 72)
    for key, value in asdict(result.settings).items():
        print(f"{key:20}: {value}")
    print(f"model               : {result.model}")
    print(f"ollama_url          : {result.base_url}")
    print()
    print(
        f"Selected batch size {result.best.batch_size}: "
        f"{result.best.seconds_per_candidate:.2f}s per candidate measured."
    )

    should_save = args.save
    if not args.save and not args.no_save and sys.stdin.isatty():
        answer = input(f"\nSave to {target} ([ollama], [models] verifier, [llm])? [Y/n] ").strip().lower()
        should_save = answer in {"", "y", "yes"}

    if should_save:
        try:
            saved = save_calibration(result, target)
        except ConfigError as exc:
            print(f"error: not saved: {exc}", file=sys.stderr)
            return 2
        print(f"Saved {saved}")
    elif args.no_save:
        print("Configuration was not saved.")
    else:
        print("Configuration was not saved. Re-run with --save to save non-interactively.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
