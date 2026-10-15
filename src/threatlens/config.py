"""
ThreatLens - local configuration (threatlens.conf).
ZEIT3118 Capstone Project

One INI file holding every per-machine setting. Where it lives - the repo
root in a checkout, the per-user config folder when pip-installed, or
THREATLENS_CONF - is decided by paths.config_file().

    [ollama]            where the Ollama server is
    [models]            which models the LLM engine uses
    [llm]               LLM performance tuning (batch_size, num_ctx, timeout, ...)
    [paths]             data folder for databases and reports (see paths.py)
    [dashboard]         address threatlens-dashboard listens on
    [database]          which db/*.db file the dashboard opens at startup
    [quality.weights]   dimension weights for the composite quality_score
    [quality.agreement] confidence multipliers per verifier-agreement grade
    [calibration]       measurements behind the [llm] values (informational)

extractors/calibration.py benchmarks the Ollama server and writes [ollama],
[models] verifier, [llm] and [calibration] into this same file, keeping the
rest. (This replaces the separate llm_calibration.conf.)

Precedence, highest first:

    ollama / models /   threatlens.conf > built-in. Command-line flags of the
    llm                 individual tools override both.
    database            THREATLENS_DB_URL / THREATLENS_DB_FILE env vars >
                        threatlens.conf > db/threatlens.db.
    quality weights     threatlens.conf > scoring_config rows > built-in.
                        Band thresholds still come from scoring_config.

A missing file is not an error: every value falls back to the built-in
default, so a fresh checkout runs unchanged. Set THREATLENS_CONF to point at
a different file (the test suite does, to stay independent of local edits).

The file is read on every call rather than cached, so an edit - by hand or
from the dashboard's Configuration page - takes effect on the next ingest
without a restart.

setup_status() reports whether this machine has actually been set up: the
file exists, has been edited from the shipped template, and has [llm] values
from a calibration run. The CLI, ingest worker and dashboard warn (never
fail) when it has not.
"""

from __future__ import annotations

import configparser
import math
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from threatlens import paths

DIMENSIONS: tuple[str, ...] = ("timeliness", "accuracy", "completeness", "relevance")
AGREEMENT_GRADES: tuple[str, ...] = ("agree", "weak", "single", "moderate", "strong")

# Same tolerance as the weights-sum-to-1.0 invariant scoring_config enforces.
WEIGHT_SUM_TOLERANCE = 0.001


def _default_weights() -> dict[str, float]:
    return {"timeliness": 0.25, "accuracy": 0.30, "completeness": 0.25, "relevance": 0.20}


def _default_agreement() -> dict[str, float]:
    return {"agree": 1.00, "weak": 0.90, "single": 0.85, "moderate": 0.75, "strong": 0.50}


VERIFICATION_POLICIES: tuple[str, ...] = ("all", "ambiguous-only", "deterministic-first")

# Smallest usable value of each integer [llm] setting. A lower value in the
# file is raised to it on load; save_config() refuses one.
LLM_MINIMUMS: dict[str, int] = {
    "batch_size": 1,
    "timeout": 30,
    "num_predict": 64,
    "num_ctx": 1024,
    "context_chars": 100,
    "max_retries": 1,
}


@dataclass(frozen=True)
class LLMSettings:
    """[llm] performance tuning for the Ollama verifier (calibration.py writes it)."""

    profile: str = "uncalibrated"
    batch_size: int = 5
    timeout: int = 600
    num_predict: int = 384
    num_ctx: int = 4096
    context_chars: int = 300
    max_retries: int = 3
    # Read and validated, but nothing acts on it yet: every candidate is sent
    # to the verifier regardless.
    verification_policy: str = "all"


@dataclass(frozen=True)
class ThreatLensConfig:
    ollama_url: str = "http://127.0.0.1:11434"
    verifier_model: str = "qwen3.5:4b"
    # Empty means "same as verifier_model".
    profiler_model: str = ""
    llm: LLMSettings = field(default_factory=LLMSettings)
    # Empty means the layout default (see paths.data_dir()).
    data_dir: str = ""
    database: str = "threatlens.db"
    # This machine only by default: the dashboard has no authentication.
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8000
    weights: dict[str, float] = field(default_factory=_default_weights)
    agreement: dict[str, float] = field(default_factory=_default_agreement)
    # What calibration.py measured when it wrote `llm`, kept verbatim so a
    # save from the dashboard does not drop it. Nothing reads it.
    calibration: dict[str, str] = field(default_factory=dict)
    # Which sections were actually present in the file, so callers can tell
    # "configured" from "defaulted" where an older source (scoring_config)
    # should otherwise win.
    present: frozenset[str] = frozenset()

    @property
    def effective_profiler_model(self) -> str:
        return self.profiler_model or self.verifier_model

    def to_dict(self) -> dict[str, Any]:
        return {
            "ollama": {"url": self.ollama_url},
            "models": {"verifier": self.verifier_model, "profiler": self.profiler_model},
            "llm": asdict(self.llm),
            "paths": {"data_dir": self.data_dir},
            "database": {"default": self.database},
            "dashboard": {"host": self.dashboard_host, "port": self.dashboard_port},
            "quality": {"weights": dict(self.weights), "agreement": dict(self.agreement)},
            "calibration": dict(self.calibration),
        }


class ConfigError(ValueError):
    """threatlens.conf exists but holds a value that cannot be used."""


# Values shipped in threatlens.conf.example, which is render(TEMPLATE, template=True).
TEMPLATE = ThreatLensConfig(verifier_model="qwen3.5:9b")

# Comment line only the generated template carries. save_config() never
# writes it, so a save from the dashboard or the calibration tool marks the
# file as reviewed; deleting the line by hand does the same.
TEMPLATE_MARKER = "# threatlens: unedited template"


@dataclass(frozen=True)
class SetupStatus:
    """How far this machine's threatlens.conf is from "set up"."""

    path: Path
    exists: bool
    # False while the file is still the copied template (marker present and
    # values unchanged), or missing.
    edited: bool
    # True once [calibration] holds a run's record, or [llm] was tuned by hand.
    calibrated: bool
    # The file exists but cannot be used; everything falls back to defaults.
    error: str = ""

    @property
    def ready(self) -> bool:
        return self.exists and self.edited and self.calibrated and not self.error

    def warnings(self, *, llm: bool = True) -> list[str]:
        """Human-readable problems, worst first. llm=False drops the calibration hint."""
        if self.error:
            return [f"{self.path} is invalid, so built-in defaults are in use: {self.error}"]
        found: list[str] = []
        if not self.exists:
            found.append(
                f"{self.path} does not exist, so built-in defaults are in use. Run "
                "`threatlens init` to create it (or use `threatlens-calibrate`, the dashboard's "
                "Configuration page"
                + (", or `cp threatlens.conf.example threatlens.conf`" if paths.is_checkout() else "")
                + ")."
            )
        elif not self.edited:
            found.append(
                f"{self.path} is still the unedited template: set the Ollama URL and models "
                "for this machine with `threatlens init` (or edit it, or save from the "
                "dashboard's Configuration page)."
            )
        if llm and not self.calibrated:
            found.append(
                "LLM performance settings ([llm]) have not been calibrated for this Ollama "
                "server: run `threatlens-calibrate`."
            )
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "exists": self.exists,
            "edited": self.edited,
            "calibrated": self.calibrated,
            "error": self.error,
            "ready": self.ready,
            "warnings": self.warnings(),
        }


def config_path() -> Path:
    """The threatlens.conf in use: THREATLENS_CONF, the checkout's, or the per-user one."""
    return paths.config_file()


def load_config(path: Path | None = None) -> ThreatLensConfig:
    """Read threatlens.conf, filling anything absent with built-in defaults."""
    selected = path or config_path()
    base = ThreatLensConfig()
    if not selected.is_file():
        return base

    # No interpolation: [calibration] values such as "100% GPU" contain '%'.
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with selected.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error) as exc:
        raise ConfigError(f"unable to read {selected}: {exc}") from exc

    def get(section: str, key: str, fallback: str) -> str:
        return parser.get(section, key, fallback=fallback).strip() or fallback

    def floats(section: str, keys: tuple[str, ...], fallback: dict[str, float]) -> dict[str, float]:
        if section not in parser:
            return fallback
        values = dict(fallback)
        for key in keys:
            raw = parser[section].get(key)
            if raw is None or not raw.strip():
                continue
            try:
                values[key] = float(raw)
            except ValueError as exc:
                raise ConfigError(f"[{section}] {key} = {raw!r} is not a number") from exc
        return values

    def llm_settings() -> LLMSettings:
        if "llm" not in parser:
            return base.llm
        section = parser["llm"]
        values: dict[str, Any] = {}
        for key, minimum in LLM_MINIMUMS.items():
            raw = section.get(key, "").strip()
            if not raw:
                continue
            try:
                values[key] = max(minimum, int(raw))
            except ValueError as exc:
                raise ConfigError(f"[llm] {key} = {raw!r} is not a whole number") from exc
        values["profile"] = section.get("profile", "").strip() or "custom"
        policy = section.get("verification_policy", "").strip().lower()
        if policy:
            values["verification_policy"] = policy
        return replace(base.llm, **values)

    def port() -> int:
        raw = parser.get("dashboard", "port", fallback="").strip()
        if not raw:
            return base.dashboard_port
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"[dashboard] port = {raw!r} is not a whole number") from exc

    config = ThreatLensConfig(
        ollama_url=get("ollama", "url", base.ollama_url),
        verifier_model=get("models", "verifier", base.verifier_model),
        profiler_model=parser.get("models", "profiler", fallback="").strip(),
        llm=llm_settings(),
        data_dir=parser.get("paths", "data_dir", fallback="").strip(),
        database=get("database", "default", base.database),
        dashboard_host=get("dashboard", "host", base.dashboard_host),
        dashboard_port=port(),
        weights=floats("quality.weights", DIMENSIONS, base.weights),
        agreement=floats("quality.agreement", AGREEMENT_GRADES, base.agreement),
        calibration=dict(parser["calibration"]) if "calibration" in parser else {},
        present=frozenset(parser.sections()),
    )
    errors = validate(config)
    if errors:
        raise ConfigError(f"{selected}: " + "; ".join(errors))
    return config


def _same_settings(a: ThreatLensConfig, b: ThreatLensConfig) -> bool:
    """Equal in every setting; ignores the calibration record and `present`."""
    return replace(a, calibration={}, present=frozenset()) == replace(b, calibration={}, present=frozenset())


def setup_status(path: Path | None = None) -> SetupStatus:
    """Whether threatlens.conf exists, has been edited from the template, and is calibrated."""
    selected = path or config_path()
    if not selected.is_file():
        return SetupStatus(path=selected, exists=False, edited=False, calibrated=False)
    try:
        config = load_config(selected)
        text = selected.read_text(encoding="utf-8")
    except (ConfigError, OSError, UnicodeError) as exc:
        return SetupStatus(path=selected, exists=True, edited=True, calibrated=False, error=str(exc))

    marked = any(line.strip().startswith(TEMPLATE_MARKER) for line in text.splitlines())
    untouched = _same_settings(config, TEMPLATE) or _same_settings(config, ThreatLensConfig())
    return SetupStatus(
        path=selected,
        exists=True,
        edited=not (marked and untouched),
        calibrated=bool(config.calibration) or config.llm != LLMSettings(),
    )


def validate(config: ThreatLensConfig) -> list[str]:
    """Every problem with `config`, as human-readable messages (empty = valid)."""
    errors: list[str] = []

    parsed = urlparse(config.ollama_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        errors.append(f"ollama url {config.ollama_url!r} must look like http://host:port")

    if not config.verifier_model:
        errors.append("verifier model must not be empty")

    for key, minimum in LLM_MINIMUMS.items():
        value = getattr(config.llm, key)
        if value < minimum:
            errors.append(f"[llm] {key} = {value} must be at least {minimum}")
    if config.llm.verification_policy not in VERIFICATION_POLICIES:
        errors.append(
            f"[llm] verification_policy {config.llm.verification_policy!r} must be one of "
            + ", ".join(VERIFICATION_POLICIES)
        )
    if not config.llm.profile or "\n" in config.llm.profile:
        errors.append("[llm] profile must be a single non-empty line")

    if config.data_dir and (
        "\n" in config.data_dir or not Path(config.data_dir).expanduser().is_absolute()
    ):
        errors.append(f"[paths] data_dir {config.data_dir!r} must be an absolute folder path")

    if not config.dashboard_host or any(ch.isspace() for ch in config.dashboard_host):
        errors.append(f"[dashboard] host {config.dashboard_host!r} must be a hostname or IP address")
    if not 1 <= config.dashboard_port <= 65535:
        errors.append(f"[dashboard] port {config.dashboard_port} must be between 1 and 65535")

    if not config.database.endswith(".db") or config.database != Path(config.database).name:
        errors.append(f"database {config.database!r} must be a bare *.db filename in db/")

    for name, value in config.weights.items():
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            errors.append(f"weight {name} = {value} must be between 0 and 1")
    total = sum(config.weights.values())
    if abs(total - 1.0) > WEIGHT_SUM_TOLERANCE:
        errors.append(f"weights must sum to 1.00 (currently {total:.3f})")

    for name, value in config.agreement.items():
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            errors.append(f"agreement multiplier {name} = {value} must be between 0 and 1")

    for key, value in config.calibration.items():
        if not key or any(ch in key for ch in "=:[]\n") or "\n" in value:
            errors.append(f"[calibration] {key!r} must be a single-line key = value")

    return errors


def save_config(config: ThreatLensConfig, path: Path | None = None) -> Path:
    """Validate and write `config`, replacing the file atomically."""
    errors = validate(config)
    if errors:
        raise ConfigError("; ".join(errors))

    selected = path or config_path()
    selected.parent.mkdir(parents=True, exist_ok=True)
    tmp = selected.with_suffix(selected.suffix + ".tmp")
    tmp.write_text(render(config), encoding="utf-8")
    tmp.replace(selected)
    return selected


def _num(value: float) -> str:
    """Two decimals when that is exact, else full precision, so a save never rounds."""
    return f"{value:.2f}" if round(value, 2) == value else repr(value)


def render(config: ThreatLensConfig, *, template: bool = False) -> str:
    """The file text for `config`, with the explanatory comments kept.

    template=True adds TEMPLATE_MARKER, for generating threatlens.conf.example.
    """
    w, a, llm = config.weights, config.agreement, config.llm
    marker = (
        f"#\n{TEMPLATE_MARKER} - delete this line once the values below suit this\n"
        "# machine (a save from the dashboard or threatlens-calibrate removes it).\n"
        if template
        else ""
    )
    if config.calibration:
        calibration = "\n".join(f"{key} = {value}" for key, value in config.calibration.items())
    else:
        calibration = "# (empty until calibration runs)"
    return f"""\
###############################################################################
# ThreatLens local configuration
#
# Per-machine settings. Editable by hand or from the dashboard's
# Configuration page (/config); either way the next ingest picks them up
# without a restart. See src/threatlens/config.py for precedence rules.
#
# The LLM calibration tool (python -m threatlens.extractors.calibration)
# benchmarks the Ollama server and rewrites [ollama], [models] verifier,
# [llm] and [calibration] here, keeping everything else.
{marker}###############################################################################

[ollama]

# Ollama server URL.
#
#   http://127.0.0.1:11434
#   http://ollama.example.lan:11434
#
url = {config.ollama_url}


[models]

# Model that verifies each regex candidate. The evaluation runs use
# qwen3.5:9b; a smaller model such as qwen3.5:4b is faster on modest
# hardware but less accurate. Pull it first: ollama pull <model>
verifier = {config.verifier_model}

# Model that classifies the whole document's scope (strategic, operational,
# tactical). Leave blank to use the verifier model.
profiler = {config.profiler_model}


[llm]

# LLM performance tuning. The calibration tool measures the server and
# writes these; edit by hand if needed. Command-line flags still override.

# Label for the hardware these values suit: cpu-minimal, cpu-low,
# cpu-balanced, gpu-balanced, gpu-high, or anything (custom).
profile = {llm.profile}

# IoC candidates sent to the LLM per request. Larger batches raise
# throughput but need more memory. Typical: CPU 2-5, small GPU 5-10,
# large GPU 10-25.
batch_size = {llm.batch_size}

# Ollama context window, in tokens (2048, 4096, 8192, 16384). Larger values
# fit more report context but need more memory.
num_ctx = {llm.num_ctx}

# Maximum tokens the model may generate per request. Increase if responses
# are truncated (512, 1024, 1536, 2048).
num_predict = {llm.num_predict}

# Characters of report context on each side of a candidate (150-600).
context_chars = {llm.context_chars}

# Seconds allowed per Ollama request. Increase for slow CPUs or large models.
timeout = {llm.timeout}

# Attempts per batch if the LLM returns invalid JSON or truncated output.
max_retries = {llm.max_retries}

# Verification strategy: all, ambiguous-only or deterministic-first.
# Validated but not yet acted on - every candidate is verified.
verification_policy = {llm.verification_policy}


[paths]

# Folder for the databases (db/) and report files (reports/). Leave blank
# for the default: the repo itself in a checkout (db/, docs/database/CTI/),
# otherwise the per-user data folder, e.g. ~/.local/share/threatlens.
# THREATLENS_HOME overrides this. The dashboard picks a change up on restart.
data_dir = {config.data_dir}


[database]

# SQLite file in db/ that the dashboard opens at startup. The dashboard's
# database dropdown still switches at runtime; THREATLENS_DB_FILE /
# THREATLENS_DB_URL still override this.
default = {config.database}


[dashboard]

# Address threatlens-dashboard listens on (its --host / --port override
# these). 127.0.0.1 keeps it to this machine. 0.0.0.0 makes it reachable
# from the local network - it has no authentication, so anyone who can reach
# it can edit and delete data and change this configuration.
host = {config.dashboard_host}
port = {config.dashboard_port}


[quality.weights]

# Weight of each 0-5 dimension in the composite 0-100 quality_score.
# Each between 0 and 1; together they must sum to 1.00. Overrides the
# weights in the database's scoring_config table. Existing indicators keep
# their old score until re-scored.
timeliness = {_num(w['timeliness'])}
accuracy = {_num(w['accuracy'])}
completeness = {_num(w['completeness'])}
relevance = {_num(w['relevance'])}


[quality.agreement]

# Confidence multiplier applied for each grade of agreement between the
# Python and LLM verifiers (0-1; 1.00 means no discount). An ingest runs one
# engine, so it always uses "single"; the others apply only when the quality
# checker's CLI compares both engines' output (--compare).
agree = {_num(a['agree'])}
weak = {_num(a['weak'])}
single = {_num(a['single'])}
moderate = {_num(a['moderate'])}
strong = {_num(a['strong'])}


[calibration]

# What the calibration tool measured when it wrote [llm]. Informational
# only; overwritten on each calibration run.
{calibration}
"""
