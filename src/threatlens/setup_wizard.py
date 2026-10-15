"""
ThreatLens - interactive setup (`threatlens init`, also `threatlens-init`).
ZEIT3118 Capstone Project

pip cannot ask questions while it installs, so this is the step after it:
it asks for each per-machine setting, writes threatlens.conf, creates the
database and can calibrate the LLM settings.

    threatlens init                     # ask, with the current values as defaults
    threatlens init --non-interactive --ollama-url http://host:11434 --verifier qwen3.5:9b

Questions, in order: data folder; whether the LLM engine will be used; the
Ollama URL (checked live); verifier and profiler models (chosen from the
server's pulled models); whether to calibrate; database name; dashboard
address; optionally the quality weights. A summary is shown before anything
is written. An existing threatlens.conf supplies every default and is kept
as threatlens.conf.bak.

Writing goes through config.save_config(), like the dashboard and the
calibration tool, so all three produce the same file. The database is
created or upgraded with the shipped migrations, and its reference tables
are filled only when empty (seed.seed_missing), so re-running on a
database in use is safe.

offer_setup() is the first-run hook: threatlens, threatlens-ingest and
threatlens-dashboard call it, and when there is no threatlens.conf and the
command runs in a terminal it offers to run this wizard first.
THREATLENS_NO_SETUP=1 turns the offer off.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import sys
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from threatlens import __version__, paths
from threatlens import config as conf

Ask = Callable[[str], str]
Out = Callable[[str], None]
Probe = Callable[[str], "tuple[list[str] | None, str]"]

LOCAL_HOST = "127.0.0.1"
NETWORK_HOST = "0.0.0.0"


def probe_ollama(url: str, timeout: float = 5) -> tuple[list[str] | None, str]:
    """Models pulled on the Ollama server at `url`, or (None, reason) if it cannot be reached."""
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/api/tags", timeout=timeout) as response:
            body = json.load(response)
    except (OSError, ValueError) as exc:  # URLError is an OSError; bad JSON a ValueError
        return None, str(getattr(exc, "reason", exc))
    models = body.get("models", []) if isinstance(body, dict) else []
    return sorted(str(m["name"]) for m in models if isinstance(m, dict) and m.get("name")), ""


def folder_error(folder: Path) -> str | None:
    """Why `folder` cannot be used as the data folder, or None."""
    if not folder.is_absolute():
        return "Enter an absolute path, e.g. ~/threatlens or /srv/threatlens."
    existing = folder
    while not existing.exists():
        existing = existing.parent
    if not existing.is_dir():
        return f"{existing} is a file, not a folder."
    if not os.access(existing, os.W_OK):
        return f"No permission to create or write in {existing}."
    return None


@dataclass(frozen=True)
class Plan:
    """What the wizard will do once confirmed."""

    config: conf.ThreatLensConfig
    create_database: bool
    calibrate: bool


class Wizard:
    """The questions and the steps after them. `ask`/`out`/`probe` are injectable for tests."""

    def __init__(self, ask: Ask = input, out: Out = print, probe: Probe = probe_ollama) -> None:
        self.ask = ask
        self.out = out
        self.probe = probe

    # -- prompts -------------------------------------------------------------

    def text(self, question: str, default: str, check: Callable[[str], str | None] | None = None) -> str:
        """A free-text answer; Enter keeps `default`. Re-asks until `check` returns None."""
        while True:
            raw = self.ask(f"{question} [{default}]: " if default else f"{question}: ").strip()
            value = raw or default
            error = check(value) if check else None
            if error is None:
                return value
            self.out(f"  {error}")

    def yes_no(self, question: str, default: bool) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            raw = self.ask(f"{question} [{hint}]: ").strip().lower()
            if not raw:
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            self.out("  Please answer y or n.")

    def choose(self, question: str, options: Sequence[str], default: str) -> str:
        """Pick a numbered option, press Enter for `default`, or type any other value."""
        for number, option in enumerate(options, 1):
            self.out(f"  {number}) {option}")
        while True:
            raw = self.ask(f"{question} [{default}]: ").strip()
            if not raw:
                return default
            if raw.isdigit():
                if 1 <= int(raw) <= len(options):
                    return options[int(raw) - 1]
                self.out(f"  Pick 1-{len(options)}, or type a name.")
                continue
            return raw

    def heading(self, title: str) -> None:
        self.out("")
        self.out(title)
        self.out("-" * len(title))

    # -- the interview ---------------------------------------------------------

    def interview(self, current: conf.ThreatLensConfig, *, exists: bool, invalid: str = "") -> Plan | None:
        """Ask every question; None if the user declines to write."""
        path = paths.config_file()
        self.out("ThreatLens setup")
        self.out("================")
        self.out(f"Settings file: {path}")
        if invalid:
            self.out(f"It cannot be read ({invalid}).")
            if not self.yes_no("Start from the built-in defaults? (the old file is kept as .bak)", True):
                return None
            current = conf.ThreatLensConfig()
        elif exists:
            self.out("Its current values are the defaults below; press Enter to keep each one.")
        else:
            self.out("It does not exist yet; press Enter to accept each suggested default.")

        config = replace(current, data_dir=self._ask_data_dir(current))

        calibrate = False
        if self._ask_use_llm():
            config, calibrate = self._ask_llm(config, current)

        config, create_database = self._ask_database(config)
        config = self._ask_dashboard(config)
        config = self._ask_weights(config)

        errors = conf.validate(config)
        if errors:  # every answer was checked, so this is a bug if it happens
            raise conf.ConfigError("; ".join(errors))

        self._summary(config, create_database=create_database, calibrate=calibrate)
        if not self.yes_no(f"Write {path}?", True):
            return None
        return Plan(config=config, create_database=create_database, calibrate=calibrate)

    def _ask_data_dir(self, current: conf.ThreatLensConfig) -> str:
        self.heading("Data folder")
        default = paths.default_data_dir()
        layout = "this checkout" if paths.is_checkout() else "your user data folder"
        self.out(f"Databases and report PDFs go here. Default: {default} ({layout}).")
        if os.environ.get("THREATLENS_HOME"):
            self.out(f"Note: THREATLENS_HOME is set ({os.environ['THREATLENS_HOME']}) and overrides this.")
        answer = self.text(
            "Data folder",
            current.data_dir or str(default),
            lambda value: folder_error(Path(value).expanduser()),
        )
        chosen = Path(answer).expanduser()
        # Store "" for the default so the file keeps following the layout.
        return "" if chosen.resolve() == default.resolve() else str(chosen)

    def _ask_use_llm(self) -> bool:
        self.heading("Extraction engine")
        self.out("The default 'llm' engine verifies candidates with a model on an Ollama server.")
        self.out("The 'python' engine needs no LLM but is less accurate.")
        return self.yes_no("Will you use the LLM engine (needs Ollama)?", True)

    def _ask_llm(
        self, config: conf.ThreatLensConfig, current: conf.ThreatLensConfig
    ) -> tuple[conf.ThreatLensConfig, bool]:
        self.heading("Ollama server")

        def url_error(value: str) -> str | None:
            bad = conf.validate(replace(conf.ThreatLensConfig(), ollama_url=value))
            return "Enter a URL like http://127.0.0.1:11434" if bad else None

        url = current.ollama_url
        while True:
            url = self.text("Ollama URL", url, url_error).rstrip("/")
            models, reason = self.probe(url)
            if models is not None:
                self.out(f"  Connected: {len(models)} model(s) pulled.")
                break
            self.out(f"  Could not reach {url}: {reason}")
            action = self.text("[r]etry with another URL, [k]eep it anyway, or [s]kip LLM setup", "r",
                               lambda v: None if v.lower() in ("r", "k", "s") else "Answer r, k or s.")
            if action.lower() == "k":
                break
            if action.lower() == "s":
                return config, False
        config = replace(config, ollama_url=url)

        self.heading("Models")
        if models:
            # The configured model, else the recommended one, else whatever is there.
            preferred = [current.verifier_model, conf.TEMPLATE.verifier_model]
            default = next((m for m in preferred if m in models), models[0])
            verifier = self.choose("Verifier model (checks each candidate)", models, default)
        else:
            if models == []:
                self.out("  The server has no models yet. Pull one first: ollama pull <model>")
            verifier = self.text("Verifier model", current.verifier_model, lambda v: None if v else "Required.")
        if models and verifier not in models:
            self.out(f"  {verifier} is not pulled on that server yet: ollama pull {verifier}")

        same = "(same as verifier)"
        if models:
            profiler = self.choose(
                "Profiler model (classifies each document's scope)",
                [same, *models],
                current.profiler_model or same,
            )
        else:
            profiler = self.text("Profiler model (blank = same as verifier)", current.profiler_model)
        profiler = "" if profiler in (same, verifier) else profiler
        config = replace(config, verifier_model=verifier, profiler_model=profiler)

        calibrate = False
        if models and verifier in models:
            self.heading("Calibration")
            already = bool(current.calibration) and current.verifier_model == verifier
            self.out("Benchmarks the server to choose batch size, timeouts and context size")
            self.out("for this hardware. Takes a few minutes; `threatlens-calibrate` re-runs it.")
            calibrate = self.yes_no("Calibrate now?", not already)
        else:
            self.out("  Skipping calibration until the model is available: run `threatlens-calibrate` later.")
        return config, calibrate

    def _ask_database(self, config: conf.ThreatLensConfig) -> tuple[conf.ThreatLensConfig, bool]:
        self.heading("Database")

        def name_error(value: str) -> str | None:
            bad = conf.validate(replace(conf.ThreatLensConfig(), database=value))
            return "Enter a file name ending in .db, with no folders (e.g. threatlens.db)." if bad else None

        name = self.text("Database file name", config.database, name_error)
        db_path = paths.planned_folders(config.data_dir)[1] / name
        state = "exists: it will be upgraded, data kept" if db_path.is_file() else "will be created"
        create = self.yes_no(f"Create or upgrade {db_path} now ({state})?", True)
        return replace(config, database=name), create

    def _ask_dashboard(self, config: conf.ThreatLensConfig) -> conf.ThreatLensConfig:
        self.heading("Dashboard")
        self.out("The web dashboard has no login: anyone who can reach it can edit and delete data.")
        options = [f"{LOCAL_HOST}  (this machine only)", f"{NETWORK_HOST}  (local network)"]
        default = {LOCAL_HOST: options[0], NETWORK_HOST: options[1]}.get(config.dashboard_host, config.dashboard_host)
        answer = self.choose("Listen on", options, default).split()[0]
        if answer in (NETWORK_HOST, "::") and not self.yes_no(
            "Anyone on your network could then change data. Continue?", False
        ):
            answer = LOCAL_HOST

        def port_error(value: str) -> str | None:
            return None if value.isdigit() and 1 <= int(value) <= 65535 else "Enter a port from 1 to 65535."

        port = int(self.text("Port", str(config.dashboard_port), port_error))
        return replace(config, dashboard_host=answer, dashboard_port=port)

    def _ask_weights(self, config: conf.ThreatLensConfig) -> conf.ThreatLensConfig:
        self.heading("Quality score")
        shown = ", ".join(f"{d} {config.weights[d]:.2f}" for d in conf.DIMENSIONS)
        self.out(f"Weights of the four quality dimensions: {shown}.")
        if not self.yes_no("Change them?", False):
            return config

        def weight_error(value: str) -> str | None:
            try:
                number = float(value)
            except ValueError:
                return "Enter a number between 0 and 1."
            return None if math.isfinite(number) and 0 <= number <= 1 else "Enter a number between 0 and 1."

        while True:
            weights = {
                dim: float(self.text(f"  {dim}", f"{config.weights[dim]:.2f}", weight_error))
                for dim in conf.DIMENSIONS
            }
            total = sum(weights.values())
            if abs(total - 1.0) <= conf.WEIGHT_SUM_TOLERANCE:
                return replace(config, weights=weights)
            self.out(f"  They add up to {total:.2f}; they must add up to 1.00. Try again.")

    def _summary(self, config: conf.ThreatLensConfig, *, create_database: bool, calibrate: bool) -> None:
        data, databases, reports = paths.planned_folders(config.data_dir)
        self.heading("Summary")
        rows = [
            ("Settings file", str(paths.config_file())),
            ("Data folder", str(data)),
            ("Reports", str(reports)),
            ("Database", f"{databases / config.database}" + ("  (create/upgrade)" if create_database else "")),
            ("Ollama", config.ollama_url),
            ("Verifier", config.verifier_model),
            ("Profiler", config.profiler_model or "(same as verifier)"),
            ("Calibrate", "now" if calibrate else "no"),
            ("Dashboard", f"http://{config.dashboard_host}:{config.dashboard_port}/"),
            ("Weights", ", ".join(f"{d} {config.weights[d]:.2f}" for d in conf.DIMENSIONS)),
        ]
        for label, value in rows:
            self.out(f"  {label:<14}{value}")

    # -- after confirmation ----------------------------------------------------

    def apply(self, plan: Plan) -> None:
        """Write the file, then create the database and calibrate as planned."""
        path = paths.config_file()
        if path.is_file():
            backup = path.with_name(path.name + ".bak")
            shutil.copy2(path, backup)
            self.out(f"Kept the previous file as {backup}")
        conf.save_config(plan.config, path)
        self.out(f"Wrote {path}")

        if plan.create_database:
            self.create_database(paths.db_dir() / plan.config.database)
        if plan.calibrate:
            self.calibrate(plan.config)

        self.finish()

    def create_database(self, db_path: Path) -> None:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        from threatlens.db.migrate import upgrade
        from threatlens.db.seed import seed_missing

        upgrade(db_path)
        self.out(f"Database ready: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        try:
            with Session(engine) as session:
                for message in seed_missing(session):
                    self.out(f"  {message}")
        finally:
            engine.dispose()

    def calibrate(self, config: conf.ThreatLensConfig) -> None:
        from threatlens.extractors.calibration import (
            CalibrationError,
            calibrate,
            save_calibration,
        )

        self.out("")
        try:
            result = calibrate(base_url=config.ollama_url, model=config.verifier_model)
        except CalibrationError as exc:
            self.out(f"Calibration failed: {exc}")
            self.out("The other settings are saved; run `threatlens-calibrate` to try again.")
            return
        save_calibration(result)
        self.out(f"Saved calibrated [llm] settings (profile {result.settings.profile}).")

    def finish(self) -> None:
        self.out("")
        remaining = conf.setup_status().warnings()
        if remaining:
            self.out("Still to do:")
            for warning in remaining:
                self.out(f"  - {warning}")
        else:
            self.out("Setup complete.")
        self.out("Next: `threatlens-dashboard` for the web UI, or `threatlens report.pdf` to try one report.")


# -- command line --------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens init",
        description="Set up threatlens.conf by answering questions, then create the database.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="ask nothing: start from the current file (or defaults), apply the options below, write",
    )
    group = parser.add_argument_group("with --non-interactive")
    group.add_argument("--data-dir", help="data folder (absolute path; '' = the default)")
    group.add_argument("--ollama-url")
    group.add_argument("--verifier", help="verifier model")
    group.add_argument("--profiler", help="profiler model ('' = same as verifier)")
    group.add_argument("--database", help="database file name, e.g. threatlens.db")
    group.add_argument("--host", help="dashboard address, e.g. 127.0.0.1")
    group.add_argument("--port", type=int, help="dashboard port")
    group.add_argument("--no-database", action="store_true", help="do not create or upgrade the database")
    group.add_argument("--calibrate", action="store_true", help="benchmark the Ollama server and save [llm]")
    return parser


def run_non_interactive(args: argparse.Namespace, current: conf.ThreatLensConfig, out: Out = print) -> int:
    changes = {
        "data_dir": None if args.data_dir is None else (str(Path(args.data_dir).expanduser()) if args.data_dir else ""),
        "ollama_url": args.ollama_url.rstrip("/") if args.ollama_url else None,
        "verifier_model": args.verifier,
        "profiler_model": args.profiler,
        "database": args.database,
        "dashboard_host": args.host,
        "dashboard_port": args.port,
    }
    config = replace(current, **{k: v for k, v in changes.items() if v is not None})
    errors = conf.validate(config)
    if errors:
        out("error: " + "; ".join(errors))
        return 2

    models, reason = probe_ollama(config.ollama_url)
    if models is None:
        out(f"warning: Ollama is not reachable at {config.ollama_url} ({reason})")
    elif config.verifier_model not in models:
        out(f"warning: {config.verifier_model} is not pulled on {config.ollama_url}")

    wizard = Wizard(out=out)
    wizard.apply(Plan(config=config, create_database=not args.no_database, calibrate=args.calibrate))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = paths.config_file()
    invalid = ""
    try:
        current = conf.load_config(path)
    except conf.ConfigError as exc:
        current, invalid = conf.ThreatLensConfig(), str(exc)

    if args.non_interactive:
        if invalid:
            print(f"error: {invalid}\nFix or move the file, or run `threatlens init` interactively.")
            return 2
        return run_non_interactive(args, current)

    if not sys.stdin.isatty():
        print("error: threatlens init asks questions, but input is not a terminal. "
              "Use --non-interactive with options instead (see --help).")
        return 2

    wizard = Wizard()
    try:
        plan = wizard.interview(current, exists=path.is_file(), invalid=invalid)
        if plan is None:
            print("Nothing written.")
            return 1
        wizard.apply(plan)
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled.")
        return 130
    return 0


def offer_setup() -> None:
    """First-run hook: with no threatlens.conf and a terminal, offer to run the wizard."""
    if paths.config_file().is_file() or os.environ.get("THREATLENS_NO_SETUP"):
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    print(f"No ThreatLens settings file yet ({paths.config_file()}).")
    try:
        run_now = Wizard().yes_no("Run the setup wizard now?", True)
    except (KeyboardInterrupt, EOFError):
        print()
        return
    if run_now:
        main([])
    else:
        print("Continuing with built-in defaults. Run `threatlens init` any time.")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
