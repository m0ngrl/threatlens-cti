"""threatlens init: the questions, what gets written, and the first-run hook."""

from __future__ import annotations

import sqlite3
import sys
import types
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from threatlens import cli, paths
from threatlens import config as conf
from threatlens import setup_wizard as sw

MODELS = ["gemma3:4b", "qwen3.5:9b"]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fresh settings file location and data folder under tmp_path."""
    monkeypatch.setenv("THREATLENS_CONF", str(tmp_path / "threatlens.conf"))
    monkeypatch.setenv("THREATLENS_HOME", str(tmp_path / "data"))
    return tmp_path


def scripted(answers: list[str]) -> tuple[sw.Wizard, list[str]]:
    """A wizard fed `answers` in order; fails loudly if it asks more questions than scripted."""
    queue: Iterator[str] = iter(answers)
    output: list[str] = []

    def ask(prompt: str) -> str:
        output.append(prompt)
        try:
            return next(queue)
        except StopIteration:
            raise AssertionError(f"unexpected question: {prompt!r}") from None

    return sw.Wizard(ask=ask, out=output.append, probe=lambda url: (MODELS, "")), output


def run_wizard(wizard: sw.Wizard) -> sw.Plan | None:
    path = paths.config_file()
    current = conf.load_config() if path.is_file() else conf.ThreatLensConfig()
    plan = wizard.interview(current, exists=path.is_file())
    if plan is not None:
        wizard.apply(plan)
    return plan


FIRST_RUN = [
    "",                         # data folder: default
    "",                         # use the LLM engine: yes
    "http://10.0.0.5:11434",    # Ollama URL
    "2",                        # verifier: qwen3.5:9b
    "",                         # profiler: same as verifier
    "n",                        # calibrate now: no
    "",                         # database name: threatlens.db
    "",                         # create it: yes
    "",                         # listen on: 127.0.0.1
    "",                         # port: 8000
    "",                         # change weights: no
    "",                         # write: yes
]


def test_first_run_writes_conf_and_creates_database(env: Path) -> None:
    wizard, output = scripted(FIRST_RUN)
    plan = run_wizard(wizard)

    assert plan is not None and not plan.calibrate
    config = conf.load_config()
    assert config.ollama_url == "http://10.0.0.5:11434"
    assert config.verifier_model == "qwen3.5:9b"
    assert config.profiler_model == ""
    assert (config.dashboard_host, config.dashboard_port) == ("127.0.0.1", 8000)
    assert config.data_dir == ""

    assert (env / "data" / "reports").is_dir()  # ready for PDFs before the dashboard runs
    db_path = env / "data" / "db" / "threatlens.db"
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT count(*) FROM scoring_config").fetchone()[0] == 4
        assert db.execute("SELECT count(*) FROM allowlist").fetchone()[0] > 0

    status = conf.setup_status()
    assert status.exists and status.edited and not status.calibrated
    assert any("Still to do" in line for line in output)


def test_verifier_default_prefers_the_recommended_model(env: Path) -> None:
    answers = FIRST_RUN.copy()
    answers[3] = ""  # Enter at the verifier menu
    wizard, _ = scripted(answers)
    run_wizard(wizard)
    assert conf.load_config().verifier_model == conf.TEMPLATE.verifier_model == "qwen3.5:9b"


def test_rerun_keeps_current_values_llm_tuning_and_a_backup(env: Path) -> None:
    tuned = conf.LLMSettings(profile="gpu-high", batch_size=8, timeout=120)
    conf.save_config(replace(
        conf.ThreatLensConfig(),
        ollama_url="http://10.0.0.5:11434",
        verifier_model="qwen3.5:9b",
        llm=tuned,
        calibration={"hostname": "box"},
        dashboard_port=8100,
    ))
    before = conf.load_config()
    # Everything at its default; "n" only to skip creating the database.
    wizard, output = scripted(["", "", "", "", "", "", "", "n", "", "", "", ""])
    run_wizard(wizard)

    after = conf.load_config()
    assert replace(after, present=frozenset()) == replace(before, present=frozenset())
    assert after.llm == tuned and after.calibration == {"hostname": "box"}
    assert (env / "threatlens.conf.bak").is_file()
    # Calibration defaults to "no" once this verifier has been calibrated.
    assert any(prompt.startswith("Calibrate now? [y/N]") for prompt in output)


def test_unreachable_ollama_can_be_kept_or_skipped(env: Path) -> None:
    wizard, output = scripted([
        "", "", "http://10.9.9.9:11434",
        "k",                # keep the URL anyway
        "qwen3.5:9b",       # verifier typed, no list to choose from
        "",                 # profiler blank
        "", "n", "", "", "", "",
    ])
    wizard.probe = lambda url: (None, "connection refused")
    plan = run_wizard(wizard)
    assert plan is not None and not plan.calibrate  # no model list, so no calibration offer
    assert conf.load_config().ollama_url == "http://10.9.9.9:11434"
    assert any("Could not reach" in line for line in output)

    wizard, _ = scripted(["", "", "http://10.9.9.9:11434", "s", "", "n", "", "", "", ""])
    wizard.probe = lambda url: (None, "connection refused")
    assert run_wizard(wizard) is not None


def test_network_access_needs_confirmation(env: Path) -> None:
    answers = FIRST_RUN[:8] + ["2", "n", "", "", ""]   # pick 0.0.0.0, then decline the warning
    wizard, _ = scripted(answers)
    run_wizard(wizard)
    assert conf.load_config().dashboard_host == "127.0.0.1"

    answers = FIRST_RUN[:8] + ["2", "y", "9000", "", ""]
    wizard, _ = scripted(answers)
    run_wizard(wizard)
    assert (conf.load_config().dashboard_host, conf.load_config().dashboard_port) == ("0.0.0.0", 9000)


def test_weights_are_re_asked_until_they_sum_to_one(env: Path) -> None:
    answers = FIRST_RUN[:10] + [
        "y",
        "0.5", "0.5", "0.5", "0.5",     # sums to 2.00: rejected
        "0.4", "0.3", "0.2", "0.1",
        "",
    ]
    wizard, output = scripted(answers)
    run_wizard(wizard)
    assert conf.load_config().weights == {"timeliness": 0.4, "accuracy": 0.3, "completeness": 0.2, "relevance": 0.1}
    assert any("must add up to 1.00" in line for line in output)


def test_declining_to_write_changes_nothing(env: Path) -> None:
    wizard, _ = scripted(FIRST_RUN[:-1] + ["n"])
    assert run_wizard(wizard) is None
    assert not paths.config_file().exists()
    assert not (env / "data").exists()


def test_bad_answers_are_re_asked(env: Path) -> None:
    answers = ["relative/folder", ""] + FIRST_RUN[1:2] + ["not a url", "http://10.0.0.5:11434"] + FIRST_RUN[3:6] + [
        "data.sqlite", "",   # bad database name, then the default
    ] + FIRST_RUN[7:9] + ["99999", ""] + FIRST_RUN[10:]
    wizard, output = scripted(answers)
    run_wizard(wizard)
    assert conf.load_config().database == "threatlens.db"
    for message in ("absolute path", "URL like", "ending in .db", "port from 1 to 65535"):
        assert any(message in line for line in output), message


def test_invalid_file_can_restart_from_defaults(env: Path) -> None:
    paths.config_file().write_text("[llm]\nbatch_size = lots\n", encoding="utf-8")
    wizard, _ = scripted(["y", *FIRST_RUN])
    plan = wizard.interview(conf.ThreatLensConfig(), exists=True, invalid="batch_size = 'lots'")
    assert plan is not None
    wizard.apply(plan)
    assert conf.load_config().verifier_model == "qwen3.5:9b"
    assert "lots" in (env / "threatlens.conf.bak").read_text(encoding="utf-8")


def test_non_interactive_applies_options(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sw, "probe_ollama", lambda url: (MODELS, ""))
    args = sw.build_parser().parse_args([
        "--non-interactive", "--ollama-url", "http://10.0.0.5:11434/", "--verifier", "gemma3:4b",
        "--database", "lab.db", "--port", "8200",
    ])
    lines: list[str] = []
    assert sw.run_non_interactive(args, conf.ThreatLensConfig(), out=lines.append) == 0
    config = conf.load_config()
    assert (config.ollama_url, config.verifier_model, config.database, config.dashboard_port) == (
        "http://10.0.0.5:11434", "gemma3:4b", "lab.db", 8200,
    )
    assert (env / "data" / "db" / "lab.db").is_file()


def test_non_interactive_rejects_bad_values(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = sw.build_parser().parse_args(["--non-interactive", "--data-dir", "relative"])
    lines: list[str] = []
    assert sw.run_non_interactive(args, conf.ThreatLensConfig(), out=lines.append) == 2
    assert not paths.config_file().exists()


def test_threatlens_init_dispatches_to_the_wizard(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sw, "probe_ollama", lambda url: ([], ""))
    assert cli.main(["init", "--non-interactive", "--no-database", "--verifier", "llama3.2:3b"]) == 0
    assert conf.load_config().verifier_model == "llama3.2:3b"


def test_interactive_init_refuses_without_a_terminal(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert sw.main([]) == 2
    assert "--non-interactive" in capsys.readouterr().out


def test_first_run_offer_stays_quiet_outside_a_terminal(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sw, "Wizard", lambda *a, **k: pytest.fail("must not prompt"))
    sw.offer_setup()  # pytest's stdin is not a terminal


def test_dashboard_listens_on_this_machine_by_default(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda app, **kw: calls.append(kw)))
    from threatlens.dashboard import server

    server.main([])
    assert (calls[-1]["host"], calls[-1]["port"]) == ("127.0.0.1", 8000)

    conf.save_config(replace(conf.ThreatLensConfig(), dashboard_host="0.0.0.0", dashboard_port=9100))
    server.main([])
    assert (calls[-1]["host"], calls[-1]["port"]) == ("0.0.0.0", 9100)

    server.main(["--host", "127.0.0.1", "--port", "9200"])
    assert (calls[-1]["host"], calls[-1]["port"]) == ("127.0.0.1", 9200)
