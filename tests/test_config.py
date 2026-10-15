"""threatlens.conf loading, validation, the [llm] section, and calibration saves."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from threatlens import config as conf
from threatlens.db.models import Base, ScoringConfig
from threatlens.extractors.calibration import (
    BenchmarkResult,
    Calibration,
    save_calibration,
)
from threatlens.quality.quality_checker import Agreement, ScoringPolicy


@pytest.fixture
def conf_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "threatlens.conf"
    monkeypatch.setenv("THREATLENS_CONF", str(path))
    return path


def test_missing_file_gives_defaults(conf_path: Path) -> None:
    config = conf.load_config()
    assert config == conf.ThreatLensConfig()
    assert config.present == frozenset()


def test_round_trip_keeps_values(conf_path: Path) -> None:
    original = conf.ThreatLensConfig(
        ollama_url="http://10.0.0.5:11434",
        verifier_model="qwen3.5:9b",
        profiler_model="gemma3:4b",
        llm=conf.LLMSettings(profile="gpu-high", batch_size=8, timeout=120, num_predict=1536),
        database="ex_threatlens.db",
        weights={"timeliness": 0.1, "accuracy": 0.4, "completeness": 0.3, "relevance": 0.2},
        agreement={"agree": 1.0, "weak": 0.8, "single": 0.7, "moderate": 0.6, "strong": 0.3},
        calibration={"hostname": "box", "ollama_runtime": "qwen3.5:9b: 100% GPU"},
    )
    conf.save_config(original)
    loaded = conf.load_config()
    assert replace(loaded, present=frozenset()) == original
    assert {"ollama", "models", "llm", "database", "quality.weights", "quality.agreement"} <= loaded.present


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"ollama_url": "192.168.1.5:11434"}, "ollama url"),
        ({"verifier_model": ""}, "verifier model"),
        ({"database": "../etc/passwd.db"}, r"bare \*\.db filename"),
        ({"weights": {"timeliness": 0.5, "accuracy": 0.5, "completeness": 0.5, "relevance": 0.0}}, "sum to 1.00"),
        ({"agreement": {**conf.ThreatLensConfig().agreement, "strong": 1.5}}, "between 0 and 1"),
        ({"llm": conf.LLMSettings(timeout=5)}, r"timeout = 5 must be at least 30"),
        ({"llm": conf.LLMSettings(verification_policy="some")}, "verification_policy"),
    ],
)
def test_validation_rejects_bad_values(conf_path: Path, change: dict, message: str) -> None:
    bad = replace(conf.ThreatLensConfig(), **change)
    with pytest.raises(conf.ConfigError, match=message):
        conf.save_config(bad)
    assert not conf_path.exists()


def test_invalid_file_raises_on_load(conf_path: Path) -> None:
    conf_path.write_text("[quality.weights]\ntimeliness = lots\n", encoding="utf-8")
    with pytest.raises(conf.ConfigError, match="not a number"):
        conf.load_config()


def test_llm_section_is_read_and_clamped(conf_path: Path) -> None:
    conf_path.write_text(
        "[llm]\nbatch_size = 8\ntimeout = 5\nnum_ctx = 8192\nverification_policy = ALL\n",
        encoding="utf-8",
    )
    llm = conf.load_config().llm
    assert llm.batch_size == 8
    assert llm.timeout == conf.LLM_MINIMUMS["timeout"]
    assert llm.num_ctx == 8192
    assert llm.verification_policy == "all"
    assert llm.profile == "custom"
    assert llm.num_predict == conf.LLMSettings().num_predict


def test_llm_section_rejects_non_integers(conf_path: Path) -> None:
    conf_path.write_text("[llm]\nbatch_size = lots\n", encoding="utf-8")
    with pytest.raises(conf.ConfigError, match="not a whole number"):
        conf.load_config()


def _calibration(model: str = "qwen3.5:9b", url: str = "http://10.0.0.9:11434") -> Calibration:
    best = BenchmarkResult(
        batch_size=5, elapsed_seconds=10.0, candidates=5, prompt_tokens=400,
        generated_tokens=90, load_seconds=0.0, prompt_seconds=1.0,
        generation_seconds=8.0, valid=True,
    )
    return Calibration(
        model=model, base_url=url, best=best, ram=16.0, gpu="none",
        ollama_runtime="qwen3.5:9b: 100% GPU",
        settings=conf.LLMSettings(profile="gpu-high", batch_size=5, timeout=70, num_predict=1056),
    )


def test_save_calibration_merges_into_conf(conf_path: Path) -> None:
    conf.save_config(
        replace(
            conf.ThreatLensConfig(),
            profiler_model="gemma3:4b",
            database="ex_threatlens.db",
            weights={"timeliness": 0.4, "accuracy": 0.4, "completeness": 0.2, "relevance": 0.0},
        )
    )
    save_calibration(_calibration())

    loaded = conf.load_config()
    assert loaded.ollama_url == "http://10.0.0.9:11434"
    assert loaded.verifier_model == "qwen3.5:9b"
    assert loaded.llm == conf.LLMSettings(profile="gpu-high", batch_size=5, timeout=70, num_predict=1056)
    assert loaded.calibration["measured_batch_size"] == "5"
    assert loaded.calibration["ollama_runtime"] == "qwen3.5:9b: 100% GPU"
    # Sections calibration does not own are untouched.
    assert loaded.profiler_model == "gemma3:4b"
    assert loaded.database == "ex_threatlens.db"
    assert loaded.weights["timeliness"] == 0.4


def test_save_calibration_creates_missing_conf(conf_path: Path) -> None:
    save_calibration(_calibration())
    assert conf.load_config().llm.profile == "gpu-high"


def test_save_calibration_refuses_to_overwrite_invalid_conf(conf_path: Path) -> None:
    conf_path.write_text("[quality.weights]\ntimeliness = lots\n", encoding="utf-8")
    with pytest.raises(conf.ConfigError):
        save_calibration(_calibration())
    assert "lots" in conf_path.read_text(encoding="utf-8")


def test_configured_policy_uses_conf_weights_and_multipliers(conf_path: Path) -> None:
    conf.save_config(
        replace(
            conf.ThreatLensConfig(),
            weights={"timeliness": 0.4, "accuracy": 0.4, "completeness": 0.2, "relevance": 0.0},
            agreement={**conf.ThreatLensConfig().agreement, "single": 0.6},
        )
    )
    policy = ScoringPolicy.configured()
    assert policy.weights["timeliness"] == 0.4
    assert policy.agreement_multipliers[Agreement.SINGLE] == 0.6
    # Built-in baseline is untouched.
    assert ScoringPolicy.default().weights["timeliness"] == 0.25


def test_conf_weights_override_scoring_config(conf_path: Path) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        for dimension, weight in ScoringPolicy.default().weights.items():
            session.add(ScoringConfig(dimension=dimension, weight=weight, parameters="{}"))
        session.commit()

        assert ScoringPolicy.from_session(session).weights["accuracy"] == 0.30

        conf_path.write_text(
            "[quality.weights]\ntimeliness = 0.1\naccuracy = 0.6\ncompleteness = 0.2\nrelevance = 0.1\n",
            encoding="utf-8",
        )
        assert ScoringPolicy.from_session(session).weights["accuracy"] == 0.6


def test_save_does_not_round_weights(conf_path: Path) -> None:
    weights = {"timeliness": 0.125, "accuracy": 0.375, "completeness": 0.25, "relevance": 0.25}
    conf.save_config(replace(conf.ThreatLensConfig(), weights=weights))
    assert conf.load_config().weights == weights


REPO_EXAMPLE = Path(__file__).resolve().parents[1] / "threatlens.conf.example"


def test_example_file_is_the_generated_template() -> None:
    assert REPO_EXAMPLE.read_text(encoding="utf-8") == conf.render(conf.TEMPLATE, template=True)


def test_setup_status_missing_file(conf_path: Path) -> None:
    status = conf.setup_status()
    assert (status.exists, status.edited, status.calibrated, status.ready) == (False, False, False, False)
    assert "does not exist" in status.warnings()[0]
    assert len(status.warnings(llm=False)) == 1


def test_setup_status_unedited_template_copy(conf_path: Path) -> None:
    conf_path.write_text(REPO_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    status = conf.setup_status()
    assert status.exists and not status.edited and not status.calibrated
    assert "unedited template" in status.warnings()[0]


def test_setup_status_template_with_changed_value_counts_as_edited(conf_path: Path) -> None:
    text = REPO_EXAMPLE.read_text(encoding="utf-8")
    conf_path.write_text(text.replace("url = http://127.0.0.1:11434", "url = http://10.0.0.7:11434"), encoding="utf-8")
    assert conf.setup_status().edited


def test_setup_status_save_marks_template_reviewed(conf_path: Path) -> None:
    conf_path.write_text(REPO_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    conf.save_config(conf.load_config())  # e.g. the dashboard saving unchanged values
    status = conf.setup_status()
    assert status.edited and conf.TEMPLATE_MARKER not in conf_path.read_text(encoding="utf-8")
    assert status.warnings(llm=False) == []


def test_setup_status_calibrated_by_run_or_hand_tuning(conf_path: Path) -> None:
    save_calibration(_calibration())
    status = conf.setup_status()
    assert status.calibrated and status.edited and status.ready
    assert status.warnings() == []

    conf.save_config(replace(conf.ThreatLensConfig(), llm=conf.LLMSettings(batch_size=10)))
    assert conf.setup_status().calibrated


def test_setup_status_invalid_file(conf_path: Path) -> None:
    conf_path.write_text("[llm]\nbatch_size = lots\n", encoding="utf-8")
    status = conf.setup_status()
    assert status.error and not status.ready
    assert status.warnings() == [status.warnings()[0]] and "invalid" in status.warnings()[0]
