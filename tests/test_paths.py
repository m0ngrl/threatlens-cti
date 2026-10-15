"""Where files live: checkout vs installed layout, overrides, stored report paths."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from threatlens import config as conf
from threatlens import paths
from threatlens.db.seed import db_url


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pretend to be a pip install, with per-user folders under tmp_path."""
    monkeypatch.delenv("THREATLENS_CONF", raising=False)
    monkeypatch.delenv("THREATLENS_HOME", raising=False)
    monkeypatch.setattr(paths, "is_checkout", lambda: False)
    monkeypatch.setattr(paths, "user_config_dir", lambda *a, **k: str(tmp_path / "config"))
    monkeypatch.setattr(paths, "user_data_dir", lambda *a, **k: str(tmp_path / "data"))
    return tmp_path


@pytest.mark.skipif(
    not (paths.REPO_ROOT / "pyproject.toml").is_file(),
    reason="testing an installed package (e.g. from the sdist), not a checkout",
)
def test_this_repo_is_a_checkout() -> None:
    assert paths.is_checkout()


def test_checkout_layout_keeps_the_repo_folders(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paths, "is_checkout", lambda: True)
    monkeypatch.delenv("THREATLENS_HOME", raising=False)
    monkeypatch.delenv("THREATLENS_CONF", raising=False)
    monkeypatch.setattr(conf, "load_config", lambda path=None: conf.ThreatLensConfig())
    assert paths.config_file() == paths.REPO_ROOT / "threatlens.conf"
    assert paths.data_dir() == paths.REPO_ROOT
    assert paths.db_dir() == paths.REPO_ROOT / "db"
    assert paths.reports_dir() == paths.REPO_ROOT / "docs" / "database" / "CTI"


def test_installed_layout_uses_per_user_folders(installed: Path) -> None:
    assert paths.config_file() == installed / "config" / "threatlens.conf"
    assert paths.data_dir() == installed / "data"
    assert paths.db_dir() == installed / "data" / "db"
    assert paths.reports_dir() == installed / "data" / "reports"
    assert db_url() == f"sqlite:///{installed / 'data' / 'db' / 'threatlens.db'}"


def test_threatlens_conf_env_overrides_config_location(installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATLENS_CONF", str(installed / "elsewhere.conf"))
    assert paths.config_file() == installed / "elsewhere.conf"


def test_conf_data_dir_moves_databases_and_reports(installed: Path) -> None:
    custom = installed / "custom"
    conf.save_config(replace(conf.ThreatLensConfig(), data_dir=str(custom)))
    assert paths.config_file().is_file()
    assert paths.db_dir() == custom / "db"
    assert paths.reports_dir() == custom / "reports"


def test_threatlens_home_beats_conf_data_dir(installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    conf.save_config(replace(conf.ThreatLensConfig(), data_dir=str(installed / "from-conf")))
    monkeypatch.setenv("THREATLENS_HOME", str(installed / "from-env"))
    assert paths.data_dir() == installed / "from-env"
    assert paths.reports_dir() == installed / "from-env" / "reports"


def test_custom_data_dir_in_a_checkout_uses_reports_subfolder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATLENS_HOME", str(tmp_path))
    assert paths.reports_dir() == tmp_path / "reports"


def test_unreadable_conf_falls_back_to_default_data_dir(installed: Path) -> None:
    config = paths.config_file()
    config.parent.mkdir(parents=True)
    config.write_text("[llm]\nbatch_size = lots\n", encoding="utf-8")
    assert paths.data_dir() == installed / "data"


def test_stored_paths_are_relative_inside_the_data_folder(installed: Path) -> None:
    inside = paths.reports_dir() / "report.pdf"
    outside = installed / "elsewhere" / "report.pdf"
    assert paths.stored_path(inside) == str(Path("reports") / "report.pdf")
    assert paths.stored_path(outside) == str(outside.resolve())
    assert paths.resolve_stored(paths.stored_path(inside)) == paths.data_dir() / "reports" / "report.pdf"
    assert paths.resolve_stored(str(outside)) == outside


def test_checkout_rows_still_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paths, "is_checkout", lambda: True)
    monkeypatch.delenv("THREATLENS_HOME", raising=False)
    monkeypatch.setattr(conf, "load_config", lambda path=None: conf.ThreatLensConfig())
    stored = "docs/database/CTI/abc.pdf"
    assert paths.resolve_stored(stored) == paths.REPO_ROOT / stored


def test_relative_data_dir_is_rejected() -> None:
    with pytest.raises(conf.ConfigError, match="absolute folder path"):
        conf.save_config(replace(conf.ThreatLensConfig(), data_dir="relative/folder"))


def test_missing_conf_warning_fits_the_layout(installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert "cp threatlens.conf.example" not in conf.setup_status().warnings()[0]
    monkeypatch.setattr(paths, "is_checkout", lambda: True)
    monkeypatch.setenv("THREATLENS_CONF", str(installed / "absent.conf"))
    assert "cp threatlens.conf.example" in conf.setup_status().warnings()[0]
