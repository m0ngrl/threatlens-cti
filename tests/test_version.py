"""Every command reports the installed package version."""

from __future__ import annotations

from importlib.metadata import version

import pytest

import threatlens
from threatlens import cli, setup_wizard
from threatlens.dashboard import ingest_worker, server
from threatlens.extractors import calibration


def test_version_comes_from_the_package_metadata() -> None:
    assert threatlens.__version__ == version("threatlens-cti")


@pytest.mark.parametrize(
    "entry_point",
    [cli.main, setup_wizard.main, calibration.main, ingest_worker.cli_main, server.main],
    ids=["threatlens", "threatlens-init", "threatlens-calibrate", "threatlens-ingest", "threatlens-dashboard"],
)
def test_every_command_has_a_version_flag(entry_point, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        entry_point(["--version"])
    assert exit_info.value.code == 0
    assert threatlens.__version__ in capsys.readouterr().out
