import pytest


@pytest.fixture(autouse=True)
def _no_local_threatlens_conf(monkeypatch, tmp_path):
    """Keep tests on built-in defaults regardless of the developer's threatlens.conf."""
    monkeypatch.setenv("THREATLENS_CONF", str(tmp_path / "absent-threatlens.conf"))
