"""ThreatLens: extract, verify and quality-score IoCs from CTI reports."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: pyproject.toml's version, via the installed metadata.
    __version__ = version("threatlens-cti")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
