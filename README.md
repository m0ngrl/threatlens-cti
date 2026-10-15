# ThreatLens

ThreatLens extracts candidate indicators of compromise (IoCs) from cyber threat
intelligence reports, checks them for quality issues (duplication, missing
context and likely false positives) and stores them in a SQLite repository with
a quality score, browsable from a web dashboard.

ZEIT3118 Capstone, UNSW Canberra, 2026.

## Requirements

- Python 3.12+
- For the default `llm` extraction engine: an [Ollama](https://ollama.com)
  server with the verifier model pulled (the evaluation runs use
  `qwen3.5:9b`). The `python` engine needs no LLM.

## Installation

    python -m pip install "threatlens-cti[dashboard]"

The package is `threatlens-cti`. It installs the `threatlens` Python package
and the `threatlens`, `threatlens-init`, `threatlens-ingest`,
`threatlens-calibrate` and `threatlens-dashboard` commands; each takes
`--version`. This is a beta (0.x): behaviour may still change between minor
versions. Leave out
`[dashboard]` if you only need the command line (no FastAPI, Uvicorn or
Datasette).

## Setup

    threatlens init

The setup wizard asks for the data folder, the Ollama URL (tested live), the
models (picked from those the server has pulled), the dashboard address and,
optionally, the quality weights. It shows a summary, then writes
`threatlens.conf`, creates the database and can calibrate the LLM settings
for your hardware. Re-run it any time: the current values are the defaults.
`threatlens init --help` lists the options for scripted
(`--non-interactive`) setups. Until setup is done, the commands print a
warning naming the missing step and, in a terminal, offer to start the wizard.

`threatlens.conf` holds every per-machine setting: Ollama URL, verifier and
profiler models, LLM performance tuning (`[llm]`), data folder, default
database, dashboard address and quality-score weights. Besides the wizard,
the dashboard's Configuration page and `threatlens-calibrate` also write it:

    threatlens-calibrate                      # re-benchmark the configured model and server
    threatlens-calibrate --model qwen3.5:9b --ollama-url http://host:11434 --save

### Where files live

| | pip install (Linux) | Source checkout |
|---|---|---|
| `threatlens.conf` | `~/.config/threatlens/` | repo root |
| Databases | `~/.local/share/threatlens/db/` | `db/` |
| Report PDFs | `~/.local/share/threatlens/reports/` | `docs/database/CTI/` |

Windows uses `%APPDATA%\threatlens` and `%LOCALAPPDATA%\threatlens`; macOS
`~/Library/Application Support/threatlens`. `THREATLENS_CONF` moves the
config file; `THREATLENS_HOME` or `[paths] data_dir` in `threatlens.conf`
moves the data folder (`db/` and `reports/`).

## Usage

    # Web dashboard: browse, upload, ingest, configure (http://127.0.0.1:8000)
    threatlens-dashboard
    threatlens-dashboard --host 0.0.0.0 --port 8000   # reachable from the local network

    # Ingest one report: extract, quality-check, store, rescore
    threatlens-ingest report.pdf --db ~/.local/share/threatlens/db/threatlens.db --engine llm

    # Inspect one report: extraction only, no database
    threatlens report.pdf
    threatlens report.pdf --engine python -o result.json

    # Quality-check extractor JSON without a database
    python -m threatlens.quality.quality_checker result.json

    # Create or upgrade a database by hand (init does this for you)
    python -m threatlens.db.migrate [path/to/file.db]

The dashboard has no login. It listens on `127.0.0.1` (this machine only)
unless you choose otherwise in `threatlens init` or pass `--host`; anyone who
can reach it can edit and delete data.

## Documentation

The full documentation ships with the package: start `threatlens-dashboard`
and open [http://127.0.0.1:8000/docs/](http://127.0.0.1:8000/docs/). The
same pages are in the repository under
[`src/threatlens/docs/`](https://github.com/m0ngrl/threatlens-cti/tree/main/src/threatlens/docs).

## License

Copyright (C) 2026 Tyler Passey, Ben King and Ethan McLachlan.

ThreatLens is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See [`LICENSE`](https://github.com/m0ngrl/threatlens-cti/blob/main/LICENSE)
or the [GNU AGPL v3](https://www.gnu.org/licenses/agpl-3.0.html).

It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. The AGPL applies to network use too: if you run a
modified dashboard for others, you must offer them its source.

PyMuPDF, a required dependency, is itself AGPL-3.0 (or commercially licensed
by Artifex), which is why ThreatLens uses the AGPL.

## Development

Source: [github.com/m0ngrl/threatlens-cti](https://github.com/m0ngrl/threatlens-cti).
From a checkout:

    python3 -m venv .venv                # Windows: py -m venv .venv
    source .venv/bin/activate            # Windows: .venv\Scripts\activate
    python -m pip install -e ".[dev,dashboard]"
    threatlens init                      # writes threatlens.conf in the repo root
    pytest

`pyproject.toml` is the source of truth for dependencies; `dev` adds pytest,
ruff, mypy, build and twine. For the exact versions the project is tested
with, install the pinned runtime set first:

    python -m pip install -r requirements.txt
    python -m pip install -e . --no-deps

In a checkout, `threatlens.conf`, `db/` and `docs/database/CTI/` are
gitignored, and `cp threatlens.conf.example threatlens.conf` is an
alternative to the wizard.

Always create and change the schema through Alembic, never `create_all()`.
The migrations ship in the package (`src/threatlens/migrations/`); from the
repo root, `alembic upgrade head` and `alembic revision --autogenerate -m "..."`
use `alembic.ini`.

The evaluation corpus (third-party reports) is not distributed; reports can be
fetched from the ORKL archive with `.dev_tools/orkl_scraper.py`. To ingest a
folder of reports in resumable batches into a fresh database:

    python .dev_tools/run_ex_pipeline.py --db-path db/exN_threatlens.db --batch 1/3
