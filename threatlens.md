# ThreatLens — Project Context

Read this first. It captures the design decisions, conventions, and standing
constraints for this project so a session does not have to rediscover them.
For how each component works in detail, see the HTML documentation in
`src/threatlens/docs/` — this file is the short version.

---

## What this project is

**ThreatLens — A Cyber Threat Intelligence Indicator Quality Checker.**

A prototype that extracts indicators of compromise (IoCs) from threat reports
and feeds, organises them into a structured repository, and checks them for
quality issues. Capstone project for **ZEIT3118**, UNSW Canberra (ADFA),
Semester 2 2026.

**Client:** Dr. Clemens Sauerwein, University of Innsbruck
(`Clemens.Sauerwein@uibk.ac.at`). Note the time zone gap — Canberra is 8–10
hours ahead of Austria, so any question to the client costs a day's round trip.
Batch questions; do not design work that blocks on client input.

**The client's brief names three quality issues explicitly: duplication,
missing context, and likely false positives.** These are what the tool must
demonstrably address. Everything else is supporting machinery.

### Team and ownership

| Member | Role | Owns |
|---|---|---|
| PLTOFF Tyler Passey | Project Lead | Data repository, dashboard/UI, export function, documentation, client comms |
| PLTOFF Ben King | Technical Lead | IoC extraction engine, ingestion, normalisation, architecture |
| OFFCDT Ethan McLachlan | QA Lead | Quality checker module, scoring, testing strategy |

Integration testing is shared across all three.

**The handover boundary is the extraction result.** The extraction engine
(Ben) produces an `IoCExtractionResult` — in memory during ingest, or as JSON
from `threatlens -o`. The quality checker (Ethan) consumes it and is what
writes the `indicators`, `sightings` and `quality_flags` rows, via
`persist_report()`. The extractor never writes to the database. Respect that
boundary when suggesting changes.

---

## Delivery model

Agile, six two-week sprints (S0–S6) across a 13-week semester, with milestones
M1–M7 at sprint boundaries.

- **M4 (Week 8)** — mid-project client demonstration
- **M5 (Week 10)** — **feature freeze**; after this, defects only, no new features
- **M7 (Week 12–13)** — final delivery and handover

Scope creep is a tracked project risk. Requirements are fixed in the Statement
of Work. Do not propose new features casually; propose them as could-haves for
a future sprint.

---

## Technology stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12+ | Installable package, `src/` layout, `pyproject.toml` |
| ORM | SQLAlchemy 2.0 | `Mapped[]` / `mapped_column` syntax |
| Migrations | **Alembic, always** | Never `create_all()` in application code |
| Database | **SQLite** (prototype) | PostgreSQL is the documented production target |
| PDF reading | PyMuPDF | |
| LLM | Ollama, `qwen3.5:9b` | `temperature: 0`; local or LAN server |
| Dashboard | FastAPI + Uvicorn | `dashboard` extra in `pyproject.toml` |
| Editor | VS Code | |
| DB viewer | DB Browser for SQLite | |
| VCS | Git / GitHub — `github.com/m0ngrl/threatlens-cti` (public) | Development history before publication is kept privately |

Install with `pip install -e ".[dev,dashboard]"` (published as `threatlens-cti`; `pip install "threatlens-cti[dashboard]"`). `pyproject.toml` is the
source of truth for dependencies. `requirements.txt` pins the full runtime
tree (core + dashboard) at the tested versions, for a reproducible install;
regenerate it when `pyproject.toml` changes.

### Why SQLite, not PostgreSQL

Decided as a team (Tier 2 consensus). Zero installation, no admin rights on
managed ADFA machines, no server process, single portable file, and trivial
client handover (`pip install -e .` then run). SQLAlchemy keeps most of the
migration path to PostgreSQL open, but the schema does use some SQLite-specific
SQL that a port would have to replace: the `ctx_malware` computed column
(`json_extract`), the `json_valid()` CHECK constraints, `datetime('now')`
defaults, and the foreign-key / WAL `PRAGMA`s in `models.py`. Do not add more
without a reason; keep new queries in the ORM.

---

## Repository layout

```
threatlens-cti/
├── pyproject.toml            Package metadata, dependencies, console scripts
├── LICENSE                   GNU AGPL v3 (the project is AGPL-3.0-or-later)
├── threatlens.conf.example   Template for threatlens.conf (per machine, gitignored;
│                             calibration.py writes its [llm] section)
├── alembic.ini               Alembic CLI config for a checkout (alembic upgrade head)
├── MANIFEST.in               Extra files for the sdist (tests, templates)
├── db/                       SQLite database files (gitignored)
├── src/threatlens/
│   ├── cli.py                `threatlens` — inspect one report, no database
│   ├── config.py             threatlens.conf loading and precedence
│   ├── paths.py              where threatlens.conf, db/ and reports live (checkout vs pip install)
│   ├── setup_wizard.py       `threatlens init` / `threatlens-init` — interactive setup
│   ├── extractors/           ioc_extract_llm_fs.py (llm engine + shared front end),
│   │                         ioc_extract_python.py, calibration.py
│   ├── quality/              quality_checker.py, allowlist.py
│   ├── db/                   models.py, ingest.py, conformance.py, seed.py, migrate.py
│   ├── migrations/           Alembic env + versions/ (head: b246eb301c95, v1.5)
│   ├── docs/                 HTML documentation (start at index.html; served at /docs)
│   ├── dashboard/            FastAPI app, ingest_worker.py (`threatlens-ingest`),
│   │                         routes/, static/, HTML pages
├── tests/                    pytest suite (the PDF test builds a synthetic report at run time)
├── docs/                     Course deliverables; database/CTI/ is the report folder
│                             (gitignored - not distributed, see below)
└── .dev_tools/               run_ex_pipeline.py, run_ex_batches.sh, orkl_scraper.py
```

`python -m threatlens.db.migrate [DB]` runs the shipped migrations against
`DB` (default: threatlens.conf's database in `db/`), installed or not; so does
`.dev_tools/run_ex_pipeline.py --db-path`. The plain `alembic` CLI works from
the repo root via `alembic.ini` (URL `db/threatlens.db`).

The wheel ships the dashboard pages and `static/`, `docs/`, and the
migrations as package data (`[tool.setuptools.package-data]`); `MANIFEST.in`
adds tests, `alembic.ini` and the conf template to the sdist.

---

## Database schema (v1.5, SQLite)

Seven tables. The logical model is unchanged from the PostgreSQL design; only
column types differ.

| Table | Holds |
|---|---|
| `sources` | One row per report or feed ingested; includes `reliability` (0–100) and `extraction_engine` (`python` / `llm` / `llm+python`, NULL if unrecorded) + `verification_model` |
| `raw_documents` | Archived original content, 1:1 with sources; `sha256` UNIQUE |
| `indicators` | Deduplicated IoCs; UNIQUE on `(ioc_type, normalised)` |
| `sightings` | Junction: indicator × source, with `excerpt` and offsets |
| `quality_flags` | Quality engine output; each tagged with its `dimension` |
| `allowlist` | Known-benign values (MISP warninglist pattern) |
| `scoring_config` | Dimension weights and band parameters; insert-only history |

### Design lineage

- **STIX 2.1** — indicator typing, 0–100 confidence, the Sighting concept
  (the schema uses `first_seen` / `last_seen`, not STIX's
  `valid_from` / `valid_until`)
- **MISP** — event→attribute hierarchy (became sources→sightings), warninglists
  (became `allowlist`)
- **OpenCTI** — the boundary reference for *deliberate exclusions*
- **Computers & Security (2024)**, "Improving quality of indicators of
  compromise using STIX graphs" — the five-dimension quality framework and the
  0–5 severity rubric in its **Table 7**

> **Citation caveat:** the paper's author names have not been verified against
> the licensed copy. Do not assert them in documentation without checking.

### Deliberately out of scope

No threat actor / campaign / kill-chain graph modelling, no inter-indicator
relationships, no intelligence sharing between organisations, no external
enrichment (VirusTotal, AbuseIPDB). These are OpenCTI territory and would
consume the semester. Note them as future work; do not build them.

### SQLite constraints that bite

- **Foreign keys are OFF by default.** `PRAGMA foreign_keys = ON` must run on
  every connection — there is a SQLAlchemy `connect` event listener in
  `models.py` for this. It fails **silently** if removed.
- **`ALTER TABLE` cannot drop or alter columns or add constraints.** Alembic
  `render_as_batch=True` is set in `env.py` and must stay.
- **Type affinity, not enforcement.** SQLite accepts a string in an INTEGER
  column, so `CHECK` constraints and model-level validation carry the real
  integrity burden.
- **One writer at a time.** WAL mode is enabled. Close DB Browser before
  running scripts, or expect "database is locked".

---

## How a report flows through the system

```
report.pdf ─▶ extraction engine (llm or python) ─▶ IoCExtractionResult
                                                       │
            ┌──────────────────────────────────────────┼──────────────────────────────┐
            ▼                                          ▼                              ▼
  threatlens (cli.py)                    threatlens-ingest / dashboard        run_ex_pipeline.py
  prints, or -o JSON                     Ingest page (ingest_worker.py)       (same worker, batched)
            │                                          │
            ▼                                          ▼
  quality_checker CLI (optional)         check_report → persist_report → rescore_from_db
  console + JSON, no database                          │
                                                       ▼
                                          SQLite ─▶ dashboard (threatlens-dashboard)
```

Only the ingest route writes to the database. `cli.py` and the quality
checker's own CLI are inspection tools.

---

## Extraction engine

Two engines, one per run, selected with `--engine` (default `llm`):

- **`llm`** — `ioc_extract_llm_fs.py`. Regex candidates, then one
  document-profile LLM call and batched LLM verification through Ollama
  (`qwen3.5:9b`, `temperature: 0`, so repeat runs are deterministic).
- **`python`** — `ioc_extract_python.py`. The same candidate stage, verified
  with local heuristics. No network. A fallback for when no LLM is available.

Both share the same front end (reading, metadata, regex candidates), so they
produce the **identical candidate set with identical ids and offsets**; only
the verdicts differ. The verifier classifies, it does not extract, so
hallucinated indicators are not a risk and the `start`/`end` offsets are
trustworthy. The two verdicts are only compared when the quality checker's CLI
is given both engines' JSON (`--compare`). On the original reference sample
(39 candidates, one Proofpoint report) they agreed on only 12, mostly
disagreeing weakly (`uncertain` vs `confirmed`) — which is why disagreement is
graded rather than treated as binary.

LLM settings (Ollama URL, models, `[llm]` tuning) come from `threatlens.conf`,
with built-in defaults for anything it leaves out. `threatlens-calibrate`
(`extractors/calibration.py`) benchmarks the server and writes them there.

### JSON shape (`threatlens -o`, or `IoCExtractionResult.to_dict()`)

```
metadata: filename, title, authors, cti_source, source_url, publish_date,
          file_sha256, extraction_method
verification_model: "python-heuristics" | "<ollama model, e.g. qwen3.5:9b>"
scope: document scope assessment (llm engine only, else null)
summary: candidate_count, confirmed_ioc_count, context_entity_count,
         rejected_count, uncertain_count
indicators[]: id, category, indicator_type, value, normalized_value,
              start, end, context (FREE TEXT excerpt), method,
              attributes{was_defanged, document_section_hint},
              verification{candidate_id, status, confidence, reason, evidence,
                           corrected_category, corrected_indicator_type},
              accepted
accepted_by_category: accepted candidates grouped by category
```

### Naming collision — important

The extractor's `context` is a **free-text excerpt**. The schema's
`indicators.context` is a **structured JSON dict**. They are not the same
thing. Each report's excerpt goes to its `sightings.excerpt`; the structured
dict is built by the quality checker from the document's surviving context
entities (`threat_actor`, `campaign`, `vulnerability`, `tool`, `malware`, …).
The first report's excerpt is also kept inside `indicators.context`, under
`excerpt`, next to the structured keys.

### Extraction defects the checker catches

First observed in the reference sample, and each now handled by a quality
checker flag:

- **Sentence fragments** — e.g. `"directed by the Russian GRU. At the"` → `sentence_fragment`
- **`.php` filenames matched as domains** — `list.js.php`, `get.php.php` → `filename_as_domain` / `invalid_format`
- **Code fragments** — `requests.get` extracted as a domain → `invalid_format`
- **Source self-reference** — the report's own URL → `self_reference` (screened)
- **Span overlap** — the same text extracted twice under two types → `span_overlap`
- **Nested values** — `roundpress` ⊂ `roundpress -` → `nested_value`
- **Technique words as values** — bare `"persistence"`, `/dev/tcp` → STIX attack-pattern context, or `technique_idiom`
- **Aliases** — `TA422`, `APT28`, `Fancy Bear` are counted as one entity
  (`ScoringPolicy.alias_groups`); full actor resolution is out of scope

---

## Quality checker

`quality/quality_checker.py`. Four layers, in order. Layers 1–3 answer the
client's three named quality issues directly; Layer 4 turns what survives into
the research-grounded score.

1. **Structural checks** — span overlap, nested values, filename/domain
   collisions, sentence fragments, trailing punctuation, length bounds,
   truncated spans, technique idioms, self-reference.
2. **STIX 2.1 conformance** — classify each candidate as an SCO (observable →
   may become an indicator), an SDO (context), or neither (rejected). A value
   that cannot form a legal STIX pattern is not an observable — this removes
   the `.php` "domains" without needing a TLD list.
3. **False-positive screening** — allowlist matching (`allowlist.py`: exact,
   CIDR and wildcard-suffix forms) and non-routable addresses.
4. **Dimension scoring** — see below.

| Extractor type | STIX 2.1 | Treatment |
|---|---|---|
| `hash`, `domain`, `hostname`, `url`, `ip`, `filepath`, `filename`, `email_address`, `registry`, `mutex`, `process`, `user_agent`, `port`, `certificate`, … | SCO | Observable |
| `threat_actor`, `campaign`, `vulnerability`, `tool`, `malware` | SDO | Context |
| `ttp`, `persistence`, `beaconing`, `process_chain`, `lateral_movement`, `exfiltration` | SDO Attack Pattern | Context (technique, not an observable) |
| `service` | none as extracted | Rejected |

Each candidate ends as one `Decision`: **REJECTED** (malformed or non-STIX —
not stored at all, visible only in the CLI's JSON report), **CONTEXT** (merged
into stored indicators' `context`), **SCREENED** (stored with a flag and
`confidence = 0`) or **INDICATOR** (stored). Structure first: a malformed value
is rejected whatever the verifier said; among what survives, the LLM verdict
wins.

### The quality dimensions (0–5 each, Table 7 bands)

| Dimension | Band criteria | Default weight | Status |
|---|---|---|---|
| Timeliness | Age of `publish_date`: <7d=5, <30d=4, <90d=3, <365d=2, older=1, unknown=0 | 0.25 | Faithful to the paper |
| Accuracy | Source reliability (% of the report's candidates not rejected): ≥90=5, ≥80=4, ≥70=3, ≥55=2, else 1; capped at 3 below 10 candidates | 0.30 | **Diverges** |
| Completeness | % of expected context keys populated: ≥80=5, ≥60=4, ≥40=3, ≥20=2 | 0.25 | **Diverges** |
| Relevance | Match of the report's audience (tactical/strategic) to the reader's role | 0.20 | Simplified proxy |
| Consistency | — | not scored | **Deferred** |

Composite: weighted mean of the scored dimensions (normalised by the weights
applied), scaled to 0–100 → `indicators.quality_score`, plus a verbal grade
(Actionable ≥85, Reliable ≥75, Usable ≥65, Marginal ≥50, Unreliable).

**Relevance is always 3 today.** Every caller scores for `ViewerRole.ANY`,
which returns the middle band; the audience profile is computed but not stored.

### The documented divergences

These must be stated in documentation, never glossed over:

1. **Accuracy** — the paper counts corroborating sources. Across 105 reports
   only 3.3% of observables appeared in more than one report, and those were
   mostly benign (LOLBins, generic paths, publisher domains). Corroboration
   needs a feed, not a corpus, so accuracy reads source reliability instead.
   Sighting counts are still recorded in `score_components` for later.
2. **Completeness** — the paper measures % of the STIX *construction graph*
   completed. ThreatLens does not build the STIX graph, so it measures the
   proportion of expected context fields populated instead.
3. **Consistency** — the paper measures *antivirus detection rate*, which
   requires enrichment APIs (out of scope). ThreatLens does not score it;
   consistency-type flags are still recorded, and verifier agreement still
   discounts `confidence`. To be added once a feed such as MISP or VirusTotal
   supplies data.

### Two scores, two meanings — do not conflate

- `indicators.confidence` = certainty the indicator is **malicious** (STIX convention)
- `indicators.quality_score` = fitness of the indicator **as data**

Both are 0–100. They measure different things. The extractor's
`verification.confidence` is confidence *in the verdict*, so it is translated
through `maliciousness_from_verdict()` before it becomes `confidence`.

### Duplication: the definition that matters

> A duplication error occurs when the same underlying intelligence is stored
> more than once as distinct records — either the same source document ingested
> repeatedly, or the same indicator value stored under multiple
> representations. **Repeated observation of an indicator across genuinely
> independent sources is not duplication; it is corroborating evidence**,
> recorded as multiple sightings of a single indicator.

Two levels of prevention, both enforced by the schema rather than by code:
`raw_documents.sha256` UNIQUE (document level) and
`indicators (ioc_type, normalised)` UNIQUE (indicator level).

---

## Settings and where they live

| Setting | Source | Notes |
|---|---|---|
| Dimension weights | `scoring_config` table, **overridden by `threatlens.conf` `[quality.weights]`** when that section exists | Defaults 0.25 / 0.30 / 0.25 / 0.20 |
| Band thresholds | `scoring_config` table | Latest row per dimension wins |
| Agreement multipliers | `threatlens.conf` `[quality.agreement]`, else built-in | |
| Allowlist | `seed.py`'s `ALLOWLIST` | The `allowlist` table is seeded but not read by any caller yet |
| Ollama URL, models, LLM tuning | `threatlens.conf` `[ollama]`, `[models]`, `[llm]`, else built-in | `threatlens-calibrate` writes `[llm]` |
| Dashboard's default database | `threatlens.conf` `[database] default` | Switchable at runtime |

Every indicator records the weights it was scored with in
`score_components.weights`. Each ingest rescores **every** stored indicator
with the current settings, so a database always reflects the weights in force
at its last ingest or rescore.

---

## Evaluation runs

`ex2`, `ex3`, `ex4` are full runs of the 103-report corpus
(`docs/database/CTI/`) into fresh databases (`db/exN_threatlens.db`). The
corpus is third-party reports and is not in the repository; the files are
ORKL archive hashes, and `.dev_tools/orkl_scraper.py` downloads reports from
the same archive. Runs are driven by
`.dev_tools/run_ex_pipeline.py` and `run_ex_batches.sh`. Reports are in
`src/threatlens/docs/` (`run_report_ex4.html`,
`llm_analysis_deviation_report.html`). ex3 and ex4 are identical, which is
consistent with `temperature: 0`. ex3/ex4 were first scored with test weights
left in `threatlens.conf` and rescored with the defaults on 13 Oct 2026.

---

## Conventions

- **snake_case** for functions and variables.
- Do not hardcode thresholds or weights. Read them through `ScoringPolicy`
  (`scoring_config` plus `threatlens.conf`). `scoring_config` is insert-only
  with `effective_from`: read the *latest effective row per dimension*, not
  all rows.
- Every quality flag carries its `dimension` — that is the traceability link
  from the research framework to the data.
- Indicators are **flagged, never deleted**. A report genuinely mentioning
  `8.8.8.8` is a fact about that report; deleting it would lose the sighting.
  (Candidates rejected as malformed are not observables and are not stored.)
- Timestamps are **ISO-8601 UTC text** in SQLite.
- JSON columns are TEXT with `json_valid()` CHECK constraints.

---

## Do not

- **Do not commit databases or `threatlens.conf`.** `*.db` and the `-shm` /
  `-wal` companions are gitignored, as is `threatlens.conf`. The migrations are
  the recipe; everyone builds their own.
- **Do not edit the database directly in DB Browser.** Schema changes go
  through Alembic so the migration history stays authoritative.
- **Do not remove the foreign-key pragma listener** or `render_as_batch=True`.
- **Do not start an evaluation run without checking `threatlens.conf`
  `[quality.weights]`.** Test weights left there are applied to the whole run.
- **Do not `git push --force`** on the shared repo.
- **Do not build the STIX graph, enrichment integrations, or actor/campaign
  modelling.** Out of scope; note as future work.

---

## Open questions

Settled since earlier drafts of this file: the LLM verdict wins after
structural checks; default weights are 0.25 / 0.30 / 0.25 / 0.20 with relevance
weighted; `filepath` is an observable, behaviour types become attack-pattern
context, and `service` is rejected.

Still open — flag them rather than assuming:

1. **Relevance role** — relevance needs a reader role (tactical / strategic).
   Nothing chooses one yet, so every indicator scores 3. Store the audience
   profile and score per reader, or drop the weight?
2. **Allowlist source** — screen against the database's `allowlist` table
   (editable) instead of the `seed.py` list?
3. **Report-level scoring** — sources now carry `reliability`, and the
   dashboard shows a per-report mean quality score, but there is no stored
   report-level quality score.
4. **Export** — the STIX/MISP export function is not built.

`first_seen` / `last_seen` are the earliest / latest **report publish
dates** among an indicator's sightings (`db.ingest.refresh_seen_dates()`),
never the ingest time. Databases built before 13 Oct 2026 need
`python .dev_tools/backfill_seen_dates.py db/<file>.db`; ex2–ex4 and
`threatlens.db` are done.
