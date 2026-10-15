"""ThreatLens dashboard - the ingest queue behind the Ingest page.

Reports queued from the dashboard are ingested one at a time, each in its
own ingest_worker.py process. One at a time on purpose: every job writes
the same SQLite file, and the LLM engine already keeps a local Ollama busy
on its own.

Each job keeps its worker's full output, so the page can show the
extractor's verbose log live, plus a progress estimate. The estimate comes
from the worker's @@progress lines and, while the LLM engine is verifying,
from its "[LLM] batch n/m" lines, which is where nearly all the time goes.

The queue lives in memory: restarting the dashboard drops queued jobs and
kills the running worker with it. The database stays consistent, since a
worker only commits a report once it has been fully processed.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatlens.dashboard.ingest_worker import PROGRESS_PREFIX, RESULT_PREFIX

ENGINES = ("llm", "python")
MAX_LOG_LINES = 20_000

# Share of the progress bar the LLM verification batches fill: the worker
# reports up to EXTRACT_DONE before them and from QA_START after.
EXTRACT_DONE = 15.0
QA_START = 88.0
_LLM_BATCH = re.compile(r"^\[LLM\] batch (\d+)/(\d+)")
_PY_CANDIDATE = re.compile(r"^\[PY\] (\d+)/(\d+) ")
_FOUND = re.compile(r"^\[INFO\] found (\d+) candidates")
_PROFILE_DONE = re.compile(r"^\[INFO\] scope=")


@dataclass
class Job:
    id: int
    filename: str
    path: Path
    db_path: Path
    engine: str
    verbose: int
    status: str = "queued"  # queued, running, done, failed, cancelled
    stage: str = "queued"
    percent: float = 0.0
    message: str = "Waiting in queue"
    queued_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    log: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))
    log_dropped: int = 0  # lines pushed out of the front of `log`
    process: subprocess.Popen[str] | None = field(default=None, repr=False)
    cancel_requested: bool = False

    @property
    def active(self) -> bool:
        return self.status in ("queued", "running")

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "database": self.db_path.name,
            "engine": self.engine,
            "verbose": self.verbose,
            "status": self.status,
            "stage": self.stage,
            "percent": round(self.percent, 1),
            "message": self.message,
            "queued_at": self.queued_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "log_lines": self.log_dropped + len(self.log),
        }


class IngestQueue:
    def __init__(self) -> None:
        self._jobs: dict[int, Job] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._wake = threading.Condition(self._lock)
        self._worker: threading.Thread | None = None

    # -- queue management -------------------------------------------------

    def enqueue(self, paths: list[Path], db_path: Path, engine: str, verbose: int) -> list[Job]:
        if engine not in ENGINES:
            raise ValueError(f"unknown engine: {engine}")
        added = []
        with self._lock:
            busy = {(job.path, job.db_path) for job in self._jobs.values() if job.active}
            for path in paths:
                if (path, db_path) in busy:
                    continue
                job = Job(next(self._ids), path.name, path, db_path, engine, verbose)
                self._jobs[job.id] = job
                added.append(job)
            self._ensure_worker()
            self._wake.notify()
        return added

    def jobs(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    def get(self, job_id: int) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def active_paths(self, db_path: Path) -> set[Path]:
        with self._lock:
            return {job.path for job in self._jobs.values() if job.active and job.db_path == db_path}

    def cancel(self, job_id: int) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or not job.active:
                return job
            job.cancel_requested = True
            if job.status == "queued":
                self._finish(job, "cancelled", "Cancelled before it started")
            elif job.process is not None:
                job.process.terminate()
            return job

    def cancel_all(self) -> int:
        with self._lock:
            ids = [job.id for job in self._jobs.values() if job.active]
        for job_id in ids:
            self.cancel(job_id)
        return len(ids)

    def clear_finished(self) -> int:
        with self._lock:
            finished = [job_id for job_id, job in self._jobs.items() if not job.active]
            for job_id in finished:
                del self._jobs[job_id]
            return len(finished)

    def log_since(self, job: Job, offset: int) -> tuple[list[str], int]:
        """Log lines from `offset` (a total line index) on, and the new offset."""
        with self._lock:
            start = max(offset - job.log_dropped, 0)
            lines = list(itertools.islice(job.log, start, None))
            return lines, job.log_dropped + len(job.log)

    # -- worker thread ----------------------------------------------------

    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._run_forever, name="ingest-queue", daemon=True)
            self._worker.start()

    def _next_job(self) -> Job:
        with self._lock:
            while True:
                for job in self._jobs.values():  # dicts keep insertion (queue) order
                    if job.status == "queued":
                        job.status = "running"
                        job.started_at = time.time()
                        job.stage, job.message = "starting", "Starting worker"
                        return job
                self._wake.wait()

    def _run_forever(self) -> None:
        while True:
            job = self._next_job()
            try:
                self._run(job)
            except Exception as exc:  # noqa: BLE001 - keep the queue alive
                with self._lock:
                    job.log.append(f"dashboard error: {exc}")
                    self._finish(job, "failed", f"Could not run the worker: {exc}", error=str(exc))

    @staticmethod
    def _workdir() -> Path:
        """The worker's working folder: the data folder, created if needed."""
        from threatlens.paths import data_dir

        folder = data_dir()
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def _run(self, job: Job) -> None:
        command = [
            sys.executable, "-u", "-m", "threatlens.dashboard.ingest_worker",
            str(job.path), "--db", str(job.db_path), "--engine", job.engine,
        ]
        if job.verbose:
            command.append("-" + "v" * job.verbose)

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=self._workdir(),
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        with self._lock:
            job.process = process
            job.log.append("$ " + " ".join(command[1:]))
            if job.cancel_requested:  # cancelled while the process was starting
                process.terminate()

        assert process.stdout is not None
        for raw in process.stdout:
            self._handle_line(job, raw.rstrip("\n"))
        returncode = process.wait()

        with self._lock:
            job.process = None
            if job.cancel_requested:
                self._finish(job, "cancelled", "Cancelled while running - nothing was committed")
            elif returncode == 0 and job.result is not None:
                self._finish(job, "done", job.message)
            else:
                errors = [line for line in job.log if line.startswith("error:")]
                error = errors[-1].removeprefix("error:").strip() if errors else f"worker exited with code {returncode}"
                self._finish(job, "failed", f"Failed: {error}", error=error)

    def _handle_line(self, job: Job, line: str) -> None:
        with self._lock:
            if line.startswith(PROGRESS_PREFIX):
                data = json.loads(line.removeprefix(PROGRESS_PREFIX))
                job.stage = data["stage"]
                job.percent = max(job.percent, float(data["percent"]))
                job.message = data["message"]
                return
            if line.startswith(RESULT_PREFIX):
                job.result = json.loads(line.removeprefix(RESULT_PREFIX))
                return

            if len(job.log) == job.log.maxlen:
                job.log_dropped += 1
            job.log.append(line)
            self._estimate_progress(job, line)

    def _estimate_progress(self, job: Job, line: str) -> None:
        """Move the bar along on the extractors' own log lines, between the worker's milestones."""
        if match := _FOUND.match(line):
            job.percent = max(job.percent, 8.0)
            job.message = f"Found {match.group(1)} candidates" + (
                " - profiling document scope with the LLM" if job.engine == "llm" else " - verifying"
            )
        elif _PROFILE_DONE.match(line):
            job.percent = max(job.percent, EXTRACT_DONE)
            job.message = "Document profiled - verifying candidates with the LLM"
        elif match := (_LLM_BATCH.match(line) or _PY_CANDIDATE.match(line)):
            done, total = int(match.group(1)) - 1, int(match.group(2))
            job.stage = "verify"
            job.percent = max(job.percent, EXTRACT_DONE + (QA_START - EXTRACT_DONE) * done / max(total, 1))
            what = "batch" if line.startswith("[LLM]") else "candidate"
            job.message = f"Verifying {what} {done + 1} of {total}"

    def _finish(self, job: Job, status: str, message: str, error: str | None = None) -> None:
        job.status = status
        job.stage = status
        job.message = message
        job.error = error
        job.finished_at = time.time()
        if status == "done":
            job.percent = 100.0


queue = IngestQueue()
