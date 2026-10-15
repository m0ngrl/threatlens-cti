// ThreatLens dashboard - Ingest page: queue un-ingested report files and
// watch each one's progress and log. Backed by /api/ingest; the queue itself
// runs server-side (ingest_jobs.py), so this page can be closed and reopened
// without affecting a run.

const Ingest = {
  pending: [],
  jobs: [],
  downloads: [],
  openLogs: new Map(), // job id -> {offset, el}, for jobs whose log panel is open
  pollTimer: null,
  lastActive: false,

  init() {
    document.getElementById("pending-refresh").addEventListener("click", () => this.loadPending());
    document.getElementById("pending-queue-selected").addEventListener("click", () =>
      this.enqueue(this.selectedPending())
    );
    document.getElementById("pending-queue-all").addEventListener("click", () =>
      this.enqueue(this.pending.filter((f) => !f.queued).map((f) => f.name))
    );
    document.getElementById("pending-select-all").addEventListener("change", (e) => {
      document.querySelectorAll(".pending-check:not(:disabled)").forEach((cb) => (cb.checked = e.target.checked));
      this.updatePendingButtons();
    });
    document.getElementById("pending-body").addEventListener("change", () => this.updatePendingButtons());
    document.getElementById("queue-clear").addEventListener("click", () => this.clearFinished());
    document.getElementById("queue-cancel-all").addEventListener("click", () => this.cancelAll());
    document.getElementById("queue-list").addEventListener("click", (e) => this.onQueueClick(e));
    document.getElementById("url-form").addEventListener("submit", (e) => {
      e.preventDefault();
      this.downloadUrl();
    });
    document.getElementById("url-list").addEventListener("click", (e) => this.onDownloadClick(e));
    document.getElementById("url-clear").addEventListener("click", () => this.clearDownloads());

    this.loadEngines();
    this.loadPending();
    this.poll();
  },

  // -- engine ---------------------------------------------------------------

  async loadEngines() {
    const chip = document.getElementById("llm-status");
    try {
      const { llm } = await Api.get("/api/ingest/engines");
      const models =
        llm.profiler_model && llm.profiler_model !== llm.model
          ? `Models: ${llm.model} (verifier), ${llm.profiler_model} (profiler)`
          : `Model: ${llm.model}`;
      document.getElementById("llm-model").textContent = llm.model ? `${models} at ${llm.url}.` : "";
      const setup = llm.setup_warnings || [];
      chip.textContent = llm.available ? (setup.length ? "ready, setup incomplete" : "ready") : "unavailable";
      chip.className = `status-chip ${!llm.available ? "error" : setup.length ? "warning" : "info"}`;
      chip.title = [llm.detail, ...setup].filter(Boolean).join("\n");
      if (!llm.available) {
        document.getElementById("llm-model").textContent += ` ${llm.detail}`;
      }
      if (setup.length) {
        document.getElementById("llm-model").textContent += ` ${setup.join(" ")}`;
      }
    } catch (err) {
      chip.textContent = "unknown";
      chip.className = "status-chip warning";
      chip.title = err.message;
    }
  },

  selectedEngine() {
    return document.querySelector('input[name="engine"]:checked').value;
  },

  // -- pending files --------------------------------------------------------

  async loadPending() {
    const body = document.getElementById("pending-body");
    try {
      const data = await Api.get("/api/ingest/pending");
      this.pending = data.pending;
      document.getElementById("ingest-db").textContent = data.database;
      document.getElementById("pending-count").textContent =
        `${data.pending.length} of ${data.total_files} file(s) - ${data.ingested} already in ${data.database}`;
    } catch (err) {
      body.innerHTML = `<tr><td colspan="4" class="empty-row">Failed to scan: ${escapeHtml(err.message)}</td></tr>`;
      return;
    }

    if (!this.pending.length) {
      body.innerHTML = `<tr><td colspan="4" class="empty-row">Every report file is already in the database.</td></tr>`;
    } else {
      body.innerHTML = this.pending
        .map((f) => {
          const name = escapeHtml(f.name);
          return `
            <tr>
              <td class="check-col"><input class="pending-check" type="checkbox" data-name="${name}" ${f.queued ? "disabled" : ""} /></td>
              <td class="wrap">${name}</td>
              <td class="nowrap">${formatBytes(f.size_bytes)}</td>
              <td class="nowrap">${f.queued ? '<span class="status-chip info">in queue</span>' : ""}</td>
            </tr>`;
        })
        .join("");
    }
    document.getElementById("pending-select-all").checked = false;
    this.updatePendingButtons();
  },

  selectedPending() {
    return Array.from(document.querySelectorAll(".pending-check:checked"), (cb) => cb.dataset.name);
  },

  updatePendingButtons() {
    const selected = this.selectedPending().length;
    const btn = document.getElementById("pending-queue-selected");
    btn.disabled = selected === 0;
    btn.textContent = selected ? `Add selected to queue (${selected})` : "Add selected to queue";
    document.getElementById("pending-queue-all").disabled = !this.pending.some((f) => !f.queued);
  },

  async enqueue(files) {
    if (!files.length) return;
    const engine = this.selectedEngine();
    const chip = document.getElementById("llm-status");
    if (engine === "llm" && chip.textContent === "unavailable" &&
        !confirm(`The LLM engine looks unavailable (${chip.title}). Queue anyway?`)) {
      return;
    }
    try {
      await Api.post("/api/ingest/queue", {
        files,
        engine,
        verbose: Number(document.getElementById("ingest-verbose").value),
      });
    } catch (err) {
      alert(`Could not queue: ${err.message}`);
      return;
    }
    await Promise.all([this.loadPending(), this.poll()]);
  },

  // -- download from URL ----------------------------------------------------

  async downloadUrl() {
    const input = document.getElementById("url-input");
    const url = input.value.trim();
    if (!url) return;
    const engine = this.selectedEngine();
    const chip = document.getElementById("llm-status");
    if (engine === "llm" && chip.textContent === "unavailable" &&
        !confirm(`The LLM engine looks unavailable (${chip.title}). Download and queue anyway?`)) {
      return;
    }
    const btn = document.getElementById("url-submit");
    btn.disabled = true;
    try {
      await Api.post("/api/ingest/url", {
        url,
        engine,
        verbose: Number(document.getElementById("ingest-verbose").value),
      });
      input.value = "";
    } catch (err) {
      alert(`Could not download: ${err.message}`);
      return;
    } finally {
      btn.disabled = false;
    }
    await this.poll();
  },

  async loadDownloads() {
    const data = await Api.get("/api/ingest/downloads");
    const wasActive = this.downloads.some((d) => d.status === "connecting" || d.status === "downloading");
    this.downloads = data.downloads;
    this.renderDownloads();
    // A finished download adds a file to the folder and a job to the queue.
    if (wasActive && !this.downloads.some((d) => d.status === "connecting" || d.status === "downloading")) {
      this.loadPending();
    }
  },

  renderDownloads() {
    const list = document.getElementById("url-list");
    const ids = new Set(this.downloads.map((d) => d.id));
    list.querySelectorAll(".queue-item").forEach((el) => {
      if (!ids.has(Number(el.dataset.id))) el.remove();
    });
    // Newest on top: new items are prepended in the order they were started.
    for (const d of this.downloads) {
      let item = list.querySelector(`.queue-item[data-id="${d.id}"]`);
      if (!item) {
        item = document.createElement("div");
        item.className = "queue-item";
        item.dataset.id = d.id;
        list.prepend(item);
      }
      item.innerHTML = this.downloadRowHtml(d);
    }
  },

  downloadRowHtml(d) {
    const active = d.status === "connecting" || d.status === "downloading";
    const statusClass = { queued: "info", failed: "error", cancelled: "warning" }[d.status] || "";
    const sizes = d.bytes_total
      ? `${formatBytes(d.bytes_done)} of ${formatBytes(d.bytes_total)}`
      : d.bytes_done ? formatBytes(d.bytes_done) : "";
    const elapsed = formatDuration((d.finished_at || Date.now() / 1000) - d.started_at);
    const width = d.percent ?? 0;
    const indeterminate = active && d.percent === null;
    const fillClass = d.status === "downloading" || d.status === "connecting" ? "running" : d.status;
    const job = d.job_id ? ` &middot; ingest job #${d.job_id} in the queue below` : "";
    return `
      <div class="queue-head">
        <span class="queue-name">${escapeHtml(d.filename || d.url)}</span>
        <span class="status-chip ${statusClass}">${d.status}</span>
        <span class="queue-elapsed">${elapsed}</span>
        <span class="queue-buttons">
          ${active ? `<button class="danger" type="button" data-action="cancel" data-id="${d.id}">Cancel</button>` : ""}
        </span>
      </div>
      <div class="progress-track"><div class="progress-fill status-${fillClass}${indeterminate ? " indeterminate" : ""}" style="width:${width}%"></div></div>
      <div class="queue-message">${d.percent !== null ? `${Math.round(d.percent)}% &middot; ` : ""}${sizes ? `${sizes} &middot; ` : ""}${escapeHtml(d.message)}${job}</div>
      ${d.filename ? `<div class="queue-message">${escapeHtml(d.url)}</div>` : ""}`;
  },

  async onDownloadClick(e) {
    const btn = e.target.closest("button[data-action=cancel]");
    if (!btn) return;
    await Api.post(`/api/ingest/downloads/${btn.dataset.id}/cancel`, {});
    await this.poll();
  },

  async clearDownloads() {
    await Api.post("/api/ingest/downloads/clear", {});
    await this.poll();
  },

  // -- queue ----------------------------------------------------------------

  async poll() {
    clearTimeout(this.pollTimer);
    try {
      await this.loadDownloads();
    } catch (_) {
      // shown via the queue status below if the server is down
    }
    try {
      const data = await Api.get("/api/ingest/jobs");
      this.jobs = data.jobs;
      this.renderQueue();
      await this.refreshLogs();
    } catch (err) {
      document.getElementById("queue-summary").textContent = `(status unavailable: ${err.message})`;
    }

    const active =
      this.jobs.some((j) => j.status === "queued" || j.status === "running") ||
      this.downloads.some((d) => d.status === "connecting" || d.status === "downloading");
    if (this.lastActive && !active) this.loadPending(); // queue drained - rescan
    this.lastActive = active;
    this.pollTimer = setTimeout(() => this.poll(), active ? 1000 : 4000);
  },

  renderQueue() {
    const list = document.getElementById("queue-list");
    const counts = { queued: 0, running: 0, done: 0, failed: 0, cancelled: 0 };
    this.jobs.forEach((j) => counts[j.status]++);

    const parts = Object.entries(counts).filter(([, n]) => n).map(([status, n]) => `${n} ${status}`);
    document.getElementById("queue-summary").textContent = parts.length ? parts.join(", ") : "";
    const total = this.jobs.length;
    const progress = total ? this.jobs.reduce((sum, j) => sum + (j.status === "running" || j.status === "queued" ? j.percent : 100), 0) / total : 0;
    document.getElementById("queue-overall-bar").style.width = `${progress}%`;

    if (!total) {
      this.openLogs.clear();
      list.innerHTML = `<p class="detail-empty">Nothing queued. Pick reports above and add them to the queue.</p>`;
      return;
    }

    // Follow mode: keep the running job's log open, and fold away the one
    // it opened for the previous job once that finishes.
    const running = this.jobs.find((j) => j.status === "running");
    if (document.getElementById("queue-follow").checked) {
      for (const [id, open] of this.openLogs) {
        if (open.follow && id !== running?.id) {
          if (open.el) open.el.textContent = "";
          this.openLogs.delete(id);
        }
      }
      if (running && !this.openLogs.has(running.id)) {
        this.openLogs.set(running.id, { offset: 0, el: null, follow: true });
      }
    }

    const ids = new Set(this.jobs.map((j) => j.id));
    for (const id of this.openLogs.keys()) if (!ids.has(id)) this.openLogs.delete(id);
    list.querySelectorAll(".queue-item").forEach((el) => {
      if (!ids.has(Number(el.dataset.id))) el.remove();
    });

    for (const job of this.jobs) {
      let item = list.querySelector(`.queue-item[data-id="${job.id}"]`);
      if (!item) {
        list.querySelector(".detail-empty")?.remove();
        item = document.createElement("div");
        item.className = "queue-item";
        item.dataset.id = job.id;
        item.innerHTML = `<div class="queue-row"></div><pre class="queue-log" hidden></pre>`;
        list.appendChild(item);
      }
      item.querySelector(".queue-row").innerHTML = this.jobRowHtml(job);
      const log = item.querySelector(".queue-log");
      const open = this.openLogs.get(job.id);
      log.hidden = !open;
      if (open) open.el = log;
    }
  },

  jobRowHtml(job) {
    const active = job.status === "queued" || job.status === "running";
    const engine = job.engine === "llm" ? "LLM" : "Python";
    const statusClass = { done: "info", failed: "error", cancelled: "warning" }[job.status] || "";
    const elapsed = job.started_at ? formatDuration((job.finished_at || Date.now() / 1000) - job.started_at) : "";
    const report = job.result && job.result.source_id
      ? ` <a class="value-link" href="/reports/${job.result.source_id}">View report ${job.result.source_id}</a>`
      : "";
    const stats = job.result
      ? `<span class="queue-stats">${job.result.accepted} accepted of ${job.result.candidates} candidates,
           +${job.result.indicators_created} new indicators, +${job.result.sightings_created} sightings</span>`
      : "";
    const percent = job.status === "done" ? 100 : job.percent;

    return `
      <div class="queue-head">
        <span class="queue-name">${escapeHtml(job.filename)}</span>
        <span class="status-chip">${engine} &middot; -v${job.verbose}</span>
        <span class="status-chip ${statusClass}">${job.status}</span>
        <span class="queue-elapsed">${elapsed}</span>
        <span class="queue-buttons">
          <button class="secondary" type="button" data-action="log" data-id="${job.id}">${this.openLogs.has(job.id) ? "Hide log" : "Show log"} (${job.log_lines})</button>
          ${active ? `<button class="danger" type="button" data-action="cancel" data-id="${job.id}">Cancel</button>` : ""}
        </span>
      </div>
      <div class="progress-track"><div class="progress-fill status-${job.status}" style="width:${percent}%"></div></div>
      <div class="queue-message">${Math.round(percent)}% &middot; ${escapeHtml(job.message)}${report} ${stats}</div>`;
  },

  async refreshLogs() {
    for (const [id, open] of this.openLogs) {
      if (!open.el) continue;
      const job = this.jobs.find((j) => j.id === id);
      if (open.offset >= (job ? job.log_lines : 0) && open.loaded) continue;
      try {
        const data = await Api.get(`/api/ingest/jobs/${id}/log?offset=${open.offset}`);
        const el = open.el;
        const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 30;
        if (data.lines.length) el.append(document.createTextNode(data.lines.join("\n") + "\n"));
        open.offset = data.offset;
        open.loaded = true;
        if (atBottom) el.scrollTop = el.scrollHeight;
      } catch (_) {
        // job cleared between polls - dropped on the next render
      }
    }
  },

  async onQueueClick(e) {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    if (btn.dataset.action === "log") {
      if (this.openLogs.has(id)) {
        const item = document.querySelector(`.queue-item[data-id="${id}"] .queue-log`);
        item.textContent = "";
        this.openLogs.delete(id);
        if (this.jobs.find((j) => j.id === id)?.status === "running") {
          document.getElementById("queue-follow").checked = false;
        }
      } else {
        this.openLogs.set(id, { offset: 0, el: null });
      }
      this.renderQueue();
      await this.refreshLogs();
    } else if (btn.dataset.action === "cancel") {
      const job = this.jobs.find((j) => j.id === id);
      if (job && job.status === "running" && !confirm(`Stop ingesting ${job.filename}? Nothing from it will be saved.`)) return;
      await Api.post(`/api/ingest/jobs/${id}/cancel`, {});
      await Promise.all([this.poll(), this.loadPending()]);
    }
  },

  async clearFinished() {
    await Api.post("/api/ingest/clear", {});
    await this.poll();
  },

  async cancelAll() {
    if (!this.jobs.some((j) => j.status === "queued" || j.status === "running")) return;
    if (!confirm("Cancel every queued and running ingest?")) return;
    await Api.post("/api/ingest/cancel-all", {});
    await Promise.all([this.poll(), this.loadPending()]);
  },
};

function formatDuration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

document.addEventListener("DOMContentLoaded", () => Ingest.init());
