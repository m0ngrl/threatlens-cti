// ThreatLens dashboard - Report Files page: upload, view and remove the CTI
// report PDFs in docs/database/CTI. Backed by /api/report-files; files only,
// so nothing here adds or removes database rows.

const ReportFiles = {
  files: [],

  init() {
    this.input = document.getElementById("upload-input");
    this.drop = document.getElementById("upload-drop");
    this.uploadBtn = document.getElementById("upload-btn");
    this.deleteBtn = document.getElementById("files-delete-selected");
    this.selectAll = document.getElementById("files-select-all");
    this.body = document.getElementById("files-body");

    this.input.addEventListener("change", () => this.updatePicked());
    this.uploadBtn.addEventListener("click", () => this.upload());
    document.getElementById("files-refresh").addEventListener("click", () => this.load());
    document.getElementById("files-search").addEventListener("input", () => this.render());
    this.deleteBtn.addEventListener("click", () => this.removeSelected());
    this.selectAll.addEventListener("change", () => {
      this.body.querySelectorAll(".file-check").forEach((cb) => (cb.checked = this.selectAll.checked));
      this.updateSelection();
    });
    this.body.addEventListener("change", (e) => {
      if (e.target.classList.contains("file-check")) this.updateSelection();
    });
    this.body.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-name]");
      if (btn) this.remove([btn.dataset.name]);
    });

    ["dragenter", "dragover"].forEach((type) =>
      this.drop.addEventListener(type, (e) => {
        e.preventDefault();
        this.drop.classList.add("dragging");
      })
    );
    ["dragleave", "drop"].forEach((type) =>
      this.drop.addEventListener(type, () => this.drop.classList.remove("dragging"))
    );
    this.drop.addEventListener("drop", (e) => {
      e.preventDefault();
      this.input.files = e.dataTransfer.files;
      this.updatePicked();
    });

    this.load();
  },

  async load() {
    try {
      const data = await Api.get("/api/report-files");
      document.getElementById("uploads-dir").textContent = data.directory;
      this.files = data.files;
      this.render();
    } catch (err) {
      this.body.innerHTML = `<tr><td colspan="6">Failed to load report files: ${escapeHtml(err.message)}</td></tr>`;
    }
  },

  render() {
    const filter = document.getElementById("files-search").value.trim().toLowerCase();
    const shown = this.files.filter((f) => f.name.toLowerCase().includes(filter));
    const ingested = this.files.filter((f) => f.source_id !== null).length;
    document.getElementById("files-summary").textContent =
      `${this.files.length} file(s), ${ingested} in the active database`;

    if (!shown.length) {
      this.body.innerHTML = `<tr><td colspan="6" class="empty-row">${
        this.files.length ? "No files match the filter." : "No report files yet."
      }</td></tr>`;
    } else {
      this.body.innerHTML = shown
        .map((f) => {
          const name = escapeHtml(f.name);
          const href = `/api/report-files/${encodeURIComponent(f.name)}`;
          const status =
            f.source_id !== null
              ? `<a class="value-link" href="/reports/${f.source_id}">Report ${f.source_id}</a>`
              : `<span class="status-chip warning">Not ingested</span>`;
          return `
            <tr>
              <td class="check-col"><input class="file-check" type="checkbox" data-name="${name}" /></td>
              <td class="wrap"><a class="report-title-link" href="${href}" target="_blank" rel="noopener">${name}</a></td>
              <td class="nowrap">${formatBytes(f.size_bytes)}</td>
              <td class="nowrap">${escapeHtml(formatDate(f.modified_at))}</td>
              <td class="nowrap">${status}</td>
              <td class="nowrap"><button class="danger" type="button" data-name="${name}">Remove</button></td>
            </tr>`;
        })
        .join("");
    }
    this.selectAll.checked = false;
    this.updateSelection();
  },

  updateSelection() {
    const count = this.body.querySelectorAll(".file-check:checked").length;
    this.deleteBtn.disabled = count === 0;
    this.deleteBtn.textContent = count ? `Remove selected (${count})` : "Remove selected";
  },

  updatePicked() {
    const count = this.input.files.length;
    document.getElementById("upload-drop-text").textContent = count
      ? Array.from(this.input.files, (f) => f.name).join(", ")
      : "Drop PDF files here, or click to choose";
    this.uploadBtn.disabled = count === 0;
  },

  async upload() {
    if (!this.input.files.length) return;
    const form = new FormData();
    for (const file of this.input.files) form.append("files", file);
    form.append("overwrite", document.getElementById("upload-overwrite").checked);

    this.uploadBtn.disabled = true;
    this.uploadBtn.textContent = "Uploading...";
    try {
      const res = await fetch("/api/report-files", { method: "POST", body: form });
      if (!res.ok) throw await Api._error(res);
      const data = await res.json();
      this.showResult(data);
      this.input.value = "";
      this.updatePicked();
      await this.load();
    } catch (err) {
      this.showResult({ error: err.message });
      this.uploadBtn.disabled = false;
    } finally {
      this.uploadBtn.textContent = "Upload";
    }
  },

  showResult(data) {
    const el = document.getElementById("upload-result");
    if (data.error) {
      el.innerHTML = `<div class="callout warning">Upload failed: ${escapeHtml(data.error)}</div>`;
      return;
    }
    let html = "";
    if (data.saved.length) {
      html += `<div class="callout">Uploaded ${data.saved.length} file(s): ${data.saved.map(escapeHtml).join(", ")}</div>`;
    }
    if (data.skipped.length) {
      html += `<div class="callout warning">Skipped ${data.skipped.length} file(s):<ul>${data.skipped
        .map((s) => `<li>${escapeHtml(s.name)} - ${escapeHtml(s.reason)}</li>`)
        .join("")}</ul></div>`;
    }
    el.innerHTML = html;
  },

  removeSelected() {
    const names = Array.from(this.body.querySelectorAll(".file-check:checked"), (cb) => cb.dataset.name);
    if (names.length) this.remove(names);
  },

  async remove(names) {
    const message =
      names.length === 1
        ? `Remove ${names[0]} from the report folder?`
        : `Remove ${names.length} files from the report folder?\n\n${names.join("\n")}`;
    if (!confirm(`${message}\n\nAny report already ingested from it stays in the database.`)) return;

    const failed = [];
    for (const name of names) {
      try {
        await Api.delete(`/api/report-files/${encodeURIComponent(name)}`);
      } catch (err) {
        failed.push(`${name}: ${err.message}`);
      }
    }
    if (failed.length) alert(`Could not remove:\n${failed.join("\n")}`);
    await this.load();
  },
};

function formatDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

document.addEventListener("DOMContentLoaded", () => ReportFiles.init());
