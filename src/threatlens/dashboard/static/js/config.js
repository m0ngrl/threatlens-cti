// ThreatLens dashboard - Configuration page: edit threatlens.conf (Ollama URL,
// models, default database, quality weights). Backed by /api/config.

const AGREEMENT_LABELS = {
  agree: "Agree",
  weak: "Weak disagreement",
  single: "Single verifier",
  moderate: "Moderate disagreement",
  strong: "Strong disagreement",
};

const Config = {
  loaded: null, // last response from the server, for "Discard changes"

  init() {
    document.getElementById("config-form").addEventListener("submit", (e) => {
      e.preventDefault();
      this.save();
    });
    document.getElementById("cfg-reset").addEventListener("click", () => this.render(this.loaded));
    document.getElementById("cfg-ollama-test").addEventListener("click", () => this.testOllama());
    document.getElementById("cfg-weights").addEventListener("input", () => this.updateTotal());
    document.getElementById("cfg-rescore").addEventListener("click", () => this.rescore());
    this.load();
  },

  async load() {
    try {
      this.render(await Api.get("/api/config"));
    } catch (err) {
      this.showError(`Failed to load configuration: ${err.message}`);
    }
  },

  showSetup(warnings) {
    const el = document.getElementById("config-setup");
    el.hidden = !warnings.length;
    el.innerHTML = warnings.length
      ? `<strong>Setup incomplete</strong><ul>${warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul>`
      : "";
  },

  render(data) {
    this.loaded = data;
    const { config } = data;
    document.getElementById("config-path").textContent = data.path;
    document.getElementById("config-missing").hidden = data.exists;
    const loc = data.locations;
    document.getElementById("config-locations").textContent = loc
      ? `Databases are in ${loc.databases} and reports in ${loc.reports} (${loc.layout} layout; set [paths] data_dir in the file or THREATLENS_HOME to move them).`
      : "";
    this.showError(data.error ? `threatlens.conf could not be read (${data.error}). Defaults are shown; saving replaces the file.` : "");
    this.showSetup(data.error ? [] : data.setup.warnings);

    document.getElementById("cfg-ollama-url").value = config.ollama.url;
    document.getElementById("cfg-model-verifier").value = config.models.verifier;
    document.getElementById("cfg-model-profiler").value = config.models.profiler;

    const dbSelect = document.getElementById("cfg-database");
    const files = data.databases.includes(config.database.default)
      ? data.databases
      : [config.database.default, ...data.databases];
    dbSelect.innerHTML = files
      .map((f) => {
        const missing = data.databases.includes(f) ? "" : " (missing)";
        return `<option value="${escapeHtml(f)}">${escapeHtml(f)}${missing}</option>`;
      })
      .join("");
    dbSelect.value = config.database.default;
    document.getElementById("cfg-active-db").textContent = data.active_database;
    document.getElementById("cfg-rescore-db").textContent = data.active_database;

    document.getElementById("cfg-weights").innerHTML = data.dimensions
      .map((d) => this.numberField("weight", d, d, config.quality.weights[d]))
      .join("");
    document.getElementById("cfg-agreement").innerHTML = data.agreement_grades
      .map((g) => this.numberField("agreement", g, AGREEMENT_LABELS[g] || g, config.quality.agreement[g]))
      .join("");
    this.updateTotal();
    this.setStatus("cfg-save-status", "");
  },

  numberField(group, key, label, value) {
    const id = `cfg-${group}-${key}`;
    return `
      <label class="config-field" for="${id}">
        <span class="dim-name">${escapeHtml(label)}</span>
        <input id="${id}" type="number" min="0" max="1" step="0.01"
               data-group="${group}" data-key="${escapeHtml(key)}" value="${Number(value).toFixed(2)}" required />
      </label>`;
  },

  collect(group) {
    const values = {};
    document.querySelectorAll(`input[data-group="${group}"]`).forEach((input) => {
      values[input.dataset.key] = Number(input.value);
    });
    return values;
  },

  updateTotal() {
    const total = Object.values(this.collect("weight")).reduce((a, b) => a + b, 0);
    const el = document.getElementById("cfg-weight-total");
    el.textContent = total.toFixed(2);
    el.className = Math.abs(total - 1) <= 0.001 ? "total-ok" : "total-bad";
  },

  async save() {
    const body = {
      ollama: { url: document.getElementById("cfg-ollama-url").value.trim() },
      models: {
        verifier: document.getElementById("cfg-model-verifier").value.trim(),
        profiler: document.getElementById("cfg-model-profiler").value.trim(),
      },
      database: { default: document.getElementById("cfg-database").value },
      quality: { weights: this.collect("weight"), agreement: this.collect("agreement") },
    };
    const button = document.getElementById("cfg-save");
    button.disabled = true;
    try {
      const data = await Api.put("/api/config", body);
      this.render(data);
      this.setStatus("cfg-save-status", "Saved.", "ok");
    } catch (err) {
      this.setStatus("cfg-save-status", err.message, "error");
    } finally {
      button.disabled = false;
    }
  },

  async testOllama() {
    const chip = document.getElementById("cfg-ollama-status");
    const url = document.getElementById("cfg-ollama-url").value.trim();
    chip.hidden = false;
    chip.className = "status-chip";
    chip.textContent = "checking...";
    chip.title = "";
    try {
      const res = await Api.post("/api/config/ollama-models", { url });
      document.getElementById("ollama-models").innerHTML = res.models
        .map((m) => `<option value="${escapeHtml(m)}"></option>`)
        .join("");
      chip.className = `status-chip ${res.reachable ? "info" : "error"}`;
      chip.textContent = res.reachable ? `reachable - ${res.models.length} model(s)` : "unreachable";
      chip.title = res.detail || res.models.join("\n");
    } catch (err) {
      chip.className = "status-chip error";
      chip.textContent = "error";
      chip.title = err.message;
    }
  },

  async rescore() {
    const db = this.loaded ? this.loaded.active_database : "the active database";
    if (!confirm(`Re-score every indicator in ${db} with the saved weights? Existing scores will be overwritten.`)) {
      return;
    }
    const button = document.getElementById("cfg-rescore");
    button.disabled = true;
    this.setStatus("cfg-rescore-status", "Re-scoring...");
    try {
      const res = await Api.post("/api/config/rescore", {});
      this.setStatus("cfg-rescore-status", `Re-scored ${res.rescored} indicator(s) in ${res.database}.`, "ok");
    } catch (err) {
      this.setStatus("cfg-rescore-status", err.message, "error");
    } finally {
      button.disabled = false;
    }
  },

  setStatus(id, text, kind = "") {
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = `config-hint ${kind ? `status-${kind}` : ""}`;
  },

  showError(text) {
    const el = document.getElementById("config-error");
    el.textContent = text;
    el.hidden = !text;
  },
};

document.addEventListener("DOMContentLoaded", () => Config.init());
