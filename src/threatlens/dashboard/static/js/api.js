// ThreatLens dashboard - thin fetch wrapper shared by every panel.

const Api = {
  async get(path) {
    const res = await fetch(path);
    if (!res.ok) throw await Api._error(res);
    return res.json();
  },

  async post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await Api._error(res);
    return res.json();
  },

  async put(path, body) {
    const res = await fetch(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await Api._error(res);
    return res.json();
  },

  async patch(path, body) {
    const res = await fetch(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw await Api._error(res);
    return res.json();
  },

  async delete(path) {
    const res = await fetch(path, { method: "DELETE" });
    if (!res.ok) throw await Api._error(res);
    return res.json();
  },

  async _error(res) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = data.detail || detail;
    } catch (_) {
      // response wasn't JSON - keep statusText
    }
    return new Error(`${res.status}: ${detail}`);
  },
};

// Same bands as quality_checker.ScoringPolicy.default() (85/75/65/50).
function gradeForScore(score) {
  if (score === null || score === undefined) return null;
  if (score >= 85) return "Actionable";
  if (score >= 75) return "Reliable";
  if (score >= 65) return "Usable";
  if (score >= 50) return "Marginal";
  return "Unreliable";
}

function gradeClass(grade) {
  return grade ? `grade-${grade.toLowerCase()}` : "";
}

// A solid-colour badge chip in the grade's colour.
// `grade` is optional - falls back to gradeForScore(score) when not given (e.g. a
// stored score_components.grade takes precedence over recomputing it from score).
function gradeBadgeHtml(score, grade) {
  if (score === null || score === undefined) return "-";
  const resolvedGrade = grade || gradeForScore(score);
  if (!resolvedGrade) return String(score);
  return `<span class="grade-badge ${gradeClass(resolvedGrade)}">${score} &middot; ${escapeHtml(resolvedGrade)}</span>`;
}

// Which verifier judged an indicator or report: sources.extraction_engine
// ('llm', 'python', 'llm+python') or null for reports ingested before it was
// recorded. `model` (the verifier's model name) goes in the tooltip.
const ENGINE_LABELS = { llm: "LLM", python: "Python", "llm+python": "LLM + Python" };

function engineBadgeHtml(engine, model) {
  const label = ENGINE_LABELS[engine] || "Unknown";
  const cls = engine ? engine.replace("+", "-") : "unknown";
  const title = engine
    ? `Verified by ${label}${model ? ` (${model})` : ""}`
    : "Extraction engine not recorded for this report";
  return `<span class="engine-badge engine-${cls}" title="${escapeHtml(title)}">${label}</span>`;
}

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let size = Number(bytes);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

// Click-to-sort column headers, shared by every table on the main page.
// Each <th data-sort="key"> becomes a button; clicking it sorts by that key,
// clicking again reverses it. data-sort-first="desc" makes the first click
// sort descending (for scores and counts, where highest-first is the useful
// view). `state` is {key, dir}, owned by the panel; onChange re-renders.
const TableSort = {
  attach(table, state, onChange) {
    table.querySelectorAll("th[data-sort]").forEach((th) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "sort-btn";
      button.textContent = th.textContent.trim();
      th.textContent = "";
      th.appendChild(button);
      button.addEventListener("click", () => {
        if (state.key === th.dataset.sort) {
          state.dir = state.dir === "asc" ? "desc" : "asc";
        } else {
          state.key = th.dataset.sort;
          state.dir = th.dataset.sortFirst || "asc";
        }
        this.mark(table, state);
        onChange();
      });
    });
    this.mark(table, state);
  },

  mark(table, state) {
    table.querySelectorAll("th[data-sort]").forEach((th) => {
      const active = th.dataset.sort === state.key;
      th.setAttribute("aria-sort", active ? (state.dir === "asc" ? "ascending" : "descending") : "none");
    });
  },

  // Client-side sort for tables that load every row at once. Empty values
  // go last in both directions; ties fall back to id so the order is stable.
  sorted(items, state, valueOf = (item, key) => item[key]) {
    const factor = state.dir === "desc" ? -1 : 1;
    return [...items].sort((x, y) => {
      const a = valueOf(x, state.key);
      const b = valueOf(y, state.key);
      const aEmpty = a === null || a === undefined || a === "";
      const bEmpty = b === null || b === undefined || b === "";
      if (aEmpty || bEmpty) return aEmpty === bEmpty ? x.id - y.id : aEmpty ? 1 : -1;
      const order =
        typeof a === "number" && typeof b === "number"
          ? a - b
          : String(a).trim().localeCompare(String(b).trim(), undefined, { numeric: true, sensitivity: "base" });
      return order * factor || x.id - y.id;
    });
  },
};
