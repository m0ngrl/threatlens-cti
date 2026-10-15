// ThreatLens dashboard - tab switching + stat cards + db selector + bootstrap.

function dbBrowserUrl(filename) {
  // Datasette names a database after its file's stem (see db_browser.py),
  // e.g. threatlens.db -> /db-browser/threatlens (no trailing slash - that's
  // the table-listing page; a trailing slash there 302s to this same URL).
  const name = filename.replace(/\.db$/, "");
  return `/db-browser/${encodeURIComponent(name)}`;
}

async function loadDbSelector() {
  const data = await Api.get("/api/db/files");
  const select = document.getElementById("db-selector");
  select.innerHTML = data.files
    .map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`)
    .join("");
  select.value = data.active;
  document.getElementById("db-browser-link").href = dbBrowserUrl(data.active);

  select.addEventListener("change", async () => {
    try {
      await Api.post("/api/db/select", { filename: select.value });
      window.location.reload();
    } catch (err) {
      alert(err.message);
    }
  });
}

async function loadStats() {
  const stats = await Api.get("/api/stats");
  const cards = document.getElementById("stat-cards");
  const entries = [
    ["Indicators", stats.indicator_count],
    ["Reports", stats.source_count],
    ["Open flags", stats.open_quality_flags],
    ["Avg quality", stats.avg_quality_score ?? "-"],
  ];
  cards.innerHTML = entries
    .map(
      ([label, value]) => `
        <div class="stat-card">
          <div class="value">${value}</div>
          <div class="label">${label}</div>
        </div>`
    )
    .join("");
}

function setupTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");

      if (btn.dataset.tab === "indicators") Indicators.load();
      if (btn.dataset.tab === "sources") Sources.load();
      if (btn.dataset.tab === "quality-flags") QualityFlags.load();
    });
  });
}

window.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  loadDbSelector();
  loadStats();
  Sources.load();
});
