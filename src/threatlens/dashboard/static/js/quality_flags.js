// ThreatLens dashboard - Quality Flags panel: list, sort + status change.

// Severity sorts by rank rather than alphabetically; unknown values sort
// after the known ones.
const SEVERITY_RANK = { info: 0, warning: 1, error: 2, critical: 3 };

const QualityFlags = {
  items: [],
  sort: { key: "id", dir: "desc" },

  async load() {
    const status = document.getElementById("flag-status-filter").value;
    const params = new URLSearchParams();
    if (status) params.set("status", status);

    const data = await Api.get(`/api/quality-flags?${params}`);
    this.items = data.items;
    this.render();
  },

  sortValue(flag, key) {
    if (key === "severity") return SEVERITY_RANK[flag.severity] ?? Object.keys(SEVERITY_RANK).length;
    if (key === "indicator_value") return flag.indicator_value ?? String(flag.indicator_id);
    return flag[key];
  },

  render() {
    const body = document.getElementById("flags-body");
    body.innerHTML = "";

    for (const flag of TableSort.sorted(this.items, this.sort, (f, k) => this.sortValue(f, k))) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${flag.id}</td>
        <td><a class="value-link" href="/indicators/${flag.indicator_id}">${escapeHtml(flag.indicator_value ?? flag.indicator_id)}</a></td>
        <td>${escapeHtml(flag.flag_type)}</td>
        <td>${escapeHtml(flag.dimension ?? "-")}</td>
        <td>${escapeHtml(flag.severity)}</td>
        <td>${escapeHtml(flag.detail ?? "-")}</td>
        <td>${escapeHtml(flag.status)}</td>
        <td>
          ${flag.status !== "resolved" ? '<button data-action="resolved">Resolve</button>' : ""}
          ${flag.status !== "dismissed" ? '<button class="secondary" data-action="dismissed">Dismiss</button>' : ""}
        </td>
      `;
      tr.querySelectorAll("button[data-action]").forEach((btn) =>
        btn.addEventListener("click", () => this.setStatus(flag.id, btn.dataset.action))
      );
      body.appendChild(tr);
    }
  },

  async setStatus(id, status) {
    await Api.patch(`/api/quality-flags/${id}`, { status });
    this.load();
  },
};

document.getElementById("flag-status-filter").addEventListener("change", () => QualityFlags.load());
document.getElementById("flag-refresh").addEventListener("click", () => QualityFlags.load());
TableSort.attach(document.getElementById("flags-table"), QualityFlags.sort, () => QualityFlags.render());
