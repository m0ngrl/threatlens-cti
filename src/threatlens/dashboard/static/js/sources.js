// ThreatLens dashboard - Reports panel: list, sort + delete.
// Backed by /api/sources (the "sources" table holds one row per ingested
// report); "title" is the report's extracted heading, "filename" is the
// document ThreatLens actually ingested.

const Sources = {
  items: [],
  sort: { key: "id", dir: "asc" },

  async load() {
    const data = await Api.get("/api/sources");
    this.items = data.items;
    this.render();
  },

  render() {
    const body = document.getElementById("sources-body");
    body.innerHTML = "";

    for (const item of TableSort.sorted(this.items, this.sort)) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${item.id}</td>
        <td><a class="report-title-link" href="/reports/${item.id}">${escapeHtml(item.title)}</a></td>
        <td>${gradeBadgeHtml(item.avg_quality_score)}</td>
        <td>${escapeHtml(item.filename)}</td>
        <td>${escapeHtml(item.source_type)}</td>
        <td>${item.reliability ?? "-"}</td>
        <td>${engineBadgeHtml(item.extraction_engine, item.verification_model)}</td>
        <td>${item.indicator_count}</td>
        <td>${escapeHtml(item.ingested_at ?? "-")}</td>
        <td><button class="danger" data-id="${item.id}">Delete</button></td>
      `;
      body.appendChild(tr);
    }

    body.querySelectorAll("button[data-id]").forEach((btn) =>
      btn.addEventListener("click", () => this.remove(Number(btn.dataset.id)))
    );
  },

  async remove(id) {
    if (
      !confirm(
        `Delete report ${id}? This also removes its raw document and sightings (indicators from other reports are kept).`
      )
    )
      return;
    await Api.delete(`/api/sources/${id}`);
    this.load();
  },
};

TableSort.attach(document.getElementById("sources-table"), Sources.sort, () => Sources.render());
