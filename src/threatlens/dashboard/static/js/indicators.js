// ThreatLens dashboard - Indicators panel: list, filter, sort, edit, delete.
// Each value links to its detail page, /indicators/{id}.

const Indicators = {
  limit: 50,
  offset: 0,
  editingId: null,
  // Sorted by the API rather than in the browser: the table is paged, so a
  // sort has to span every page, not just the 50 rows on screen.
  sort: { key: "id", dir: "asc" },

  async load() {
    const search = document.getElementById("indicator-search").value.trim();
    const iocType = document.getElementById("indicator-type-filter").value;
    const minScore = document.getElementById("indicator-min-score").value;
    const engine = document.getElementById("indicator-engine-filter").value;

    const params = new URLSearchParams({
      limit: this.limit,
      offset: this.offset,
      sort: this.sort.key,
      order: this.sort.dir,
    });
    if (search) params.set("search", search);
    if (iocType) params.set("ioc_type", iocType);
    if (minScore) params.set("min_score", minScore);
    if (engine) params.set("engine", engine);

    const data = await Api.get(`/api/indicators?${params}`);
    this._renderRows(data.items);
    this._renderPager(data.total);
    this._populateTypeFilter(data.items, iocType);
  },

  _populateTypeFilter(items, selected) {
    const select = document.getElementById("indicator-type-filter");
    if (select.dataset.populated) return;

    const types = [...new Set(items.map((item) => item.ioc_type))].sort();
    for (const type of types) {
      const opt = document.createElement("option");
      opt.value = type;
      opt.textContent = type;
      if (type === selected) opt.selected = true;
      select.appendChild(opt);
    }
    select.dataset.populated = "1";
  },

  _renderRows(items) {
    const body = document.getElementById("indicators-body");
    body.innerHTML = "";

    for (const item of items) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${item.id}</td>
        <td>${escapeHtml(item.ioc_type)}</td>
        <td><a class="value-link" href="/indicators/${item.id}">${escapeHtml(item.value)}</a></td>
        <td>${item.confidence ?? "-"}</td>
        <td>${gradeBadgeHtml(item.quality_score)}</td>
        <td>${item.sighting_count}</td>
        <td>${engineBadgeHtml(item.extraction_engine)}</td>
        <td>${escapeHtml(item.last_seen ?? "-")}</td>
        <td>
          <button class="secondary" data-action="edit" data-id="${item.id}">Edit</button>
          <button class="danger" data-action="delete" data-id="${item.id}">Delete</button>
        </td>
      `;
      body.appendChild(tr);
    }

    body.querySelectorAll('[data-action="edit"]').forEach((btn) =>
      btn.addEventListener("click", () => this.openEdit(Number(btn.dataset.id)))
    );
    body.querySelectorAll('[data-action="delete"]').forEach((btn) =>
      btn.addEventListener("click", () => this.remove(Number(btn.dataset.id)))
    );
  },

  _renderPager(total) {
    const pager = document.getElementById("indicators-pager");
    const start = total === 0 ? 0 : this.offset + 1;
    const end = Math.min(this.offset + this.limit, total);
    pager.innerHTML = "";

    const label = document.createElement("span");
    label.textContent = `${start}-${end} of ${total}`;
    pager.appendChild(label);

    const prev = document.createElement("button");
    prev.textContent = "Prev";
    prev.className = "secondary";
    prev.disabled = this.offset === 0;
    prev.addEventListener("click", () => {
      this.offset = Math.max(0, this.offset - this.limit);
      this.load();
    });
    pager.appendChild(prev);

    const next = document.createElement("button");
    next.textContent = "Next";
    next.className = "secondary";
    next.disabled = end >= total;
    next.addEventListener("click", () => {
      this.offset += this.limit;
      this.load();
    });
    pager.appendChild(next);
  },

  async openEdit(id) {
    const indicator = await Api.get(`/api/indicators/${id}`);
    this.editingId = id;

    const fields = [
      ["ioc_type", "Type", indicator.ioc_type],
      ["value", "Value", indicator.value],
      ["normalised", "Normalised", indicator.normalised],
      ["confidence", "Confidence (0-100)", indicator.confidence],
      ["quality_score", "Quality score (0-100)", indicator.quality_score],
      ["first_seen", "First seen", indicator.first_seen],
      ["last_seen", "Last seen", indicator.last_seen],
      ["context", "Context (JSON)", indicator.context],
    ];

    const form = document.getElementById("edit-form");
    form.innerHTML = fields
      .map(([name, label, value]) => {
        const tag = name === "context" ? "textarea" : "input";
        const extra = tag === "textarea" ? "rows=4" : 'type="text"';
        return `<label>${label}</label><${tag} name="${name}" ${extra}>${escapeHtml(
          value ?? ""
        )}</${tag}>`;
      })
      .join("");

    // Plain <input> can't carry a value via innerHTML text content, so set it directly.
    for (const [name, , value] of fields) {
      if (name === "context") continue;
      form.querySelector(`[name="${name}"]`).value = value ?? "";
    }

    document.getElementById("edit-modal").classList.remove("hidden");
  },

  async saveEdit() {
    const form = document.getElementById("edit-form");
    const payload = {};

    for (const el of form.elements) {
      if (!el.name) continue;
      const raw = el.value.trim();
      if (raw === "") continue;
      if (el.name === "confidence" || el.name === "quality_score") {
        payload[el.name] = Number(raw);
      } else {
        payload[el.name] = raw;
      }
    }

    try {
      await Api.patch(`/api/indicators/${this.editingId}`, payload);
      document.getElementById("edit-modal").classList.add("hidden");
      this.load();
    } catch (err) {
      alert(err.message);
    }
  },

  async remove(id) {
    if (!confirm(`Delete indicator ${id}? This also removes its sightings.`)) return;
    await Api.delete(`/api/indicators/${id}`);
    this.load();
  },
};

document.getElementById("indicator-refresh").addEventListener("click", () => {
  Indicators.offset = 0;
  Indicators.load();
});
document.getElementById("edit-cancel").addEventListener("click", () => {
  document.getElementById("edit-modal").classList.add("hidden");
});
document.getElementById("edit-save").addEventListener("click", () => Indicators.saveEdit());
TableSort.attach(document.getElementById("indicators-table"), Indicators.sort, () => {
  Indicators.offset = 0;
  Indicators.load();
});
