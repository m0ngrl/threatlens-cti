// ThreatLens dashboard - Indicator detail page: everything the database holds
// about one indicator. Its confidence and quality score are broken down step
// by step, then come the verifier's reasoning (stored as quality flags), its
// threat context, the reports it was sighted in and the indicators it was
// seen alongside. Report titles link to the report page, with this
// indicator's row highlighted.

// Readable names for context keys the extractor writes (see
// conformance.EXPECTED_CONTEXT_KEYS). Any other key is shown under its own name.
const CONTEXT_LABELS = {
  threat_actor: "Threat actors",
  campaign: "Campaigns",
  malware: "Malware",
  malware_family: "Malware families",
  tool: "Tools",
  vulnerability: "Vulnerabilities",
  attack_pattern: "Attack patterns",
};

// Shown elsewhere on the page, so left out of the context section.
const CONTEXT_SHOWN_ELSEWHERE = new Set(["excerpt", "extraction_method", "attributes"]);

const VERDICT_LABELS = {
  confirmed_ioc: "Confirmed IoC",
  rejected: "Rejected",
  uncertain: "Uncertain",
  context_entity: "Context entity",
};

const AGREEMENT_LABELS = {
  agree: "Both verifiers agree",
  weak: "Weak disagreement",
  moderate: "Moderate disagreement",
  strong: "Strong disagreement",
  single_verifier: "Only one verifier ran",
};

function indicatorIdFromPath() {
  const match = window.location.pathname.match(/\/indicators\/(\d+)/);
  return match ? match[1] : null;
}

function fmt(value, fallback = "-") {
  return value === null || value === undefined || value === "" ? fallback : value;
}

function pct(unit) {
  return unit === null || unit === undefined ? "-" : `${Math.round(unit * 100)}%`;
}

function emptyNote(text) {
  return `<p class="detail-empty">${escapeHtml(text)}</p>`;
}

// Escape `text` and wrap the first case-insensitive occurrence of any needle in <mark>.
function highlightHtml(text, needles) {
  if (!text) return "";
  const lower = text.toLowerCase();
  for (const needle of needles) {
    if (!needle) continue;
    const at = lower.indexOf(needle.toLowerCase());
    if (at === -1) continue;
    return (
      escapeHtml(text.slice(0, at)) +
      `<mark>${escapeHtml(text.slice(at, at + needle.length))}</mark>` +
      escapeHtml(text.slice(at + needle.length))
    );
  }
  return escapeHtml(text);
}

function heroHtml(label, value, badge) {
  return `
    <div class="hero-label">${escapeHtml(label)}</div>
    <div class="score">${fmt(value)}</div>
    ${badge || ""}
  `;
}

async function loadIndicatorDetail() {
  const id = indicatorIdFromPath();
  const valueEl = document.getElementById("indicator-value");
  if (!id) {
    valueEl.textContent = "No indicator id in URL";
    return;
  }

  let ind;
  try {
    ind = await Api.get(`/api/indicators/${id}`);
  } catch (err) {
    valueEl.textContent = "Failed to load indicator";
    document.getElementById("indicator-normalised").textContent = err.message;
    return;
  }

  document.title = `ThreatLens - ${ind.value}`;
  renderHeader(ind);
  renderFacts(ind);
  renderConfidence(ind.confidence_breakdown, ind.confidence);
  renderQuality(ind.quality_breakdown);
  renderFlags(ind.quality_flags);
  renderContext(ind.context_data);
  renderSightings(ind);
  renderRelated(ind.related_indicators);
  renderRaw(ind);
}

function renderHeader(ind) {
  const stix = ind.stix ? `STIX ${ind.stix.kind?.toUpperCase() ?? ""} ${ind.stix.type ?? ""}`.trim() : null;
  document.getElementById("indicator-kicker").textContent = [`Indicator #${ind.id}`, ind.ioc_type, stix]
    .filter(Boolean)
    .join(" · ");
  document.getElementById("indicator-value").textContent = ind.value;
  document.getElementById("indicator-normalised").textContent =
    ind.normalised && ind.normalised !== ind.value ? `Normalised: ${ind.normalised}` : "";
  document.getElementById("indicator-meta").innerHTML =
    `Sighted in ${ind.sighting_count} report${ind.sighting_count === 1 ? "" : "s"} · ` +
    engineBadgeHtml(ind.extraction_engine, verificationModels(ind));

  const screened = ind.confidence_breakdown?.screened_by?.length;
  document.getElementById("indicator-confidence-hero").innerHTML = heroHtml(
    "Confidence",
    ind.confidence,
    screened ? '<span class="status-chip warning">Screened</span>' : ""
  );

  const grade = ind.quality_breakdown?.grade || gradeForScore(ind.quality_score);
  document.getElementById("indicator-score-hero").innerHTML = heroHtml(
    "Quality score",
    ind.quality_score,
    grade ? `<span class="grade-badge ${gradeClass(grade)}">${escapeHtml(grade)}</span>` : ""
  );
}

// Distinct verifier model names across the reports this indicator was sighted in.
function verificationModels(ind) {
  const models = new Set();
  for (const s of ind.sightings || []) {
    for (const name of (s.verification_model || "").split(",")) {
      if (name.trim()) models.add(name.trim());
    }
  }
  return [...models].join(", ");
}

function renderFacts(ind) {
  const ctx = ind.context_data || {};
  const attrs = ctx.attributes || {};
  const facts = [
    ["First seen", ind.first_seen],
    ["Last seen", ind.last_seen],
    ["Scored at", ind.scored_at],
    ["Detection rule", ctx.extraction_method],
    ["Verified by", verificationModels(ind)],
    ["Defanged in source", attrs.was_defanged === undefined ? null : attrs.was_defanged ? "Yes" : "No"],
    ["Document section", attrs.document_section_hint],
  ];
  // Any other extractor attribute is shown as-is rather than hidden.
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "was_defanged" || key === "document_section_hint") continue;
    facts.push([key.replace(/_/g, " "), typeof value === "object" ? JSON.stringify(value) : value]);
  }

  document.getElementById("indicator-facts").innerHTML = facts
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(
      ([label, value]) => `
        <div class="detail-fact">
          <div class="label">${escapeHtml(label)}</div>
          <div class="value">${escapeHtml(value)}</div>
        </div>`
    )
    .join("");
}

function renderConfidence(cb, stored) {
  const el = document.getElementById("confidence-breakdown");
  if (!cb) {
    el.innerHTML = emptyNote("No verifier record is stored for this indicator, so its confidence can't be broken down.");
    return;
  }

  const verifierRow = (name, key) => {
    const status = cb[`${key}_status`];
    const isWinner = cb.winner === key;
    return `
      <tr class="${isWinner ? "winner-row" : ""}">
        <td>${escapeHtml(name)}${isWinner ? ' <span class="status-chip">used</span>' : ""}</td>
        <td>${status ? escapeHtml(VERDICT_LABELS[status] || status) : '<span class="dim">did not run</span>'}</td>
        <td>${status ? pct(cb[`${key}_confidence`]) : "-"}</td>
        <td>${status ? (cb[`${key}_maliciousness`] === null ? "no claim" : pct(cb[`${key}_maliciousness`])) : "-"}</td>
      </tr>`;
  };

  let result;
  if (cb.screened_by.length) {
    result = `
      <div class="callout warning">
        <strong>Set to 0 because the indicator was screened</strong>
        (${cb.screened_by.map(escapeHtml).join(", ")}). A screened observable is well-formed data but
        not treated as malicious, whatever the verifiers said. See the flags below.
      </div>`;
  } else if (cb.base_maliciousness === null) {
    result = `<div class="callout">The winning verdict makes no claim about maliciousness, so confidence is 0.</div>`;
  } else {
    const computed = Math.round(Math.min(Math.max(cb.base_maliciousness * cb.multiplier, 0), 1) * 100);
    result = `
      <div class="formula">
        <span>${pct(cb.base_maliciousness)}<small>maliciousness</small></span>
        <span class="op">&times;</span>
        <span>${cb.multiplier ?? "-"}<small>agreement multiplier</small></span>
        <span class="op">=</span>
        <span class="result">${computed}<small>confidence</small></span>
      </div>
      ${
        stored !== null && stored !== computed
          ? `<div class="callout warning">The stored confidence is ${stored}, not ${computed}. It was edited after scoring, or scored with different multipliers.</div>`
          : ""
      }`;
  }

  el.innerHTML = `
    <table class="data-table compact">
      <thead><tr><th>Verifier</th><th>Verdict</th><th>Sure of verdict</th><th>Maliciousness</th></tr></thead>
      <tbody>${verifierRow("LLM", "llm")}${verifierRow("Python heuristics", "python")}</tbody>
    </table>
    <div class="kv-line">
      <span class="label">Agreement</span>
      <span>${escapeHtml(AGREEMENT_LABELS[cb.agreement] || cb.agreement || "-")}
        ${cb.multiplier != null ? `<span class="dim">(&times;${cb.multiplier})</span>` : ""}</span>
    </div>
    ${result}
    <p class="detail-note">
      "Sure of verdict" is how certain the verifier was of its own verdict, not how malicious the value is.
      A confirmed IoC's maliciousness is that certainty; uncertain counts as 50%, rejected as 0, and a
      context entity makes no claim. Agreeing verdicts are averaged, otherwise the LLM's verdict is used.
    </p>`;
}

function renderQuality(qb) {
  const el = document.getElementById("quality-breakdown");
  if (!qb || !qb.dimensions.length) {
    el.innerHTML = emptyNote("This indicator has not been scored.");
    return;
  }

  const rows = qb.dimensions
    .map(
      (d) => `
      <tr>
        <td>
          <div class="dim-name">${escapeHtml(d.dimension)}</div>
          ${d.rule ? `<div class="dim-rule">${escapeHtml(d.rule)}</div>` : ""}
        </td>
        <td>
          <div class="dim-score">
            <div class="meter"><div style="width:${((d.score ?? 0) / 5) * 100}%"></div></div>
            <span>${fmt(d.score)}/5</span>
          </div>
        </td>
        <td>${d.weight > 0 ? `${Math.round(d.weight * 100)}%` : '<span class="dim">not weighted</span>'}</td>
        <td>${fmt(d.points)}</td>
      </tr>`
    )
    .join("");

  // Consistency is the fifth research-paper dimension but isn't scored yet
  // (see the quality checker docs), so it is listed for completeness only.
  const consistencyRow = `
      <tr>
        <td>
          <div class="dim-name">consistency</div>
          <div class="dim-rule">Not implemented. <a href="/docs/quality-checker.html#quality-dimensions" target="_blank" rel="noopener">See the quality checker documentation</a></div>
        </td>
        <td><span class="dim">-</span></td>
        <td><span class="dim">not weighted</span></td>
        <td><span class="dim">-</span></td>
      </tr>`;

  el.innerHTML = `
    <table class="data-table compact">
      <thead><tr><th>Dimension</th><th>Score</th><th>Weight</th><th>Points</th></tr></thead>
      <tbody>${rows}${consistencyRow}</tbody>
      <tfoot><tr><td colspan="3">Quality score</td><td>${gradeBadgeHtml(qb.quality_score, qb.grade)}</td></tr></tfoot>
    </table>`;
}

function renderFlags(flags) {
  const el = document.getElementById("indicator-flags");
  if (!flags.length) {
    el.innerHTML = emptyNote(
      "No quality flags were raised. The database keeps the verifier's written reasoning only when it raises a flag, so none is stored for this indicator."
    );
    return;
  }
  el.innerHTML = `
    <table class="data-table compact">
      <thead><tr><th>Flag</th><th>Dimension</th><th>Severity</th><th>Status</th><th>Detail</th><th>Raised</th></tr></thead>
      <tbody>
        ${flags
          .map(
            (f) => `
          <tr>
            <td>${escapeHtml(f.flag_type)}</td>
            <td>${escapeHtml(fmt(f.dimension))}</td>
            <td><span class="status-chip ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
            <td>${escapeHtml(f.status)}</td>
            <td class="wrap">${escapeHtml(fmt(f.detail))}</td>
            <td class="nowrap">${escapeHtml(f.raised_at)}</td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>`;
}

function renderContext(ctx) {
  const el = document.getElementById("indicator-context");
  const entries = Object.entries(ctx || {}).filter(
    ([key, value]) => !CONTEXT_SHOWN_ELSEWHERE.has(key) && value !== null && !(Array.isArray(value) && !value.length)
  );
  if (!entries.length) {
    el.innerHTML = emptyNote("No threat context is stored for this indicator.");
    return;
  }
  el.innerHTML = entries
    .map(([key, value]) => {
      const items = Array.isArray(value) ? value : [value];
      return `
        <div class="context-group">
          <div class="label">${escapeHtml(CONTEXT_LABELS[key] || key.replace(/_/g, " "))}</div>
          <div class="chips">${items
            .map((item) => `<span class="chip">${escapeHtml(typeof item === "object" ? JSON.stringify(item) : item)}</span>`)
            .join("")}</div>
        </div>`;
    })
    .join("");
}

function renderSightings(ind) {
  const el = document.getElementById("indicator-sightings");
  if (!ind.sightings.length) {
    el.innerHTML = emptyNote("This indicator has no sightings - no report links to it.");
    return;
  }
  el.innerHTML = `
    <table class="data-table compact">
      <thead><tr><th>Report</th><th>Type</th><th>Reliability</th><th>Engine</th><th>Seen</th><th>Excerpt</th></tr></thead>
      <tbody>
        ${ind.sightings
          .map(
            (s) => `
          <tr>
            <td>
              <a class="report-title-link" href="/reports/${s.source_id}#indicator-${ind.id}">${escapeHtml(s.source_title)}</a>
              <div class="dim-rule">${escapeHtml(s.source_name)}</div>
            </td>
            <td>${escapeHtml(fmt(s.source_type))}</td>
            <td>${fmt(s.reliability)}</td>
            <td>${engineBadgeHtml(s.extraction_engine, s.verification_model)}</td>
            <td class="nowrap">${escapeHtml(s.seen_at)}</td>
            <td class="wrap excerpt">${s.excerpt ? highlightHtml(s.excerpt, [ind.value, ind.normalised]) : '<span class="dim">-</span>'}</td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>`;
}

function renderRelated(related) {
  const el = document.getElementById("indicator-related");
  if (!related.length) {
    el.innerHTML = emptyNote("No other indicators share a report with this one.");
    return;
  }
  el.innerHTML = `
    <table class="data-table compact">
      <thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Quality</th><th>Shared reports</th></tr></thead>
      <tbody>
        ${related
          .map(
            (r) => `
          <tr>
            <td>${escapeHtml(r.ioc_type)}</td>
            <td class="wrap"><a class="value-link" href="/indicators/${r.id}">${escapeHtml(r.value)}</a></td>
            <td>${fmt(r.confidence)}</td>
            <td>${gradeBadgeHtml(r.quality_score)}</td>
            <td>${r.shared_reports}</td>
          </tr>`
          )
          .join("")}
      </tbody>
    </table>`;
}

function renderRaw(ind) {
  const pretty = (raw) => {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch (_) {
      return raw;
    }
  };
  document.getElementById("indicator-raw").innerHTML = `
    <div class="label">context</div>
    <pre>${escapeHtml(ind.context ? pretty(ind.context) : "null")}</pre>
    <div class="label">score_components</div>
    <pre>${escapeHtml(ind.score_components ? pretty(ind.score_components) : "null")}</pre>`;
}

window.addEventListener("DOMContentLoaded", loadIndicatorDetail);
