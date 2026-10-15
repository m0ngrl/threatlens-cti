// ThreatLens dashboard - Report detail page: one report's full indicator
// breakdown, plus the report PDF itself underneath, with each indicator highlighted
// wherever it appears. Rows and highlights link both ways: click a row to
// step through its occurrences, click a highlight to find its row. Each
// indicator's value links to its own detail page.

function reportIdFromPath() {
  const match = window.location.pathname.match(/\/reports\/(\d+)/);
  return match ? match[1] : null;
}

async function loadReportDetail() {
  const id = reportIdFromPath();
  if (!id) {
    document.getElementById("report-title").textContent = "No report id in URL";
    return;
  }

  let report;
  try {
    report = await Api.get(`/api/sources/${id}`);
  } catch (err) {
    document.getElementById("report-title").textContent = "Failed to load report";
    document.getElementById("report-filename").textContent = err.message;
    return;
  }

  document.title = `ThreatLens - ${report.title}`;
  document.getElementById("report-title").textContent = report.title;
  document.getElementById("report-filename").textContent = report.filename;

  const metaParts = [
    report.source_type,
    report.ingested_at ? `ingested ${report.ingested_at}` : null,
    `${report.indicator_count} indicator${report.indicator_count === 1 ? "" : "s"}`,
    report.reliability !== null && report.reliability !== undefined
      ? `reliability ${report.reliability}`
      : null,
  ].filter(Boolean);
  document.getElementById("report-meta").innerHTML =
    metaParts.map(escapeHtml).join(" · ") +
    ` · ${engineBadgeHtml(report.extraction_engine, report.verification_model)}`;

  const hero = document.getElementById("report-score-hero");
  const grade = gradeForScore(report.avg_quality_score);
  hero.innerHTML = `
    <div class="score">${report.avg_quality_score ?? "-"}</div>
    ${grade ? `<span class="grade-badge ${gradeClass(grade)}">${grade}</span>` : ""}
  `;

  const body = document.getElementById("report-indicators-body");
  body.innerHTML = "";
  for (const item of report.indicators) {
    const dims = item.dimensions || {};
    const tr = document.createElement("tr");
    tr.dataset.indicatorId = item.id;
    tr.innerHTML = `
      <td>${escapeHtml(item.ioc_type)}</td>
      <td title="${escapeHtml(item.excerpt ?? "")}"><a class="value-link" href="/indicators/${item.id}">${escapeHtml(item.value)}</a></td>
      <td>${dims.timeliness ?? "-"}</td>
      <td>${dims.accuracy ?? "-"}</td>
      <td>${dims.completeness ?? "-"}</td>
      <td>${dims.relevance ?? "-"}</td>
      <td>${gradeBadgeHtml(item.quality_score, item.grade)}</td>
      <td>${item.confidence ?? "-"}</td>
      <td>${item.flag_count || "-"}</td>
      <td class="pdf-hit-count">&hellip;</td>
    `;
    body.appendChild(tr);
  }
  // The value links to the indicator page; don't also jump the PDF viewer.
  body.querySelectorAll("a").forEach((a) => a.addEventListener("click", (event) => event.stopPropagation()));

  highlightLinkedIndicator();
  loadReportPdf(id, report);
}

// Arriving from an indicator page (/reports/{id}#indicator-{indicatorId}),
// bring that indicator's row into view and flash it.
function highlightLinkedIndicator() {
  const match = window.location.hash.match(/^#indicator-(\d+)$/);
  if (!match) return;
  const tr = document.querySelector(`#report-indicators-body tr[data-indicator-id="${match[1]}"]`);
  if (!tr) return;
  tr.classList.add("row-linked");
  tr.scrollIntoView({ block: "center" });
  flash(tr, "row-flash");
}

// Render-scale steps page images are requested in, so resizing the window a
// little reuses the browser's cached image instead of fetching a new one.
const PDF_RENDER_STEPS = [0.75, 1, 1.5, 2, 3, 4];
const PDF_FIT_KEY = "threatlens.pdfFit";

async function loadReportPdf(id, report) {
  const status = document.getElementById("report-pdf-status");
  const rows = document.querySelectorAll("#report-indicators-body tr");
  const setCounts = (text) => rows.forEach((tr) => (tr.lastElementChild.textContent = text));

  if (!report.raw_document) {
    status.textContent = "No document is stored for this report.";
    setCounts("-");
    return;
  }

  status.textContent = "Loading document and locating indicators...";
  let data;
  try {
    data = await Api.get(`/api/sources/${id}/pdf/highlights`);
  } catch (err) {
    status.textContent = `Document unavailable - ${err.message}`;
    setCounts("-");
    return;
  }

  const openLink = document.getElementById("report-pdf-open");
  openLink.href = `/api/sources/${id}/pdf`;
  openLink.hidden = false;

  const indicators = new Map(report.indicators.map((item) => [item.id, item]));
  const matches = data.matches.filter((match) => indicators.has(match.indicator_id));
  const viewer = createPdfViewer(id, data.pages, matches, indicators);

  // indicator id -> its occurrences, in page order (the API returns them that way)
  const hitsByIndicator = new Map();
  for (const match of matches) {
    if (!hitsByIndicator.has(match.indicator_id)) hitsByIndicator.set(match.indicator_id, []);
    hitsByIndicator.get(match.indicator_id).push(match);
  }

  let located = 0;
  for (const tr of rows) {
    const indicatorId = Number(tr.dataset.indicatorId);
    const hits = hitsByIndicator.get(indicatorId) || [];
    const cell = tr.lastElementChild;
    if (!hits.length) {
      cell.textContent = "-";
      cell.classList.add("missing");
      cell.title = "Not found in the PDF text - it may only appear in an image, or be written differently";
      continue;
    }
    located += 1;
    cell.textContent = hits.length === 1 ? "1 hit" : `${hits.length} hits`;
    tr.classList.add("locatable");

    let next = 0;
    tr.addEventListener("click", () => {
      const current = next % hits.length;
      next += 1;
      if (hits.length > 1) cell.textContent = `${current + 1} of ${hits.length}`;
      viewer.showMatch(hits[current]);
    });
    tr.addEventListener("mouseenter", () => viewer.setHover(indicatorId, true));
    tr.addEventListener("mouseleave", () => viewer.setHover(indicatorId, false));
  }

  const total = report.indicators.length;
  status.textContent =
    `${located} of ${total} indicator${total === 1 ? "" : "s"} located in the text · ` +
    "click a row to jump to it";
}

// One-page-at-a-time viewer: page images rendered server-side, highlight
// boxes overlaid as percentages of the page, fitted to the window.
function createPdfViewer(id, pages, matches, indicators) {
  const section = document.getElementById("report-pdf");
  const nav = document.getElementById("pdf-nav");
  const viewport = document.getElementById("pdf-viewport");
  const pageEl = document.getElementById("pdf-page");
  const pageInput = document.getElementById("pdf-page-number");
  const buttons = {
    first: document.getElementById("pdf-first"),
    prev: document.getElementById("pdf-prev"),
    next: document.getElementById("pdf-next"),
    last: document.getElementById("pdf-last"),
    prevHit: document.getElementById("pdf-prev-hit"),
    nextHit: document.getElementById("pdf-next-hit"),
  };
  const fitButtons = nav.querySelectorAll("[data-fit]");
  const pageHits = document.getElementById("pdf-page-hits");

  const matchesByPage = pages.map(() => []);
  for (const match of matches) matchesByPage[match.page].push(match);
  const pagesWithHits = matchesByPage.flatMap((list, index) => (list.length ? [index] : []));

  let current = 0;
  let fit = "page";
  try {
    fit = localStorage.getItem(PDF_FIT_KEY) === "width" ? "width" : "page";
  } catch (_) {
    // storage unavailable - default fit
  }
  const hovered = new Set();

  document.getElementById("pdf-page-count").textContent = pages.length;
  pageInput.max = pages.length;
  nav.hidden = false;
  viewport.hidden = false;

  const pageUrl = (index, scale) => `/api/sources/${id}/pdf/pages/${index}.png?scale=${scale}`;

  function renderScale(displayScale) {
    const wanted = displayScale * (window.devicePixelRatio || 1);
    return PDF_RENDER_STEPS.find((step) => step >= wanted) ?? PDF_RENDER_STEPS.at(-1);
  }

  // Size the viewport to the window (below the nav bar), then the page to the viewport.
  function layout() {
    viewport.style.height = `${Math.max(360, window.innerHeight - nav.offsetHeight - 16)}px`;
    const size = pages[current];
    const style = getComputedStyle(viewport);
    const availWidth = viewport.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    const availHeight = viewport.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom);
    const widthScale = availWidth / size.width;
    const scale = fit === "width" ? widthScale : Math.min(widthScale, availHeight / size.height);
    pageEl.style.width = `${Math.floor(size.width * scale)}px`;
    pageEl.style.height = `${Math.floor(size.height * scale)}px`;

    const img = pageEl.querySelector("img");
    const src = pageUrl(current, renderScale(scale));
    if (img && img.getAttribute("src") !== src) img.src = src;
    return scale;
  }

  function render() {
    const size = pages[current];
    const pct = (value, total) => `${(value / total) * 100}%`;
    pageEl.innerHTML = `<img alt="Page ${current + 1}" />`;
    for (const match of matchesByPage[current]) {
      const item = indicators.get(match.indicator_id);
      const grade = item.grade || gradeForScore(item.quality_score);
      // A value wrapped across lines has one rect per line.
      match.els = match.rects.map(([x0, y0, x1, y1]) => {
        const hl = document.createElement("div");
        hl.className = `pdf-hl ${grade ? gradeClass(grade) : "grade-none"}`;
        if (hovered.has(item.id)) hl.classList.add("hover");
        hl.dataset.indicatorId = item.id;
        hl.title = `${item.ioc_type}: ${item.value}` + (item.quality_score != null ? ` (score ${item.quality_score})` : "");
        Object.assign(hl.style, {
          left: pct(x0, size.width),
          top: pct(y0, size.height),
          width: pct(x1 - x0, size.width),
          height: pct(y1 - y0, size.height),
        });
        pageEl.appendChild(hl);
        return hl;
      });
    }
    const scale = layout();
    viewport.scrollTop = 0;

    // Warm the cache for the page the reader is most likely to go to next.
    if (current + 1 < pages.length) new Image().src = pageUrl(current + 1, renderScale(scale));

    pageInput.value = current + 1;
    buttons.first.disabled = buttons.prev.disabled = current === 0;
    buttons.next.disabled = buttons.last.disabled = current === pages.length - 1;
    buttons.prevHit.disabled = !pagesWithHits.some((index) => index < current);
    buttons.nextHit.disabled = !pagesWithHits.some((index) => index > current);
    const count = matchesByPage[current].length;
    pageHits.textContent = count
      ? `${count} highlight${count === 1 ? "" : "s"} on this page`
      : "No highlights on this page";
    fitButtons.forEach((button) => button.classList.toggle("selected", button.dataset.fit === fit));
  }

  function goTo(index) {
    const clamped = Math.min(Math.max(index, 0), pages.length - 1);
    if (clamped !== current || !pageEl.firstChild) {
      current = clamped;
      render();
    } else {
      pageInput.value = current + 1;
    }
  }

  buttons.first.addEventListener("click", () => goTo(0));
  buttons.prev.addEventListener("click", () => goTo(current - 1));
  buttons.next.addEventListener("click", () => goTo(current + 1));
  buttons.last.addEventListener("click", () => goTo(pages.length - 1));
  buttons.prevHit.addEventListener("click", () => {
    const earlier = pagesWithHits.filter((index) => index < current);
    if (earlier.length) goTo(earlier.at(-1));
  });
  buttons.nextHit.addEventListener("click", () => {
    const later = pagesWithHits.find((index) => index > current);
    if (later !== undefined) goTo(later);
  });
  pageInput.addEventListener("change", () => goTo(Number(pageInput.value) - 1));
  fitButtons.forEach((button) =>
    button.addEventListener("click", () => {
      fit = button.dataset.fit;
      try {
        localStorage.setItem(PDF_FIT_KEY, fit);
      } catch (_) {
        // storage unavailable - fit just won't be remembered
      }
      render();
    })
  );

  document.addEventListener("keydown", (event) => {
    if (event.target.closest("input, textarea, select") || event.altKey || event.ctrlKey || event.metaKey) return;
    const inViewer = section.contains(document.activeElement);
    if (event.key === "ArrowLeft") goTo(current - 1);
    else if (event.key === "ArrowRight") goTo(current + 1);
    else if (inViewer && event.key === "Home") goTo(0);
    else if (inViewer && event.key === "End") goTo(pages.length - 1);
    else return;
    event.preventDefault();
  });

  pageEl.addEventListener("click", (event) => {
    const hl = event.target.closest(".pdf-hl");
    if (!hl) return;
    const tr = document.querySelector(`#report-indicators-body tr[data-indicator-id="${hl.dataset.indicatorId}"]`);
    if (!tr) return;
    tr.scrollIntoView({ behavior: "smooth", block: "center" });
    flash(tr, "row-flash");
  });

  let resizeFrame = 0;
  const relayout = () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(layout);
  };
  window.addEventListener("resize", relayout);
  new ResizeObserver(relayout).observe(viewport);

  goTo(0);

  return {
    showMatch(match) {
      goTo(match.page);
      document.querySelectorAll(".pdf-hl.active").forEach((el) => el.classList.remove("active"));
      match.els.forEach((el) => flash(el, "active", false));
      // Bring the viewer on screen, then the highlight into the middle of it
      // (only matters in fit-width mode, where the page scrolls).
      // The inner scroll is instant: two smooth scrolls at once can cancel
      // each other in some browsers.
      viewport.scrollTop = match.els[0].offsetTop + pageEl.offsetTop - viewport.clientHeight / 2;
      nav.scrollIntoView({ behavior: "smooth", block: "start" });
    },
    setHover(indicatorId, on) {
      if (on) hovered.add(indicatorId);
      else hovered.delete(indicatorId);
      pageEl
        .querySelectorAll(`.pdf-hl[data-indicator-id="${indicatorId}"]`)
        .forEach((el) => el.classList.toggle("hover", on));
    },
  };
}

// Re-trigger a CSS animation class; `transient` removes it again afterwards.
function flash(el, className, transient = true) {
  el.classList.remove(className);
  void el.offsetWidth; // force reflow so the animation restarts
  el.classList.add(className);
  if (transient) setTimeout(() => el.classList.remove(className), 1200);
}

window.addEventListener("DOMContentLoaded", loadReportDetail);
