/**
 * Timeline OSINT — visualisation chronologique
 */
const TimelineUI = (() => {
  let currentTimeline = null;
  let activeFilter = "all";

  function init() {
    document.getElementById("tlExportJson")?.addEventListener("click", exportJson);
    document.getElementById("tlClearBtn")?.addEventListener("click", clearTimeline);
  }

  function loadFromInvestigation(investigation) {
    const tl = investigation?.synthesis?.timeline;
    if (tl) {
      renderTimeline(tl);
      showPanel();
      return;
    }

    fetch("/api/timeline/from-investigation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ investigation }),
    })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok) throw new Error(d.detail || "Erreur");
        renderTimeline(d);
        showPanel();
      })
      .catch((err) => setStatus(`Erreur : ${err.message}`));
  }

  function renderTimeline(tl) {
    currentTimeline = tl;
    activeFilter = "all";

    setStatus(`${tl.event_count || 0} événement(s)`);
    renderMeta(tl);
    renderFilters(tl);
    renderTrack(tl);
    renderInsights(tl);
    renderDetail(null);
  }

  function setStatus(text) {
    const el = document.getElementById("tlStatus");
    if (el) el.textContent = text;
  }

  function renderMeta(tl) {
    const el = document.getElementById("tlMeta");
    if (!el) return;
    const range = tl.range || {};
    el.innerHTML = `
      <span>Cible : <code>${esc(tl.target)}</code></span>
      ${range.start ? `<span>Période : ${fmtDate(range.start)} → ${fmtDate(range.end)}</span>` : ""}
      <span>${tl.event_count || 0} événements</span>`;
  }

  function renderFilters(tl) {
    const el = document.getElementById("tlFilters");
    if (!el) return;
    const sources = tl.sources || [];
    el.innerHTML = `
      <button type="button" class="tl-filter active" data-source="all">Tous</button>
      ${sources.map((s) => `
        <button type="button" class="tl-filter" data-source="${esc(s)}">
          ${SOURCE_ICON[s] || "•"} ${esc(tl.source_labels?.[s] || s)}
        </button>`).join("")}`;

    el.querySelectorAll(".tl-filter").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeFilter = btn.dataset.source;
        el.querySelectorAll(".tl-filter").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        renderTrack(tl);
      });
    });
  }

  function renderTrack(tl) {
    const track = document.getElementById("tlTrack");
    if (!track) return;

    let events = tl.events || [];
    if (activeFilter !== "all") {
      events = events.filter((e) => e.source === activeFilter);
    }

    if (!events.length) {
      track.innerHTML = `<div class="tl-empty">Aucun événement pour ce filtre.</div>`;
      return;
    }

    track.innerHTML = `
      <div class="tl-line" aria-hidden="true"></div>
      <div class="tl-events">
        ${events.map((e, i) => renderEvent(e, i)).join("")}
      </div>`;

    track.querySelectorAll(".tl-event").forEach((node) => {
      node.addEventListener("click", () => {
        track.querySelectorAll(".tl-event").forEach((n) => n.classList.remove("selected"));
        node.classList.add("selected");
        const id = node.dataset.id;
        const ev = (tl.events || []).find((x) => x.id === id);
        renderDetail(ev);
      });
    });
  }

  function renderEvent(e, index) {
    const sev = e.severity || "info";
    const dateLabel = e.date_precision === "unknown" ? "Date inconnue" : fmtDate(e.occurred_at);
    return `
      <div class="tl-event tl-sev-${sev}" data-id="${esc(e.id)}" style="--i:${index}">
        <div class="tl-event-dot">${e.icon || "•"}</div>
        <div class="tl-event-card">
          <div class="tl-event-date">${esc(dateLabel)}</div>
          <div class="tl-event-title">${esc(e.title)}</div>
          <div class="tl-event-source">${esc(e.source_label || e.source)}</div>
        </div>
      </div>`;
  }

  function renderInsights(tl) {
    const el = document.getElementById("tlInsights");
    if (!el) return;
    const patterns = tl.patterns || {};
    const insights = patterns.insights || [];
    const byYear = patterns.events_by_year || {};

    const yearBars = Object.entries(byYear).map(([y, c]) => `
      <div class="tl-year-bar">
        <span class="tl-year">${y}</span>
        <div class="tl-year-fill-wrap"><div class="tl-year-fill" style="width:${Math.min(100, c * 20)}%"></div></div>
        <span class="tl-year-count">${c}</span>
      </div>`).join("");

    el.innerHTML = `
      <div class="tl-insights-list">
        ${insights.map((i) => `<div class="tl-insight">💡 ${esc(i)}</div>`).join("")}
      </div>
      ${yearBars ? `<div class="tl-year-chart">${yearBars}</div>` : ""}`;
  }

  function renderDetail(ev) {
    const el = document.getElementById("tlDetail");
    if (!el) return;
    if (!ev) {
      el.innerHTML = `<p class="tl-detail-empty">Cliquez sur un événement pour voir les détails.</p>`;
      return;
    }
    el.innerHTML = `
      <div class="tl-detail-type">${ev.icon || ""} ${esc((ev.event_type || "").replace(/_/g, " "))}</div>
      <h4>${esc(ev.title)}</h4>
      <div class="tl-detail-meta">
        <span>${esc(ev.source_label || ev.source)}</span>
        <span>${ev.date_precision === "unknown" ? "Date inconnue" : fmtDate(ev.occurred_at)}</span>
      </div>
      ${ev.description ? `<p>${esc(ev.description)}</p>` : ""}
      ${ev.metadata && Object.keys(ev.metadata).length ? `
        <pre class="tl-detail-meta-json">${esc(JSON.stringify(ev.metadata, null, 2))}</pre>` : ""}`;
  }

  function showPanel() {
    window.activatePGPanel?.("panel-timeline");
  }

  function clearTimeline() {
    currentTimeline = null;
    document.getElementById("tlTrack").innerHTML = `<div class="tl-empty">Aucune timeline chargée.</div>`;
    document.getElementById("tlMeta").innerHTML = "";
    document.getElementById("tlFilters").innerHTML = "";
    document.getElementById("tlInsights").innerHTML = "";
    renderDetail(null);
    setStatus("Timeline effacée");
  }

  function exportJson() {
    if (!currentTimeline) return;
    const blob = new Blob([JSON.stringify(currentTimeline, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `timeline-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  const SOURCE_ICON = {
    leakcheck: "🔓", whois: "📋", sherlock: "📱", virustotal: "🦠",
    abuseipdb: "🚫", shodan_ip: "📡", shodan_search: "📡", investigation: "🔬",
  };

  function fmtDate(iso) {
    if (!iso || iso.startsWith("0000")) return "Inconnue";
    const parts = iso.split("-");
    if (parts.length === 3) return `${parts[2]}/${parts[1]}/${parts[0]}`;
    return iso;
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init, loadFromInvestigation, showPanel };
})();

document.addEventListener("DOMContentLoaded", () => {
  try { TimelineUI.init(); } catch (e) { console.error("[TIMELINE]", e); }
});

window.TimelineUI = TimelineUI;
