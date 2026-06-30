/**
 * Watch OSINT — surveillance de cibles et alertes
 */
const WatchUI = (() => {
  let watches = [];
  let alerts = [];
  let pollTimer = null;

  const SEV_CLASS = {
    critical: "watch-sev-critical",
    high: "watch-sev-high",
    medium: "watch-sev-medium",
    low: "watch-sev-low",
    info: "watch-sev-info",
  };

  const RISK_CLASS = {
    critical: "risk-critique",
    high: "risk-eleve",
    medium: "risk-modere",
    low: "risk-faible",
  };

  function init() {
    document.getElementById("watchCreateForm")?.addEventListener("submit", onCreate);
    document.getElementById("watchRefreshBtn")?.addEventListener("click", refresh);
    document.getElementById("watchReadAllBtn")?.addEventListener("click", markAllRead);
    refresh();
    pollTimer = setInterval(refresh, 60000);
  }

  async function refresh() {
    try {
      const [wRes, aRes] = await Promise.all([
        fetch("/api/watches"),
        fetch("/api/alerts?limit=50"),
      ]);
      const wData = await wRes.json();
      const aData = await aRes.json();
      if (!wRes.ok) throw new Error(wData.detail || "Erreur watches");
      watches = wData.watches || [];
      alerts = aData.alerts || [];
      renderWatches();
      renderAlerts();
      renderStats(wData.status || {});
      updateNavBadge(aData.unread_count ?? 0);
      setStatus(`${watches.length} surveillance(s) · ${aData.unread_count || 0} alerte(s) non lue(s)`);
    } catch (e) {
      setStatus(`Erreur : ${e.message}`);
    }
  }

  function setStatus(text) {
    const el = document.getElementById("watchStatus");
    if (el) el.textContent = text;
  }

  function updateNavBadge(count) {
    const badge = document.getElementById("watchNavBadge");
    if (!badge) return;
    if (count > 0) {
      badge.textContent = count > 99 ? "99+" : String(count);
      badge.classList.remove("hidden");
    } else {
      badge.classList.add("hidden");
    }
  }

  function renderStats(st) {
    const el = document.getElementById("watchStats");
    if (!el) return;
    el.innerHTML = `
      <div class="watch-stat-row"><span>Actives</span><strong>${st.active_watches || 0}</strong></div>
      <div class="watch-stat-row"><span>Alertes</span><strong>${st.alert_count || 0}</strong></div>
      <div class="watch-stat-row"><span>Auto-check</span><strong>${st.auto_check_enabled ? "ON" : "OFF"}</strong></div>
      <div class="watch-stat-row"><span>Polling</span><strong>${st.poll_interval_minutes || 15} min</strong></div>`;
  }

  function renderWatches() {
    const el = document.getElementById("watchList");
    if (!el) return;
    if (!watches.length) {
      el.innerHTML = `<p class="watch-empty">Aucune surveillance active. Ajoutez une cible ou utilisez « Surveiller » depuis Playbooks.</p>`;
      return;
    }

    el.innerHTML = watches.map((w) => `
      <div class="watch-card ${w.status === "paused" ? "watch-paused" : ""}" data-id="${esc(w.id)}">
        <div class="watch-card-head">
          <div>
            <div class="watch-card-label">${esc(w.label || w.target)}</div>
            <code class="watch-card-target">${esc(w.target)}</code>
          </div>
          <span class="watch-status-pill watch-status-${esc(w.status)}">${w.status === "paused" ? "Pause" : "Active"}</span>
        </div>
        <div class="watch-card-meta">
          <span class="${RISK_CLASS[w.last_risk] || "risk-faible"}">${(w.last_risk || "low").toUpperCase()}</span>
          <span>Score ${Math.round(w.last_score || 0)}/100</span>
          <span>${w.interval_hours}h</span>
          ${w.unread_alerts > 0 ? `<span class="watch-unread">${w.unread_alerts} nouvelle(s)</span>` : ""}
        </div>
        <div class="watch-card-times">
          ${w.last_check_at ? `<span>Dernier scan : ${fmtDate(w.last_check_at)}</span>` : ""}
          ${w.next_check_at ? `<span>Prochain : ${fmtDate(w.next_check_at)}</span>` : ""}
        </div>
        <div class="watch-card-actions">
          <button type="button" class="pb-export-btn watch-check-btn" data-id="${esc(w.id)}">🔍 Vérifier</button>
          <button type="button" class="pb-export-btn watch-toggle-btn" data-id="${esc(w.id)}" data-status="${esc(w.status)}">
            ${w.status === "paused" ? "▶ Reprendre" : "⏸ Pause"}
          </button>
          <button type="button" class="pb-export-btn watch-delete-btn" data-id="${esc(w.id)}">🗑</button>
        </div>
      </div>`).join("");

    el.querySelectorAll(".watch-check-btn").forEach((btn) => {
      btn.addEventListener("click", () => runCheck(btn.dataset.id, btn));
    });
    el.querySelectorAll(".watch-toggle-btn").forEach((btn) => {
      btn.addEventListener("click", () => toggleWatch(btn.dataset.id, btn.dataset.status));
    });
    el.querySelectorAll(".watch-delete-btn").forEach((btn) => {
      btn.addEventListener("click", () => deleteWatch(btn.dataset.id));
    });
  }

  function renderAlerts() {
    const el = document.getElementById("watchAlerts");
    if (!el) return;
    if (!alerts.length) {
      el.innerHTML = `<p class="watch-empty">Aucune alerte pour le moment.</p>`;
      return;
    }

    el.innerHTML = alerts.map((a) => `
      <div class="watch-alert ${SEV_CLASS[a.severity] || ""} ${a.read ? "watch-alert-read" : ""}" data-id="${esc(a.id)}">
        <div class="watch-alert-head">
          <span class="watch-alert-sev">${(a.severity || "info").toUpperCase()}</span>
          <span class="watch-alert-time">${fmtDate(a.created_at)}</span>
        </div>
        <div class="watch-alert-title">${esc(a.title)}</div>
        <div class="watch-alert-msg">${esc(a.message)}</div>
        <div class="watch-alert-foot">
          <code>${esc(a.target)}</code>
          ${!a.read ? `<button type="button" class="watch-read-btn" data-id="${esc(a.id)}">Marquer lu</button>` : ""}
        </div>
      </div>`).join("");

    el.querySelectorAll(".watch-read-btn").forEach((btn) => {
      btn.addEventListener("click", () => markRead(btn.dataset.id));
    });
  }

  async function onCreate(e) {
    e.preventDefault();
    const target = document.getElementById("watchTarget")?.value?.trim();
    const label = document.getElementById("watchLabel")?.value?.trim();
    const interval = parseInt(document.getElementById("watchInterval")?.value || "24", 10);
    const btn = document.getElementById("watchCreateBtn");
    if (!target) return;

    btn?.classList.add("loading");
    btn && (btn.disabled = true);
    try {
      const res = await fetch("/api/watches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, label: label || undefined, interval_hours: interval }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      document.getElementById("watchTarget").value = "";
      document.getElementById("watchLabel").value = "";
      window.updateTerminal?.(`[WATCH] Surveillance ajoutée : ${target}`);
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
    } finally {
      btn?.classList.remove("loading");
      if (btn) btn.disabled = false;
    }
  }

  async function addFromInvestigation(investigation, label) {
    if (!investigation?.target) return;
    try {
      const res = await fetch("/api/watches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: investigation.target,
          playbook_id: investigation.playbook_id,
          label: label || investigation.target,
          baseline_investigation: investigation,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      window.updateTerminal?.(`[WATCH] ${investigation.target} ajouté à la watchlist`);
      showPanel();
      await refresh();
      return data;
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
      throw err;
    }
  }

  async function runCheck(watchId, btn) {
    if (!watchId) return;
    const prev = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = "⏳…"; }
    try {
      const res = await fetch(`/api/watches/${watchId}/check`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      const n = data.changes_detected || 0;
      window.updateTerminal?.(`[WATCH] Scan terminé — ${n} changement(s) détecté(s)`);
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = prev || "🔍 Vérifier"; }
    }
  }

  async function toggleWatch(watchId, currentStatus) {
    const next = currentStatus === "paused" ? "active" : "paused";
    try {
      const res = await fetch(`/api/watches/${watchId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: next }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
    }
  }

  async function deleteWatch(watchId) {
    if (!confirm("Supprimer cette surveillance ?")) return;
    try {
      const res = await fetch(`/api/watches/${watchId}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
    }
  }

  async function markRead(alertId) {
    try {
      await fetch(`/api/alerts/${alertId}/read`, { method: "POST" });
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
    }
  }

  async function markAllRead() {
    try {
      await fetch("/api/alerts/read-all", { method: "POST" });
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WATCH] ${err.message}`);
    }
  }

  function showPanel() {
    window.activatePGPanel?.("panel-watch");
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
    } catch {
      return iso.slice(0, 16);
    }
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init, refresh, addFromInvestigation, showPanel };
})();

window.WatchUI = WatchUI;

document.addEventListener("DOMContentLoaded", () => {
  try { WatchUI.init(); } catch (e) { console.error("[WATCH]", e); }
});
