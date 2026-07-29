/**
 * Privacy Score — évaluation de la vie privée personnelle
 */
const PrivacyUI = (() => {
  let current = null;

  function init() {
    document.getElementById("pvClearBtn")?.addEventListener("click", clearPanel);
    document.getElementById("pvLoadLastBtn")?.addEventListener("click", () => {
      refreshFromLast({ force: true });
    });
    document.getElementById("pvGauge")?.addEventListener("click", (e) => {
      if (e.target.closest("[data-pv-load]")) {
        e.preventDefault();
        refreshFromLast({ force: true });
      }
    });
  }

  function resolveInvestigation(explicit) {
    if (explicit) return explicit;
    return (
      window.PlaybooksUI?.getLatestHistoryResult?.() ||
      window.PlaybooksUI?.getLastResult?.() ||
      null
    );
  }

  function loadFromInvestigation(investigation, opts = {}) {
    const navigate = opts.navigate !== false;
    const inv = resolveInvestigation(investigation);
    if (!inv) {
      setStatus("Aucune investigation");
      showEmpty("Lancez une investigation dans Playbooks, puis revenez ici.");
      if (navigate) showPanel();
      return;
    }

    const ps = inv?.synthesis?.privacy_score;
    if (ps && typeof ps.score === "number") {
      render(ps, inv);
      if (navigate) showPanel();
      return;
    }

    setStatus("Calcul…");
    fetch("/api/privacy/from-investigation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ investigation: inv }),
    })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok) {
          const detail = d.detail;
          const msg = typeof detail === "string" ? detail : (detail?.[0]?.msg || "Erreur API");
          throw new Error(msg);
        }
        if (inv.synthesis) inv.synthesis.privacy_score = d;
        else inv.synthesis = { privacy_score: d };
        render(d, inv);
        if (navigate) showPanel();
      })
      .catch((err) => {
        setStatus(`Erreur`);
        showEmpty(`Impossible de calculer le Privacy Score : ${err.message}`);
        if (navigate) showPanel();
      });
  }

  function refreshFromLast(opts = {}) {
    const inv = resolveInvestigation(null);
    if (!inv) {
      if (opts.force) {
        setStatus("Aucune investigation");
        showEmpty("Aucune investigation récente. Lancez un playbook d’abord.");
      }
      return false;
    }
    if (
      !opts.force &&
      current?.ps &&
      current?.investigation?.target &&
      current.investigation.target === inv.target
    ) {
      return true;
    }
    loadFromInvestigation(inv, { navigate: false });
    return true;
  }

  function showEmpty(message) {
    const gauge = document.getElementById("pvGauge");
    if (gauge) {
      gauge.innerHTML = `
        <div class="pv-empty">
          <p>${esc(message || "Aucune donnée.")}</p>
          <button type="button" class="pb-export-btn" data-pv-load style="margin-top:12px">
            Charger la dernière investigation
          </button>
        </div>`;
    }
    const factors = document.getElementById("pvFactors");
    const recs = document.getElementById("pvRecs");
    const summary = document.getElementById("pvSummary");
    const meta = document.getElementById("pvMeta");
    if (factors) factors.innerHTML = "";
    if (recs) recs.innerHTML = "";
    if (summary) summary.textContent = "";
    if (meta) meta.innerHTML = "";
  }

  function render(ps, investigation) {
    current = { ps, investigation };
    setStatus(`${ps.score}/100 — ${ps.grade_label || ""}`);

    const meta = document.getElementById("pvMeta");
    if (meta) {
      meta.innerHTML = `
        <span>Cible : <code>${esc(investigation?.target || ps.target)}</code></span>
        <span>Type : ${esc(investigation?.target_type || ps.target_type)}</span>
        <span>Exposition : ${ps.exposure_total ?? 0}/100</span>`;
    }

    const gauge = document.getElementById("pvGauge");
    if (gauge) {
      const color = ps.color || "#22c55e";
      const score = ps.score || 0;
      const circ = 2 * Math.PI * 52;
      const offset = circ - (score / 100) * circ;
      gauge.innerHTML = `
        <svg width="140" height="140" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="8"/>
          <circle id="pvRing" cx="60" cy="60" r="52" fill="none" stroke-width="8"
            stroke="${color}" stroke-linecap="round"
            stroke-dasharray="${circ}" stroke-dashoffset="${circ}"
            data-offset="${offset}" transform="rotate(-90 60 60)"/>
        </svg>
        <div class="pv-gauge-center" style="color:${color}">
          <span id="pvScoreVal">0</span><span class="pv-max">/100</span>
          <span class="pv-grade">${esc(ps.grade_label || "")}</span>
        </div>`;
      animateScore(score);
    }

    const summary = document.getElementById("pvSummary");
    if (summary) summary.textContent = ps.summary || "";

    const factors = document.getElementById("pvFactors");
    if (factors) {
      factors.innerHTML = (ps.factors || []).map((f) => `
        <div class="pv-factor as-sev-${f.severity || "info"}">
          <div class="as-factor-head">
            <span>${esc(f.label)}</span>
            <span class="as-factor-pts">exposition ${f.exposure}/${f.max_exposure}</span>
          </div>
          <div class="as-bar"><div class="pv-bar-fill as-bar-fill" data-pct="${f.pct_exposed || 0}" style="width:0;background:${sevColor(f.severity)}"></div></div>
          <div class="as-factor-detail">${esc(f.details)}</div>
        </div>`).join("");
      requestAnimationFrame(() => {
        factors.querySelectorAll(".pv-bar-fill").forEach((bar) => {
          bar.style.width = `${parseFloat(bar.dataset.pct) || 0}%`;
        });
      });
    }

    const recs = document.getElementById("pvRecs");
    if (recs) {
      const list = ps.recommendations || [];
      recs.innerHTML = list.length
        ? `<ul>${list.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`
        : `<p class="pv-empty">Aucune recommandation.</p>`;
    }
  }

  function animateScore(end) {
    const el = document.getElementById("pvScoreVal");
    const ring = document.getElementById("pvRing");
    if (!el) return;
    const start = performance.now();
    const dur = 900;
    const targetOffset = ring ? parseFloat(ring.dataset.offset) : 0;
    const circ = ring ? parseFloat(ring.getAttribute("stroke-dasharray")) : 0;
    function tick(now) {
      const t = Math.min((now - start) / dur, 1);
      const ease = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(end * ease);
      if (ring) ring.style.strokeDashoffset = circ - (circ - targetOffset) * ease;
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function clearPanel() {
    current = null;
    setStatus("Prêt");
    showEmpty("Lancez une investigation dans Playbooks, puis ouvrez Privacy.");
  }

  function setStatus(text) {
    const el = document.getElementById("pvStatus");
    if (el) el.textContent = text;
  }

  function showPanel() {
    window.activatePGPanel?.("panel-privacy");
  }

  function sevColor(sev) {
    return { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#22c55e", info: "#64748b" }[sev] || "#64748b";
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init, loadFromInvestigation, refreshFromLast, showPanel };
})();

window.PrivacyUI = PrivacyUI;

document.addEventListener("DOMContentLoaded", () => {
  try { PrivacyUI.init(); } catch (e) { console.error("[PRIVACY]", e); }
});
