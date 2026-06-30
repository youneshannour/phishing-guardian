/**
 * Playbooks OSINT — Investigation Workspace UI (animated)
 */

const PlaybooksUI = (() => {
  let cache = [];
  let selectedId = null;
  let lastResult = null;
  let suggestTimer = null;
  let loadingInterval = null;

  const RISK_COLORS = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#f59e0b",
    low: "#22c55e",
  };

  const RISK_SCORE = { critical: 95, high: 72, medium: 45, low: 18 };

  const PLUGIN_LABELS = {
    leakcheck: "Leak Check",
    sherlock: "Sherlock",
    whois: "WHOIS",
    virustotal: "VirusTotal",
    abuseipdb: "AbuseIPDB",
    shodan_ip: "Shodan IP",
    shodan_search: "Shodan Search",
  };

  function init() {
    const targetInput = document.getElementById("playbookTarget");
    const runBtn = document.getElementById("playbookRunBtn");
    const listEl = document.getElementById("playbookList");
    const wrap = targetInput?.closest(".pb-search-input-wrap");

    if (!targetInput || !runBtn) return;

    loadPlaybooks();

    targetInput.addEventListener("input", () => {
      clearTimeout(suggestTimer);
      suggestTimer = setTimeout(() => suggest(targetInput.value.trim()), 350);
    });

    targetInput.addEventListener("focus", () => wrap?.classList.add("focused"));
    targetInput.addEventListener("blur", () => wrap?.classList.remove("focused"));

    targetInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runInvestigation();
      }
    });

    runBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      runInvestigation();
    });

    if (listEl) {
      listEl.addEventListener("click", (e) => {
        const card = e.target.closest(".pb-playbook-card[data-id]");
        if (!card) return;
        e.preventDefault();
        selectedId = card.dataset.id;
        renderPlaybookCards();
        updateTargetMeta();
      });
    }

    document.getElementById("playbookResults")?.addEventListener("click", (e) => {
      const btn = e.target.closest("button[id]");
      if (!btn || !lastResult) return;
      e.preventDefault();
      e.stopPropagation();
      switch (btn.id) {
        case "pbViewGraph":
          window.GraphUI?.loadFromInvestigation(lastResult);
          break;
        case "pbViewTimeline":
          window.TimelineUI?.loadFromInvestigation(lastResult);
          break;
        case "pbViewPrivacy":
          window.PrivacyUI?.loadFromInvestigation(lastResult);
          break;
        case "pbAddWatch":
          window.WatchUI?.addFromInvestigation(lastResult);
          break;
        case "pbAddWorkspace":
          window.WorkspaceUI?.addInvestigation(lastResult);
          break;
        case "pbExportJson":
          exportJson();
          break;
        case "pbExportPdf":
          exportPdf();
          break;
        case "pbCopyReport":
          copyReport();
          break;
        default:
          break;
      }
    });
  }

  async function loadPlaybooks() {
    const listEl = document.getElementById("playbookList");
    try {
      const res = await fetch("/api/playbooks");
      const data = await res.json();
      cache = data.playbooks || [];
      if (cache.length && !selectedId) selectedId = cache[0].id;
      renderPlaybookCards();
    } catch (err) {
      if (listEl) {
        listEl.innerHTML = `<div class="pb-empty-state" style="padding:2rem"><p>Erreur: ${esc(err.message)}</p></div>`;
      }
    }
  }

  function renderPlaybookCards() {
    const listEl = document.getElementById("playbookList");
    if (!listEl) return;

    listEl.innerHTML = cache.map((pb) => `
      <button type="button" class="pb-playbook-card ${pb.id === selectedId ? "selected" : ""}"
              data-id="${pb.id}">
        <div class="pb-playbook-icon">${pb.icon || "📋"}</div>
        <div class="pb-playbook-info">
          <h4>${esc(pb.name)}</h4>
          <p>${esc(pb.description)}</p>
          <div class="pb-playbook-tags">
            ${pb.target_types.map((t) => `<span class="pb-tag">${esc(t)}</span>`).join("")}
          </div>
        </div>
      </button>
    `).join("");
  }

  async function suggest(target) {
    const typeEl = document.getElementById("pbTargetType");
    const hintEl = document.getElementById("playbookHint");
    if (!target) {
      if (typeEl) typeEl.innerHTML = "";
      if (hintEl) hintEl.textContent = "Saisissez une cible pour détecter le type automatiquement.";
      return;
    }

    try {
      const res = await fetch(`/api/playbooks/suggest?target=${encodeURIComponent(target)}`);
      const data = await res.json();
      selectedId = data.suggested_playbook_id;
      renderPlaybookCards();
      if (typeEl) {
        typeEl.innerHTML = `<span class="badge badge-info">${esc(data.target_type)}</span>`;
      }
      if (hintEl) {
        hintEl.textContent = `Playbook suggéré : ${data.suggested_playbook?.name || data.suggested_playbook_id}`;
      }
    } catch {
      if (hintEl) hintEl.textContent = "Détection automatique indisponible.";
    }
  }

  function updateTargetMeta() {
    const pb = cache.find((p) => p.id === selectedId);
    const hintEl = document.getElementById("playbookHint");
    if (pb && hintEl) hintEl.textContent = `Playbook sélectionné : ${pb.name}`;
  }

  function getSelectedSteps() {
    const pb = cache.find((p) => p.id === selectedId);
    return pb?.steps || [];
  }

  async function runInvestigation() {
    const target = document.getElementById("playbookTarget")?.value.trim();
    const runBtn = document.getElementById("playbookRunBtn");
    const resultsEl = document.getElementById("playbookResults");

    if (!target) {
      window.updateTerminal?.("Cible requise pour l'investigation");
      shakeElement(document.getElementById("playbookTarget"));
      return;
    }

    if (!runBtn || !resultsEl) return;

    runBtn.disabled = true;
    runBtn.classList.add("running");
    showAnimatedLoading(resultsEl);
    window.updateTerminal?.(`Investigation lancée : ${target}`);

    const fetchPromise = fetch("/api/playbooks/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, playbook_id: selectedId }),
    });

    try {
      const res = await fetchPromise;
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur serveur");

      stopLoadingAnimation();
      lastResult = data;
      renderDashboard(data);
      window.updateTerminal?.(`Investigation terminée (${data.duration_ms}ms) — surface d'attaque ${synth.attack_surface?.score ?? "N/A"}/100`);
    } catch (err) {
      stopLoadingAnimation();
      resultsEl.innerHTML = `
        <div class="pb-empty-state">
          <div class="pb-empty-icon">⚠️</div>
          <h3>Investigation échouée</h3>
          <p>${esc(err.message)}</p>
        </div>`;
      window.updateTerminal?.(`Erreur investigation : ${err.message}`);
    } finally {
      if (runBtn) {
        runBtn.disabled = false;
        runBtn.classList.remove("running");
      }
    }
  }

  function shakeElement(el) {
    if (!el) return;
    el.style.animation = "none";
    el.offsetHeight;
    el.style.animation = "shake 0.4s ease";
    setTimeout(() => { el.style.animation = ""; }, 400);
  }

  function showAnimatedLoading(el) {
    const steps = getSelectedSteps();
    const stepHtml = steps.length
      ? steps.map((s, i) => `
          <div class="pb-step running" data-step="${i}" id="load-step-${i}">
            <div class="pb-step-indicator">◌</div>
            <div class="pb-step-content">
              <div class="pb-step-header">
                <span class="pb-step-name">${esc(PLUGIN_LABELS[s.plugin_id] || s.plugin_id)}</span>
                <span class="pb-step-duration">—</span>
              </div>
              <div class="pb-step-status">en attente</div>
            </div>
          </div>`).join("")
      : `<div class="pb-step running active"><div class="pb-step-indicator">◌</div>
         <div class="pb-step-content"><span class="pb-step-name">Orchestration OSINT…</span></div></div>`;

    el.innerHTML = `
      <div class="pb-loading-advanced">
        <div class="pb-loading-header">
          <div class="pb-radar"></div>
          <div>
            <div style="font-weight:600;font-size:0.9375rem">Pipeline en cours d'exécution</div>
            <div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.25rem" id="loadStatusText">Initialisation…</div>
          </div>
        </div>
        <div class="pb-pipeline pb-loading-pipeline" style="background:transparent;border:none;padding:0">
          ${stepHtml}
        </div>
      </div>`;

    let current = 0;
    const texts = ["Collecte des données…", "Analyse des sources…", "Corrélation des entités…", "Génération du rapport…"];

    if (steps.length) {
      loadingInterval = setInterval(() => {
        if (current > 0) {
          const prev = document.getElementById(`load-step-${current - 1}`);
          if (prev) {
            prev.classList.remove("active", "running");
            prev.classList.add("done");
            prev.querySelector(".pb-step-indicator").textContent = "✓";
            prev.querySelector(".pb-step-status").textContent = "terminé";
          }
        }
        if (current < steps.length) {
          const step = document.getElementById(`load-step-${current}`);
          if (step) {
            step.classList.add("active");
            step.querySelector(".pb-step-status").textContent = "en cours…";
          }
          const statusEl = document.getElementById("loadStatusText");
          if (statusEl) statusEl.textContent = texts[current % texts.length];
          current++;
        }
      }, 900);
    }
  }

  function stopLoadingAnimation() {
    if (loadingInterval) {
      clearInterval(loadingInterval);
      loadingInterval = null;
    }
  }

  function renderDashboard(data) {
    const el = document.getElementById("playbookResults");
    const synth = data.synthesis || {};
    const risk = synth.overall_risk || "low";
    const riskColor = RISK_COLORS[risk] || RISK_COLORS.low;
    const as = synth.attack_surface || null;
    const ps = synth.privacy_score || null;

    el.innerHTML = `
      <div class="pb-dashboard">
        <div class="pb-dashboard-header">
          <div class="pb-dashboard-title">
            <h3>${esc(data.playbook_name)}</h3>
            <div class="target">${esc(data.target)}</div>
            <div class="pb-dashboard-meta">
              Type <strong>${esc(data.target_type)}</strong> ·
              ${data.steps?.length || 0} outils ·
              ${formatDuration(data.duration_ms)} ·
              Risque <strong style="color:${riskColor}">${risk.toUpperCase()}</strong>
            </div>
          </div>
          <div class="pb-dashboard-gauges">
            <div class="pb-gauge-wrap" title="Attack Surface — exposition technique">
              <span class="pb-gauge-label">Surface d'attaque</span>
              ${renderAttackSurfaceGauge(as)}
            </div>
            <div class="pb-gauge-wrap" title="Privacy Score — protection vie privée">
              <span class="pb-gauge-label">Privacy Score</span>
              ${renderPrivacyGauge(ps)}
            </div>
          </div>
        </div>

        ${renderAttackSurfaceDetails(as)}
        ${renderPrivacyDetails(ps)}

        <div class="pb-stats">
          <div class="pb-stat success"><div class="pb-stat-value" data-count="${synth.tools_success || 0}">0</div><div class="pb-stat-label">Succès</div></div>
          <div class="pb-stat error"><div class="pb-stat-value" data-count="${synth.tools_failed || 0}">0</div><div class="pb-stat-label">Erreurs</div></div>
          <div class="pb-stat skipped"><div class="pb-stat-value" data-count="${(synth.tools_skipped || 0) + (synth.tools_unavailable || 0)}">0</div><div class="pb-stat-label">Ignorés</div></div>
          <div class="pb-stat entities"><div class="pb-stat-value" data-count="${synth.entities_found || 0}">0</div><div class="pb-stat-label">Entités</div></div>
        </div>

        ${renderFindings(synth.key_findings)}

        <div class="pb-pipeline">
          <div class="pb-section-title">⚙ Pipeline d'investigation</div>
          ${renderPipeline(data.steps)}
        </div>

        ${renderEntities(data.entities)}

        <div class="pb-actions-bar">
          <button type="button" class="pb-export-btn" id="pbViewGraph">🕸 Graphe</button>
          <button type="button" class="pb-export-btn" id="pbViewTimeline">📅 Timeline</button>
          <button type="button" class="pb-export-btn" id="pbViewPrivacy">🔒 Privacy</button>
          <button type="button" class="pb-export-btn" id="pbAddWatch">👁 Surveiller</button>
          <button type="button" class="pb-export-btn" id="pbAddWorkspace">👥 Workspace</button>
          <button type="button" class="pb-export-btn" id="pbExportPdf">📄 Exporter PDF</button>
          <button type="button" class="pb-export-btn" id="pbExportJson">⬇ Exporter JSON</button>
          <button type="button" class="pb-export-btn" id="pbCopyReport">📋 Copier le rapport</button>
        </div>
      </div>`;

    if (as) {
      el.querySelectorAll(".pb-attack-surface .as-bar-fill").forEach((bar) => {
        const pct = parseFloat(bar.dataset.pct) || 0;
        requestAnimationFrame(() => { bar.style.width = `${pct}%`; });
      });
      animateGaugeScore(el.querySelector(".pb-as-gauge .as-score-value"), as.score || 0);
    }

    if (ps) {
      el.querySelectorAll(".pb-privacy .pv-bar-fill").forEach((bar) => {
        const pct = parseFloat(bar.dataset.pct) || 0;
        requestAnimationFrame(() => { bar.style.width = `${pct}%`; });
      });
      animateGaugeScore(el.querySelector(".pb-pv-gauge .pv-score-value"), ps.score || 0);
    }

    el.querySelectorAll(".pb-stat-value[data-count]").forEach((statEl) => {
      const end = parseInt(statEl.dataset.count, 10) || 0;
      animateCount(statEl, end);
    });
  }

  function renderPrivacyGauge(ps) {
    if (!ps) {
      return `<div class="pb-pv-gauge pb-as-empty"><span>N/A</span></div>`;
    }
    const color = ps.color || "#94a3b8";
    const score = ps.score || 0;
    const circ = 2 * Math.PI * 36;
    const offset = circ - (score / 100) * circ;
    return `
      <div class="pb-pv-gauge pb-as-gauge">
        <svg width="100" height="100" viewBox="0 0 88 88">
          <circle cx="44" cy="44" r="36" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="6"/>
          <circle class="pv-ring-fill as-ring-fill" cx="44" cy="44" r="36" fill="none" stroke-width="6"
            stroke="${color}" stroke-linecap="round"
            stroke-dasharray="${circ}" stroke-dashoffset="${circ}"
            data-offset="${offset}" transform="rotate(-90 44 44)"/>
        </svg>
        <div class="pb-as-gauge-center" style="color:${color}">
          <span class="pv-score-value as-score-value">0</span>
          <span class="as-score-max">/100</span>
          <span class="as-grade">${esc(ps.grade_label || "")}</span>
        </div>
      </div>`;
  }

  function renderPrivacyDetails(ps) {
    if (!ps) return "";
    const factors = ps.factors || [];
    const recs = ps.recommendations || [];
    return `
      <div class="pb-privacy pb-attack-surface">
        <div class="pb-section-title">🔒 Privacy Score personnel</div>
        <p class="as-summary">${esc(ps.summary || "")}</p>
        <p class="pv-exposure-line">Exposition totale : <strong>${ps.exposure_total ?? 0}/100</strong></p>
        <div class="as-factors">
          ${factors.map((f) => `
            <div class="as-factor as-sev-${f.severity || "info"}">
              <div class="as-factor-head">
                <span>${esc(f.label)}</span>
                <span class="as-factor-pts">−${f.exposure}/${f.max_exposure}</span>
              </div>
              <div class="as-bar"><div class="pv-bar-fill as-bar-fill" data-pct="${f.pct_exposed || 0}" style="width:0;background:${severityColor(f.severity)}"></div></div>
              <div class="as-factor-detail">${esc(f.details)}</div>
            </div>`).join("")}
        </div>
        ${recs.length ? `
          <div class="as-recs pv-recs">
            <div class="pb-section-title" style="margin-top:12px">🛡 Conseils confidentialité</div>
            <ul>${recs.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
          </div>` : ""}
      </div>`;
  }

  function renderAttackSurfaceGauge(as) {
    if (!as) {
      return `<div class="pb-as-gauge pb-as-empty"><span>Score N/A</span></div>`;
    }
    const color = as.color || "#94a3b8";
    const score = as.score || 0;
    const circ = 2 * Math.PI * 36;
    const offset = circ - (score / 100) * circ;
    return `
      <div class="pb-as-gauge">
        <svg width="100" height="100" viewBox="0 0 88 88">
          <circle cx="44" cy="44" r="36" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="6"/>
          <circle class="as-ring-fill" cx="44" cy="44" r="36" fill="none" stroke-width="6"
            stroke="${color}" stroke-linecap="round"
            stroke-dasharray="${circ}" stroke-dashoffset="${circ}"
            data-offset="${offset}" transform="rotate(-90 44 44)"/>
        </svg>
        <div class="pb-as-gauge-center" style="color:${color}">
          <span class="as-score-value">0</span>
          <span class="as-score-max">/100</span>
          <span class="as-grade">${esc(as.grade_label || "")}</span>
        </div>
      </div>`;
  }

  function renderAttackSurfaceDetails(as) {
    if (!as) return "";
    const factors = as.factors || [];
    const recs = as.recommendations || [];
    return `
      <div class="pb-attack-surface">
        <div class="pb-section-title">🎯 Attack Surface Score</div>
        <p class="as-summary">${esc(as.summary || "")}</p>
        <div class="as-factors">
          ${factors.map((f) => `
            <div class="as-factor as-sev-${f.severity || "info"}">
              <div class="as-factor-head">
                <span>${esc(f.label)}</span>
                <span class="as-factor-pts">${f.score}/${f.max_score}</span>
              </div>
              <div class="as-bar"><div class="as-bar-fill" data-pct="${f.pct || 0}" style="width:0;background:${severityColor(f.severity)}"></div></div>
              <div class="as-factor-detail">${esc(f.details)}</div>
            </div>`).join("")}
        </div>
        ${recs.length ? `
          <div class="as-recs">
            <div class="pb-section-title" style="margin-top:12px">💡 Recommandations</div>
            <ul>${recs.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
          </div>` : ""}
      </div>`;
  }

  function severityColor(sev) {
    return { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#22c55e", info: "#64748b" }[sev] || "#64748b";
  }

  function animateGaugeScore(el, end) {
    if (!el) return;
    const gauge = el.closest(".pb-as-gauge, .pb-pv-gauge");
    const ring = gauge?.querySelector(".as-ring-fill, .pv-ring-fill");
    const start = performance.now();
    const dur = 800;
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

  function animateAttackScore(el, end) {
    animateGaugeScore(el, end);
  }

  function animateCount(el, end) {
    const start = performance.now();
    const dur = 700;
    function tick(now) {
      const t = Math.min((now - start) / dur, 1);
      el.textContent = Math.round(end * (1 - Math.pow(1 - t, 3)));
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function renderFindings(findings) {
    if (!findings?.length) return "";
    return `
      <div class="pb-findings">
        <div class="pb-section-title">🔍 Constats clés</div>
        ${findings.map((f) => `
          <div class="pb-finding-item">
            <span class="pb-finding-dot ${f.includes("VirusTotal") || f.includes("vulnérabilité") ? "critical" : ""}"></span>
            <span>${esc(f)}</span>
          </div>`).join("")}
      </div>`;
  }

  function renderPipeline(steps) {
    if (!steps?.length) return `<p style="color:var(--text-muted);font-size:0.8125rem">Aucune étape.</p>`;
    const icons = { success: "✓", error: "✗", skipped: "—", unavailable: "○" };

    return steps.map((step, i) => `
      <div class="pb-step ${step.status}">
        <div class="pb-step-indicator">${icons[step.status] || i + 1}</div>
        <div class="pb-step-content">
          <div class="pb-step-header">
            <span class="pb-step-name">${esc(step.plugin_name)}</span>
            <span class="pb-step-duration">${step.duration_ms}ms</span>
          </div>
          <div class="pb-step-status">${step.status}</div>
          ${step.error ? `<div class="pb-step-error">${esc(step.error)}</div>` : ""}
          ${step.status === "success" ? `<div class="pb-step-detail">${stepSummary(step)}</div>` : ""}
        </div>
      </div>`).join("");
  }

  function stepSummary(step) {
    const d = step.data || {};
    const map = {
      leakcheck: () => `${d.breach_count || 0} fuite(s) · risque ${d.risk_level || "N/A"}`,
      sherlock: () => `${d.count || 0} profil(s) trouvé(s)`,
      virustotal: () => `${d.detections || 0}/${d.total || 0} détections antivirus`,
      abuseipdb: () => `Score réputation : ${d.abuseConfidence || 0}%`,
      shodan_ip: () => `${(d.ports || []).length} port(s) · ${d.vuln_count || 0} vulnérabilité(s)`,
      shodan_search: () => `${d.matches_count || 0} résultat(s) Shodan`,
      whois: () => {
        const org = d.data?.org || d.data?.asn_org || "N/A";
        return `Type ${d.type} · ${org}`;
      },
    };
    return esc(map[step.plugin_id]?.() || "Données collectées");
  }

  function renderEntities(entities) {
    if (!entities?.length) {
      return `<div class="pb-entities"><div class="pb-section-title" style="padding:0 0 8px">Entités découvertes</div>
        <p style="padding:0 1rem 1rem;color:var(--text-muted);font-size:0.8125rem">Aucune entité extraite.</p></div>`;
    }

    return `
      <div class="pb-entities">
        <div class="pb-section-title" style="padding:1rem 1rem 0">🔗 Entités découvertes (${entities.length})</div>
        <table class="pb-entities-table">
          <thead><tr><th>Type</th><th>Valeur</th><th>Source</th></tr></thead>
          <tbody>
            ${entities.map((e, i) => `
              <tr style="animation-delay:${i * 0.05}s">
                <td><span class="entity-type-badge">${esc(e.type)}</span></td>
                <td><span class="entity-value">${esc(e.value)}</span></td>
                <td>${esc(e.source)}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  function exportJson() {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `investigation-${lastResult.target.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    window.updateTerminal?.("Rapport JSON exporté");
  }

  async function exportPdf() {
    if (!lastResult) return;
    const btn = document.getElementById("pbExportPdf");
    const prev = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Génération…"; }
    try {
      const res = await fetch("/api/report/from-investigation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ investigation: lastResult }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const disp = res.headers.get("Content-Disposition") || "";
      const match = disp.match(/filename="?([^";]+)"?/);
      const filename = match?.[1] || `rapport-osint_${Date.now()}.pdf`;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      URL.revokeObjectURL(a.href);
      window.updateTerminal?.("Rapport PDF exporté");
    } catch (e) {
      window.updateTerminal?.(`[PDF] Erreur : ${e.message}`);
      console.error("[PDF]", e);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = prev || "📄 Exporter PDF"; }
    }
  }

  function copyReport() {
    if (!lastResult) return;
    const s = lastResult.synthesis || {};
    const lines = [
      `RAPPORT D'INVESTIGATION OSINT`,
      `==============================`,
      `Playbook : ${lastResult.playbook_name}`,
      `Cible    : ${lastResult.target} (${lastResult.target_type})`,
      `Durée    : ${formatDuration(lastResult.duration_ms)}`,
      `Risque   : ${(s.overall_risk || "low").toUpperCase()}`,
      `Attack Surface : ${s.attack_surface?.score ?? "N/A"}/100 (${s.attack_surface?.grade_label || "N/A"})`,
      `Privacy Score  : ${s.privacy_score?.score ?? "N/A"}/100 (${s.privacy_score?.grade_label || "N/A"})`,
      ``,
      `CONSTATS :`,
      ...(s.key_findings || []).map((f) => `  • ${f}`),
      ``,
      `PIPELINE :`,
      ...(lastResult.steps || []).map((st) => `  [${st.status}] ${st.plugin_name} (${st.duration_ms}ms)`),
      ``,
      `ENTITÉS (${(lastResult.entities || []).length}) :`,
      ...(lastResult.entities || []).map((e) => `  ${e.type}: ${e.value}`),
    ];
    navigator.clipboard.writeText(lines.join("\n")).then(() => {
      window.updateTerminal?.("Rapport copié dans le presse-papiers");
    });
  }

  function formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init };
})();

document.addEventListener("DOMContentLoaded", () => {
  try { PlaybooksUI.init(); } catch (e) { console.error("[PLAYBOOKS]", e); }
});
