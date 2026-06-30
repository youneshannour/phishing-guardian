/**
 * Investigator AI — Chat OSINT + orchestration playbooks
 */
const InvestigatorAI = (() => {
  let history = [];
  let busy = false;

  const RISK_COLORS = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#f59e0b",
    low: "#22c55e",
  };

  function init() {
    const form = document.getElementById("aiChatForm");
    const input = document.getElementById("aiChatInput");
    const prompts = document.querySelector(".ai-quick-prompts");
    if (!form || !input) return;

    checkStatus();
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      e.stopPropagation();
      sendMessage(input.value.trim());
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage(input.value.trim());
      }
    });

    if (prompts) {
      prompts.addEventListener("click", (e) => {
        const chip = e.target.closest(".ai-prompt-chip[data-prompt]");
        if (!chip) return;
        e.preventDefault();
        sendMessage(chip.getAttribute("data-prompt") || "");
      });
    }
  }

  async function checkStatus() {
    const badge = document.getElementById("aiStatusBadge");
    const help = document.getElementById("aiOllamaHelp");
    if (!badge) return;

    try {
      const res = await fetch("/api/ai/status");
      const data = await res.json();
      const online = data.available && data.model_available;
      badge.classList.toggle("online", online);
      badge.classList.toggle("offline", !online);

      const text = badge.querySelector(".ai-status-text");
      if (text) {
        if (online) {
          text.textContent = `Ollama · ${data.active_model || data.configured_model}`;
        } else if (data.available) {
          text.textContent = "Ollama sans modèle";
        } else {
          text.textContent = "OSINT actif · IA hors-ligne";
        }
      }

      if (help) {
        help.classList.toggle("hidden", online);
        const models = (data.models || []).slice(0, 4).join(", ");
        const modelHint = data.available
          ? `Modèle attendu : <code>${esc(data.configured_model)}</code>${models ? ` — installés : ${esc(models)}` : ""}`
          : "Ollama n'est pas démarré sur ce PC.";
        help.innerHTML = `
          <strong>Investigations OSINT : disponibles</strong> même sans Ollama (rapport automatique).
          <span class="ai-ollama-hint">${modelHint}</span>
          <ol class="ai-ollama-steps">
            <li>Installez <a href="https://ollama.com/download" target="_blank" rel="noopener">Ollama</a></li>
            <li>Dans un terminal : <code>ollama pull mistral</code></li>
            <li>Vérifiez : <code>ollama serve</code> (démarre souvent automatiquement)</li>
          </ol>`;
      }
    } catch {
      badge.classList.add("offline");
      badge.classList.remove("online");
      const text = badge.querySelector(".ai-status-text");
      if (text) text.textContent = "Serveur IA indisponible";
      help?.classList.remove("hidden");
    }
  }

  async function sendMessage(message) {
    if (!message || busy) return;

    const input = document.getElementById("aiChatInput");
    const sendBtn = document.getElementById("aiChatSend");
    busy = true;
    if (sendBtn) sendBtn.classList.add("running");
    if (input) input.disabled = true;

    appendMessage("user", message);
    history.push({ role: "user", content: message });
    if (input) input.value = "";

    const typingEl = appendMessage("assistant", "Analyse en cours…", true);

    try {
      const res = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, history: history.slice(-10) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur serveur");

      typingEl.remove();
      appendMessage("assistant", data.reply, false, data.ai_powered);
      history.push({ role: "assistant", content: data.reply });

      if (data.investigation) {
        renderInvestigation(data.investigation, data.target);
        window.updateTerminal?.(`[AI] Investigation ${data.target} — risque ${data.investigation.synthesis?.overall_risk || "N/A"}`);
      } else {
        window.updateTerminal?.(`[AI] ${message.substring(0, 80)}`);
      }
    } catch (err) {
      typingEl.remove();
      appendMessage("assistant", `Erreur : ${err.message}`);
    } finally {
      busy = false;
      if (sendBtn) sendBtn.classList.remove("running");
      if (input) {
        input.disabled = false;
        input.focus();
      }
    }
  }

  function appendMessage(role, content, isTyping = false, aiPowered = false) {
    const container = document.getElementById("aiChatMessages");
    if (!container) return document.createElement("div");

    const el = document.createElement("div");
    el.className = `ai-msg ${role}${isTyping ? " typing" : ""}`;

    const avatar = role === "user" ? "👤" : "🤖";
    const formatted = formatMarkdown(content);

    el.innerHTML = `
      <div class="ai-msg-avatar">${avatar}</div>
      <div class="ai-msg-body">
        ${formatted}
        ${aiPowered && role === "assistant" ? '<span class="ai-powered-tag">IA</span>' : ""}
      </div>`;

    container.appendChild(el);
    container.scrollTop = container.scrollHeight;
    return el;
  }

  function formatMarkdown(text) {
    if (!text) return "";
    let html = esc(text);
    html = html.replace(/^## (.+)$/gm, "<h4>$1</h4>");
    html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
    html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
    html = html.replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`);
    html = html.replace(/\n\n/g, "</p><p>");
    html = `<p>${html}</p>`;
    html = html.replace(/<p><h4>/g, "<h4>").replace(/<\/h4><\/p>/g, "</h4>");
    html = html.replace(/<p><ul>/g, "<ul>").replace(/<\/ul><\/p>/g, "</ul>");
    return html;
  }

  function renderInvestigation(data, target) {
    const panel = document.getElementById("aiInvestigationContent");
    if (!panel) return;

    const synth = data.synthesis || {};
    const as = synth.attack_surface || {};
    const ps = synth.privacy_score || {};
    const risk = synth.overall_risk || "low";
    const riskColor = RISK_COLORS[risk] || RISK_COLORS.low;

    panel.innerHTML = `
      <div class="ai-inv-summary">
        <div class="ai-inv-target">
          <span class="label">Cible</span>
          <code>${esc(target || data.target)}</code>
        </div>
        <div class="ai-inv-risk" style="--risk-color:${riskColor}">
          <span class="label">Surface</span>
          <span class="value" style="color:${as.color || riskColor}">${as.score ?? "—"}/100</span>
        </div>
        <div class="ai-inv-risk">
          <span class="label">Privacy</span>
          <span class="value" style="color:${ps.color || '#22c55e'}">${ps.score ?? "—"}/100</span>
        </div>
      </div>
      <div class="ai-inv-as-grade" style="color:${as.color || '#94a3b8'}">${esc(as.grade_label || "")} · <span style="color:${ps.color || '#22c55e'}">${esc(ps.grade_label || "")}</span></div>
      <div class="ai-inv-stats">
        <div class="ai-inv-stat"><span>${synth.tools_success || 0}</span><small>Succès</small></div>
        <div class="ai-inv-stat"><span>${synth.entities_found || 0}</span><small>Entités</small></div>
        <div class="ai-inv-stat"><span>${data.duration_ms || 0}ms</span><small>Durée</small></div>
      </div>
      <div class="ai-inv-playbook">
        <span class="label">Playbook</span> ${esc(data.playbook_name)}
      </div>
      ${(synth.key_findings || []).length ? `
        <div class="ai-inv-findings">
          <div class="label">Constats</div>
          <ul>${synth.key_findings.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>
        </div>` : ""}
      <div class="ai-inv-actions">
        <button type="button" class="pb-export-btn" id="aiViewGraph">🕸 Graphe</button>
        <button type="button" class="pb-export-btn" id="aiViewTimeline">📅 Timeline</button>
        <button type="button" class="pb-export-btn" id="aiViewPrivacy">🔒 Privacy</button>
        <button type="button" class="pb-export-btn" id="aiAddWatch">👁 Surveiller</button>
        <button type="button" class="pb-export-btn" id="aiAddWorkspace">👥 Workspace</button>
        <button type="button" class="pb-export-btn" id="aiExportPdf">📄 PDF</button>
        <button type="button" class="pb-export-btn" id="aiOpenPlaybooks">Playbooks</button>
      </div>`;

    document.getElementById("aiViewGraph")?.addEventListener("click", () => {
      window.GraphUI?.loadFromInvestigation(data);
    });
    document.getElementById("aiViewTimeline")?.addEventListener("click", () => {
      window.TimelineUI?.loadFromInvestigation(data);
    });
    document.getElementById("aiViewPrivacy")?.addEventListener("click", () => {
      window.PrivacyUI?.loadFromInvestigation(data);
    });
    document.getElementById("aiAddWatch")?.addEventListener("click", () => {
      window.WatchUI?.addFromInvestigation(data);
    });
    document.getElementById("aiAddWorkspace")?.addEventListener("click", () => {
      window.WorkspaceUI?.addInvestigation(data);
    });
    document.getElementById("aiExportPdf")?.addEventListener("click", () => exportPdf(data));
    document.getElementById("aiOpenPlaybooks")?.addEventListener("click", () => {
      window.activatePGPanel?.("panel-playbooks");
      const targetInput = document.getElementById("playbookTarget");
      if (targetInput && data.target) {
        targetInput.value = data.target;
        targetInput.dispatchEvent(new Event("input"));
      }
    });
  }

  async function exportPdf(investigation) {
    if (!investigation) return;
    const btn = document.getElementById("aiExportPdf");
    const prev = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = "⏳…"; }
    try {
      const res = await fetch("/api/report/from-investigation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ investigation }),
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
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = prev || "📄 PDF"; }
    }
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init, checkStatus };
})();

window.InvestigatorAI = InvestigatorAI;

document.addEventListener("DOMContentLoaded", () => {
  try { InvestigatorAI.init(); } catch (e) { console.error("[AI]", e); }
});
