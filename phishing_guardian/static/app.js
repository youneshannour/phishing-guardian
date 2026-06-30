// ========== INITIALISATION ==========
document.addEventListener("DOMContentLoaded", () => {
  try { initNavigation(); } catch (e) { console.error("[NAV]", e); }
  try { initPhishing(); } catch (e) { console.error("[PHISHING]", e); }
  try { initShodan(); } catch (e) { console.error("[SHODAN]", e); }
  try { initVirusTotal(); } catch (e) { console.error("[VT]", e); }
  try { initAbuseIPDB(); } catch (e) { console.error("[ABUSEIPDB]", e); }
  try { initWhois(); } catch (e) { console.error("[WHOIS]", e); }
  try { initLeakCheck(); } catch (e) { console.error("[LEAKCHECK]", e); }
  try { initExifTool(); } catch (e) { console.error("[EXIF]", e); }
  try { initVulnerabilities(); } catch (e) { console.error("[VULN]", e); }
  updateTerminal("Tous les modules initialisés et prêts.");
});

// ========== ACTIVITY LOG ==========
function updateTerminal(message) {
  const terminalOutput = document.getElementById("terminalOutput");
  if (terminalOutput) {
    const time = new Date().toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const newLine = document.createElement("div");
    newLine.className = "log-line";
    newLine.textContent = `${time} — ${message}`;
    terminalOutput.appendChild(newLine);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
    while (terminalOutput.children.length > 50) {
      terminalOutput.removeChild(terminalOutput.firstChild);
    }
  }
}
window.updateTerminal = updateTerminal;

// ========== SIDEBAR NAVIGATION ==========
function initNavigation() {
  const pageTitle = document.getElementById("pageTitle");
  const pageSubtitle = document.getElementById("pageSubtitle");

  function getPanels() {
    return document.querySelectorAll("main.content > .panel");
  }

  function activatePanel(btn) {
    const target = btn.getAttribute("data-target");
    if (!target) return;

    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");

    getPanels().forEach((panel) => panel.classList.add("hidden"));
    document.getElementById(target)?.classList.remove("hidden");

    if (pageTitle) pageTitle.textContent = btn.getAttribute("data-title") || "";
    if (pageSubtitle) pageSubtitle.textContent = btn.getAttribute("data-subtitle") || "";
    updateTerminal(`Module actif : ${btn.getAttribute("data-title")}`);

    if (target === "panel-investigator") {
      window.InvestigatorAI?.checkStatus?.();
    }
  }

  const nav = document.querySelector(".sidebar-nav");
  if (nav) {
    nav.addEventListener("click", (e) => {
      const btn = e.target.closest(".nav-item[data-target]");
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      activatePanel(btn);
    });
  }

  window.activatePGPanel = (panelId) => {
    const btn = document.querySelector(`.nav-item[data-target="${panelId}"]`);
    if (btn) activatePanel(btn);
  };

  const activeNav = document.querySelector(".nav-item.active[data-target]");
  if (activeNav) {
    activatePanel(activeNav);
  }
}

// ========== PHISHING ANALYSIS ==========
function initPhishing() {
  const analyzeBtn = document.getElementById("analyzeBtn");
  const emailImageInput = document.getElementById("emailImage");
  const imagePreview = document.getElementById("imagePreview");
  const previewImg = document.getElementById("previewImg");
  
  if (!analyzeBtn) return;

  // Gestion de l'upload d'image
  if (emailImageInput) {
    emailImageInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
          previewImg.src = event.target.result;
          imagePreview.classList.remove("hidden");
        };
        reader.readAsDataURL(file);
      } else {
        imagePreview.classList.add("hidden");
      }
    });
  }

  analyzeBtn.addEventListener("click", async () => {
    const email = document.getElementById("email").value.trim();
    const urlsRaw = document.getElementById("urls").value.trim();
    const urls = urlsRaw.length > 0 ? urlsRaw.split(",").map((u) => u.trim()).filter((u) => u.length > 0) : [];
    const imageFile = emailImageInput?.files[0];

    // Si une image est fournie, utiliser l'OCR
    if (imageFile) {
      analyzeBtn.disabled = true;
      document.getElementById("spinner").classList.remove("hidden");
      updateTerminal("[PHISHING] Analyzing image with OCR...");

      try {
        const formData = new FormData();
        formData.append("file", imageFile);

        const response = await fetch("/api/analyze-image", {
          method: "POST",
          body: formData,
        });

        if (!response.ok) throw new Error("HTTP " + response.status);

        const data = await response.json();
        
        // Afficher le résultat de l'OCR avec statistiques
        if (data.success && data.extracted_text) {
          const stats = data.statistics || {};
          const statsMsg = stats.words ? ` (${stats.words} mots, ${stats.lines} lignes)` : '';
          updateTerminal(`[OCR] ✅ Texte extrait: ${data.extracted_text.substring(0, 150)}${data.extracted_text.length > 150 ? '...' : ''}${statsMsg}`);
          
          if (stats.has_email) {
            updateTerminal(`[OCR] 📧 Email détecté dans le texte`);
          }
          if (stats.has_url) {
            updateTerminal(`[OCR] 🔗 URL détectée dans le texte`);
          }
          
          // Remplir automatiquement le champ email avec le texte extrait
          document.getElementById("email").value = data.extracted_text;
          
          // Analyser le texte extrait
          updateTerminal(`[PHISHING] 🔍 Analyse du texte extrait...`);
          const analyzeResponse = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
              email: data.extracted_text, 
              urls 
            }),
          });

          if (!analyzeResponse.ok) {
            const errorText = await analyzeResponse.text();
            throw new Error(`HTTP ${analyzeResponse.status}: ${errorText}`);
          }

          const analyzeData = await analyzeResponse.json();
          renderPhishingResult(analyzeData);
          updateTerminal(`[PHISHING] ✅ Analyse complète. ${data.message || 'Texte analysé avec succès.'}`);
        } else {
          // Afficher un message d'erreur ou d'avertissement avec détails
          const errorMsg = data.message || data.warning || "Aucun texte extrait de l'image";
          updateTerminal(`[OCR] ⚠️ ${errorMsg}`);
          
          if (data.ocr_errors && data.ocr_errors.length > 0) {
            updateTerminal(`[OCR] Erreurs: ${data.ocr_errors.join(', ')}`);
          }
          
          // Afficher le message dans l'interface avec plus de détails
          const resultDiv = document.getElementById("phishingResult");
          if (resultDiv) {
            const imageInfo = data.image_info || {};
            resultDiv.innerHTML = `
              <div class="bg-yellow-500/10 border border-yellow-500/50 rounded-lg p-4">
                <h3 class="text-yellow-400 font-bold mb-2">⚠️ OCR - Avertissement</h3>
                <p class="text-gray-300 mb-2">${errorMsg}</p>
                ${imageInfo.original_size ? `<p class="text-gray-400 text-sm mb-1">Taille image: ${imageInfo.original_size} → ${imageInfo.processed_size || 'N/A'}</p>` : ''}
                ${data.extracted_text ? `
                  <div class="mt-3 p-2 bg-gray-800/50 rounded">
                    <p class="text-gray-400 text-xs mb-1">Texte partiel extrait:</p>
                    <p class="text-gray-300 text-sm font-mono">${data.extracted_text.substring(0, 300)}${data.extracted_text.length > 300 ? '...' : ''}</p>
                  </div>
                ` : ''}
                ${data.ocr_errors && data.ocr_errors.length > 0 ? `
                  <div class="mt-2 p-2 bg-red-900/20 rounded">
                    <p class="text-red-400 text-xs">Erreurs OCR:</p>
                    <ul class="text-red-300 text-xs list-disc list-inside">
                      ${data.ocr_errors.map(e => `<li>${e}</li>`).join('')}
                    </ul>
                  </div>
                ` : ''}
              </div>
            `;
          }
        }
      } catch (err) {
        updateTerminal(`[ERROR] ${err.message}`);
      } finally {
        analyzeBtn.disabled = false;
        document.getElementById("spinner").classList.add("hidden");
      }
      return;
    }

    // Analyse normale (texte)
    if (!email && urls.length === 0) {
      updateTerminal("[ERROR] No input provided");
      return;
    }

    analyzeBtn.disabled = true;
    document.getElementById("spinner").classList.remove("hidden");
    updateTerminal("[PHISHING] Executing analysis...");

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, urls }),
      });

      if (!response.ok) throw new Error("HTTP " + response.status);

      const data = await response.json();
      renderPhishingResult(data);
      updateTerminal("[PHISHING] Analysis complete. Results displayed.");
    } catch (err) {
      updateTerminal(`[ERROR] ${err.message}`);
    } finally {
      analyzeBtn.disabled = false;
      document.getElementById("spinner").classList.add("hidden");
    }
  });
}

function renderPhishingResult(data) {
  const synth = data.synthetique || { niveau: "faible", score: 0 };
  const stats = data.statistics || {};
  const riskBadge = document.getElementById("riskBadge");
  const riskSummaryEl = document.getElementById("riskSummary");
  const detailsEl = document.getElementById("details");

  const styles = {
    critique: { class: "risk-critique", text: "[CRITICAL_THREAT]" },
    eleve: { class: "risk-eleve", text: "[HIGH_RISK]" },
    modere: { class: "risk-modere", text: "[MODERATE_RISK]" },
    default: { class: "risk-faible", text: "[LOW_RISK]" },
  };
  const style = styles[synth.niveau] || styles.default;

  riskBadge.className = `px-4 py-2 rounded border-2 font-share-tech text-xs ${style.class}`;
  riskBadge.textContent = style.text;
  riskBadge.classList.remove("hidden");

  riskSummaryEl.innerHTML = `
    <div class="text-green-400 font-share-tech space-y-2">
      <div>&gt; RISK_SCORE: <span class="text-green-300 font-bold text-lg">${synth.score.toFixed(3)}</span></div>
      <div>&gt; LEVEL: <span class="${style.class.replace('risk-', 'text-')} font-bold">${synth.niveau.toUpperCase()}</span></div>
      ${Object.keys(stats).length > 0 ? `
        <div class="mt-3 pt-2 border-t border-green-500/30">
          <div class="text-green-500 font-bold mb-1">&gt; STATISTICS</div>
          <div class="text-xs space-y-1">
            ${stats.total_urls_analyzed !== undefined ? `<div>URLS_ANALYZED: ${stats.total_urls_analyzed}</div>` : ""}
            ${stats.phishing_urls !== undefined ? `<div>PHISHING_URLS: <span class="text-red-400 font-bold">${stats.phishing_urls}</span></div>` : ""}
            ${stats.legitimate_urls !== undefined ? `<div>LEGITIMATE_URLS: <span class="text-green-300">${stats.legitimate_urls}</span></div>` : ""}
            ${stats.email_analyzed !== undefined ? `<div>EMAIL_ANALYZED: ${stats.email_analyzed ? "YES" : "NO"}</div>` : ""}
            ${stats.email_is_phishing !== undefined ? `<div>EMAIL_PHISHING: <span class="${stats.email_is_phishing ? 'text-red-400' : 'text-green-300'}">${stats.email_is_phishing ? "YES" : "NO"}</span></div>` : ""}
          </div>
        </div>
      ` : ""}
      <div class="text-green-600 text-xs mt-2">&gt; Calculated from max risk between email and URLs</div>
    </div>
  `;

  detailsEl.innerHTML = "";

  if (data.email) {
    const e = data.email;
    const div = document.createElement("div");
    div.className = "result-hacking mb-3";
    div.innerHTML = `
      <div class="text-green-500 font-bold mb-2">&gt; EMAIL_ANALYSIS</div>
      <div class="text-green-400 text-xs font-share-tech space-y-1">
        <div>LABEL: <span class="${e.label === 'phishing' ? 'text-red-400' : e.label === 'suspect' ? 'text-yellow-400' : 'text-green-300'} font-bold text-base">${e.label.toUpperCase()}</span></div>
        <div>SCORE: <span class="font-mono font-bold">${e.score.toFixed(3)}</span></div>
        ${(e.indicators || []).length > 0 ? `<div class="mt-2">INDICATORS:<ul class="list-disc list-inside ml-4 space-y-1">${e.indicators.map(i => `<li class="text-green-300">${i}</li>`).join("")}</ul></div>` : ""}
        <div class="mt-1 text-green-600">MODEL: ${e.model_used}</div>
      </div>
    `;
    detailsEl.appendChild(div);
  }

  if (data.urls && data.urls.length > 0) {
    data.urls.forEach((u) => {
      const div = document.createElement("div");
      div.className = "result-hacking mb-3";
      div.innerHTML = `
        <div class="text-green-500 font-bold mb-2">&gt; URL: <span class="text-green-300 break-all font-mono text-xs">${u.url}</span></div>
        <div class="text-green-400 text-xs font-share-tech space-y-1">
          <div>LABEL: <span class="${u.label === 'phishing' ? 'text-red-400' : u.label === 'suspect' ? 'text-yellow-400' : 'text-green-300'} font-bold">${u.label.toUpperCase()}</span></div>
          <div>SCORE: <span class="font-mono font-bold">${u.score.toFixed(3)}</span></div>
          ${(u.indicators || []).length > 0 ? `<div class="mt-2">INDICATORS:<ul class="list-disc list-inside ml-4 space-y-1">${u.indicators.map(i => `<li class="text-green-300">${i}</li>`).join("")}</ul></div>` : ""}
          <div class="mt-1 text-green-600">MODEL: ${u.model_used}</div>
        </div>
      `;
      detailsEl.appendChild(div);
    });
  }
}

// ========== SHODAN ==========
function initShodan() {
  const shodanIpBtn = document.getElementById("shodanIpBtn");
  const shodanQueryBtn = document.getElementById("shodanQueryBtn");

  if (shodanIpBtn) {
    shodanIpBtn.addEventListener("click", async () => {
      const ip = document.getElementById("shodanIp").value.trim();
      if (!ip) return;
      updateTerminal(`[SHODAN] Querying IP: ${ip}`);
      const el = document.getElementById("shodanResults");
      el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Querying Shodan...</div>';

      try {
        const res = await fetch("/api/shodan/ip", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip }),
        });
        if (!res.ok) throw new Error((await res.json()).detail || "Error");
        const data = await res.json();
        renderShodanIp(data, el);
        updateTerminal(`[SHODAN] Query complete for ${ip}`);
      } catch (e) {
        el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
        updateTerminal(`[ERROR] ${e.message}`);
      }
    });
  }

  if (shodanQueryBtn) {
    shodanQueryBtn.addEventListener("click", async () => {
      const query = document.getElementById("shodanQuery").value.trim();
      if (!query) return;
      updateTerminal(`[SHODAN] Executing search: ${query}`);
      const el = document.getElementById("shodanResults");
      el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Searching...</div>';

      try {
        const res = await fetch("/api/shodan/search", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query }),
        });
        if (!res.ok) throw new Error((await res.json()).detail || "Error");
        const data = await res.json();
        renderShodanSearch(data, el);
        updateTerminal("[SHODAN] Search complete");
      } catch (e) {
        el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
        updateTerminal(`[ERROR] ${e.message}`);
      }
    });
  }
}

function renderShodanIp(data, el) {
  const analysis = data.analysis || {};
  const services = data.services || [];
  const geoloc = data.geolocation || {};
  
  el.innerHTML = `
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; IP: ${data.ip}</div>
      <div class="text-green-400 text-xs font-share-tech space-y-1">
        <div>ORG: <span class="text-green-300 font-bold">${data.org || "N/A"}</span></div>
        <div>ISP: ${data.isp || "N/A"}</div>
        <div>OS: ${data.os || "N/A"}</div>
        <div>PORTS_OPEN: <span class="text-blue-300 font-mono font-bold">${(data.ports || []).join(", ") || "N/A"}</span> (${analysis.total_ports || 0} total)</div>
        <div>HOSTNAMES: <span class="text-amber-300">${(data.hostnames || []).join(", ") || "N/A"}</span></div>
        <div>VULNS: <span class="text-red-300 font-bold">${(data.vulns || []).join(", ") || "None"}</span> (${analysis.total_vulns || 0} total)</div>
        ${geoloc.country ? `<div>LOCATION: ${geoloc.city || ""} ${geoloc.country || ""}</div>` : ""}
        <div class="text-green-600 mt-2">RISK_LEVEL: <span class="${analysis.risk_level === 'high' ? 'text-red-400' : analysis.risk_level === 'medium' ? 'text-yellow-400' : 'text-green-300'}">${(analysis.risk_level || 'low').toUpperCase()}</span></div>
        <div class="text-green-600">LAST_UPDATE: ${data.last_update || "N/A"}</div>
      </div>
    </div>
    ${services.length > 0 ? `
      <div class="result-hacking">
        <div class="text-green-500 font-bold mb-2">&gt; SERVICES_DETECTED (${services.length})</div>
        <div class="space-y-2 max-h-96 overflow-y-auto">
          ${services.map(s => `
            <div class="bg-black/40 p-2 rounded border border-green-500/30">
              <div class="text-green-400 text-xs font-share-tech">
                <div>PORT: <span class="text-blue-300 font-mono">${s.port || "N/A"}</span> | PRODUCT: <span class="text-green-300">${s.product || "N/A"}</span> ${s.version ? `| VERSION: ${s.version}` : ""}</div>
                ${s.banner ? `<div class="text-green-600 mt-1 font-mono text-[10px]">BANNER: ${s.banner.substring(0, 100)}...</div>` : ""}
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    ` : ""}
  `;
}

function renderShodanSearch(data, el) {
  const matches = data.matches || [];
  if (matches.length === 0) {
    el.innerHTML = '<div class="text-green-400">&gt; No results found</div>';
    return;
  }
  const html = matches.slice(0, 25).map((m) => `
    <div class="result-hacking mb-2">
      <div class="text-green-500 font-mono text-xs font-bold">${m.ip_str || "N/A"}:${m.port || "N/A"}</div>
      <div class="text-green-400 text-xs">ORG: ${m.org || "N/A"} | ${(m.location || {}).country_name || ""}</div>
      <div class="text-green-600 text-xs">PRODUCT: ${m.product || "N/A"}</div>
    </div>
  `).join("");
  el.innerHTML = `<div class="space-y-2 max-h-[500px] overflow-y-auto">${html}</div>`;
}

// ========== VIRUSTOTAL ==========
function initVirusTotal() {
  const btn = document.getElementById("virustotalBtn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const query = document.getElementById("virustotalQuery").value.trim();
    if (!query) return;
    updateTerminal(`[VIRUSTOTAL] Scanning: ${query}`);
    const el = document.getElementById("virustotalResults");
    el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Scanning with 70+ engines...</div>';

    try {
      const res = await fetch("/api/virustotal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Error");
      const data = await res.json();
      renderVirusTotal(data, el);
      updateTerminal("[VIRUSTOTAL] Scan complete");
    } catch (e) {
      el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
      updateTerminal(`[ERROR] ${e.message}`);
    }
  });
}

function renderVirusTotal(data, el) {
  const detections = data.detections || 0;
  const total = data.total || 0;
  const ratio = data.ratio || 0;
  const riskLevel = data.risk_level || "low";
  const engines = data.detecting_engines || [];
  
  el.innerHTML = `
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; SCAN_RESULTS: ${data.query}</div>
      <div class="text-green-400 text-xs font-share-tech space-y-2">
        <div>TYPE: <span class="text-green-300 font-bold">${data.type.toUpperCase()}</span></div>
        <div>DETECTIONS: <span class="${detections > 0 ? 'text-red-400' : 'text-green-300'} font-bold text-lg">${detections}/${total}</span></div>
        <div>DETECTION_RATIO: <span class="font-mono font-bold">${ratio}%</span></div>
        <div>RISK_LEVEL: <span class="${riskLevel === 'critical' ? 'text-red-400' : riskLevel === 'high' ? 'text-orange-400' : riskLevel === 'medium' ? 'text-yellow-400' : 'text-green-300'} font-bold">${riskLevel.toUpperCase()}</span></div>
        ${data.scan_date ? `<div>SCAN_DATE: ${data.scan_date}</div>` : ""}
        ${engines.length > 0 ? `
          <div class="mt-2">
            <div class="text-green-500 font-bold mb-1">DETECTING_ENGINES (${engines.length}):</div>
            <div class="text-green-600 text-[10px] font-mono">${engines.join(", ")}</div>
          </div>
        ` : ""}
        ${detections > 0 ? '<div class="text-red-400 font-bold mt-3">⚠️ THREAT DETECTED</div>' : '<div class="text-green-300 font-bold mt-3">✓ CLEAN</div>'}
        ${data.permalink ? `<div class="mt-2"><a href="${data.permalink}" target="_blank" class="text-blue-400 hover:text-blue-300 text-[10px]">View on VirusTotal →</a></div>` : ""}
      </div>
    </div>
  `;
}

// ========== ABUSEIPDB ==========
function initAbuseIPDB() {
  const btn = document.getElementById("abuseipdbBtn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const ip = document.getElementById("abuseipdbIp").value.trim();
    if (!ip) return;
    updateTerminal(`[ABUSEIPDB] Checking reputation: ${ip}`);
    const el = document.getElementById("abuseipdbResults");
    el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Checking...</div>';

    try {
      const res = await fetch("/api/abuseipdb", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Error");
      const data = await res.json();
      renderAbuseIPDB(data, el);
      updateTerminal("[ABUSEIPDB] Check complete");
    } catch (e) {
      el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
      updateTerminal(`[ERROR] ${e.message}`);
    }
  });
}

function renderAbuseIPDB(data, el) {
  const confidence = data.abuseConfidence || 0;
  const riskLevel = data.risk_level || "low";
  const reports = data.recent_reports || [];
  
  el.innerHTML = `
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; IP: ${data.ip}</div>
      <div class="text-green-400 text-xs font-share-tech space-y-1">
        <div>PUBLIC: <span class="text-green-300">${data.isPublic ? "YES" : "NO"}</span></div>
        <div>ABUSE_CONFIDENCE: <span class="${confidence > 50 ? 'text-red-400' : confidence > 25 ? 'text-yellow-400' : 'text-green-300'} font-bold text-lg">${confidence}%</span></div>
        <div>RISK_LEVEL: <span class="${riskLevel === 'critical' ? 'text-red-400' : riskLevel === 'high' ? 'text-orange-400' : riskLevel === 'medium' ? 'text-yellow-400' : 'text-green-300'} font-bold">${riskLevel.toUpperCase()}</span></div>
        <div>USAGE_TYPE: ${data.usageType || "N/A"}</div>
        <div>COUNTRY: ${data.country || "N/A"}</div>
        <div>DOMAIN: ${data.domain || "N/A"}</div>
        <div>TOTAL_REPORTS: <span class="font-bold">${data.totalReports || 0}</span></div>
        <div>DISTINCT_USERS: ${data.numDistinctUsers || 0}</div>
        ${data.lastReportedAt ? `<div>LAST_REPORTED: ${data.lastReportedAt}</div>` : ""}
        ${data.hostnames && data.hostnames.length > 0 ? `<div>HOSTNAMES: ${data.hostnames.join(", ")}</div>` : ""}
        ${confidence > 50 ? '<div class="text-red-400 font-bold mt-2">⚠️ HIGH ABUSE RISK</div>' : ''}
      </div>
    </div>
    ${reports.length > 0 ? `
      <div class="result-hacking">
        <div class="text-green-500 font-bold mb-2">&gt; RECENT_REPORTS (${reports.length})</div>
        <div class="space-y-1 max-h-64 overflow-y-auto text-xs font-share-tech">
          ${reports.map(r => `<div class="text-green-600">${JSON.stringify(r)}</div>`).join("")}
        </div>
      </div>
    ` : ""}
  `;
}

// ========== WHOIS ==========
function initWhois() {
  const btn = document.getElementById("whoisBtn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const query = document.getElementById("whoisQuery").value.trim();
    if (!query) return;
    updateTerminal(`[WHOIS] Querying: ${query}`);
    const el = document.getElementById("whoisResults");
    el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Querying...</div>';

    try {
      const res = await fetch("/api/whois", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Error");
      const data = await res.json();
      renderWhois(data, el);
      updateTerminal("[WHOIS] Query complete");
    } catch (e) {
      el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
      updateTerminal(`[ERROR] ${e.message}`);
    }
  });
}

function renderWhois(data, el) {
  const d = data.data || {};
  const entries = Object.entries(d).filter(([k, v]) => v);
  
  el.innerHTML = `
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; WHOIS: ${data.query}</div>
      <div class="text-green-400 text-xs font-share-tech space-y-1">
        <div>TYPE: <span class="text-green-300 font-bold">${data.type.toUpperCase()}</span></div>
        ${d.domain_name ? `<div>DOMAIN: <span class="text-green-300 font-bold">${d.domain_name}</span></div>` : ""}
        ${d.registrar ? `<div>REGISTRAR: ${d.registrar}</div>` : ""}
        ${d.registrar_url ? `<div>REGISTRAR_URL: <span class="text-blue-300">${d.registrar_url}</span></div>` : ""}
        ${d.creation_date ? `<div>CREATION_DATE: <span class="text-blue-300">${d.creation_date}</span></div>` : ""}
        ${d.expiration_date ? `<div>EXPIRATION_DATE: <span class="text-amber-300">${d.expiration_date}</span></div>` : ""}
        ${d.updated_date ? `<div>UPDATED_DATE: <span class="text-green-300">${d.updated_date}</span></div>` : ""}
        ${d.org ? `<div>ORGANIZATION: ${d.org}</div>` : ""}
        ${d.country ? `<div>COUNTRY: ${d.country}</div>` : ""}
        ${d.state ? `<div>STATE/REGION: ${d.state}</div>` : ""}
        ${d.city ? `<div>CITY: ${d.city}</div>` : ""}
        ${d.address ? `<div>ADDRESS: ${d.address}</div>` : ""}
        ${d.zipcode ? `<div>ZIPCODE: ${d.zipcode}</div>` : ""}
        ${d.phone ? `<div>PHONE: ${d.phone}</div>` : ""}
        ${d.fax ? `<div>FAX: ${d.fax}</div>` : ""}
        ${d.status ? `<div>STATUS: ${Array.isArray(d.status) ? d.status.join(", ") : d.status}</div>` : ""}
      </div>
    </div>
    ${d.name_servers && d.name_servers.length > 0 ? `
      <div class="result-hacking mb-3">
        <div class="text-green-500 font-bold mb-2">&gt; NAME_SERVERS (${d.name_servers.length})</div>
        <div class="text-green-400 text-xs font-share-tech font-mono space-y-1">
          ${d.name_servers.map(ns => `<div>${ns}</div>`).join("")}
        </div>
      </div>
    ` : ""}
    ${d.emails && d.emails.length > 0 ? `
      <div class="result-hacking">
        <div class="text-green-500 font-bold mb-2">&gt; CONTACT_EMAILS (${d.emails.length})</div>
        <div class="text-green-400 text-xs font-share-tech font-mono space-y-1">
          ${d.emails.map(email => `<div>${email}</div>`).join("")}
        </div>
      </div>
    ` : ""}
    ${entries.length > 10 ? `
      <div class="result-hacking mt-3">
        <div class="text-green-500 font-bold mb-2">&gt; ALL_DATA (${entries.length} fields)</div>
        <div class="text-green-400 text-xs font-share-tech font-mono space-y-1 max-h-[300px] overflow-y-auto">
          ${entries.map(([k, v]) => `<div>${k.toUpperCase()}: ${Array.isArray(v) ? v.join(", ") : v}</div>`).join("")}
        </div>
      </div>
    ` : ""}
  `;
}

// ========== LEAKCHECK ==========
function initLeakCheck() {
  const btn = document.getElementById("leakcheckBtn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const email = document.getElementById("leakcheckEmail").value.trim();
    if (!email) return;
    updateTerminal(`[LEAKCHECK] Checking breaches: ${email}`);
    const el = document.getElementById("leakcheckResults");
    el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Checking HaveIBeenPwned...</div>';

    try {
      const res = await fetch("/api/leakcheck", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Error");
      const data = await res.json();
      renderLeakCheck(data, el);
      updateTerminal("[LEAKCHECK] Check complete");
    } catch (e) {
      el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
      updateTerminal(`[ERROR] ${e.message}`);
    }
  });
}

function renderLeakCheck(data, el) {
  const riskLevel = data.risk_level || "low";
  const breachDetails = data.breach_details || [];
  
  if (data.found) {
    el.innerHTML = `
      <div class="result-hacking border-red-500 mb-3">
        <div class="text-red-400 font-bold mb-2">&gt; ⚠️ BREACH DETECTED</div>
        <div class="text-green-400 text-xs font-share-tech space-y-1">
          <div>EMAIL: <span class="font-mono text-green-300">${data.email}</span></div>
          <div>TOTAL_BREACHES: <span class="text-red-400 font-bold text-lg">${data.breach_count || 0}</span></div>
          <div>PASSWORD_BREACHES: ${data.password_breaches || 0}</div>
          <div>EMAIL_BREACHES: ${data.email_breaches || 0}</div>
          <div>RISK_LEVEL: <span class="${riskLevel === 'critical' ? 'text-red-400' : riskLevel === 'high' ? 'text-orange-400' : 'text-yellow-400'} font-bold">${riskLevel.toUpperCase()}</span></div>
          ${(data.sources || []).length > 0 ? `
            <div class="mt-2">
              <div class="text-green-500 font-bold mb-1">SOURCES:</div>
              <ul class="list-disc list-inside ml-2 space-y-1">
                ${data.sources.map(s => `<li class="text-green-300">${s}</li>`).join("")}
              </ul>
            </div>
          ` : ""}
        </div>
      </div>
      ${breachDetails.length > 0 ? `
        <div class="result-hacking">
          <div class="text-green-500 font-bold mb-2">&gt; BREACH_DETAILS (${breachDetails.length})</div>
          <div class="space-y-2 max-h-64 overflow-y-auto">
            ${breachDetails.map(b => `
              <div class="bg-black/40 p-2 rounded border border-red-500/30">
                <div class="text-green-400 text-xs font-share-tech">
                  <div class="font-bold text-red-300">${b.Name || "Unknown"}</div>
                  <div>Domain: ${b.Domain || "N/A"}</div>
                  <div>Breach Date: ${b.BreachDate || "N/A"}</div>
                  <div>Pwn Count: ${b.PwnCount || "N/A"}</div>
                </div>
              </div>
            `).join("")}
          </div>
        </div>
      ` : ""}
    `;
  } else {
    el.innerHTML = `
      <div class="result-hacking border-green-500">
        <div class="text-green-300 font-bold mb-2">&gt; ✓ NO BREACHES FOUND</div>
        <div class="text-green-400 text-xs font-share-tech">
          <div>EMAIL: <span class="font-mono text-green-300">${data.email}</span></div>
          <div class="mt-2">STATUS: Clean</div>
          <div>RISK_LEVEL: <span class="text-green-300 font-bold">LOW</span></div>
        </div>
      </div>
    `;
  }
}

// ========== EXIFTOOL ==========
function initExifTool() {
  const btn = document.getElementById("exiftoolBtn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const fileInput = document.getElementById("exiftoolFile");
    const file = fileInput.files[0];
    if (!file) {
      updateTerminal("[ERROR] No file selected");
      return;
    }

    updateTerminal(`[EXIFTOOL] Extracting metadata: ${file.name}`);
    const el = document.getElementById("exiftoolResults");
    el.innerHTML = '<div class="text-green-400 animate-pulse">&gt; Extracting metadata...</div>';

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("/api/exiftool", { method: "POST", body: formData });
      if (!res.ok) throw new Error((await res.json()).detail || "Error");
      const data = await res.json();
      renderExifTool(data, el);
      updateTerminal("[EXIFTOOL] Extraction complete");
    } catch (e) {
      el.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
      updateTerminal(`[ERROR] ${e.message}`);
    }
  });
}

function renderExifTool(data, el) {
  const summary = data.summary || {};
  const analysis = data.analysis || {};
  const gps = data.gps || {};
  const camera = data.camera || {};
  const security = data.security_flags || {};
  const entries = Object.entries(summary).slice(0, 50);
  
  el.innerHTML = `
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; FILE: ${data.filename}</div>
      <div class="text-green-400 text-xs font-share-tech space-y-2">
        <div>FILE_SIZE: ${analysis.file_size || "N/A"}</div>
        <div>MIME_TYPE: ${analysis.mime_type || "N/A"}</div>
        <div>RISK_LEVEL: <span class="${security.risk_level === 'high' ? 'text-red-400' : security.risk_level === 'medium' ? 'text-yellow-400' : 'text-green-300'} font-bold">${(security.risk_level || 'low').toUpperCase()}</span></div>
      </div>
    </div>
    
    ${gps.latitude ? `
      <div class="result-hacking border-red-500 mb-3">
        <div class="text-red-400 font-bold mb-2">&gt; ⚠️ GPS_LOCATION DETECTED</div>
        <div class="text-green-400 text-xs font-share-tech space-y-1">
          <div>LATITUDE: <span class="font-mono">${gps.latitude}</span></div>
          <div>LONGITUDE: <span class="font-mono">${gps.longitude}</span></div>
          ${gps.google_maps ? `<div><a href="${gps.google_maps}" target="_blank" class="text-blue-400 hover:text-blue-300">View on Google Maps →</a></div>` : ""}
        </div>
      </div>
    ` : ""}
    
    ${Object.keys(camera).length > 0 ? `
      <div class="result-hacking mb-3">
        <div class="text-green-500 font-bold mb-2">&gt; CAMERA_INFO</div>
        <div class="text-green-400 text-xs font-share-tech space-y-1">
          ${camera.make ? `<div>MAKE: ${camera.make}</div>` : ""}
          ${camera.model ? `<div>MODEL: ${camera.model}</div>` : ""}
          ${camera.lens ? `<div>LENS: ${camera.lens}</div>` : ""}
          ${camera.focal_length ? `<div>FOCAL_LENGTH: ${camera.focal_length}</div>` : ""}
          ${camera.aperture ? `<div>APERTURE: ${camera.aperture}</div>` : ""}
          ${camera.iso ? `<div>ISO: ${camera.iso}</div>` : ""}
          ${camera.exposure ? `<div>EXPOSURE: ${camera.exposure}</div>` : ""}
        </div>
      </div>
    ` : ""}
    
    <div class="result-hacking">
      <div class="text-green-500 font-bold mb-2">&gt; ALL_METADATA (${Object.keys(summary).length} fields)</div>
      <div class="text-green-400 text-xs font-share-tech font-mono space-y-1 max-h-[400px] overflow-y-auto">
        ${entries.map(([k, v]) => `<div>${k}: <span class="text-green-300">${v}</span></div>`).join("")}
      </div>
    </div>
  `;
}

// ========== VULNERABILITIES ==========
function initVulnerabilities() {
  const btn = document.getElementById("vulnBtn");
  if (!btn) {
    console.error("[VULN] Button vulnBtn not found");
    return;
  }
  
  console.log("[VULN] Initializing vulnerabilities scanner...");
  
  btn.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    console.log("[VULN] Button clicked");
    
    const ip = document.getElementById("vulnIp")?.value.trim() || null;
    const cveText = document.getElementById("vulnCveList")?.value.trim() || "";
    const cveList = cveText.split("\n").map(c => c.trim()).filter(c => c && c.toUpperCase().startsWith("CVE-"));
    
    console.log("[VULN] IP:", ip, "CVE List:", cveList);
    
    if (!ip && cveList.length === 0) {
      const resultsEl = document.getElementById("vulnResults");
      if (resultsEl) {
        resultsEl.innerHTML = '<div class="text-red-400">&gt; ERROR: Veuillez fournir une IP ou une liste de CVE</div>';
      }
      updateTerminal("[ERROR] Veuillez fournir une IP ou une liste de CVE");
      return;
    }
    
    const resultsEl = document.getElementById("vulnResults");
    if (!resultsEl) {
      console.error("[VULN] Results element not found");
      updateTerminal("[ERROR] Élément de résultats introuvable");
      return;
    }
    
    resultsEl.innerHTML = '<div class="text-green-600">&gt; Analyzing vulnerabilities...</div>';
    updateTerminal(`[VULN_SCAN] Analyzing ${cveList.length} CVE(s)${ip ? ` for IP ${ip}` : ""}...`);
    
    try {
      const payload = { 
        ip: ip || null, 
        cve_list: cveList.length > 0 ? cveList : null 
      };
      console.log("[VULN] Sending request:", payload);
      
      const response = await fetch("/api/vulnerabilities", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      console.log("[VULN] Response status:", response.status);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log("[VULN] Response data:", data);
      
      if (data.error) {
        renderVulnerabilityError(data, resultsEl);
        updateTerminal(`[ERROR] ${data.message}`);
      } else {
        renderVulnerabilityResults(data, resultsEl);
        const portsCount = data.ports_analysis?.ports_analyzed || 0;
        updateTerminal(`[VULN_SCAN] Analysis complete: ${data.cve_analysis?.analyzed || 0} CVE(s) analyzed, ${portsCount} port(s) analyzed`);
      }
    } catch (e) {
      console.error("[VULN] Error:", e);
      resultsEl.innerHTML = `<div class="text-red-400">&gt; ERROR: ${e.message}</div>`;
      updateTerminal(`[ERROR] ${e.message}`);
    }
  });
}

function renderVulnerabilityResults(data, el) {
  const analysis = data.cve_analysis || {};
  const summary = analysis.summary || {};
  const vulns = analysis.vulnerabilities || [];
  const recommendations = data.recommendations || [];
  const portsAnalysis = data.ports_analysis || {};
  const portsDetails = portsAnalysis.ports_details || [];
  const attackVectors = portsAnalysis.attack_vectors || [];
  const globalRiskScore = data.global_risk_score || analysis.risk_score || 0;
  
  el.innerHTML = `
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; VULNERABILITY_ANALYSIS</div>
      ${data.original_input && data.original_input !== data.ip ? `
        <div class="text-green-400 text-xs mb-1">
          URL/DOMAINE: <span class="text-green-300 font-mono">${data.original_input}</span> → IP: <span class="text-green-300 font-mono">${data.ip}</span>
        </div>
      ` : data.ip ? `
        <div class="text-green-400 text-xs mb-1">
          IP: <span class="text-green-300 font-mono">${data.ip}</span>
        </div>
      ` : ''}
      <div class="text-green-400 text-xs font-share-tech space-y-2">
        <div>TOTAL_CVE: <span class="text-green-300 font-bold">${analysis.total || 0}</span></div>
        <div>ANALYZED: <span class="text-green-300 font-bold">${analysis.analyzed || 0}</span></div>
        ${portsAnalysis.ports_analyzed !== undefined ? `<div>PORTS_ANALYZED: <span class="text-blue-300 font-bold">${portsAnalysis.ports_analyzed || 0}</span></div>` : ""}
        <div>GLOBAL_RISK_SCORE: <span class="${globalRiskScore >= 7 ? 'text-red-400' : globalRiskScore >= 4 ? 'text-yellow-400' : 'text-green-300'} font-bold text-lg">${globalRiskScore.toFixed(2)}/10</span></div>
      </div>
    </div>
    
    ${data.scan_method ? `
      <div class="result-hacking mb-3 border-blue-500">
        <div class="text-blue-400 font-bold mb-2">&gt; SCAN_METHOD</div>
        <div class="text-green-400 text-xs font-share-tech">
          <div>Méthode: <span class="text-green-300 font-bold">${data.scan_method.toUpperCase()}</span></div>
          ${data.nmap_available ? `<div class="text-green-300 text-[10px] mt-1">✓ Nmap disponible - Scan avancé activé</div>` : `<div class="text-yellow-400 text-[10px] mt-1">⚠ Scan manuel (Nmap non détecté - Installez Nmap pour un scan complet)</div>`}
        </div>
      </div>
    ` : ""}
    
    ${data.scan_error ? `
      <div class="result-hacking mb-3 border-yellow-500">
        <div class="text-yellow-400 font-bold mb-2">&gt; ⚠️ SCAN_INFO</div>
        <div class="text-green-400 text-xs font-share-tech">
          <div>${data.scan_error}</div>
          <div class="text-yellow-400 text-[10px] mt-1">Utilisation du scan manuel en fallback</div>
        </div>
      </div>
    ` : ""}
    
    ${portsAnalysis.message ? `
      <div class="result-hacking mb-3 border-yellow-500">
        <div class="text-yellow-400 font-bold mb-2">&gt; INFO</div>
        <div class="text-green-400 text-xs font-share-tech">
          ${portsAnalysis.message}
          ${portsAnalysis.info_only ? '<div class="text-yellow-300 text-[10px] mt-1">⚠️ Analyse informative - Les ports peuvent être protégés par un firewall</div>' : ''}
        </div>
      </div>
    ` : ""}
    
    <div class="result-hacking mb-3">
      <div class="text-green-500 font-bold mb-2">&gt; SEVERITY_SUMMARY</div>
      <div class="text-green-400 text-xs font-share-tech space-y-1">
        <div>CRITICAL: <span class="text-red-400 font-bold">${summary.critical || 0}</span></div>
        <div>HIGH: <span class="text-orange-400 font-bold">${summary.high || 0}</span></div>
        <div>MEDIUM: <span class="text-yellow-400 font-bold">${summary.medium || 0}</span></div>
        <div>LOW: <span class="text-green-300 font-bold">${summary.low || 0}</span></div>
        <div>UNKNOWN: <span class="text-gray-400 font-bold">${summary.unknown || 0}</span></div>
      </div>
    </div>
    
    ${portsDetails && portsDetails.length > 0 ? `
      <div class="result-hacking mb-3 border-blue-500">
        <div class="text-blue-400 font-bold mb-2">&gt; PORTS_ANALYSIS (${portsDetails.length} ports ouverts)</div>
        <div class="space-y-3 max-h-[500px] overflow-y-auto">
          ${portsDetails.map(port => `
            <div class="bg-black/40 p-3 rounded border ${port.risk_level === 'critical' ? 'border-red-500' : port.risk_level === 'high' ? 'border-orange-500' : port.risk_level === 'medium' ? 'border-yellow-500' : 'border-green-500/30'}">
              <div class="text-green-400 text-xs font-share-tech space-y-1">
                <div class="flex items-center gap-2">
                  <span class="text-green-500 font-bold">PORT:</span>
                  <span class="text-blue-300 font-mono font-bold text-lg">${port.port}</span>
                  <span class="text-green-300">${port.service}</span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold ${port.risk_level === 'critical' ? 'bg-red-500/20 text-red-400' : port.risk_level === 'high' ? 'bg-orange-500/20 text-orange-400' : port.risk_level === 'medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'}">
                    ${(port.risk_level || 'low').toUpperCase()}
                  </span>
                </div>
                ${port.product && port.product !== 'Unknown' ? `<div>PRODUCT: <span class="text-green-300">${port.product}</span> ${port.version && port.version !== 'Unknown' ? `<span class="text-yellow-400">v${port.version}</span>` : ''}</div>` : ""}
                ${port.banner_preview ? `<div class="text-green-600 text-[10px] font-mono mt-1">BANNER: ${port.banner_preview}</div>` : ""}
                ${port.vulnerabilities && port.vulnerabilities.length > 0 ? `
                  <div class="mt-2">
                    <div class="text-red-400 font-bold text-xs">VULNERABILITIES (${port.vulnerabilities.length}):</div>
                    <div class="text-red-300 text-[10px] space-y-1 mt-1">
                      ${port.vulnerabilities.map(v => `<div>• ${v}</div>`).join("")}
                    </div>
                  </div>
                ` : ""}
                ${port.attack_vectors && port.attack_vectors.length > 0 ? `
                  <div class="mt-2">
                    <div class="text-orange-400 font-bold text-xs">ATTACK_VECTORS:</div>
                    <div class="text-orange-300 text-[10px] space-y-1 mt-1">
                      ${port.attack_vectors.map(av => `<div>→ ${av}</div>`).join("")}
                    </div>
                  </div>
                ` : ""}
                ${port.exploit_tools && port.exploit_tools.length > 0 ? `
                  <div class="mt-2">
                    <div class="text-purple-400 font-bold text-xs">EXPLOIT_TOOLS:</div>
                    <div class="text-purple-300 text-[10px] space-y-1 mt-1">
                      ${port.exploit_tools.map(tool => `<div>🔧 ${tool}</div>`).join("")}
                    </div>
                  </div>
                ` : ""}
                ${port.recommendations && port.recommendations.length > 0 ? `
                  <div class="mt-2 border-t border-green-500/30 pt-2">
                    <div class="text-yellow-400 font-bold text-xs">RECOMMENDATIONS:</div>
                    <div class="text-yellow-300 text-[10px] space-y-1 mt-1">
                      ${port.recommendations.map(rec => `<div>${rec}</div>`).join("")}
                    </div>
                  </div>
                ` : ""}
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    ` : portsAnalysis.ports_analyzed === 0 && data.ip ? `
      <div class="result-hacking mb-3 border-yellow-500">
        <div class="text-yellow-400 font-bold mb-2">&gt; PORTS_ANALYSIS</div>
        <div class="text-green-400 text-xs font-share-tech">
          <div>Aucun port ouvert détecté pour cette IP dans Shodan</div>
          <div class="text-green-600 text-[10px] mt-2">Note: L'IP peut être protégée par un firewall ou non scannée par Shodan</div>
        </div>
      </div>
    ` : ""}
    
    ${attackVectors && attackVectors.length > 0 ? `
      <div class="result-hacking mb-3 border-red-500">
        <div class="text-red-400 font-bold mb-2">&gt; ATTACK_VECTORS (${attackVectors.length} vecteurs critiques)</div>
        <div class="space-y-3 max-h-[400px] overflow-y-auto">
          ${attackVectors.map(av => `
            <div class="bg-red-500/10 p-3 rounded border border-red-500/50">
              <div class="text-green-400 text-xs font-share-tech space-y-1">
                <div class="flex items-center gap-2">
                  <span class="text-red-400 font-bold">PORT:</span>
                  <span class="text-blue-300 font-mono font-bold">${av.port}</span>
                  <span class="text-green-300">${av.service}</span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400">
                    ${av.risk_level.toUpperCase()}
                  </span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-400">
                    ${av.exploitation_difficulty}
                  </span>
                </div>
                <div class="mt-2">
                  <div class="text-orange-400 font-bold text-xs">ATTACK_METHODS:</div>
                  <div class="text-orange-300 text-[10px] space-y-1 mt-1">
                    ${av.attack_methods.map(method => `<div>→ ${method}</div>`).join("")}
                  </div>
                </div>
                ${av.vulnerabilities && av.vulnerabilities.length > 0 ? `
                  <div class="mt-2">
                    <div class="text-red-400 font-bold text-xs">EXPLOITABLE_VULNS:</div>
                    <div class="text-red-300 text-[10px] space-y-1 mt-1">
                      ${av.vulnerabilities.slice(0, 5).map(v => `<div>• ${v}</div>`).join("")}
                    </div>
                  </div>
                ` : ""}
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    ` : ""}
    
    ${portsAnalysis.exploit_commands && portsAnalysis.exploit_commands.length > 0 ? `
      <div class="result-hacking mb-3 border-purple-500">
        <div class="text-purple-400 font-bold mb-2">&gt; EXPLOIT_COMMANDS (${portsAnalysis.exploit_commands.length} commandes)</div>
        <div class="space-y-2 max-h-[400px] overflow-y-auto">
          ${portsAnalysis.exploit_commands.map(cmd => `
            <div class="bg-purple-500/10 p-2 rounded border border-purple-500/30">
              <div class="text-green-400 text-xs font-share-tech space-y-1">
                <div class="flex items-center gap-2">
                  <span class="text-purple-400 font-bold">TOOL:</span>
                  <span class="text-purple-300 font-bold">${cmd.tool.toUpperCase()}</span>
                  <span class="text-blue-300">Port ${cmd.port} (${cmd.service})</span>
                </div>
                <div class="text-green-300 font-mono text-[10px] bg-black/40 p-2 rounded mt-1">
                  ${cmd.command}
                </div>
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    ` : ""}
    
    ${recommendations.length > 0 ? `
      <div class="result-hacking mb-3 border-yellow-500">
        <div class="text-yellow-400 font-bold mb-2">&gt; RECOMMENDATIONS</div>
        <div class="text-green-400 text-xs font-share-tech space-y-1">
          ${recommendations.map(rec => `<div>${rec}</div>`).join("")}
        </div>
      </div>
    ` : ""}
    
    ${vulns.length > 0 ? `
      <div class="result-hacking">
        <div class="text-green-500 font-bold mb-2">&gt; CVE_DETAILS (${vulns.length})</div>
        <div class="space-y-3 max-h-[400px] overflow-y-auto">
          ${vulns.map(v => `
            <div class="bg-black/40 p-3 rounded border                 ${v.severity === 'critical' ? 'border-red-500' : v.severity === 'high' ? 'border-orange-500' : v.severity === 'medium' ? 'border-yellow-500' : 'border-green-500/30'}">
              <div class="text-green-400 text-xs font-share-tech space-y-1">
                <div class="flex items-center gap-2">
                  <span class="text-green-500 font-bold">CVE:</span>
                  <span class="text-green-300 font-mono font-bold">${v.cve_id}</span>
                  ${v.not_found ? `
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-400">
                      NOT FOUND
                    </span>
                  ` : `
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${v.severity === 'critical' ? 'bg-red-500/20 text-red-400' : v.severity === 'high' ? 'bg-orange-500/20 text-orange-400' : v.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-gray-500/20 text-gray-400'}">
                      ${(v.severity || 'unknown').toUpperCase()}
                    </span>
                  `}
                </div>
                ${v.cvss_score !== null ? `
                  <div>CVSS_SCORE: <span class="text-green-300 font-bold">${v.cvss_score}</span></div>
                ` : ""}
                <div class="text-green-600 text-[10px]">${v.description || "No description"}</div>
                ${v.exploits_available ? `
                  <div class="text-red-400 font-bold text-xs mt-1">
                    ⚠️ EXPLOITS_AVAILABLE: ${v.exploits_count || 0} exploit(s) public(s)
                  </div>
                  ${v.exploits && v.exploits.length > 0 ? `
                    <div class="text-red-300 text-[10px] mt-1 space-y-1">
                      ${v.exploits.slice(0, 3).map(exp => `
                        <div><a href="${exp.url}" target="_blank" class="text-blue-400 hover:text-blue-300">${exp.title || exp.url}</a></div>
                      `).join("")}
                    </div>
                  ` : ""}
                ` : ""}
                ${v.published ? `<div class="text-green-600 text-[10px]">PUBLISHED: ${v.published}</div>` : ""}
                ${v.references && v.references.length > 0 ? `
                  <div class="text-green-600 text-[10px] mt-1">
                    REFERENCES: ${v.references.slice(0, 2).map(ref => `<a href="${ref}" target="_blank" class="text-blue-400 hover:text-blue-300">[Link]</a>`).join(" ")}
                  </div>
                ` : ""}
              </div>
            </div>
          `).join("")}
        </div>
      </div>
    ` : ""}
  `;
}

function renderVulnerabilityError(data, el) {
  el.innerHTML = `
    <div class="result-hacking" style="border-color:var(--danger)">
      <div style="color:var(--danger);font-weight:600;margin-bottom:0.5rem">Erreur</div>
      <div>${data.message || "Erreur inconnue"}</div>
    </div>
  `;
}
