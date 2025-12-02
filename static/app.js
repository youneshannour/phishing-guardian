const analyzeBtn = document.getElementById("analyzeBtn");
const spinner = document.getElementById("spinner");
const statusEl = document.getElementById("status");
const riskBadge = document.getElementById("riskBadge");
const riskSummaryEl = document.getElementById("riskSummary");
const detailsEl = document.getElementById("details");
const tabButtons = document.querySelectorAll(".tab-btn");
const panelPhishing = document.getElementById("panel-phishing");
const panelOsint = document.getElementById("panel-osint");
const shodanResultsEl = document.getElementById("shodanResults");
const shodanIpBtn = document.getElementById("shodanIpBtn");
const shodanQueryBtn = document.getElementById("shodanQueryBtn");

function levelToStyle(level) {
  switch (level) {
    case "critique":
      return {
        badge: "border-red-500/60 bg-red-500/10 text-red-300",
        text: "Risque critique",
      };
    case "eleve":
      return {
        badge: "border-orange-500/60 bg-orange-500/10 text-orange-300",
        text: "Risque élevé",
      };
    case "modere":
      return {
        badge: "border-amber-400/60 bg-amber-400/10 text-amber-200",
        text: "Risque modéré",
      };
    default:
      return {
        badge: "border-emerald-500/60 bg-emerald-500/10 text-emerald-300",
        text: "Risque faible",
      };
  }
}

async function onAnalyze() {
  const email = document.getElementById("email").value.trim();
  const urlsRaw = document.getElementById("urls").value.trim();
  const urls =
    urlsRaw.length > 0
      ? urlsRaw.split(",").map((u) => u.trim()).filter((u) => u.length > 0)
      : [];

  if (!email && urls.length === 0) {
    statusEl.textContent = "Veuillez fournir un email ou au moins une URL.";
    return;
  }

  analyzeBtn.disabled = true;
  spinner.classList.remove("hidden");
  statusEl.textContent = "Analyse en cours...";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, urls }),
    });

    if (!response.ok) {
      throw new Error("Erreur HTTP " + response.status);
    }

    const data = await response.json();
    renderResult(data);
    statusEl.textContent = "Analyse terminée.";
  } catch (err) {
    console.error(err);
    statusEl.textContent = "Erreur lors de l'analyse.";
    riskSummaryEl.textContent = "Une erreur est survenue : " + err.message;
  } finally {
    analyzeBtn.disabled = false;
    spinner.classList.add("hidden");
  }
}

function renderResult(data) {
  // Synthèse
  const synth = data.synthetique || { niveau: "faible", score: 0 };
  const style = levelToStyle(synth.niveau);

  riskBadge.className =
    "text-xs px-3 py-1 rounded-full border " + style.badge;
  riskBadge.textContent = style.text;
  riskBadge.classList.remove("hidden");

  riskSummaryEl.innerHTML = `
    <p class="mb-1">Score global : <span class="font-semibold">${synth.score}</span></p>
    <p class="text-xs text-slate-400">
      Le score est calculé à partir du risque maximal entre l'email et les URLs analysés.
    </p>
  `;

  // Détails
  detailsEl.innerHTML = "";

  if (data.email) {
    const e = data.email;
    const emailBlock = document.createElement("div");
    emailBlock.className = "border border-slate-800 rounded-lg p-3 bg-slate-950/40";
    emailBlock.innerHTML = `
      <h3 class="text-xs font-semibold text-slate-300 mb-1">Email</h3>
      <p class="text-xs text-slate-400 mb-1">Label&nbsp;: <span class="font-semibold">${e.label}</span> &mdash; Score&nbsp;: <span class="font-mono">${e.score.toFixed(
        3
      )}</span></p>
      ${
        (e.indicators || []).length > 0
          ? `<ul class="mt-1 text-xs text-slate-300 list-disc list-inside">
               ${e.indicators.map((i) => `<li>${i}</li>`).join("")}
             </ul>`
          : `<p class="text-xs text-slate-500">Aucun indicateur particulier détecté.</p>`
      }
      <p class="mt-1 text-[11px] text-slate-500">Modèle&nbsp;: ${e.model_used}</p>
    `;
    detailsEl.appendChild(emailBlock);
  }

  if (data.urls && data.urls.length > 0) {
    const urlsWrap = document.createElement("div");
    urlsWrap.className = "space-y-2";

    data.urls.forEach((u) => {
      const urlBlock = document.createElement("div");
      urlBlock.className =
        "border border-slate-800 rounded-lg p-3 bg-slate-950/40";
      urlBlock.innerHTML = `
        <h3 class="text-xs font-semibold text-slate-300 mb-1 break-all">${u.url}</h3>
        <p class="text-xs text-slate-400 mb-1">Label&nbsp;: <span class="font-semibold">${u.label}</span> &mdash; Score&nbsp;: <span class="font-mono">${u.score.toFixed(
          3
        )}</span></p>
        ${
          (u.indicators || []).length > 0
            ? `<ul class="mt-1 text-xs text-slate-300 list-disc list-inside">
                 ${u.indicators.map((i) => `<li>${i}</li>`).join("")}
               </ul>`
            : `<p class="text-xs text-slate-500">Aucun indicateur particulier détecté.</p>`
        }
        <p class="mt-1 text-[11px] text-slate-500">Modèle&nbsp;: ${u.model_used}</p>
      `;
      urlsWrap.appendChild(urlBlock);
    });

    detailsEl.appendChild(urlsWrap);
  }
}

// Gestion onglets
tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.getAttribute("data-target");

    tabButtons.forEach((b) => {
      b.classList.remove("border-blue-500", "text-blue-400");
      b.classList.add("border-transparent", "text-slate-400");
    });
    btn.classList.add("border-blue-500", "text-blue-400");
    btn.classList.remove("text-slate-400");

    if (target === "panel-phishing") {
      panelPhishing.classList.remove("hidden");
      panelOsint.classList.add("hidden");
    } else {
      panelOsint.classList.remove("hidden");
      panelPhishing.classList.add("hidden");
    }
  });
});

// Shodan IP
async function onShodanIp() {
  const ip = document.getElementById("shodanIp").value.trim();
  if (!ip) return;

  shodanResultsEl.innerHTML =
    '<p class="text-slate-400 text-xs">Interrogation Shodan pour ' +
    ip +
    "...</p>";

  try {
    const res = await fetch("/api/shodan/ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Erreur Shodan IP");
    }
    const data = await res.json();
    renderShodanIp(data);
  } catch (e) {
    shodanResultsEl.innerHTML =
      '<p class="text-red-400 text-xs">Erreur : ' + e.message + "</p>";
  }
}

function renderShodanIp(data) {
  const vulns = (data.vulns || []).join(", ") || "Aucune vulnérabilité connue";
  const hostnames = (data.hostnames || []).join(", ") || "N/A";
  const ports = (data.ports || []).join(", ") || "N/A";

  shodanResultsEl.innerHTML = `
    <div class="border border-slate-800 rounded-lg p-3 bg-slate-950/40">
      <h3 class="text-xs font-semibold text-slate-300 mb-1">IP ${data.ip}</h3>
      <p class="text-xs text-slate-400">Organisation : <span class="font-semibold">${
        data.org || "N/A"
      }</span></p>
      <p class="text-xs text-slate-400">ISP / OS : ${
        data.isp || "N/A"
      } / ${data.os || "N/A"}</p>
      <p class="text-xs text-slate-400 mt-1">Ports ouverts : <span class="font-mono">${ports}</span></p>
      <p class="text-xs text-slate-400">Virtual hosts : <span>${hostnames}</span></p>
      <p class="text-xs text-slate-400 mt-1">Vulnérabilités : <span class="text-red-300">${vulns}</span></p>
      <p class="text-[11px] text-slate-500 mt-1">Dernière mise à jour Shodan : ${
        data.last_update || "N/A"
      }</p>
    </div>
  `;
}

// Shodan Search
async function onShodanQuery() {
  const query = document.getElementById("shodanQuery").value.trim();
  if (!query) return;

  shodanResultsEl.innerHTML =
    '<p class="text-slate-400 text-xs">Recherche Shodan en cours...</p>';

  try {
    const res = await fetch("/api/shodan/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Erreur Shodan search");
    }
    const data = await res.json();
    renderShodanSearch(data);
  } catch (e) {
    shodanResultsEl.innerHTML =
      '<p class="text-red-400 text-xs">Erreur : ' + e.message + "</p>";
  }
}

function renderShodanSearch(data) {
  const matches = data.matches || [];
  if (matches.length === 0) {
    shodanResultsEl.innerHTML =
      '<p class="text-slate-400 text-xs">Aucun résultat.</p>';
    return;
  }

  const limited = matches.slice(0, 25); // limite affichage
  const html = limited
    .map((m) => {
      const hostnames = (m.hostnames || []).join(", ") || "N/A";
      const ip = m.ip_str || "N/A";
      const org = m.org || "N/A";
      const port = m.port || "N/A";
      const product = m.product || "";
      const location = m.location || {};
      const country = location.country_name || "";
      return `
        <div class="border border-slate-800 rounded-lg p-3 bg-slate-950/40">
          <p class="text-xs text-slate-300 mb-1 font-mono">${ip}:${port} ${
        product ? "— " + product : ""
      }</p>
          <p class="text-[11px] text-slate-400">Org : ${org} ${
        country ? "— " + country : ""
      }</p>
          <p class="text-[11px] text-slate-500">Hostnames : ${hostnames}</p>
        </div>
      `;
    })
    .join("");

  shodanResultsEl.innerHTML = `
    <p class="text-[11px] text-slate-400 mb-1">Résultats affichés : ${
      limited.length
    } / ${matches.length}</p>
    <div class="space-y-2 max-h-80 overflow-y-auto pr-1">
      ${html}
    </div>
  `;
}

if (analyzeBtn) analyzeBtn.addEventListener("click", onAnalyze);
if (shodanIpBtn) shodanIpBtn.addEventListener("click", onShodanIp);
if (shodanQueryBtn) shodanQueryBtn.addEventListener("click", onShodanQuery);


