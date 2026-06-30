const $ = (id) => document.getElementById(id);
let lastInvestigation = null;

document.addEventListener("DOMContentLoaded", async () => {
  $("saveApiBtn")?.addEventListener("click", saveApi);
  $("analyzeUrlBtn")?.addEventListener("click", analyzeCurrentUrl);
  $("playbookBtn")?.addEventListener("click", runPlaybook);
  $("openDashBtn")?.addEventListener("click", openDashboard);
  $("openFullBtn")?.addEventListener("click", openDashboard);

  await loadSettings();
  await checkHealth();
  await loadPageContext();
  await loadPending();
});

async function loadSettings() {
  const data = await chrome.storage.sync.get(["apiBase"]);
  if (data.apiBase) $("apiBase").value = data.apiBase;
}

async function saveApi() {
  const base = $("apiBase").value.trim().replace(/\/$/, "");
  await chrome.storage.sync.set({ apiBase: base });
  await checkHealth();
}

async function getApiBase() {
  const data = await chrome.storage.sync.get(["apiBase"]);
  return (data.apiBase || "http://127.0.0.1:8000").replace(/\/$/, "");
}

async function apiFetch(path, options = {}) {
  const base = await getApiBase();
  const res = await fetch(`${base}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof body.detail === "string" ? body.detail : `HTTP ${res.status}`);
  return body;
}

async function checkHealth() {
  const dot = $("statusDot");
  try {
    await apiFetch("/api/health");
    dot.classList.remove("offline");
    dot.classList.add("online");
    dot.title = "API connectée";
    hideError();
  } catch (e) {
    dot.classList.remove("online");
    dot.classList.add("offline");
    dot.title = "API hors ligne — lancez lancer_web.bat";
    showError(`API inaccessible : ${e.message}`);
  }
}

async function loadPageContext() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url && !tab.url.startsWith("chrome")) {
    $("pageUrl").textContent = `Page : ${tab.url}`;
    if (!$("target").value) $("target").placeholder = tab.url;
  }
}

async function loadPending() {
  const pending = await chrome.storage.local.get(["pendingTarget", "pendingAction"]);
  if (pending.pendingTarget) {
    $("target").value = pending.pendingTarget;
    await chrome.storage.local.remove(["pendingTarget", "pendingAction"]);
    if (pending.pendingAction === "url") analyzeUrl(pending.pendingTarget);
    else if (pending.pendingAction === "playbook") runPlaybook();
  }
}

function setLoading(on) {
  $("loader").classList.toggle("hidden", !on);
  document.querySelectorAll(".pg-btn").forEach((b) => { b.disabled = on; });
}

function showError(msg) {
  $("error").textContent = msg;
  $("error").classList.remove("hidden");
}

function hideError() {
  $("error").classList.add("hidden");
}

async function analyzeCurrentUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return showError("URL de page introuvable");
  await analyzeUrl(tab.url);
}

async function analyzeUrl(url) {
  setLoading(true);
  hideError();
  $("results").classList.add("hidden");
  try {
    const data = await apiFetch("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ urls: [url] }),
    });
    const u = (data.urls || [])[0] || {};
    const label = u.label || "unknown";
    const score = u.score != null ? Math.round(u.score * 100) : "—";
    const cls = label === "phishing" ? "risk-phishing" : label === "suspect" ? "risk-suspect" : "risk-legitimate";

    $("resultSummary").innerHTML = `<span class="${cls}">${label.toUpperCase()}</span> — score ${score}%`;
    $("resultScores").innerHTML = "";
    $("resultFindings").innerHTML = (u.indicators || [])
      .slice(0, 5)
      .map((i) => `<li>${esc(i)}</li>`)
      .join("") || "<li>Aucun indicateur notable</li>";
    $("results").classList.remove("hidden");
    lastInvestigation = null;
  } catch (e) {
    showError(e.message);
  } finally {
    setLoading(false);
  }
}

async function runPlaybook() {
  const target = $("target").value.trim();
  if (!target) return showError("Entrez une cible OSINT");

  setLoading(true);
  hideError();
  $("results").classList.add("hidden");

  try {
    const data = await apiFetch("/api/playbooks/run", {
      method: "POST",
      body: JSON.stringify({ target }),
    });
    lastInvestigation = data;
    const synth = data.synthesis || {};
    const as = synth.attack_surface || {};
    const ps = synth.privacy_score || {};
    const risk = (synth.overall_risk || "low").toUpperCase();

    $("resultSummary").innerHTML = `
      <div>${esc(data.playbook_name)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:4px">${esc(data.target)} · Risque ${risk}</div>`;

    $("resultScores").innerHTML = `
      <div class="pg-score-chip" style="color:${as.color || '#94a3b8'}">
        <span>${as.score ?? "—"}</span><small>Attack Surface</small>
      </div>
      <div class="pg-score-chip" style="color:${ps.color || '#22c55e'}">
        <span>${ps.score ?? "—"}</span><small>Privacy</small>
      </div>`;

    $("resultFindings").innerHTML = (synth.key_findings || [])
      .slice(0, 6)
      .map((f) => `<li>${esc(f)}</li>`)
      .join("") || "<li>Investigation terminée sans constat majeur</li>";

    $("results").classList.remove("hidden");
  } catch (e) {
    showError(e.message);
  } finally {
    setLoading(false);
  }
}

async function openDashboard() {
  const base = await getApiBase();
  const url = lastInvestigation
    ? `${base}/?investigation=${encodeURIComponent(lastInvestigation.id || "")}`
    : base;
  chrome.tabs.create({ url: base });
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = String(s ?? "");
  return d.innerHTML;
}
