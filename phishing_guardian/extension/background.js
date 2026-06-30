const DEFAULT_API = "http://127.0.0.1:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(["apiBase"], (data) => {
    if (!data.apiBase) {
      chrome.storage.sync.set({ apiBase: DEFAULT_API });
    }
  });

  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "pg-analyze-selection",
      title: "🔍 OSINT sur « %s »",
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: "pg-analyze-url",
      title: "🎣 Analyser l'URL de la page",
      contexts: ["page"],
    });
    chrome.contextMenus.create({
      id: "pg-open-dashboard",
      title: "🛡 Ouvrir Phishing Guardian",
      contexts: ["page", "action"],
    });
  });
});

async function getApiBase() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiBase"], (data) => {
      resolve((data.apiBase || DEFAULT_API).replace(/\/$/, ""));
    });
  });
}

async function apiFetch(path, options = {}) {
  const base = await getApiBase();
  const res = await fetch(`${base}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `HTTP ${res.status}`);
  return body;
}

function setBadge(text, color) {
  chrome.action.setBadgeText({ text: text || "" });
  if (color) chrome.action.setBadgeBackgroundColor({ color });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId === "pg-open-dashboard") {
      const base = await getApiBase();
      chrome.tabs.create({ url: base });
      return;
    }

    if (info.menuItemId === "pg-analyze-url" && tab?.url) {
      chrome.storage.local.set({ pendingTarget: tab.url, pendingAction: "url" });
      chrome.action.openPopup?.();
      return;
    }

    if (info.menuItemId === "pg-analyze-selection" && info.selectionText) {
      chrome.storage.local.set({
        pendingTarget: info.selectionText.trim(),
        pendingAction: "playbook",
      });
      chrome.action.openPopup?.();
    }
  } catch (e) {
    console.error("[PG]", e);
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "PG_CHECK_HEALTH") {
    getApiBase()
      .then((base) => fetch(`${base}/api/health`).then((r) => r.json()))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === "PG_ANALYZE_URL") {
    apiFetch("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ urls: [msg.url] }),
    })
      .then((data) => {
        const urls = data.urls || [];
        const label = urls[0]?.label || "unknown";
        const color = label === "phishing" ? "#ef4444" : label === "suspect" ? "#f59e0b" : "#22c55e";
        setBadge(label === "phishing" ? "!" : label === "suspect" ? "?" : "OK", color);
        sendResponse({ ok: true, data });
      })
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === "PG_RUN_PLAYBOOK") {
    apiFetch("/api/playbooks/run", {
      method: "POST",
      body: JSON.stringify({ target: msg.target, playbook_id: msg.playbook_id || null }),
    })
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === "PG_SUGGEST") {
    apiFetch(`/api/playbooks/suggest?target=${encodeURIComponent(msg.target)}`)
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
});
