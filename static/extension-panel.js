/**
 * Panneau Extension navigateur — statut API et instructions
 */
const ExtensionPanel = (() => {
  function init() {
    const pathEl = document.getElementById("extFolderPath");
    if (pathEl) {
      pathEl.textContent = `${window.location.origin.replace(/:\d+$/, "")} → dossier extension/ du projet`;
    }
    refresh();
    document.querySelector('[data-target="panel-extension"]')?.addEventListener("click", refresh);
  }

  async function refresh() {
    const statusEl = document.getElementById("extApiStatus");
    const jsonEl = document.getElementById("extStatusJson");
    try {
      const [health, ext] = await Promise.all([
        fetch("/api/health").then((r) => r.json()),
        fetch("/api/extension/status").then((r) => r.json()),
      ]);
      if (statusEl) {
        statusEl.textContent = health.status === "ok" ? "API prête pour l'extension" : "API indisponible";
        statusEl.className = `graph-status ${health.status === "ok" ? "graph-status-ok" : "graph-status-error"}`;
      }
      if (jsonEl) {
        jsonEl.textContent = JSON.stringify({ health: health.modules, extension: ext }, null, 2);
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = `Erreur : ${e.message}`;
      if (jsonEl) jsonEl.textContent = String(e.message);
    }
  }

  return { init };
})();

document.addEventListener("DOMContentLoaded", () => {
  try { ExtensionPanel.init(); } catch (e) { console.error("[EXT]", e); }
});
