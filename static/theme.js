/**
 * Phishing Guardian — thème sombre / clair
 */
const PGTheme = (() => {
  const STORAGE_KEY = "pg-theme";

  function preferred() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function apply(theme) {
    const next = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem(STORAGE_KEY, next);

    document.querySelectorAll(".theme-toggle").forEach((btn) => {
      btn.setAttribute("aria-pressed", next === "light" ? "true" : "false");
      btn.setAttribute("title", next === "light" ? "Passer en mode sombre" : "Passer en mode clair");
      btn.setAttribute("aria-label", btn.getAttribute("title"));
    });

    const label = document.getElementById("themeLabel");
    if (label) label.textContent = next === "light" ? "Clair" : "Sombre";

    window.dispatchEvent(new CustomEvent("pg-theme-change", { detail: { theme: next } }));
    if (document.readyState === "complete" || document.readyState === "interactive") {
      window.updateTerminal?.(`Thème : mode ${next === "light" ? "clair" : "sombre"}`);
    }
  }

  function toggle() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    apply(current === "light" ? "dark" : "light");
  }

  function init() {
    apply(preferred());
    document.querySelectorAll(".theme-toggle").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        toggle();
      });
    });
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
      if (!localStorage.getItem(STORAGE_KEY)) apply(e.matches ? "light" : "dark");
    });
  }

  return { init, toggle, apply, preferred };
})();

document.addEventListener("DOMContentLoaded", () => PGTheme.init());
window.PGTheme = PGTheme;
