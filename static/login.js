(() => {
  const form = document.getElementById("loginForm");
  const err = document.getElementById("loginError");
  const btn = document.getElementById("loginBtn");
  const userInput = document.getElementById("username");
  const passInput = document.getElementById("password");

  function showError(msg) {
    err.hidden = false;
    err.textContent = msg;
  }

  function hideError() {
    err.hidden = true;
    err.textContent = "";
  }

  // Déjà connecté ? aller au dashboard
  fetch("/api/auth/me", { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : null))
    .then((data) => {
      if (data && data.authenticated) {
        window.location.replace("/");
      }
    })
    .catch(() => {});

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();
    const username = (userInput?.value || "").trim();
    const password = passInput?.value || "";
    if (!username || !password) {
      showError("Identifiant et mot de passe requis.");
      return;
    }

    btn.disabled = true;
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showError(typeof data.detail === "string" ? data.detail : "Connexion refusée.");
        return;
      }
      if (data.api_key) {
        localStorage.setItem("pg_api_key", data.api_key);
      }
      if (data.username) {
        localStorage.setItem("pg_username", data.username);
      }
      const next = new URLSearchParams(window.location.search).get("next") || "/";
      window.location.replace(next.startsWith("/") ? next : "/");
    } catch (ex) {
      showError("Impossible de joindre le serveur.");
    } finally {
      btn.disabled = false;
    }
  });
})();
