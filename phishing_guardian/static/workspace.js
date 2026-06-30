/**
 * Workspace collaboratif — dossiers partagés, notes, activité
 */
const WorkspaceUI = (() => {
  const LS_USER = "pg_username";
  const LS_WORKSPACE = "pg_active_workspace";

  let workspaces = [];
  let current = null;
  let selectedCaseId = null;

  function init() {
    ensureUser();
    document.getElementById("wsUserForm")?.addEventListener("submit", onSetUser);
    document.getElementById("wsCreateForm")?.addEventListener("submit", onCreateWorkspace);
    document.getElementById("wsRefreshBtn")?.addEventListener("click", refresh);
    document.getElementById("wsAddMemberForm")?.addEventListener("submit", onAddMember);
    document.getElementById("wsCaseForm")?.addEventListener("submit", onCreateCase);
    document.getElementById("wsNoteForm")?.addEventListener("submit", onAddNote);
    document.getElementById("wsWorkspaceSelect")?.addEventListener("change", onSelectWorkspace);
    refresh();
  }

  function getUser() {
    return (localStorage.getItem(LS_USER) || "").trim().toLowerCase();
  }

  function apiHeaders() {
    const user = getUser();
    return user ? { "Content-Type": "application/json", "X-PG-User": user } : { "Content-Type": "application/json" };
  }

  function ensureUser() {
    const user = getUser();
    const banner = document.getElementById("wsUserBanner");
    const label = document.getElementById("wsCurrentUser");
    if (user) {
      banner?.classList.add("hidden");
      if (label) label.textContent = user;
    } else {
      banner?.classList.remove("hidden");
    }
  }

  function onSetUser(e) {
    e.preventDefault();
    const input = document.getElementById("wsUsername");
    const name = input?.value?.trim().toLowerCase();
    if (!name || name.length < 2) return;
    localStorage.setItem(LS_USER, name);
    ensureUser();
    refresh();
    window.updateTerminal?.(`[WORKSPACE] Connecté en tant que ${name}`);
  }

  async function refresh() {
    if (!getUser()) {
      setStatus("Identifiez-vous pour accéder aux workspaces");
      return;
    }
    try {
      const res = await fetch("/api/workspaces", { headers: apiHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      workspaces = data.workspaces || [];
      renderWorkspaceSelect();
      const activeId = localStorage.getItem(LS_WORKSPACE);
      if (activeId && workspaces.some((w) => w.id === activeId)) {
        await loadWorkspace(activeId);
      } else if (workspaces.length) {
        await loadWorkspace(workspaces[0].id);
      } else {
        current = null;
        renderEmpty();
      }
      setStatus(`${workspaces.length} workspace(s)`);
    } catch (e) {
      setStatus(`Erreur : ${e.message}`);
    }
  }

  function setStatus(text) {
    const el = document.getElementById("wsStatus");
    if (el) el.textContent = text;
  }

  function renderWorkspaceSelect() {
    const sel = document.getElementById("wsWorkspaceSelect");
    if (!sel) return;
    sel.innerHTML = workspaces.length
      ? workspaces.map((w) => `<option value="${esc(w.id)}">${esc(w.name)} (${w.open_cases || 0} ouverts)</option>`).join("")
      : `<option value="">— Aucun workspace —</option>`;
    const active = localStorage.getItem(LS_WORKSPACE);
    if (active) sel.value = active;
  }

  async function onSelectWorkspace(e) {
    const id = e.target.value;
    if (!id) return;
    localStorage.setItem(LS_WORKSPACE, id);
    await loadWorkspace(id);
  }

  async function loadWorkspace(workspaceId) {
    const res = await fetch(`/api/workspaces/${workspaceId}`, { headers: apiHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Erreur");
    current = data;
    localStorage.setItem(LS_WORKSPACE, workspaceId);
    const sel = document.getElementById("wsWorkspaceSelect");
    if (sel) sel.value = workspaceId;
    renderWorkspaceDetail();
  }

  function renderEmpty() {
    document.getElementById("wsDetail")?.classList.add("hidden");
    document.getElementById("wsEmpty")?.classList.remove("hidden");
  }

  function renderWorkspaceDetail() {
    document.getElementById("wsEmpty")?.classList.add("hidden");
    document.getElementById("wsDetail")?.classList.remove("hidden");
    if (!current) return;

    const ws = current.workspace;
    document.getElementById("wsTitle").textContent = ws.name;
    document.getElementById("wsDesc").textContent = ws.description || "Aucune description";
    document.getElementById("wsMeta").innerHTML = `
      <span>👤 ${ws.member_count || (ws.members || []).length} membre(s)</span>
      <span>📁 ${(current.cases || []).length} dossier(s)</span>
      <span>Propriétaire : <strong>${esc(ws.owner)}</strong></span>`;

    renderMembers(ws.members || []);
    renderCases(current.cases || []);
    renderNotes(current.notes || []);
    renderActivity(current.recent_activity || []);
  }

  function renderMembers(members) {
    const el = document.getElementById("wsMembers");
    if (!el) return;
    el.innerHTML = members.map((m) => `
      <div class="ws-member">
        <span class="ws-member-name">${esc(m.username)}</span>
        <span class="ws-role ws-role-${esc(m.role)}">${esc(m.role)}</span>
        ${m.username !== getUser() && isOwner() ? `
          <button type="button" class="ws-remove-member" data-user="${esc(m.username)}">✕</button>` : ""}
      </div>`).join("");

    el.querySelectorAll(".ws-remove-member").forEach((btn) => {
      btn.addEventListener("click", () => removeMember(btn.dataset.user));
    });
  }

  function renderCases(cases) {
    const el = document.getElementById("wsCases");
    if (!el) return;
    if (!cases.length) {
      el.innerHTML = `<p class="ws-empty-inline">Aucun dossier — créez-en un ou ajoutez une investigation.</p>`;
      return;
    }
    el.innerHTML = cases.map((c) => `
      <div class="ws-case ${selectedCaseId === c.id ? "selected" : ""}" data-id="${esc(c.id)}">
        <div class="ws-case-head">
          <span class="ws-case-title">${esc(c.title)}</span>
          <span class="ws-case-status ws-status-${esc(c.status)}">${fmtStatus(c.status)}</span>
        </div>
        <div class="ws-case-meta">
          <span class="ws-priority ws-pri-${esc(c.priority)}">${(c.priority || "medium").toUpperCase()}</span>
          <span>${(c.investigations || []).length} inv.</span>
          <span>${fmtDate(c.updated_at)}</span>
        </div>
        ${(c.investigations || []).map((inv) => `
          <div class="ws-inv-chip">
            <code>${esc(inv.target)}</code>
            <span class="ws-risk-${esc(inv.overall_risk)}">${(inv.overall_risk || "low").toUpperCase()}</span>
          </div>`).join("")}
      </div>`).join("");

    el.querySelectorAll(".ws-case").forEach((card) => {
      card.addEventListener("click", () => {
        selectedCaseId = card.dataset.id;
        renderCases(cases);
        const noteCase = document.getElementById("wsNoteCase");
        if (noteCase) noteCase.value = selectedCaseId;
      });
    });
  }

  function renderNotes(notes) {
    const el = document.getElementById("wsNotes");
    if (!el) return;
    if (!notes.length) {
      el.innerHTML = `<p class="ws-empty-inline">Aucune note collaborative.</p>`;
      return;
    }
    el.innerHTML = notes.map((n) => `
      <div class="ws-note">
        <div class="ws-note-head">
          <strong>${esc(n.author)}</strong>
          <span>${fmtDate(n.created_at)}</span>
        </div>
        <p>${esc(n.content)}</p>
      </div>`).join("");
  }

  function renderActivity(items) {
    const el = document.getElementById("wsActivity");
    if (!el) return;
    if (!items.length) {
      el.innerHTML = `<p class="ws-empty-inline">Aucune activité récente.</p>`;
      return;
    }
    el.innerHTML = items.map((a) => `
      <div class="ws-activity-item">
        <span class="ws-act-time">${fmtDate(a.created_at)}</span>
        <span class="ws-act-actor">${esc(a.actor)}</span>
        <span class="ws-act-msg">${esc(a.message)}</span>
      </div>`).join("");
  }

  function isOwner() {
    const ws = current?.workspace;
    if (!ws) return false;
    return ws.owner === getUser() || (ws.members || []).some(
      (m) => m.username === getUser() && m.role === "owner"
    );
  }

  async function onCreateWorkspace(e) {
    e.preventDefault();
    const name = document.getElementById("wsNewName")?.value?.trim();
    const desc = document.getElementById("wsNewDesc")?.value?.trim();
    if (!name) return;
    try {
      const res = await fetch("/api/workspaces", {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({ name, description: desc || "" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      document.getElementById("wsNewName").value = "";
      document.getElementById("wsNewDesc").value = "";
      localStorage.setItem(LS_WORKSPACE, data.workspace.id);
      window.updateTerminal?.(`[WORKSPACE] « ${name} » créé`);
      await refresh();
    } catch (err) {
      window.updateTerminal?.(`[WORKSPACE] ${err.message}`);
    }
  }

  async function onAddMember(e) {
    e.preventDefault();
    if (!current) return;
    const username = document.getElementById("wsMemberName")?.value?.trim();
    const role = document.getElementById("wsMemberRole")?.value || "analyst";
    if (!username) return;
    try {
      const res = await fetch(`/api/workspaces/${current.workspace.id}/members`, {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({ username, role }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      document.getElementById("wsMemberName").value = "";
      await loadWorkspace(current.workspace.id);
    } catch (err) {
      window.updateTerminal?.(`[WORKSPACE] ${err.message}`);
    }
  }

  async function removeMember(username) {
    if (!current || !confirm(`Retirer ${username} ?`)) return;
    try {
      const res = await fetch(`/api/workspaces/${current.workspace.id}/members/${username}`, {
        method: "DELETE",
        headers: apiHeaders(),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Erreur");
      }
      await loadWorkspace(current.workspace.id);
    } catch (err) {
      window.updateTerminal?.(`[WORKSPACE] ${err.message}`);
    }
  }

  async function onCreateCase(e) {
    e.preventDefault();
    if (!current) return;
    const title = document.getElementById("wsCaseTitle")?.value?.trim();
    if (!title) return;
    try {
      const res = await fetch(`/api/workspaces/${current.workspace.id}/cases`, {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({ title }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      document.getElementById("wsCaseTitle").value = "";
      await loadWorkspace(current.workspace.id);
    } catch (err) {
      window.updateTerminal?.(`[WORKSPACE] ${err.message}`);
    }
  }

  async function onAddNote(e) {
    e.preventDefault();
    if (!current) return;
    const content = document.getElementById("wsNoteContent")?.value?.trim();
    const caseId = document.getElementById("wsNoteCase")?.value || selectedCaseId || null;
    if (!content) return;
    try {
      const res = await fetch(`/api/workspaces/${current.workspace.id}/notes`, {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({ content, case_id: caseId || undefined }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      document.getElementById("wsNoteContent").value = "";
      await loadWorkspace(current.workspace.id);
    } catch (err) {
      window.updateTerminal?.(`[WORKSPACE] ${err.message}`);
    }
  }

  async function addInvestigation(investigation, caseTitle) {
    if (!getUser()) {
      showPanel();
      window.updateTerminal?.("[WORKSPACE] Identifiez-vous d'abord dans l'onglet Workspace");
      return;
    }
    let workspaceId = localStorage.getItem(LS_WORKSPACE);
    if (!workspaceId || !workspaces.some((w) => w.id === workspaceId)) {
      if (!workspaces.length) {
        showPanel();
        window.updateTerminal?.("[WORKSPACE] Créez un workspace avant d'ajouter une investigation");
        return;
      }
      workspaceId = workspaces[0].id;
    }

    try {
      const res = await fetch(`/api/workspaces/${workspaceId}/investigations`, {
        method: "POST",
        headers: apiHeaders(),
        body: JSON.stringify({
          investigation,
          case_id: selectedCaseId || undefined,
          case_title: caseTitle || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur");
      window.updateTerminal?.(`[WORKSPACE] Investigation ajoutée au dossier`);
      showPanel();
      await refresh();
      return data;
    } catch (err) {
      window.updateTerminal?.(`[WORKSPACE] ${err.message}`);
      throw err;
    }
  }

  function showPanel() {
    window.activatePGPanel?.("panel-workspace");
  }

  function getActiveWorkspaceId() {
    return localStorage.getItem(LS_WORKSPACE);
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
    } catch {
      return iso.slice(0, 16);
    }
  }

  function fmtStatus(s) {
    return { open: "Ouvert", in_progress: "En cours", closed: "Fermé", archived: "Archivé" }[s] || s;
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init, refresh, addInvestigation, showPanel, getUser, getActiveWorkspaceId };
})();

window.WorkspaceUI = WorkspaceUI;

document.addEventListener("DOMContentLoaded", () => {
  try { WorkspaceUI.init(); } catch (e) { console.error("[WORKSPACE]", e); }
});
