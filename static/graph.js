/**
 * Graphe de relations OSINT — Cytoscape.js (léger, annulable)
 */
const GraphUI = (() => {
  let cy = null;
  let currentGraph = null;
  let lastInvestigation = null;
  let loadedKey = null;
  let busy = false;
  let renderToken = 0;
  let pendingTimer = null;
  let abortCtrl = null;

  const MAX_CLIENT_NODES = 20;

  const TYPE_COLORS = {
    email: "#3d8bfd",
    username: "#64748b",
    domain: "#1ec98a",
    ip: "#38bdf8",
    url: "#94a3b8",
    company: "#fb923c",
    unknown: "#94a3b8",
  };

  function yieldToUI(ms = 0) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function investigationKey(inv) {
    if (!inv) return null;
    return String(inv.id || inv.target || "") + ":" + String((inv.entities || []).length);
  }

  function init() {
    const pivotBtn = document.getElementById("graphPivotBtn");
    const exportJsonBtn = document.getElementById("graphExportJson");
    const exportPngBtn = document.getElementById("graphExportPng");
    const fitBtn = document.getElementById("graphFitBtn");
    const clearBtn = document.getElementById("graphClearBtn");
    const loadBtn = document.getElementById("graphLoadBtn");

    pivotBtn?.addEventListener("click", (e) => {
      e.preventDefault();
      pivotSelected();
    });
    exportJsonBtn?.addEventListener("click", exportJson);
    exportPngBtn?.addEventListener("click", exportPng);
    fitBtn?.addEventListener("click", () => {
      if (!cy) return;
      try {
        cy.resize();
        cy.fit(undefined, 48);
      } catch (_) { /* ignore */ }
    });
    clearBtn?.addEventListener("click", clearGraph);
    loadBtn?.addEventListener("click", () => {
      const inv =
        lastInvestigation ||
        window.PlaybooksUI?.getLastResult?.() ||
        window.PlaybooksUI?.getLatestHistoryResult?.();
      if (!inv) {
        setStatus("Aucune investigation — lancez un playbook d'abord", "error");
        return;
      }
      loadFromInvestigation(inv, { navigate: false, force: true });
    });

    if (typeof cytoscape === "undefined") {
      setStatus("Cytoscape.js non chargé", "error");
    } else {
      setStatus("Prêt — chargez une investigation", "idle");
    }
  }

  function setStatus(text, state = "idle") {
    const el = document.getElementById("graphStatus");
    if (!el) return;
    el.textContent = text;
    el.className = `graph-status graph-status-${state}`;
  }

  function setMeta(graph) {
    const el = document.getElementById("graphMeta");
    if (!el || !graph?.meta) return;
    const m = graph.meta;
    el.innerHTML = `
      <span>${m.node_count || 0} nœuds</span>
      <span>${m.edge_count || 0} liens</span>
      ${m.target ? `<span>Cible : <code>${esc(m.target)}</code></span>` : ""}`;
  }

  function destroyCy() {
    if (cy) {
      try {
        cy.destroy();
      } catch (_) { /* ignore */ }
      cy = null;
    }
  }

  /** Annule un rendu en cours et libère Cytoscape (appelé en quittant le panneau). */
  function suspend() {
    renderToken += 1;
    if (pendingTimer) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
    if (abortCtrl) {
      try {
        abortCtrl.abort();
      } catch (_) { /* ignore */ }
      abortCtrl = null;
    }
    busy = false;
    destroyCy();
    window.PGMatrix?.resume?.();
    window.FX?.resume?.();
  }

  function pauseBgFx() {
    window.PGMatrix?.pause?.();
    window.FX?.pause?.();
  }

  function slimInvestigation(investigation) {
    if (!investigation || typeof investigation !== "object") return investigation;
    const entities = Array.isArray(investigation.entities)
      ? investigation.entities.slice(0, 30)
      : [];
    const steps = (investigation.steps || []).map((step) => {
      const data = step.data || {};
      const plugin = step.plugin_id;
      if (plugin === "sherlock" && data.profiles) {
        const entries = Object.entries(data.profiles).slice(0, 10);
        return {
          plugin_id: plugin,
          plugin_name: step.plugin_name,
          status: step.status,
          data: {
            username: data.username,
            count: Math.min(data.count || entries.length, 10),
            sites_found: (data.sites_found || []).slice(0, 10),
            profiles: Object.fromEntries(entries),
          },
        };
      }
      // Ne garder que des champs utiles / courts pour éviter un JSON énorme
      const slimData = {};
      for (const [k, v] of Object.entries(data)) {
        if (v == null || typeof v === "boolean" || typeof v === "number") {
          slimData[k] = v;
        } else if (typeof v === "string") {
          slimData[k] = v.length > 300 ? v.slice(0, 300) : v;
        } else if (Array.isArray(v)) {
          slimData[k] = v.slice(0, 12);
        }
      }
      return {
        plugin_id: plugin,
        plugin_name: step.plugin_name,
        status: step.status,
        data: slimData,
      };
    });
    return {
      id: investigation.id,
      target: investigation.target,
      target_type: investigation.target_type,
      playbook_name: investigation.playbook_name,
      playbook_id: investigation.playbook_id,
      entities,
      steps,
    };
  }

  function scheduleLoad(investigation, opts = {}) {
    if (pendingTimer) clearTimeout(pendingTimer);
    pendingTimer = setTimeout(() => {
      pendingTimer = null;
      loadFromInvestigation(investigation, opts);
    }, opts.delayMs || 40);
  }

  async function loadFromInvestigation(investigation, opts = {}) {
    if (!investigation) return;
    const key = investigationKey(investigation);
    const navigate = opts.navigate !== false;
    const force = !!opts.force;

    lastInvestigation = investigation;
    if (navigate) showPanel();

    // Déjà affiché pour cette investigation → ne pas reconstruire (évite freeze)
    if (!force && key && key === loadedKey && cy && currentGraph) {
      setStatus("Graphe déjà chargé", "ok");
      setMeta(currentGraph);
      return;
    }

    if (busy && !force) return;
    busy = true;
    setStatus("Construction du graphe…", "loading");
    pauseBgFx();

    const token = ++renderToken;
    if (abortCtrl) {
      try {
        abortCtrl.abort();
      } catch (_) { /* ignore */ }
    }
    abortCtrl = typeof AbortController !== "undefined" ? new AbortController() : null;

    try {
      await yieldToUI(16);
      if (token !== renderToken) return;

      const payload = slimInvestigation(investigation);
      await yieldToUI(0);
      if (token !== renderToken) return;

      const res = await fetch("/api/graph/from-investigation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ investigation: payload }),
        signal: abortCtrl?.signal,
      });
      if (token !== renderToken) return;
      const data = await res.json();
      if (token !== renderToken) return;
      if (!res.ok) throw new Error(data.detail || "Erreur serveur");

      await renderGraph(data.graph, data.cytoscape, { token });
      if (token !== renderToken) return;
      loadedKey = key;
      window.updateTerminal?.(
        `[GRAPH] ${data.graph.meta?.node_count || 0} nœuds, ${data.graph.meta?.edge_count || 0} liens`
      );
    } catch (err) {
      if (err?.name === "AbortError") return;
      if (token === renderToken) setStatus(`Erreur : ${err.message}`, "error");
    } finally {
      if (token === renderToken) busy = false;
    }
  }

  function assignCirclePositions(nodeElements) {
    const n = nodeElements.length;
    if (!n) return;
    const R = Math.max(100, n * 16);
    nodeElements.forEach((el, i) => {
      const a = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
      el.position = { x: Math.cos(a) * R, y: Math.sin(a) * R };
    });
  }

  async function renderGraph(graph, cytoscapeData, opts = {}) {
    if (typeof cytoscape === "undefined") {
      setStatus("Cytoscape.js indisponible", "error");
      return;
    }

    const token = opts.token || ++renderToken;
    currentGraph = graph;
    const container = document.getElementById("cyGraph");
    if (!container) return;

    await yieldToUI(0);
    if (token !== renderToken) return;

    const rawList = Array.isArray(cytoscapeData?.elements) ? cytoscapeData.elements : [];
    const isEdge = (d) => d && d.source != null && d.target != null;

    const nodeIds = new Set(
      rawList
        .filter((el) => el?.data?.id && !isEdge(el.data))
        .map((el) => el.data.id)
    );

    let rawElements = rawList;
    if (!rawElements.length) {
      rawElements = [];
      for (const node of graph?.nodes || []) {
        rawElements.push({
          data: {
            id: node.id,
            label: node.label,
            type: node.type,
            is_root: !!node.is_root,
            color: node.color || TYPE_COLORS[node.type] || TYPE_COLORS.unknown,
            icon: node.icon,
            source: node.source,
          },
        });
        nodeIds.add(node.id);
      }
      for (const edge of graph?.edges || []) {
        rawElements.push({
          data: {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            label: edge.label || "",
            relation: edge.relation || "",
          },
        });
      }
    }

    const elements = rawElements
      .filter((el) => {
        const d = el?.data;
        if (!d?.id) return false;
        if (isEdge(d)) return nodeIds.has(d.source) && nodeIds.has(d.target);
        return true;
      })
      .map((el) => {
        const d = { ...el.data };
        if (!isEdge(d)) {
          d.is_root = !!d.is_root;
          d.color = d.color || TYPE_COLORS[d.type] || TYPE_COLORS.unknown;
          d.label = d.label || d.id;
        }
        return { data: d };
      });

    const nodesOnly = elements.filter((e) => !isEdge(e.data));
    const edgesOnly = elements.filter((e) => isEdge(e.data));
    const cappedNodes = nodesOnly.slice(0, MAX_CLIENT_NODES);
    const keep = new Set(cappedNodes.map((n) => n.data.id));
    const cappedEdges = edgesOnly.filter(
      (e) => keep.has(e.data.source) && keep.has(e.data.target)
    );

    assignCirclePositions(cappedNodes);
    const finalElements = [...cappedNodes, ...cappedEdges];
    const nodeCount = cappedNodes.length;

    destroyCy();
    await yieldToUI(16);
    if (token !== renderToken) return;

    if (container.clientHeight < 200) {
      container.style.minHeight = "420px";
      container.style.height = "420px";
    }

    // Positions pré-calculées : pas d'algo cose/circle (bloque Firefox)
    cy = cytoscape({
      container,
      elements: finalElements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            "font-size": "9px",
            color: "#e2e8f0",
            "text-outline-color": "#030508",
            "text-outline-width": 2,
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 4,
            "text-wrap": "ellipsis",
            "text-max-width": "90px",
            width: 36,
            height: 36,
            "border-width": 2,
            "border-color": "rgba(255,255,255,0.18)",
          },
        },
        {
          selector: "node[?is_root]",
          style: {
            width: 48,
            height: 48,
            "border-width": 3,
            "border-color": "#4f83f1",
            "font-weight": "bold",
            "font-size": "10px",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#00e676",
            "border-width": 3,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "rgba(79, 131, 241, 0.4)",
            "target-arrow-color": "rgba(79, 131, 241, 0.55)",
            "target-arrow-shape": "triangle",
            "curve-style": "haystack",
            "haystack-radius": 0.4,
            label: "",
          },
        },
      ],
      layout: { name: "preset", fit: true, padding: 40 },
      wheelSensitivity: 0.2,
      minZoom: 0.25,
      maxZoom: 2.5,
      pixelRatio: 1,
      textureOnViewport: true,
      hideEdgesOnViewport: true,
      motionBlur: false,
    });

    if (token !== renderToken) {
      destroyCy();
      return;
    }

    cy.on("tap", "node", (evt) => {
      showNodeDetail(evt.target.data());
    });

    cy.on("dbltap", "node", (evt) => {
      const d = evt.target.data();
      if (!d.is_root) pivotNode(d.label, d.type);
    });

    await yieldToUI(0);
    if (token !== renderToken || !cy) return;
    try {
      cy.resize();
      cy.fit(undefined, 40);
    } catch (_) { /* ignore */ }

    setMeta(graph);
    const n = Math.min(graph.meta?.node_count || nodeCount, nodeCount);
    const trunc =
      graph.meta?.truncated || (nodesOnly.length > MAX_CLIENT_NODES)
        ? " (aperçu limité)"
        : "";
    setStatus(n ? `${n} entités reliées${trunc}` : "Aucune entité", n ? "ok" : "idle");
  }

  function showNodeDetail(data) {
    const panel = document.getElementById("graphNodeDetail");
    if (!panel) return;
    const color = TYPE_COLORS[data.type] || TYPE_COLORS.unknown;
    panel.innerHTML = `
      <div class="graph-node-type" style="color:${color}">${esc(data.type?.toUpperCase() || "?")}</div>
      <div class="graph-node-value">${esc(data.label)}</div>
      ${data.source ? `<div class="graph-node-source">Source : ${esc(data.source)}</div>` : ""}
      <button type="button" class="pb-export-btn graph-pivot-inline" data-target="${esc(data.label)}" data-type="${esc(data.type)}">
        Pivot OSINT
      </button>
      <p class="graph-node-hint">Double-clic sur un nœud pour pivoter</p>`;

    panel.querySelector(".graph-pivot-inline")?.addEventListener("click", (e) => {
      const btn = e.currentTarget;
      pivotNode(btn.dataset.target, btn.dataset.type);
    });
  }

  function pivotSelected() {
    const selected = cy?.$("node:selected");
    if (!selected || selected.length === 0) {
      setStatus("Sélectionnez un nœud à investiguer", "error");
      return;
    }
    const d = selected[0].data();
    pivotNode(d.label, d.type);
  }

  async function pivotNode(target, entityType) {
    if (!target || busy) return;
    busy = true;
    setStatus(`Pivot sur ${target}…`, "loading");
    showPanel();
    pauseBgFx();
    const token = ++renderToken;

    try {
      const res = await fetch("/api/graph/pivot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          entity_type: entityType,
          existing_graph: currentGraph,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur pivot");
      if (token !== renderToken) return;

      lastInvestigation = data.investigation;
      loadedKey = null;
      await renderGraph(data.graph, data.cytoscape, { token });
      window.updateTerminal?.(
        `[GRAPH] Pivot ${target} — ${data.graph.meta?.node_count || 0} nœuds`
      );
    } catch (err) {
      if (token === renderToken) setStatus(`Pivot échoué : ${err.message}`, "error");
    } finally {
      if (token === renderToken) busy = false;
    }
  }

  function showPanel() {
    // Ne PAS appeler activatePGPanel ici → boucle infinie (Firefox freeze)
    const panel = document.getElementById("panel-graph");
    if (!panel) return;
    document.querySelectorAll("main.content > .panel").forEach((p) => p.classList.add("hidden"));
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    panel.classList.remove("hidden");
    const btn = document.querySelector('.nav-item[data-target="panel-graph"]');
    btn?.classList.add("active");
    const pageTitle = document.getElementById("pageTitle");
    const pageSubtitle = document.getElementById("pageSubtitle");
    if (pageTitle) pageTitle.textContent = btn?.getAttribute("data-title") || "Graphe OSINT";
    if (pageSubtitle) {
      pageSubtitle.textContent =
        btn?.getAttribute("data-subtitle") || "Relations entre entités découvertes";
    }
    pauseBgFx();
  }

  function clearGraph() {
    suspend();
    currentGraph = null;
    lastInvestigation = null;
    loadedKey = null;
    const detail = document.getElementById("graphNodeDetail");
    if (detail) {
      detail.innerHTML =
        '<p class="graph-side-empty">Cliquez sur un nœud pour voir les détails et lancer un pivot.</p>';
    }
    const meta = document.getElementById("graphMeta");
    if (meta) meta.innerHTML = "";
    setStatus("Graphe effacé", "idle");
  }

  function exportJson() {
    if (!currentGraph) return;
    const blob = new Blob([JSON.stringify(currentGraph, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `osint-graph-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    window.updateTerminal?.("[GRAPH] Export JSON");
  }

  function exportPng() {
    if (!cy) return;
    try {
      const png = cy.png({ bg: "#030508", full: true, scale: 1 });
      const a = document.createElement("a");
      a.href = png;
      a.download = `osint-graph-${Date.now()}.png`;
      a.click();
      window.updateTerminal?.("[GRAPH] Export PNG");
    } catch (err) {
      setStatus(`Export PNG échoué : ${err.message}`, "error");
    }
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  function hasGraph() {
    return !!(cy && currentGraph);
  }

  function getLoadedKey() {
    return loadedKey;
  }

  return {
    init,
    loadFromInvestigation,
    scheduleLoad,
    showPanel,
    pivotNode,
    suspend,
    hasGraph,
    getLoadedKey,
  };
})();

document.addEventListener("DOMContentLoaded", () => {
  try {
    GraphUI.init();
  } catch (e) {
    console.error("[GRAPH] init failed", e);
  }
});

window.GraphUI = GraphUI;
