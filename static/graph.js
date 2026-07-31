/**
 * Graphe de relations OSINT — Cytoscape.js
 */
const GraphUI = (() => {
  let cy = null;
  let currentGraph = null;
  let lastInvestigation = null;
  let busy = false;
  let renderToken = 0;

  const TYPE_COLORS = {
    email: "#3d8bfd",
    username: "#64748b",
    domain: "#1ec98a",
    ip: "#38bdf8",
    url: "#94a3b8",
    company: "#fb923c",
    unknown: "#94a3b8",
  };

  function init() {
    const pivotBtn = document.getElementById("graphPivotBtn");
    const exportJsonBtn = document.getElementById("graphExportJson");
    const exportPngBtn = document.getElementById("graphExportPng");
    const fitBtn = document.getElementById("graphFitBtn");
    const clearBtn = document.getElementById("graphClearBtn");

    pivotBtn?.addEventListener("click", (e) => {
      e.preventDefault();
      pivotSelected();
    });
    exportJsonBtn?.addEventListener("click", exportJson);
    exportPngBtn?.addEventListener("click", exportPng);
    fitBtn?.addEventListener("click", () => {
      if (!cy) return;
      cy.resize();
      cy.fit(undefined, 48);
    });
    clearBtn?.addEventListener("click", clearGraph);

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

  function waitForVisible(el, timeoutMs = 800) {
    return new Promise((resolve) => {
      const start = Date.now();
      const tick = () => {
        const rect = el.getBoundingClientRect();
        if (rect.width >= 40 && rect.height >= 40) {
          resolve(true);
          return;
        }
        if (Date.now() - start > timeoutMs) {
          resolve(false);
          return;
        }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  async function loadFromInvestigation(investigation) {
    if (!investigation) return;
    lastInvestigation = investigation;
    setStatus("Construction du graphe…", "loading");
    showPanel();

    try {
      const res = await fetch("/api/graph/from-investigation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ investigation }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur serveur");
      await renderGraph(data.graph, data.cytoscape);
      window.updateTerminal?.(
        `[GRAPH] ${data.graph.meta?.node_count || 0} nœuds, ${data.graph.meta?.edge_count || 0} liens`
      );
    } catch (err) {
      setStatus(`Erreur : ${err.message}`, "error");
    }
  }

  async function renderGraph(graph, cytoscapeData) {
    if (typeof cytoscape === "undefined") {
      setStatus("Cytoscape.js indisponible", "error");
      return;
    }

    currentGraph = graph;
    const container = document.getElementById("cyGraph");
    if (!container) return;

    const token = ++renderToken;
    showPanel();
    await waitForVisible(container);
    if (token !== renderToken) return;

    const rawList = Array.isArray(cytoscapeData?.elements) ? cytoscapeData.elements : [];
    const isEdge = (d) => d && d.source != null && d.target != null;

    const nodeIds = new Set(
      rawList
        .filter((el) => el?.data?.id && !isEdge(el.data))
        .map((el) => el.data.id)
    );

    // Fallback si le serveur n'a pas fourni le format Cytoscape
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

    const elements = rawElements.filter((el) => {
      const d = el?.data;
      if (!d?.id) return false;
      if (isEdge(d)) {
        return nodeIds.has(d.source) && nodeIds.has(d.target);
      }
      return true;
    }).map((el) => {
      const d = { ...el.data };
      if (!isEdge(d)) {
        d.is_root = !!d.is_root;
        d.color = d.color || TYPE_COLORS[d.type] || TYPE_COLORS.unknown;
        d.label = d.label || d.id;
      }
      return { data: d };
    });

    if (cy) {
      cy.destroy();
      cy = null;
    }

    // Forcer une taille minimale avant init (évite canvas 0×0)
    if (container.clientHeight < 200) {
      container.style.minHeight = "420px";
      container.style.height = "420px";
    }

    const nodeCount = elements.filter((e) => !isEdge(e.data)).length;

    cy = cytoscape({
      container,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            "font-size": "10px",
            color: "#e2e8f0",
            "text-outline-color": "#030508",
            "text-outline-width": 2,
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 6,
            "text-wrap": "ellipsis",
            "text-max-width": "100px",
            width: 44,
            height: 44,
            "border-width": 2,
            "border-color": "rgba(255,255,255,0.18)",
          },
        },
        {
          selector: "node[?is_root]",
          style: {
            width: 58,
            height: 58,
            "border-width": 3,
            "border-color": "#4f83f1",
            "font-weight": "bold",
            "font-size": "11px",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#00e676",
            "border-width": 4,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "rgba(79, 131, 241, 0.45)",
            "target-arrow-color": "rgba(79, 131, 241, 0.65)",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "8px",
            color: "#94a3b8",
            "text-rotation": "autorotate",
            "text-background-color": "#030508",
            "text-background-opacity": 0.7,
            "text-background-padding": 2,
          },
        },
      ],
      layout: {
        name: nodeCount > 20 ? "breadthfirst" : "cose",
        animate: false,
        padding: 48,
        directed: true,
        spacingFactor: nodeCount > 20 ? 1.15 : 1.35,
        avoidOverlap: true,
        randomize: nodeCount <= 20,
        componentSpacing: 60,
        nestingFactor: 1.1,
        gravity: 1,
        numIter: nodeCount > 20 ? 400 : 900,
        initialTemp: 120,
        coolingFactor: 0.95,
        minTemp: 1.0,
        nodeRepulsion: () => 6000,
        idealEdgeLength: () => 90,
        edgeElasticity: () => 80,
        nodeOverlap: 20,
      },
      wheelSensitivity: 0.25,
      minZoom: 0.2,
      maxZoom: 3,
    });

    cy.on("tap", "node", (evt) => {
      showNodeDetail(evt.target.data());
    });

    cy.on("dbltap", "node", (evt) => {
      const d = evt.target.data();
      if (!d.is_root) pivotNode(d.label, d.type);
    });

    // Resize après affichage du panneau (sinon nœuds empilés / canvas vide)
    requestAnimationFrame(() => {
      if (!cy || token !== renderToken) return;
      cy.resize();
      cy.fit(undefined, 48);
      setTimeout(() => {
        if (!cy || token !== renderToken) return;
        cy.resize();
        cy.fit(undefined, 48);
      }, 80);
    });

    setMeta(graph);
    const n = graph.meta?.node_count || nodeCount;
    const trunc = graph.meta?.truncated
      ? ` (aperçu — ${graph.meta.entities_total || "?"} entités au total)`
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

      lastInvestigation = data.investigation;
      await renderGraph(data.graph, data.cytoscape);
      window.updateTerminal?.(
        `[GRAPH] Pivot ${target} — ${data.graph.meta?.node_count || 0} nœuds`
      );
    } catch (err) {
      setStatus(`Pivot échoué : ${err.message}`, "error");
    } finally {
      busy = false;
    }
  }

  function showPanel() {
    window.activatePGPanel?.("panel-graph");
  }

  function clearGraph() {
    renderToken += 1;
    if (cy) {
      cy.destroy();
      cy = null;
    }
    currentGraph = null;
    lastInvestigation = null;
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
    const png = cy.png({ bg: "#030508", full: true, scale: 2 });
    const a = document.createElement("a");
    a.href = png;
    a.download = `osint-graph-${Date.now()}.png`;
    a.click();
    window.updateTerminal?.("[GRAPH] Export PNG");
  }

  function esc(str) {
    if (str == null) return "";
    const d = document.createElement("div");
    d.textContent = String(str);
    return d.innerHTML;
  }

  return { init, loadFromInvestigation, showPanel, pivotNode };
})();

document.addEventListener("DOMContentLoaded", () => {
  try {
    GraphUI.init();
  } catch (e) {
    console.error("[GRAPH]", e);
  }
});

window.GraphUI = GraphUI;
