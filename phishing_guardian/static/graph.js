/**
 * Graphe de relations OSINT — Cytoscape.js
 */
const GraphUI = (() => {
  let cy = null;
  let currentGraph = null;
  let lastInvestigation = null;
  let busy = false;

  const TYPE_COLORS = {
    email: "#60a5fa",
    username: "#a78bfa",
    domain: "#34d399",
    ip: "#fbbf24",
    url: "#f472b6",
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
    fitBtn?.addEventListener("click", () => cy?.fit(undefined, 40));
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

  async function loadFromInvestigation(investigation) {
    if (!investigation) return;
    lastInvestigation = investigation;
    setStatus("Construction du graphe…", "loading");

    try {
      const res = await fetch("/api/graph/from-investigation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ investigation }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur serveur");
      renderGraph(data.graph, data.cytoscape);
      window.updateTerminal?.(`[GRAPH] ${data.graph.meta?.node_count || 0} nœuds, ${data.graph.meta?.edge_count || 0} liens`);
    } catch (err) {
      setStatus(`Erreur : ${err.message}`, "error");
    }
  }

  function renderGraph(graph, cytoscapeData) {
    if (typeof cytoscape === "undefined") {
      setStatus("Cytoscape.js indisponible", "error");
      return;
    }

    currentGraph = graph;
    const container = document.getElementById("cyGraph");
    if (!container) return;

    const elements = cytoscapeData?.elements || [];

    if (cy) {
      cy.destroy();
      cy = null;
    }

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
            "text-wrap": "ellipsis",
            "text-max-width": "90px",
            width: 42,
            height: 42,
            "border-width": 2,
            "border-color": "rgba(255,255,255,0.15)",
          },
        },
        {
          selector: "node[is_root = true]",
          style: {
            width: 54,
            height: 54,
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
            color: "#64748b",
            "text-rotation": "autorotate",
          },
        },
      ],
      layout: { name: "cose", animate: true, padding: 40, nodeRepulsion: 8000, idealEdgeLength: 100 },
      wheelSensitivity: 0.3,
    });

    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      showNodeDetail(node.data());
    });

    cy.on("dbltap", "node", (evt) => {
      const d = evt.target.data();
      if (!d.is_root) pivotNode(d.label, d.type);
    });

    setMeta(graph);
    setStatus(`${graph.meta?.node_count || 0} entités reliées`, "ok");
    showPanel();
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
        🔍 Pivot OSINT
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
      renderGraph(data.graph, data.cytoscape);
      window.updateTerminal?.(`[GRAPH] Pivot ${target} — ${data.graph.meta?.node_count || 0} nœuds`);
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
    if (cy) {
      cy.destroy();
      cy = null;
    }
    currentGraph = null;
    lastInvestigation = null;
    document.getElementById("graphNodeDetail").innerHTML =
      '<p class="graph-side-empty">Cliquez sur un nœud pour voir les détails et lancer un pivot.</p>';
    document.getElementById("graphMeta").innerHTML = "";
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
  try { GraphUI.init(); } catch (e) { console.error("[GRAPH]", e); }
});

window.GraphUI = GraphUI;
