from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from services.entity_resolver import resolve_entity_type, suggest_playbook_id

ENTITY_COLORS = {
    "email": "#60a5fa",
    "username": "#a78bfa",
    "domain": "#34d399",
    "ip": "#fbbf24",
    "url": "#f472b6",
    "company": "#fb923c",
    "unknown": "#94a3b8",
}

ENTITY_ICONS = {
    "email": "✉",
    "username": "👤",
    "domain": "🌐",
    "ip": "📡",
    "url": "🔗",
    "company": "🏢",
    "unknown": "❓",
}


def _node_id(entity_type: str, value: str) -> str:
    safe = re.sub(r"[^a-z0-9@._:-]+", "_", value.lower().strip())
    return f"{entity_type}:{safe}"


def _add_edge(
    edges: List[Dict[str, Any]],
    seen: Set[str],
    source: str,
    target: str,
    label: str,
    relation: str,
    weight: float = 1.0,
) -> None:
    if source == target:
        return
    key = f"{source}|{target}|{relation}"
    if key in seen:
        return
    seen.add(key)
    edges.append(
        {
            "id": f"edge_{len(edges) + 1}",
            "source": source,
            "target": target,
            "label": label,
            "relation": relation,
            "weight": weight,
        }
    )


def _make_node(
    node_id: str,
    value: str,
    entity_type: str,
    *,
    is_root: bool = False,
    source: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "id": node_id,
        "label": value,
        "type": entity_type,
        "is_root": is_root,
        "source": source,
        "color": ENTITY_COLORS.get(entity_type, ENTITY_COLORS["unknown"]),
        "icon": ENTITY_ICONS.get(entity_type, ENTITY_ICONS["unknown"]),
        "metadata": metadata or {},
    }


def _ensure_node(
    nodes: Dict[str, Dict[str, Any]],
    entity_type: str,
    value: str,
    *,
    source: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    if not value or not str(value).strip():
        return ""
    etype = entity_type if entity_type in ENTITY_COLORS else resolve_entity_type(value).value
    nid = _node_id(etype, value)
    if nid not in nodes:
        nodes[nid] = _make_node(nid, value, etype, source=source, metadata=metadata)
    return nid


def _infer_from_target(
    target: str,
    target_type: str,
    root_id: str,
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    if target_type == "email" and "@" in target:
        user, domain = target.split("@", 1)
        domain_id = _ensure_node(nodes, "domain", domain, source="inferred")
        user_id = _ensure_node(nodes, "username", user, source="inferred")
        if domain_id:
            _add_edge(edges, seen, root_id, domain_id, "domaine", "uses_domain")
        if user_id:
            _add_edge(edges, seen, root_id, user_id, "pseudo", "has_username")

    if target_type == "url":
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if parsed.netloc:
            domain_id = _ensure_node(nodes, "domain", parsed.netloc, source="inferred")
            if domain_id:
                _add_edge(edges, seen, root_id, domain_id, "hôte", "hosted_on")


def _infer_from_step(
    step: Dict[str, Any],
    root_id: str,
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    plugin = step.get("plugin_id", "")
    data = step.get("data") or {}

    if plugin == "whois" and data.get("type") == "domain":
        record = data.get("data") or {}
        org = record.get("org")
        if org:
            org_id = _ensure_node(nodes, "company", str(org), source=plugin)
            domain_nodes = [n for n in nodes.values() if n["type"] == "domain"]
            for dn in domain_nodes[:3]:
                _add_edge(edges, seen, dn["id"], org_id, "registrant", "registered_by")

    if plugin == "shodan_ip":
        ip_id = _ensure_node(nodes, "ip", data.get("ip", ""), source=plugin) or root_id
        for hostname in (data.get("hostnames") or [])[:8]:
            hid = _ensure_node(nodes, "domain", hostname, source=plugin)
            if hid:
                _add_edge(edges, seen, ip_id, hid, "hostname", "resolves_to")

    if plugin == "abuseipdb" and data.get("domain") and data["domain"] != "N/A":
        ip_id = _ensure_node(nodes, "ip", data.get("ip", ""), source=plugin) or root_id
        did = _ensure_node(nodes, "domain", data["domain"], source=plugin)
        if did:
            _add_edge(edges, seen, ip_id, did, "PTR", "reverse_dns")

    if plugin == "sherlock":
        username = data.get("username")
        uid = _ensure_node(nodes, "username", username, source=plugin) if username else root_id
        for site, info in (data.get("profiles") or {}).items():
            url = info.get("url_main") or info.get("url_user")
            if url:
                url_id = _ensure_node(
                    nodes, "url", url, source=plugin, metadata={"platform": site}
                )
                if url_id and uid:
                    _add_edge(edges, seen, uid, url_id, site, "profile_on")

    if plugin == "shodan_search":
        for match in (data.get("matches") or [])[:10]:
            ip = match.get("ip_str")
            if ip:
                ip_id = _ensure_node(nodes, "ip", ip, source=plugin)
                if ip_id:
                    _add_edge(edges, seen, root_id, ip_id, "exposé", "exposed_ip")

    if plugin == "leakcheck" and data.get("found"):
        for source in (data.get("sources") or [])[:5]:
            breach_id = _ensure_node(
                nodes, "unknown", source, source=plugin, metadata={"kind": "breach"}
            )
            if breach_id:
                _add_edge(edges, seen, root_id, breach_id, "fuite", "breached_in")


def build_graph_from_investigation(result: Dict[str, Any]) -> Dict[str, Any]:
    """Construit un graphe de relations à partir d'un résultat d'investigation."""
    target = (result.get("target") or "").strip()
    target_type = result.get("target_type") or resolve_entity_type(target).value
    if not target:
        return {"nodes": [], "edges": [], "meta": {"empty": True}}

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    root_id = _node_id(target_type, target)
    nodes[root_id] = _make_node(root_id, target, target_type, is_root=True)

    _infer_from_target(target, target_type, root_id, nodes, edges, seen)

    for ent in result.get("entities") or []:
        etype = ent.get("type", "unknown")
        value = ent.get("value", "")
        source = ent.get("source")
        meta = ent.get("metadata") or {}
        nid = _ensure_node(nodes, etype, value, source=source, metadata=meta)
        if nid and nid != root_id:
            _add_edge(edges, seen, root_id, nid, "découvert", "related_to", weight=0.8)

    for step in result.get("steps") or []:
        if step.get("status") == "success":
            _infer_from_step(step, root_id, nodes, edges, seen)

    # Liens entre entités du même type de relation logique
    _link_email_domain_username(nodes, edges, seen)

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "meta": {
            "investigation_id": result.get("id"),
            "target": target,
            "target_type": target_type,
            "playbook": result.get("playbook_name"),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
    }


def _link_email_domain_username(
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    seen: Set[str],
) -> None:
    emails = [n for n in nodes.values() if n["type"] == "email"]
    domains = [n for n in nodes.values() if n["type"] == "domain"]
    usernames = [n for n in nodes.values() if n["type"] == "username"]

    for email in emails:
        if "@" not in email["label"]:
            continue
        user, domain = email["label"].split("@", 1)
        for dn in domains:
            if dn["label"].lower() == domain.lower():
                _add_edge(edges, seen, email["id"], dn["id"], "domaine", "uses_domain")
        for un in usernames:
            if un["label"].lower() == user.lower():
                _add_edge(edges, seen, email["id"], un["id"], "pseudo", "has_username")


def merge_graphs(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Fusionne deux graphes (pivot / investigations multiples)."""
    nodes_map = {n["id"]: n for n in base.get("nodes", [])}
    for n in incoming.get("nodes", []):
        if n["id"] not in nodes_map:
            nodes_map[n["id"]] = n
        elif n.get("is_root"):
            nodes_map[n["id"]]["is_root"] = True

    edges = list(base.get("edges", []))
    seen = {f"{e['source']}|{e['target']}|{e['relation']}" for e in edges}
    for e in incoming.get("edges", []):
        key = f"{e['source']}|{e['target']}|{e['relation']}"
        if key not in seen:
            seen.add(key)
            edges.append(e)

    return {
        "nodes": list(nodes_map.values()),
        "edges": edges,
        "meta": {
            "merged": True,
            "node_count": len(nodes_map),
            "edge_count": len(edges),
            "targets": list(
                {
                    incoming.get("meta", {}).get("target"),
                    base.get("meta", {}).get("target"),
                }
                - {None}
            ),
        },
    }


def graph_to_cytoscape(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Format Cytoscape.js elements."""
    elements = []
    for node in graph.get("nodes", []):
        elements.append(
            {
                "data": {
                    "id": node["id"],
                    "label": node["label"],
                    "type": node["type"],
                    "is_root": node.get("is_root", False),
                    "color": node.get("color"),
                    "icon": node.get("icon"),
                    "source": node.get("source"),
                }
            }
        )
    for edge in graph.get("edges", []):
        elements.append(
            {
                "data": {
                    "id": edge["id"],
                    "source": edge["source"],
                    "target": edge["target"],
                    "label": edge.get("label", ""),
                    "relation": edge.get("relation", ""),
                }
            }
        )
    return {"elements": elements, "meta": graph.get("meta", {})}


def suggest_pivot_playbook(entity_type: str) -> str:
    try:
        from models.playbook import EntityType

        return suggest_playbook_id(EntityType(entity_type))
    except (ValueError, KeyError):
        return "breach_check"
