from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

SOURCE_LABELS = {
    "leakcheck": "Leak Check",
    "whois": "WHOIS",
    "sherlock": "Sherlock",
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "shodan_ip": "Shodan IP",
    "shodan_search": "Shodan",
    "investigation": "Investigation",
}

SOURCE_ICONS = {
    "leakcheck": "🔓",
    "whois": "📋",
    "sherlock": "📱",
    "virustotal": "🦠",
    "abuseipdb": "🚫",
    "shodan_ip": "📡",
    "shodan_search": "📡",
    "investigation": "🔬",
}

EVENT_TYPE_ICONS = {
    "breach": "🔓",
    "domain_registered": "🌐",
    "domain_expires": "⏳",
    "profile_found": "👤",
    "scan": "🔍",
    "reputation": "⚠️",
    "network": "📡",
    "tool_run": "⚙️",
}


def _event_id() -> str:
    return f"evt_{uuid4().hex[:10]}"


def _parse_date(value: Any) -> Optional[Tuple[str, str]]:
    """Retourne (iso_date, precision) ou None."""
    if not value:
        return None
    text = str(value).strip()
    if not text or text.lower() in ("none", "n/a", "[]"):
        return None

    # ISO datetime
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%Y-%m",
    ):
        try:
            dt = datetime.strptime(text[:19] if "T" in fmt else text[:10], fmt.replace("%z", ""))
            if fmt == "%Y-%m":
                return dt.strftime("%Y-%m-01"), "month"
            return dt.strftime("%Y-%m-%d"), "day"
        except ValueError:
            continue

    # Year only
    m = re.search(r"\b(19|20)\d{2}\b", text)
    if m:
        return f"{m.group(0)}-01-01", "year"

    return None


def _make_event(
    *,
    occurred_at: str,
    date_precision: str,
    source: str,
    event_type: str,
    title: str,
    description: str = "",
    severity: str = "info",
    metadata: Optional[Dict[str, Any]] = None,
    sort_key: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "id": _event_id(),
        "occurred_at": occurred_at,
        "date_precision": date_precision,
        "source": source,
        "source_label": SOURCE_LABELS.get(source, source),
        "event_type": event_type,
        "title": title,
        "description": description,
        "severity": severity,
        "icon": EVENT_TYPE_ICONS.get(event_type, SOURCE_ICONS.get(source, "•")),
        "metadata": metadata or {},
        "_sort": sort_key or occurred_at,
    }


def _events_from_leakcheck(step: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    data = step.get("data") or {}
    if not data.get("found"):
        return events

    details = data.get("breach_details") or []
    for breach in details:
        if not isinstance(breach, dict):
            continue
        name = breach.get("Name") or breach.get("name") or "Breach inconnu"
        parsed = _parse_date(breach.get("BreachDate") or breach.get("breach_date"))
        if parsed:
            iso, prec = parsed
            desc = breach.get("Description", "")[:200]
            events.append(
                _make_event(
                    occurred_at=iso,
                    date_precision=prec,
                    source="leakcheck",
                    event_type="breach",
                    title=f"Fuite : {name}",
                    description=desc or f"Données exposées via {name}",
                    severity="high",
                    metadata={"breach": name},
                )
            )
        else:
            events.append(
                _make_event(
                    occurred_at="0000-01-01",
                    date_precision="unknown",
                    source="leakcheck",
                    event_type="breach",
                    title=f"Fuite : {name}",
                    description="Date de breach inconnue",
                    severity="medium",
                    metadata={"breach": name},
                    sort_key="0000-01-01",
                )
            )

    for src in data.get("sources") or []:
        if isinstance(src, str) and src.startswith("Password breaches"):
            continue
        if any(e.get("title", "").endswith(str(src)) for e in events):
            continue
        events.append(
            _make_event(
                occurred_at="0000-01-01",
                date_precision="unknown",
                source="leakcheck",
                event_type="breach",
                title=f"Fuite signalée : {src}",
                severity="medium",
            )
        )

    return events


def _events_from_whois(step: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    data = step.get("data") or {}
    record = data.get("data") or {}
    domain = data.get("query") or record.get("domain_name") or "domaine"

    for field, etype, title_tpl, sev in (
        ("creation_date", "domain_registered", "Enregistrement {d}", "info"),
        ("expiration_date", "domain_expires", "Expiration {d}", "low"),
    ):
        parsed = _parse_date(record.get(field))
        if parsed:
            iso, prec = parsed
            events.append(
                _make_event(
                    occurred_at=iso,
                    date_precision=prec,
                    source="whois",
                    event_type=etype,
                    title=title_tpl.format(d=domain),
                    description=f"WHOIS — {field.replace('_', ' ')}",
                    severity=sev,
                )
            )
    return events


def _events_from_sherlock(step: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    data = step.get("data") or {}
    username = data.get("username", "")
    profiles = data.get("profiles") or {}
    if not profiles:
        return events

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for site, info in list(profiles.items())[:12]:
        url = ""
        if isinstance(info, dict):
            url = info.get("url_main") or info.get("url_user") or ""
        events.append(
            _make_event(
                occurred_at=now,
                date_precision="day",
                source="sherlock",
                event_type="profile_found",
                title=f"Profil {site}",
                description=url or f"Compte {username} sur {site}",
                severity="medium",
                metadata={"platform": site, "url": url},
            )
        )
    return events


def _events_from_virustotal(step: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = step.get("data") or {}
    raw = data.get("data") or {}
    scan_date = raw.get("scan_date") or raw.get("scan_date_utc")
    parsed = _parse_date(scan_date)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    iso, prec = parsed if parsed else (now, "day")

    detections = data.get("detections", 0)
    total = data.get("total", 0)
    if detections == 0:
        return []

    return [
        _make_event(
            occurred_at=iso,
            date_precision=prec,
            source="virustotal",
            event_type="reputation",
            title=f"VirusTotal : {detections}/{total} détections",
            description=f"Analyse de réputation sur {data.get('query', '')}",
            severity="high" if detections > 5 else "medium",
        )
    ]


def _events_from_abuseipdb(step: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = step.get("data") or {}
    raw = data.get("data") or {}
    reports = raw.get("reports") or []
    events: List[Dict[str, Any]] = []

    for report in reports[:8]:
        if not isinstance(report, dict):
            continue
        reported = report.get("reportedAt") or report.get("reported_at")
        parsed = _parse_date(reported)
        if not parsed:
            continue
        iso, prec = parsed
        events.append(
            _make_event(
                occurred_at=iso,
                date_precision=prec,
                source="abuseipdb",
                event_type="reputation",
                title="Signalement AbuseIPDB",
                description=report.get("comment", "Rapport de réputation IP")[:150],
                severity="medium",
            )
        )

    if not events and data.get("totalReports", 0) > 0:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events.append(
            _make_event(
                occurred_at=now,
                date_precision="day",
                source="abuseipdb",
                event_type="reputation",
                title=f"{data['totalReports']} signalement(s) AbuseIPDB",
                description=f"Confiance abus : {data.get('abuseConfidence', 0)}%",
                severity="high" if data.get("abuseConfidence", 0) > 50 else "medium",
            )
        )
    return events


def _events_from_shodan(step: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    data = step.get("data") or {}
    raw = data.get("data") or data
    source = step.get("plugin_id", "shodan_ip")

    ts = raw.get("last_update") or raw.get("timestamp")
    parsed = _parse_date(ts)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    iso, prec = parsed if parsed else (now, "day")

    vulns = data.get("vuln_count") or len(data.get("vulns") or [])
    ports = data.get("ports") or []

    if vulns:
        events.append(
            _make_event(
                occurred_at=iso,
                date_precision=prec,
                source=source,
                event_type="network",
                title=f"{vulns} vulnérabilité(s) exposée(s)",
                description=f"Ports : {', '.join(str(p) for p in ports[:8])}",
                severity="high",
            )
        )
    elif ports:
        events.append(
            _make_event(
                occurred_at=iso,
                date_precision=prec,
                source=source,
                event_type="network",
                title=f"{len(ports)} port(s) exposé(s)",
                description=f"Shodan — {data.get('ip') or data.get('query', '')}",
                severity="medium",
            )
        )
    return events


def _events_from_step(step: Dict[str, Any], inv_completed: Optional[str]) -> List[Dict[str, Any]]:
    if step.get("status") != "success":
        return []

    pid = step.get("plugin_id", "")
    extractors = {
        "leakcheck": _events_from_leakcheck,
        "whois": _events_from_whois,
        "sherlock": _events_from_sherlock,
        "virustotal": _events_from_virustotal,
        "abuseipdb": _events_from_abuseipdb,
        "shodan_ip": _events_from_shodan,
        "shodan_search": _events_from_shodan,
    }
    fn = extractors.get(pid)
    if fn:
        return fn(step)
    return []


def _analyze_patterns(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    dated = [e for e in events if e.get("date_precision") != "unknown"]
    by_year: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    night_count = 0

    for e in dated:
        year = e["occurred_at"][:4]
        by_year[year] = by_year.get(year, 0) + 1
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1

    insights: List[str] = []
    if by_year:
        peak_year = max(by_year, key=by_year.get)
        if by_year[peak_year] >= 2:
            insights.append(f"Pic d'activité en {peak_year} ({by_year[peak_year]} événements)")

    if by_source.get("leakcheck", 0) >= 3:
        insights.append("Historique de fuites récurrent — risque credential stuffing élevé")

    breach_events = [e for e in events if e.get("event_type") == "breach"]
    if len(breach_events) >= 2:
        insights.append(f"{len(breach_events)} incidents de fuite identifiés sur la période")

    social = by_source.get("sherlock", 0)
    if social >= 5:
        insights.append("Forte empreinte sociale — surface d'attaque élargie")

    if not insights:
        insights.append("Peu de patterns temporels détectés — données historiques limitées")

    return {
        "events_by_year": dict(sorted(by_year.items())),
        "events_by_source": by_source,
        "insights": insights,
        "dated_events": len(dated),
        "unknown_date_events": len(events) - len(dated),
    }


def build_timeline(investigation: Dict[str, Any]) -> Dict[str, Any]:
    """Construit une timeline d'activité depuis un résultat d'investigation."""
    steps = investigation.get("steps") or []
    completed = investigation.get("completed_at") or datetime.now(timezone.utc).isoformat()
    completed_day = completed[:10] if completed else datetime.now(timezone.utc).strftime("%Y-%m-%d")

    events: List[Dict[str, Any]] = []

    for step in steps:
        events.extend(_events_from_step(step, completed))

    # Marqueurs d'exécution des outils (présent)
    for step in steps:
        if step.get("status") not in ("success", "error"):
            continue
        pid = step.get("plugin_id", "tool")
        events.append(
            _make_event(
                occurred_at=completed_day,
                date_precision="day",
                source="investigation",
                event_type="tool_run",
                title=f"{step.get('plugin_name', pid)} exécuté",
                description=f"Statut : {step.get('status')} · {step.get('duration_ms', 0)}ms",
                severity="success" if step.get("status") == "success" else "low",
                metadata={"plugin_id": pid},
            )
        )

    # Tri chronologique (unknown dates en fin)
    events.sort(key=lambda e: (e.get("_sort", e["occurred_at"]), e["title"]))
    for e in events:
        e.pop("_sort", None)

    sources = sorted({e["source"] for e in events})
    patterns = _analyze_patterns(events)

    return {
        "target": investigation.get("target", ""),
        "target_type": investigation.get("target_type", ""),
        "investigation_id": investigation.get("id"),
        "events": events,
        "event_count": len(events),
        "sources": sources,
        "source_labels": {s: SOURCE_LABELS.get(s, s) for s in sources},
        "patterns": patterns,
        "range": _compute_range(events),
    }


def _compute_range(events: List[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    dated = [e["occurred_at"] for e in events if e.get("date_precision") != "unknown"]
    if not dated:
        return {"start": None, "end": None}
    return {"start": min(dated), "end": max(dated)}
