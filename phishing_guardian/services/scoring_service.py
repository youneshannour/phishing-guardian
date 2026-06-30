from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Plus le score est élevé, plus la surface d'attaque est grande (0–100).

GRADE_THRESHOLDS = [
    (80, "critical", "Critique"),
    (60, "high", "Élevée"),
    (35, "medium", "Modérée"),
    (15, "low", "Faible"),
    (0, "minimal", "Minimale"),
]

GRADE_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#22c55e",
    "minimal": "#4ade80",
}


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _grade(score: float) -> Tuple[str, str]:
    for threshold, grade_id, label in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade_id, label
    return "minimal", "Minimale"


def _factor(
    factor_id: str,
    label: str,
    score: float,
    max_score: float,
    details: str,
    severity: str = "info",
) -> Dict[str, Any]:
    return {
        "id": factor_id,
        "label": label,
        "score": round(score, 1),
        "max_score": max_score,
        "pct": round((score / max_score * 100) if max_score else 0, 1),
        "details": details,
        "severity": severity,
    }


def _score_breaches(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_pts = 25.0
    pts = 0.0
    details: List[str] = []

    for step in steps:
        if step.get("plugin_id") != "leakcheck" or step.get("status") != "success":
            continue
        data = step.get("data") or {}
        if not data.get("found"):
            return 0.0, _factor(
                "breaches",
                "Fuites de données",
                0,
                max_pts,
                "Aucune fuite connue détectée pour cette cible.",
                "low",
            )

        count = int(data.get("breach_count") or 0)
        sources = data.get("sources") or []
        if count >= 10:
            pts = 25.0
            severity = "critical"
        elif count >= 5:
            pts = 20.0
            severity = "high"
        elif count >= 2:
            pts = 14.0
            severity = "medium"
        else:
            pts = 8.0
            severity = "medium"

        details.append(f"{count} fuite(s) identifiée(s)")
        if sources:
            details.append(f"Sources : {', '.join(str(s) for s in sources[:4])}")
        if count > 4:
            details.append(f"+{len(sources) - 4} autres" if len(sources) > 4 else "")

        return pts, _factor(
            "breaches",
            "Fuites de données",
            pts,
            max_pts,
            " · ".join(d for d in details if d),
            severity,
        )

    return 0.0, _factor(
        "breaches",
        "Fuites de données",
        0,
        max_pts,
        "Leak Check non exécuté ou indisponible.",
        "info",
    )


def _score_social(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_pts = 20.0
    for step in steps:
        if step.get("plugin_id") != "sherlock" or step.get("status") != "success":
            continue
        data = step.get("data") or {}
        count = int(data.get("count") or len(data.get("profiles") or {}))
        if count == 0:
            return 0.0, _factor(
                "social",
                "Empreinte sociale",
                0,
                max_pts,
                "Aucun profil social public détecté.",
                "low",
            )
        if count >= 15:
            pts, severity = 20.0, "critical"
        elif count >= 8:
            pts, severity = 15.0, "high"
        elif count >= 3:
            pts, severity = 10.0, "medium"
        else:
            pts, severity = 5.0, "low"

        platforms = list((data.get("profiles") or {}).keys())[:5]
        detail = f"{count} profil(s) trouvé(s)"
        if platforms:
            detail += f" — {', '.join(platforms)}"
        return pts, _factor("social", "Empreinte sociale", pts, max_pts, detail, severity)

    return 0.0, _factor(
        "social",
        "Empreinte sociale",
        0,
        max_pts,
        "Sherlock non exécuté.",
        "info",
    )


def _score_network(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_pts = 25.0
    pts = 0.0
    parts: List[str] = []
    severity = "info"

    for step in steps:
        if step.get("status") != "success":
            continue
        pid = step.get("plugin_id")
        data = step.get("data") or {}

        if pid == "shodan_ip":
            ports = data.get("ports") or []
            vulns = int(data.get("vuln_count") or 0)
            port_pts = min(12.0, len(ports) * 1.5)
            vuln_pts = min(13.0, vulns * 4.0)
            pts += port_pts + vuln_pts
            if ports:
                parts.append(f"{len(ports)} port(s) exposé(s)")
            if vulns:
                parts.append(f"{vulns} vulnérabilité(s) CVE")
            if vulns > 0:
                severity = "critical"
            elif len(ports) > 5:
                severity = "high"
            elif ports:
                severity = "medium"

        if pid == "shodan_search":
            matches = int(data.get("matches_count") or len(data.get("matches") or []))
            if matches:
                m_pts = min(10.0, matches * 2.0)
                pts += m_pts
                parts.append(f"{matches} hôte(s) Shodan associé(s)")
                if _severity_rank("medium") > _severity_rank(severity):
                    severity = "medium"

    pts = min(max_pts, pts)
    detail = " · ".join(parts) if parts else "Pas d'exposition réseau Shodan détectée."
    return pts, _factor("network", "Exposition réseau", pts, max_pts, detail, severity)


def _severity_rank(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)


def _score_reputation(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_pts = 20.0
    pts = 0.0
    parts: List[str] = []
    severity = "info"

    for step in steps:
        if step.get("status") != "success":
            continue
        pid = step.get("plugin_id")
        data = step.get("data") or {}

        if pid == "virustotal":
            detections = int(data.get("detections") or 0)
            total = int(data.get("total") or 70)
            ratio = (detections / total * 100) if total else 0
            if detections > 0:
                v_pts = min(12.0, ratio * 0.15 + detections * 0.5)
                pts += v_pts
                parts.append(f"VirusTotal {detections}/{total} détections")
                severity = "high" if ratio > 10 else "medium"

        if pid == "abuseipdb":
            conf = int(data.get("abuseConfidence") or 0)
            if conf > 0:
                a_pts = min(10.0, conf * 0.12)
                pts += a_pts
                parts.append(f"AbuseIPDB {conf}% confiance")
                severity = "high" if conf > 50 else "medium"

    pts = min(max_pts, pts)
    detail = " · ".join(parts) if parts else "Réputation neutre (VT / AbuseIPDB)."
    return pts, _factor("reputation", "Réputation & menaces", pts, max_pts, detail, severity)


def _score_footprint(
    entities: List[Dict[str, Any]],
    steps: List[Dict[str, Any]],
) -> Tuple[float, Dict[str, Any]]:
    max_pts = 10.0
    count = len(entities)
    url_count = sum(1 for e in entities if e.get("type") == "url")
    domain_count = sum(1 for e in entities if e.get("type") == "domain")

    pts = min(max_pts, count * 0.8 + url_count * 0.5 + domain_count * 0.3)
    if count == 0:
        detail = "Empreinte numérique limitée."
        severity = "low"
    else:
        detail = f"{count} entité(s) corrélée(s)"
        if url_count:
            detail += f", {url_count} URL(s)"
        if domain_count:
            detail += f", {domain_count} domaine(s)"
        severity = "medium" if count > 8 else "low"

    whois_public = False
    for step in steps:
        if step.get("plugin_id") == "whois" and step.get("status") == "success":
            record = (step.get("data") or {}).get("data") or {}
            if record.get("org") or record.get("emails"):
                whois_public = True
                pts = min(max_pts, pts + 2.0)
                detail += " · WHOIS avec données publiques"

    return pts, _factor("footprint", "Empreinte & données publiques", pts, max_pts, detail, severity)


def _build_recommendations(factors: List[Dict[str, Any]], grade: str) -> List[str]:
    recs: List[str] = []
    by_id = {f["id"]: f for f in factors}

    if by_id.get("breaches", {}).get("score", 0) > 0:
        recs.append("Réinitialiser les mots de passe compromis et activer le 2FA sur tous les comptes liés.")
        recs.append("Surveiller les alertes HaveIBeenPwned pour cette adresse email.")

    if by_id.get("social", {}).get("score", 0) >= 10:
        recs.append("Auditer la visibilité des profils sociaux et supprimer les informations personnelles sensibles.")

    if by_id.get("network", {}).get("score", 0) >= 10:
        recs.append("Fermer les ports non essentiels et patcher les CVE exposées sur Shodan.")
        recs.append("Restreindre l'accès aux services exposés via firewall / VPN.")

    if by_id.get("reputation", {}).get("score", 0) >= 8:
        recs.append("Investiguer les détections VirusTotal et isoler la cible si compromise.")

    if by_id.get("footprint", {}).get("score", 0) >= 5:
        recs.append("Réduire l'empreinte OSINT : WHOIS privé, séparation des identités en ligne.")

    if grade in ("critical", "high"):
        recs.append("Prioriser un pentest ciblé sur les vecteurs identifiés.")
    elif grade == "minimal":
        recs.append("Maintenir la posture actuelle et planifier des scans périodiques.")

    if not recs:
        recs.append("Surface d'attaque limitée — continuer la surveillance passive.")

    return recs[:6]


def compute_attack_surface(
    investigation: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calcule le score de surface d'attaque (0–100) depuis un résultat d'investigation.
    100 = exposition maximale.
    """
    steps = investigation.get("steps") or []
    entities = investigation.get("entities") or []
    target = investigation.get("target", "")
    target_type = investigation.get("target_type", "unknown")

    factors: List[Dict[str, Any]] = []
    total = 0.0

    for scorer in (_score_breaches, _score_social, _score_network, _score_reputation):
        pts, factor = scorer(steps)
        total += pts
        factors.append(factor)

    pts, factor = _score_footprint(entities, steps)
    total += pts
    factors.append(factor)

    score = round(_clamp(total), 1)
    grade_id, grade_label = _grade(score)
    recommendations = _build_recommendations(factors, grade_id)

    return {
        "score": score,
        "grade": grade_id,
        "grade_label": grade_label,
        "color": GRADE_COLORS.get(grade_id, "#94a3b8"),
        "target": target,
        "target_type": target_type,
        "max_score": 100,
        "factors": factors,
        "recommendations": recommendations,
        "summary": _build_summary(score, grade_label, factors),
    }


def _build_summary(score: float, grade_label: str, factors: List[Dict[str, Any]]) -> str:
    top = sorted(factors, key=lambda f: f["score"], reverse=True)
    top_active = [f for f in top if f["score"] > 0][:2]
    if not top_active:
        return f"Surface d'attaque {grade_label.lower()} ({score}/100). Peu de signaux d'exposition détectés."
    drivers = " et ".join(f["label"].lower() for f in top_active)
    return f"Surface d'attaque {grade_label.lower()} ({score}/100), principalement due à : {drivers}."
