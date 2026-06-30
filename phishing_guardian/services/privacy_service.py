from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from services.timeline_service import build_timeline

# Score 0–100 : plus c'est élevé, meilleure est la protection de la vie privée.

PRIVACY_GRADES = [
    (80, "excellent", "Très privé", "#22c55e"),
    (60, "good", "Bien protégé", "#4ade80"),
    (35, "moderate", "Exposition modérée", "#f59e0b"),
    (15, "poor", "Peu privé", "#f97316"),
    (0, "critical", "Très exposé", "#ef4444"),
]


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _privacy_grade(score: float) -> Tuple[str, str, str]:
    for threshold, grade_id, label, color in PRIVACY_GRADES:
        if score >= threshold:
            return grade_id, label, color
    return "critical", "Très exposé", "#ef4444"


def _factor(
    factor_id: str,
    label: str,
    exposure: float,
    max_exposure: float,
    details: str,
    severity: str = "info",
) -> Dict[str, Any]:
    privacy_pts = round(max(0.0, max_exposure - exposure), 1)
    return {
        "id": factor_id,
        "label": label,
        "exposure": round(exposure, 1),
        "max_exposure": max_exposure,
        "privacy_pts": privacy_pts,
        "pct_exposed": round((exposure / max_exposure * 100) if max_exposure else 0, 1),
        "details": details,
        "severity": severity,
    }


def _exposure_breaches(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_exp = 30.0
    for step in steps:
        if step.get("plugin_id") != "leakcheck" or step.get("status") != "success":
            continue
        data = step.get("data") or {}
        if not data.get("found"):
            return 0.0, _factor(
                "data_breaches",
                "Fuites de données personnelles",
                0,
                max_exp,
                "Aucune fuite connue — bon signal pour la confidentialité.",
                "low",
            )
        count = int(data.get("breach_count") or 0)
        if count >= 10:
            exp, severity = 30.0, "critical"
        elif count >= 5:
            exp, severity = 24.0, "high"
        elif count >= 2:
            exp, severity = 16.0, "medium"
        else:
            exp, severity = 8.0, "medium"
        sources = data.get("sources") or []
        detail = f"{count} fuite(s) — vos données circulent sur le dark web"
        if sources:
            detail += f" ({', '.join(str(s) for s in sources[:3])})"
        return exp, _factor("data_breaches", "Fuites de données personnelles", exp, max_exp, detail, severity)

    return 0.0, _factor(
        "data_breaches",
        "Fuites de données personnelles",
        0,
        max_exp,
        "Leak Check non exécuté.",
        "info",
    )


def _exposure_social(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_exp = 25.0
    for step in steps:
        if step.get("plugin_id") != "sherlock" or step.get("status") != "success":
            continue
        data = step.get("data") or {}
        count = int(data.get("count") or len(data.get("profiles") or {}))
        if count == 0:
            return 0.0, _factor(
                "social_footprint",
                "Empreinte sociale publique",
                0,
                max_exp,
                "Aucun profil public trouvé — discrétion en ligne élevée.",
                "low",
            )
        if count >= 15:
            exp, severity = 25.0, "critical"
        elif count >= 8:
            exp, severity = 19.0, "high"
        elif count >= 3:
            exp, severity = 12.0, "medium"
        else:
            exp, severity = 6.0, "low"
        platforms = list((data.get("profiles") or {}).keys())[:5]
        detail = f"{count} profil(s) public(s) indexable(s)"
        if platforms:
            detail += f" — {', '.join(platforms)}"
        return exp, _factor("social_footprint", "Empreinte sociale publique", exp, max_exp, detail, severity)

    return 0.0, _factor(
        "social_footprint",
        "Empreinte sociale publique",
        0,
        max_exp,
        "Sherlock non exécuté.",
        "info",
    )


def _exposure_identity(entities: List[Dict[str, Any]], target_type: str) -> Tuple[float, Dict[str, Any]]:
    max_exp = 15.0
    types_found = {e.get("type") for e in entities}
    count = len(entities)
    exp = 0.0
    parts: List[str] = []

    if count >= 10:
        exp += 10.0
    elif count >= 5:
        exp += 6.0
    elif count >= 2:
        exp += 3.0

    link_types = {"email", "username", "domain", "url"}
    linked = types_found & link_types
    if len(linked) >= 3:
        exp += 5.0
        parts.append("identités corrélées (email, pseudo, domaine)")
    elif len(linked) >= 2:
        exp += 2.5
        parts.append("liens entre identifiants détectés")

    if target_type == "email" and "username" in types_found:
        exp += 2.0
        parts.append("pseudo dérivé de l'email exposé")

    exp = min(max_exp, exp)
    if exp == 0:
        detail = "Peu de corrélation entre identifiants — bonne séparation."
        severity = "low"
    else:
        detail = f"{count} entité(s) liée(s)"
        if parts:
            detail += " · " + " · ".join(parts)
        severity = "high" if exp >= 10 else "medium" if exp >= 5 else "low"

    return exp, _factor("identity_links", "Corrélation d'identité", exp, max_exp, detail, severity)


def _exposure_public_records(steps: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_exp = 10.0
    for step in steps:
        if step.get("plugin_id") != "whois" or step.get("status") != "success":
            continue
        record = (step.get("data") or {}).get("data") or {}
        exp = 0.0
        parts: List[str] = []
        if record.get("emails"):
            exp += 4.0
            parts.append("email dans WHOIS")
        if record.get("name") or record.get("org"):
            exp += 3.0
            parts.append("nom/organisation publique")
        if record.get("address"):
            exp += 3.0
            parts.append("adresse publique")
        exp = min(max_exp, exp)
        if exp == 0:
            return 0.0, _factor(
                "public_records",
                "Données publiques (WHOIS)",
                0,
                max_exp,
                "Pas de données personnelles visibles dans le WHOIS.",
                "low",
            )
        return exp, _factor(
            "public_records",
            "Données publiques (WHOIS)",
            exp,
            max_exp,
            " · ".join(parts),
            "medium" if exp < 7 else "high",
        )

    return 0.0, _factor(
        "public_records",
        "Données publiques (WHOIS)",
        0,
        max_exp,
        "WHOIS non consulté ou sans données personnelles.",
        "info",
    )


def _exposure_history(investigation: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    max_exp = 10.0
    timeline = investigation.get("synthesis", {}).get("timeline")
    if not timeline:
        timeline = build_timeline(investigation)
    events = timeline.get("events") or []
    if not events:
        return 0.0, _factor(
            "digital_history",
            "Historique numérique",
            0,
            max_exp,
            "Peu d'événements historiques indexables.",
            "low",
        )

    count = len(events)
    years = timeline.get("patterns", {}).get("events_by_year") or {}
    span = len(years)

    if count >= 15 or span >= 8:
        exp, severity = 10.0, "high"
    elif count >= 8 or span >= 5:
        exp, severity = 6.0, "medium"
    elif count >= 3:
        exp, severity = 3.0, "low"
    else:
        exp, severity = 1.0, "low"

    detail = f"{count} événement(s) sur {span or 1} année(s) — trace numérique longue"
    return exp, _factor("digital_history", "Historique numérique", exp, max_exp, detail, severity)


def _exposure_reuse(steps: List[Dict[str, Any]], entities: List[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
    max_exp = 10.0
    exp = 0.0
    parts: List[str] = []

    for step in steps:
        if step.get("plugin_id") != "sherlock" or step.get("status") != "success":
            continue
        profiles = (step.get("data") or {}).get("profiles") or {}
        if len(profiles) >= 5:
            exp += 5.0
            parts.append("pseudo réutilisé sur de nombreuses plateformes")

    usernames = [e.get("value") for e in entities if e.get("type") == "username"]
    emails = [e.get("value") for e in entities if e.get("type") == "email"]
    if usernames and emails:
        exp += 3.0
        parts.append("email et pseudo liés — facilite le doxxing")

    domains = sum(1 for e in entities if e.get("type") == "domain")
    if domains >= 2:
        exp += 2.0
        parts.append("plusieurs domaines associés à la même personne")

    exp = min(max_exp, exp)
    if exp == 0:
        detail = "Pas de réutilisation d'identité détectée entre plateformes."
        severity = "low"
    else:
        detail = " · ".join(parts) if parts else "Réutilisation d'identifiants détectée"
        severity = "medium" if exp < 7 else "high"

    return exp, _factor("profile_correlation", "Réutilisation d'identité", exp, max_exp, detail, severity)


def _build_recommendations(factors: List[Dict[str, Any]], grade: str) -> List[str]:
    recs: List[str] = []
    by_id = {f["id"]: f for f in factors}

    if by_id.get("data_breaches", {}).get("exposure", 0) > 0:
        recs.append("Changez immédiatement les mots de passe des comptes compromis et activez l'authentification à deux facteurs.")
        recs.append("Utilisez un gestionnaire de mots de passe unique par service.")
        recs.append("Surveillez vos comptes via HaveIBeenPwned et des alertes de crédit.")

    if by_id.get("social_footprint", {}).get("exposure", 0) >= 12:
        recs.append("Passez les profils sociaux en privé ou limitez les informations visibles publiquement.")
        recs.append("Supprimez les comptes inactifs qui exposent encore votre identité.")

    if by_id.get("identity_links", {}).get("exposure", 0) >= 5:
        recs.append("Séparez vos identités en ligne : emails jetables, pseudos différents par contexte.")
        recs.append("Évitez d'utiliser la même adresse email pour services personnels et professionnels.")

    if by_id.get("public_records", {}).get("exposure", 0) > 0:
        recs.append("Activez la protection WHOIS / domain privacy sur vos noms de domaine.")
        recs.append("Retirez les coordonnées personnelles des registres publics si possible.")

    if by_id.get("digital_history", {}).get("exposure", 0) >= 6:
        recs.append("Demandez la suppression de vos données sur les anciens services et fuites indexées.")
        recs.append("Réduisez votre trace en supprimant les comptes et contenus obsolètes.")

    if by_id.get("profile_correlation", {}).get("exposure", 0) >= 5:
        recs.append("Ne réutilisez pas le même pseudo sur des forums, jeux et réseaux professionnels.")

    if grade in ("excellent", "good"):
        recs.append("Maintenez vos bonnes pratiques : audits de confidentialité trimestriels.")
    elif grade == "critical":
        recs.append("Priorité urgente : plan d'action privacy sous 48 h — fuites et profils publics.")

    if not recs:
        recs.append("Continuez à limiter votre empreinte numérique et vérifiez régulièrement vos paramètres de confidentialité.")

    return recs[:7]


def _build_summary(score: float, grade_label: str, total_exposure: float, factors: List[Dict[str, Any]]) -> str:
    if score >= 80:
        return f"Vie privée {grade_label.lower()} ({score}/100). Peu d'exposition personnelle détectée."
    top = sorted(factors, key=lambda f: f["exposure"], reverse=True)
    top_active = [f for f in top if f["exposure"] > 0][:2]
    if not top_active:
        return f"Score privacy {score}/100 — {grade_label}."
    drivers = " et ".join(f["label"].lower() for f in top_active)
    return (
        f"Vie privée {grade_label.lower()} ({score}/100). "
        f"Exposition totale {round(total_exposure, 0)}/100, principalement : {drivers}."
    )


def compute_privacy_score(investigation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calcule le Privacy Score personnel (0–100).
    100 = excellente protection / discrétion, 0 = exposition maximale.
    """
    steps = investigation.get("steps") or []
    entities = investigation.get("entities") or []
    target = investigation.get("target", "")
    target_type = investigation.get("target_type", "unknown")

    factors: List[Dict[str, Any]] = []
    total_exposure = 0.0

    for scorer in (
        lambda: _exposure_breaches(steps),
        lambda: _exposure_social(steps),
        lambda: _exposure_identity(entities, target_type),
        lambda: _exposure_public_records(steps),
        lambda: _exposure_history(investigation),
        lambda: _exposure_reuse(steps, entities),
    ):
        exp, factor = scorer()
        total_exposure += exp
        factors.append(factor)

    total_exposure = _clamp(total_exposure, 0, 100)
    score = round(_clamp(100.0 - total_exposure), 1)
    grade_id, grade_label, color = _privacy_grade(score)
    recommendations = _build_recommendations(factors, grade_id)

    return {
        "score": score,
        "exposure_total": round(total_exposure, 1),
        "grade": grade_id,
        "grade_label": grade_label,
        "color": color,
        "target": target,
        "target_type": target_type,
        "max_score": 100,
        "factors": factors,
        "recommendations": recommendations,
        "summary": _build_summary(score, grade_label, total_exposure, factors),
    }
