"""Threat Intelligence Fusion pour le module Phishing.

Enrichit un rapport heuristique avec OpenPhish/URLHaus, VirusTotal,
SPF/DMARC et âge WHOIS, puis fusionne les boosts dans le score synthétique.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\)\]\"'<>]+", re.I)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")
MAX_URLS = 8
MAX_DOMAINS = 4


def extract_urls(email_text: Optional[str], urls: Optional[List[str]] = None) -> List[str]:
    """URLs du payload + URLs auto-extraites du corps email (dédupliquées)."""
    seen: Set[str] = set()
    out: List[str] = []

    def _add(raw: str) -> None:
        u = (raw or "").strip().rstrip(".,;:)")
        if not u or not u.lower().startswith("http"):
            return
        key = u.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(u)

    for u in urls or []:
        _add(u)
    if email_text:
        for m in URL_RE.findall(email_text):
            _add(m)
            if len(out) >= MAX_URLS:
                break
    return out[:MAX_URLS]


def extract_domains(email_text: Optional[str], urls: Optional[List[str]] = None) -> List[str]:
    """Domaines From + hosts d'URLs (registrable-ish, dédupliqués)."""
    seen: Set[str] = set()
    out: List[str] = []

    def _add_host(host: str) -> None:
        h = (host or "").lower().rstrip(".")
        if not h or "." not in h or len(h) < 4:
            return
        # strip www.
        if h.startswith("www."):
            h = h[4:]
        if h in seen:
            return
        seen.add(h)
        out.append(h)

    if email_text:
        for m in EMAIL_RE.finditer(email_text):
            _add_host(m.group(1))
            if len(out) >= MAX_DOMAINS:
                return out[:MAX_DOMAINS]

    for u in extract_urls(email_text, urls):
        try:
            host = urlparse(u).hostname or ""
        except Exception:
            host = ""
        _add_host(host)
        if len(out) >= MAX_DOMAINS:
            break

    return out[:MAX_DOMAINS]


def _parse_whois_age_days(creation_raw: Any) -> Optional[int]:
    if not creation_raw:
        return None
    # whois peut renvoyer list / datetime / str
    if isinstance(creation_raw, list):
        creation_raw = creation_raw[0] if creation_raw else None
    if creation_raw is None:
        return None
    if isinstance(creation_raw, datetime):
        created = creation_raw
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    else:
        text = str(creation_raw).strip()
        created = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
            "%d-%b-%Y",
        ):
            try:
                created = datetime.strptime(text[:26].replace("+00:00", ""), fmt.replace("%z", ""))
                break
            except ValueError:
                continue
        if created is None:
            # fallback ISO-ish
            try:
                created = datetime.fromisoformat(text.replace("Z", "+00:00").split(".")[0])
            except ValueError:
                return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0, (now - created.astimezone(timezone.utc)).days)


def _risk_niveau(score: float) -> str:
    if score >= 0.8:
        return "critique"
    if score >= 0.6:
        return "eleve"
    if score >= 0.4:
        return "modere"
    return "faible"


def _safe_call(name: str, fn, arg: str) -> Tuple[str, Dict[str, Any]]:
    try:
        data = fn(arg)
        if not isinstance(data, dict):
            return name, {"success": False, "error": "Réponse invalide"}
        return name, data
    except Exception as exc:
        return name, {"success": False, "error": str(exc), "unavailable": True}


def enrich_phishing_report(
    result: Dict[str, Any],
    email_text: Optional[str] = None,
    urls: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Enrichit `result` in-place et retourne le même dict."""
    from services.osint_tools import run_email_auth, run_virustotal, run_whois
    from services.threat_feeds import run_blocklist_check

    auto_urls = extract_urls(email_text, urls)
    domains = extract_domains(email_text, urls)

    # Cibles prioritaires pour les lookups
    primary_url = auto_urls[0] if auto_urls else None
    primary_domain = domains[0] if domains else None
    vt_target = primary_url or primary_domain
    bl_target = primary_url or primary_domain
    auth_target = primary_domain
    whois_target = primary_domain

    jobs = []
    if bl_target:
        jobs.append(("blocklist", run_blocklist_check, bl_target))
    if vt_target:
        jobs.append(("virustotal", run_virustotal, vt_target))
    if auth_target:
        jobs.append(("email_auth", run_email_auth, auth_target))
    if whois_target:
        jobs.append(("whois", run_whois, whois_target))

    sources_ok: List[str] = []
    sources_failed: List[str] = []
    raw: Dict[str, Any] = {}

    if jobs:
        with ThreadPoolExecutor(max_workers=min(4, len(jobs))) as pool:
            futures = {
                pool.submit(_safe_call, name, fn, arg): name for name, fn, arg in jobs
            }
            for fut in as_completed(futures):
                name, data = fut.result()
                raw[name] = data
                ok = bool(data.get("success")) and not data.get("unavailable")
                if ok or (name == "blocklist" and data.get("success")):
                    # blocklist success même si non listé
                    if data.get("success") and not data.get("unavailable"):
                        sources_ok.append(name)
                    elif data.get("unavailable") or data.get("error"):
                        sources_failed.append(name)
                    else:
                        sources_ok.append(name)
                else:
                    sources_failed.append(name)

    # --- Normaliser les vues UI ---
    blocklist = raw.get("blocklist") or {}
    vt = raw.get("virustotal") or {}
    auth = raw.get("email_auth") or {}
    whois = raw.get("whois") or {}

    whois_data = whois.get("data") or {}
    age_days = _parse_whois_age_days(whois_data.get("creation_date"))
    registrar = whois_data.get("registrar")

    vt_detections = int(vt.get("detections") or 0)
    vt_total = int(vt.get("total") or 0)
    auth_score = auth.get("auth_score")
    dmarc_absent = any("DMARC absent" in str(f) for f in (auth.get("findings") or []))
    spf_absent = any("SPF absent" in str(f) for f in (auth.get("findings") or []))

    # Signaux email locaux déjà présents
    email_block = result.get("email") or {}
    domain_analysis = email_block.get("domain_analysis") or {}
    brand_mismatch = False
    free_mail = False
    typosquat = False
    for d in domain_analysis.get("domains") or []:
        if d.get("brand_mismatch"):
            brand_mismatch = True
        if d.get("free_mail"):
            free_mail = True
        if d.get("typosquat"):
            typosquat = True

    # --- Fusion de score ---
    synth = result.get("synthetique") or {"score": 0.0, "niveau": "faible"}
    base = float(synth.get("score") or 0.0)
    boost = 0.0
    boosts: List[Dict[str, Any]] = []

    def _boost(amount: float, reason: str) -> None:
        nonlocal boost
        boost += amount
        boosts.append({"delta": round(amount, 3), "reason": reason})

    if blocklist.get("listed"):
        sources = ", ".join(blocklist.get("sources_hit") or []) or "blocklist"
        _boost(0.35, f"Listé en blocklist ({sources})")

    if vt_detections >= 5:
        _boost(0.30, f"VirusTotal : {vt_detections}/{vt_total} détections")
    elif vt_detections >= 2:
        _boost(0.18, f"VirusTotal : {vt_detections}/{vt_total} détections")
    elif vt_detections == 1:
        _boost(0.08, f"VirusTotal : 1 détection ({vt_total} moteurs)")

    if age_days is not None and age_days < 30:
        msg = f"Domaine très récent ({age_days} j)"
        if brand_mismatch or typosquat:
            _boost(0.25, msg + " + usurpation de marque")
        else:
            _boost(0.12, msg)
    elif age_days is not None and age_days < 90:
        _boost(0.06, f"Domaine jeune ({age_days} j)")

    if dmarc_absent and (brand_mismatch or free_mail or typosquat):
        _boost(0.15, "DMARC absent + signaux d'usurpation")
    elif dmarc_absent and spf_absent:
        _boost(0.08, "SPF et DMARC absents")
    elif dmarc_absent:
        _boost(0.04, "DMARC absent")

    if auth_score is not None and int(auth_score) == 0 and primary_domain:
        _boost(0.05, "Aucune protection auth email détectée")

    # Cap boost
    boost = min(boost, 0.55)
    final = min(1.0, round(base + boost, 3))
    niveau = _risk_niveau(final)

    result["synthetique"] = {
        "score": final,
        "niveau": niveau,
        "score_heuristique": round(base, 3),
        "boost_intel": round(boost, 3),
    }

    enrichment = {
        "auto_extracted_urls": auto_urls,
        "domains": domains,
        "primary_domain": primary_domain,
        "primary_url": primary_url,
        "sources_ok": sources_ok,
        "sources_failed": sources_failed,
        "boosts": boosts,
        "blocklist": {
            "listed": bool(blocklist.get("listed")),
            "sources_hit": blocklist.get("sources_hit") or [],
            "findings": blocklist.get("findings") or [],
            "query": blocklist.get("query") or bl_target,
        }
        if bl_target
        else None,
        "virustotal": {
            "query": vt.get("query") or vt_target,
            "detections": vt_detections,
            "total": vt_total,
            "risk_level": vt.get("risk_level"),
            "source": vt.get("source") or ("virustotal" if vt.get("success") else None),
            "message": vt.get("message"),
        }
        if vt_target
        else None,
        "email_auth": {
            "domain": auth.get("domain") or auth_target,
            "auth_score": auth_score,
            "findings": auth.get("findings") or [],
            "risk_level": auth.get("risk_level"),
            "spf": bool(auth.get("spf")),
            "dmarc": bool(auth.get("dmarc")),
            "dkim_selectors": auth.get("dkim_selectors") or [],
        }
        if auth_target
        else None,
        "whois": {
            "domain": whois.get("query") or whois_target,
            "age_days": age_days,
            "registrar": registrar,
            "creation_date": whois_data.get("creation_date"),
            "org": whois_data.get("org"),
            "country": whois_data.get("country"),
        }
        if whois_target
        else None,
    }
    result["enrichment"] = enrichment
    return result
