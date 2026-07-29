from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

_shodan_scanner = None


def get_shodan_scanner():
    global _shodan_scanner
    if _shodan_scanner is not None:
        return _shodan_scanner
    if not os.getenv("SHODAN_API_KEY"):
        return None
    try:
        from osint_scanner import OSINTScanner

        _shodan_scanner = OSINTScanner()
    except SystemExit:
        return None
    except Exception:
        return None
    return _shodan_scanner


def run_leakcheck(email: str) -> Dict[str, Any]:
    email = email.strip().lower()
    if not email or "@" not in email:
        return {"success": False, "error": "Email invalide"}

    sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        timeout=10,
        headers={"User-Agent": "PhishingGuardian"},
    )
    response.raise_for_status()

    found_password = False
    password_breach_count = 0
    for line in response.text.split("\n"):
        if line.startswith(suffix):
            password_breach_count = int(line.split(":")[1].strip())
            found_password = True
            break

    found_email = False
    email_breaches: List[dict] = []
    hibp_api_key = os.getenv("HAVEIBEENPWNED_API_KEY")
    if hibp_api_key:
        try:
            hibp_email_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {"hibp-api-key": hibp_api_key, "User-Agent": "PhishingGuardian"}
            email_response = requests.get(hibp_email_url, headers=headers, timeout=10)
            if email_response.status_code == 200:
                found_email = True
                email_breaches = email_response.json()
        except Exception:
            pass

    total_breaches = password_breach_count + len(email_breaches)
    found = found_password or found_email
    sources = []
    if found_password:
        sources.append(f"Password breaches: {password_breach_count}")
    if found_email:
        sources.extend(b.get("Name", "Unknown") for b in email_breaches)

    return {
        "success": True,
        "email": email,
        "found": found,
        "sources": sources,
        "breach_count": total_breaches,
        "password_breaches": password_breach_count,
        "email_breaches": len(email_breaches),
        "breach_details": email_breaches[:10],
        "risk_level": (
            "critical"
            if total_breaches > 10
            else "high"
            if total_breaches > 5
            else "medium"
            if total_breaches > 0
            else "low"
        ),
    }


def run_whois(query: str) -> Dict[str, Any]:
    import socket

    query = query.strip()
    if not query:
        return {"success": False, "error": "Query vide"}

    try:
        import whois
    except ImportError:
        return {"success": False, "error": "Module whois non installé"}

    try:
        socket.inet_aton(query)
        is_ip = True
    except (socket.error, ValueError):
        is_ip = False

    if is_ip:
        response = requests.get(f"https://ipwhois.app/json/{query}", timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "success": True,
            "query": query,
            "type": "ip",
            "data": {
                "ip": data.get("ip", query),
                "country": data.get("country", "N/A"),
                "asn": data.get("asn", "N/A"),
                "asn_org": data.get("asn_org", data.get("org", "N/A")),
                "isp": data.get("isp", "N/A"),
                "org": data.get("org", "N/A"),
                "city": data.get("city", "N/A"),
            },
        }

    w = whois.whois(query)

    def clean_value(v):
        if isinstance(v, list):
            return v[0] if v else None
        return v

    return {
        "success": True,
        "query": query,
        "type": "domain",
        "data": {
            "domain_name": clean_value(w.domain_name),
            "registrar": clean_value(w.registrar),
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "org": clean_value(w.org),
            "country": clean_value(w.country),
            "name_servers": (
                w.name_servers
                if isinstance(w.name_servers, list)
                else [w.name_servers]
                if w.name_servers
                else []
            ),
            "emails": (
                w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
            ),
        },
    }


def _resolve_sherlock_cmd() -> Optional[List[str]]:
    """Trouve la commande Sherlock (CLI moderne = sherlock-project)."""
    import sys

    candidates = [
        ["sherlock"],
        [sys.executable, "-m", "sherlock_project"],
        [sys.executable, "-m", "sherlock"],
        ["python3", "-m", "sherlock_project"],
        ["python", "-m", "sherlock"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd + ["--version"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            blob = f"{result.stdout or ''}{result.stderr or ''}".lower()
            if result.returncode == 0 or "sherlock" in blob:
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _parse_sherlock_profiles(stdout: str, out_dir: Path, username: str) -> Dict[str, Any]:
    """Parse stdout + fichiers générés par Sherlock 0.16+."""
    profiles: Dict[str, Any] = {}

    # 1) URLs dans stdout (--print-found)
    for line in (stdout or "").splitlines():
        line = line.strip()
        if "http://" not in line and "https://" not in line:
            continue
        # Formats typiques: "[+] Site: https://..." ou juste une URL
        for token in line.replace("\t", " ").split():
            if token.startswith("http://") or token.startswith("https://"):
                url = token.rstrip("),];")
                site = url.split("/")[2] if "://" in url else url
                profiles[site] = {"url": url, "url_main": url, "status": "Claimed"}

    # 2) Fichier texte généré (--folderoutput / -o)
    for candidate in (
        out_dir / f"{username}.txt",
        out_dir / f"{username}.csv",
        Path.cwd() / f"{username}.txt",
    ):
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if candidate.suffix.lower() == ".csv":
            import csv
            import io

            try:
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    url = (row.get("url") or row.get("URL") or "").strip()
                    site = (row.get("name") or row.get("site") or row.get("Site") or "").strip()
                    if not url and not site:
                        continue
                    if not site and url:
                        site = url.split("/")[2] if "://" in url else url
                    profiles[site or url] = {
                        "url": url,
                        "url_main": url,
                        "status": (row.get("status") or row.get("Status") or "Claimed"),
                    }
            except Exception:
                pass
        else:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http://") or line.startswith("https://"):
                    url = line
                    site = url.split("/")[2]
                    profiles[site] = {"url": url, "url_main": url, "status": "Claimed"}

    return profiles


def run_sherlock(username: str) -> Dict[str, Any]:
    """Lance Sherlock 0.16+ et retourne les profils trouvés (URLs)."""
    import tempfile

    username = username.strip().lstrip("@")
    if not username:
        return {"success": False, "error": "Nom d'utilisateur vide"}

    sherlock_cmd = _resolve_sherlock_cmd()
    if not sherlock_cmd:
        return {"success": False, "error": "Sherlock non installé", "unavailable": True}

    with tempfile.TemporaryDirectory(prefix="pg-sherlock-") as tmp:
        out_dir = Path(tmp)
        # NOTE: --json dans Sherlock 0.16 = charger une liste de sites, PAS exporter du JSON
        cmd = sherlock_cmd + [
            "--no-color",
            "--print-found",
            "--csv",
            "--folderoutput",
            str(out_dir),
            "--timeout",
            "15",
            username,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=str(out_dir),
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Sherlock timeout (>180s)",
                "username": username,
                "profiles": {},
                "count": 0,
            }

        profiles = _parse_sherlock_profiles(result.stdout or "", out_dir, username)
        # Fallback stderr parfois
        if not profiles and result.stderr:
            profiles = _parse_sherlock_profiles(result.stderr, out_dir, username)

    count = len(profiles)
    # Liste plate pour l'UI
    urls = [
        (v.get("url") if isinstance(v, dict) else str(v))
        for v in profiles.values()
        if v
    ]
    urls = [u for u in urls if u and str(u).startswith("http")]

    return {
        "success": True,
        "username": username,
        "profiles": profiles,
        "urls": urls,
        "count": count,
        "sites_found": list(profiles.keys()),
        "risk_level": "high" if count > 5 else "medium" if count > 0 else "low",
        "raw_preview": (result.stdout or "")[:800],
    }


def _normalize_vt_query(query: str):
    """Normalise la cible VT (email → domaine, etc.). Retourne (query, type)."""
    q = (query or "").strip()
    if not q:
        return "", "unknown"
    if q.startswith("http"):
        return q, "url"
    if "@" in q and " " not in q.split("@", 1)[0]:
        domain = q.split("@", 1)[1].strip().lower()
        return domain, "domain"
    if len(q) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in q):
        return q, "hash"
    if q.replace(".", "").replace(":", "").isdigit() or (
        q.count(".") == 3 and all(p.isdigit() for p in q.split("."))
    ):
        return q, "ip"
    return q.lower().rstrip("."), "domain"


def _local_reputation(query: str, query_type: str) -> Dict[str, Any]:
    """Analyse locale de réputation quand VirusTotal n'est pas configuré."""
    import math
    import re
    import socket

    indicators: List[str] = []
    score = 0.1

    target = query
    if query_type == "url":
        from urllib.parse import urlparse

        target = urlparse(query).hostname or query

    host = (target or "").lower()
    labels = [p for p in host.split(".") if p]

    core = labels[-2] if len(labels) >= 2 else (labels[0] if labels else host)
    if core:
        probs = [core.count(c) / len(core) for c in set(core)]
        entropy = -sum(p * math.log2(p) for p in probs) if probs else 0
        if entropy > 3.5 and len(core) >= 8:
            indicators.append(f"Nom de domaine aléatoire (entropie {entropy:.1f})")
            score += 0.35
        if re.search(r"\d", core) and len(core) >= 8:
            indicators.append("Label long avec chiffres (souvent généré)")
            score += 0.15

    if len(labels) >= 4:
        indicators.append(f"Sous-domaines multiples ({len(labels)} niveaux)")
        score += 0.2

    suspicious_tlds = {"xyz", "tk", "top", "gq", "ml", "cf", "ga", "zip", "click", "work"}
    if labels and labels[-1] in suspicious_tlds:
        indicators.append(f"TLD douteux: .{labels[-1]}")
        score += 0.25

    dns_ok = None
    try:
        socket.getaddrinfo(host, None)
        dns_ok = True
        indicators.append("Domaine résolvable en DNS")
    except socket.gaierror:
        dns_ok = False
        indicators.append("Domaine introuvable en DNS")
        score += 0.3
    except Exception:
        pass

    brands = ("paypal", "apple", "microsoft", "google", "amazon", "netflix", "orange")
    compact = host.replace("-", "").replace(".", "")
    for brand in brands:
        if brand not in compact and brand[:4] in compact and re.search(r"\d", compact):
            indicators.append(f"Possible imitation de {brand}")
            score += 0.3
            break

    score = min(score, 0.95)
    risk = (
        "critical"
        if score >= 0.75
        else "high"
        if score >= 0.55
        else "medium"
        if score >= 0.35
        else "low"
    )
    fake_total = 10
    fake_positives = int(round(score * fake_total))

    return {
        "success": True,
        "source": "local",
        "query": query,
        "type": query_type,
        "detections": fake_positives,
        "total": fake_total,
        "ratio": round(score * 100, 2),
        "risk_level": risk,
        "detecting_engines": [],
        "scan_date": None,
        "permalink": None,
        "dns_ok": dns_ok,
        "indicators": indicators,
        "message": (
            "Analyse locale (VirusTotal non configuré). "
            "Ajoutez VIRUSTOTAL_API_KEY dans .env pour 70+ moteurs : "
            "https://www.virustotal.com/gui/my-apikey"
        ),
        "vt_configured": False,
    }


def run_virustotal(query: str) -> Dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    normalized, query_type = _normalize_vt_query(query)
    if not normalized:
        return {"success": False, "error": "Requête vide", "unavailable": True}

    if not api_key:
        return _local_reputation(normalized, query_type)

    try:
        if query_type == "url":
            data = requests.get(
                "https://www.virustotal.com/vtapi/v2/url/report",
                params={"apikey": api_key, "resource": normalized},
                timeout=15,
            ).json()
        elif query_type == "hash":
            data = requests.get(
                "https://www.virustotal.com/vtapi/v2/file/report",
                params={"apikey": api_key, "resource": normalized},
                timeout=15,
            ).json()
        elif query_type == "domain":
            data = requests.get(
                "https://www.virustotal.com/vtapi/v2/domain/report",
                params={"apikey": api_key, "domain": normalized},
                timeout=15,
            ).json()
        else:
            data = requests.get(
                "https://www.virustotal.com/vtapi/v2/ip-address/report",
                params={"apikey": api_key, "ip": normalized},
                timeout=15,
            ).json()
    except Exception as exc:
        local = _local_reputation(normalized, query_type)
        local["message"] = f"VirusTotal inaccessible ({exc}). Analyse locale utilisée."
        return local

    if isinstance(data, dict) and data.get("response_code") == 0:
        local = _local_reputation(normalized, query_type)
        local["message"] = "Aucune donnée VirusTotal — analyse locale complémentaire."
        local["source"] = "local+vt_empty"
        return local

    detections = 0
    total = 0
    ratio = 0.0
    risk_level = "low"
    indicators: List[str] = []
    scans = {}

    if query_type == "domain" and isinstance(data, dict):
        det_urls = len(data.get("detected_urls") or [])
        undet_urls = len(data.get("undetected_urls") or [])
        det_comm = len(data.get("detected_communicating_samples") or [])
        undet_comm = len(data.get("undetected_communicating_samples") or [])
        det_dl = len(data.get("detected_downloaded_samples") or [])
        undet_dl = len(data.get("undetected_downloaded_samples") or [])

        malicious = det_urls + det_comm + det_dl
        clean = undet_urls + undet_comm + undet_dl
        total = malicious + clean
        detections = malicious
        ratio = (malicious / total * 100) if total > 0 else 0.0

        alexa_raw = data.get("Alexa rank")
        alexa_n = None
        try:
            if alexa_raw is not None and str(alexa_raw).strip():
                alexa_n = int(str(alexa_raw).replace(",", "").strip())
                indicators.append(f"Alexa rank: {alexa_n}")
        except ValueError:
            pass

        bad_categories = []
        for key, val in data.items():
            if "category" not in str(key).lower():
                continue
            text = str(val).lower()
            if any(w in text for w in ("malware", "phishing", "suspicious", "spam", "malicious")):
                bad_categories.append(f"{key}: {val}")
        if bad_categories:
            indicators.extend(bad_categories[:5])

        indicators.append(f"URLs détectées/historiques: {det_urls} (propres: {undet_urls})")
        indicators.append(f"Samples suspects: {det_comm + det_dl} (propres: {undet_comm + undet_dl})")

        # Domaines très populaires : le bruit historique VT n'implique pas un domaine malveillant
        if alexa_n is not None and alexa_n <= 50000 and not bad_categories:
            risk_level = "low"
            detections = 0
            total = max(total, 70)
            ratio = 0.0
            indicators.append("Domaine populaire — risque VT historique non bloquant")
        elif bad_categories or ratio >= 70:
            risk_level = "high" if ratio < 85 and not bad_categories else "critical"
        elif ratio >= 45:
            risk_level = "medium"
        else:
            risk_level = "low"
    else:
        detections = data.get("positives", 0) if isinstance(data, dict) else 0
        total = data.get("total", 0) if isinstance(data, dict) else 0
        ratio = (detections / total * 100) if total > 0 else 0
        risk_level = (
            "critical"
            if ratio > 50
            else "high"
            if ratio > 25
            else "medium"
            if ratio > 10
            else "low"
        )
        if isinstance(data, dict) and "scans" in data:
            scans = {k: v for k, v in data["scans"].items() if v.get("detected", False)}

    return {
        "success": True,
        "source": "virustotal",
        "query": normalized,
        "original_query": query,
        "type": query_type,
        "detections": detections,
        "total": total,
        "ratio": round(ratio, 2),
        "risk_level": risk_level,
        "detecting_engines": list(scans.keys())[:10],
        "scan_date": data.get("scan_date") if isinstance(data, dict) else None,
        "permalink": data.get("permalink") if isinstance(data, dict) else (
            f"https://www.virustotal.com/gui/domain/{normalized}" if query_type == "domain" else None
        ),
        "data": data if isinstance(data, dict) else {},
        "vt_configured": True,
        "indicators": indicators,
        "message": None,
    }


def _resolve_to_ip(target: str) -> Dict[str, Any]:
    """Résout email/domaine/URL vers une IP si possible."""
    import re
    import socket
    from urllib.parse import urlparse

    raw = (target or "").strip()
    original = raw
    host = raw

    if "@" in raw and " " not in raw.split("@", 1)[0]:
        host = raw.split("@", 1)[1].strip()
    elif raw.startswith("http"):
        host = urlparse(raw).hostname or raw
    host = host.lower().rstrip(".")

    ip_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if ip_re.match(host):
        parts = host.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return {"ip": host, "host": host, "original": original, "resolved": False}

    try:
        ip = socket.gethostbyname(host)
        return {"ip": ip, "host": host, "original": original, "resolved": True}
    except Exception:
        return {"ip": None, "host": host, "original": original, "resolved": False, "error": "DNS resolution failed"}


def _local_abuse_check(target: str) -> Dict[str, Any]:
    """Réputation locale quand AbuseIPDB n'est pas configuré."""
    resolved = _resolve_to_ip(target)
    host = resolved.get("host") or target
    ip = resolved.get("ip")
    indicators: List[str] = []
    confidence = 5

    if "@" in (resolved.get("original") or ""):
        indicators.append(f"Entrée email détectée -> domaine {host}")

    if not ip:
        indicators.append(f"Impossible de résoudre {host} en IP")
        confidence += 55
        # Analyse domaine locale complémentaire
        local = _local_reputation(host, "domain")
        indicators.extend(local.get("indicators") or [])
        confidence = max(confidence, int(local.get("ratio") or 0))
    else:
        indicators.append(f"IP résolue: {ip}" if resolved.get("resolved") else f"IP fournie: {ip}")
        # Heuristiques IP privées / réservées
        parts = ip.split(".")
        try:
            a, b = int(parts[0]), int(parts[1])
            if a == 10 or a == 127 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
                indicators.append("IP privée / non routable")
                confidence = 0
            else:
                indicators.append("IP publique (pas de score AbuseIPDB cloud)")
                confidence += 10
        except Exception:
            pass

        # Sous-domaines suspects sur le host d'origine
        if host.count(".") >= 3:
            indicators.append("Hostname multi-niveaux (souvent suspect)")
            confidence += 25

    confidence = min(confidence, 95)
    risk = (
        "critical"
        if confidence > 75
        else "high"
        if confidence > 50
        else "medium"
        if confidence > 25
        else "low"
    )

    return {
        "success": True,
        "source": "local",
        "ip": ip or host,
        "host": host,
        "original_query": resolved.get("original") or target,
        "isPublic": bool(ip) and confidence > 0,
        "abuseConfidence": confidence,
        "usageType": "N/A (local)",
        "country": "N/A",
        "domain": host if not ip or ip != host else "N/A",
        "hostnames": [host] if host and host != ip else [],
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "risk_level": risk,
        "recent_reports": [],
        "indicators": indicators,
        "message": (
            "Analyse locale (AbuseIPDB non configuré). "
            "Ajoutez ABUSEIPDB_API_KEY dans .env — clé gratuite : "
            "https://www.abuseipdb.com/account/api"
        ),
        "abuseipdb_configured": False,
        "data": {},
    }


def run_abuseipdb(ip: str) -> Dict[str, Any]:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    resolved = _resolve_to_ip(ip)
    target_ip = resolved.get("ip")

    if not api_key:
        return _local_abuse_check(ip)

    if not target_ip:
        local = _local_abuse_check(ip)
        local["message"] = (
            f"Impossible de résoudre « {resolved.get('host')} » en IP pour AbuseIPDB. "
            "Analyse locale utilisée."
        )
        return local

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": target_ip, "maxAgeInDays": 90, "verbose": ""}
        response = requests.get(url, headers=headers, params=params, timeout=12)
        response.raise_for_status()
        check_data = response.json().get("data", {})
        abuse_confidence = check_data.get("abuseConfidencePercentage", 0)

        reports = []
        try:
            reports_response = requests.get(
                "https://api.abuseipdb.com/api/v2/check-block",
                headers=headers,
                params={"network": f"{target_ip}/32", "maxAgeInDays": 90},
                timeout=10,
            )
            if reports_response.status_code == 200:
                reports = (
                    reports_response.json().get("data", {}).get("reportedAddress", [])[:10]
                )
        except Exception:
            pass

        indicators = []
        if resolved.get("host") and resolved.get("resolved"):
            indicators.append(f"Resolu depuis {resolved['host']} -> {target_ip}")

        return {
            "success": True,
            "source": "abuseipdb",
            "ip": target_ip,
            "host": resolved.get("host"),
            "original_query": resolved.get("original") or ip,
            "isPublic": check_data.get("isPublic", False),
            "abuseConfidence": abuse_confidence,
            "usageType": check_data.get("usageType", "N/A"),
            "country": check_data.get("countryCode", "N/A"),
            "domain": check_data.get("domain", "N/A"),
            "hostnames": check_data.get("hostnames", []),
            "totalReports": check_data.get("totalReports", 0),
            "numDistinctUsers": check_data.get("numDistinctUsers", 0),
            "lastReportedAt": check_data.get("lastReportedAt"),
            "risk_level": (
                "critical"
                if abuse_confidence > 75
                else "high"
                if abuse_confidence > 50
                else "medium"
                if abuse_confidence > 25
                else "low"
            ),
            "recent_reports": reports,
            "indicators": indicators,
            "message": None,
            "abuseipdb_configured": True,
            "data": check_data,
        }
    except Exception as exc:
        local = _local_abuse_check(ip)
        local["message"] = f"AbuseIPDB inaccessible ({exc}). Analyse locale utilisée."
        return local


def run_shodan_ip(ip: str) -> Dict[str, Any]:
    scanner = get_shodan_scanner()
    if not scanner:
        return {
            "success": False,
            "error": "Shodan non configuré (SHODAN_API_KEY manquante)",
            "unavailable": True,
        }

    info = scanner.check_ip_shodan(ip)
    if not info:
        return {"success": False, "error": "Aucune information Shodan pour cette IP"}

    vuln_count = len(info.get("vulns", []))
    return {
        "success": True,
        "ip": ip,
        "ports": info.get("ports", []),
        "hostnames": info.get("hostnames", []),
        "org": info.get("org"),
        "vulns": info.get("vulns", []),
        "vuln_count": vuln_count,
        "risk_level": (
            "high"
            if vuln_count > 0
            else "medium"
            if len(info.get("ports", [])) > 10
            else "low"
        ),
        "data": info,
    }


def run_shodan_search(query: str) -> Dict[str, Any]:
    scanner = get_shodan_scanner()
    if not scanner:
        return {
            "success": False,
            "error": "Shodan non configuré (SHODAN_API_KEY manquante)",
            "unavailable": True,
        }

    results = scanner.search_shodan(query)
    if not results:
        return {"success": False, "error": "Aucun résultat Shodan"}

    matches = results.get("matches", [])
    return {
        "success": True,
        "query": query,
        "total": results.get("total", len(matches)),
        "matches_count": len(matches),
        "matches": matches[:5],
        "risk_level": "medium" if matches else "low",
        "data": results,
    }


def _normalize_domain(value: str) -> str:
    from urllib.parse import urlparse

    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "@" in raw and " " not in raw.split("@", 1)[0]:
        raw = raw.split("@", 1)[1]
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = urlparse(raw).netloc or raw
    return raw.strip().rstrip(".")


def run_dns_lookup(target: str) -> Dict[str, Any]:
    """Résolution DNS A/AAAA/MX/NS/TXT."""
    import socket

    domain = _normalize_domain(target)
    if not domain:
        return {"success": False, "error": "Domaine vide"}

    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    errors: List[str] = []

    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(domain, rtype)
                for ans in answers:
                    records[rtype].append(ans.to_text())
            except Exception as exc:
                errors.append(f"{rtype}: {exc.__class__.__name__}")
    except ImportError:
        # Fallback sans dnspython
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                ip = info[4][0]
                if ":" in ip:
                    if ip not in records["AAAA"]:
                        records["AAAA"].append(ip)
                elif ip not in records["A"]:
                    records["A"].append(ip)
        except socket.gaierror as exc:
            errors.append(str(exc))

    has_data = any(records[k] for k in records)
    return {
        "success": has_data,
        "domain": domain,
        "records": records,
        "errors": errors[:8],
        "risk_level": "low" if records["A"] or records["AAAA"] else "medium",
        "error": None if has_data else "Aucune donnée DNS",
    }


def run_email_auth(target: str) -> Dict[str, Any]:
    """Vérifie SPF / DMARC / sélecteurs DKIM courants via DNS TXT."""
    domain = _normalize_domain(target)
    if not domain:
        return {"success": False, "error": "Domaine vide"}

    def _txt(name: str) -> List[str]:
        try:
            import dns.resolver  # type: ignore

            answers = dns.resolver.resolve(name, "TXT")
            out = []
            for ans in answers:
                text = ans.to_text().strip().strip('"')
                out.append(text.replace('" "', ""))
            return out
        except Exception:
            return []

    spf_records = [t for t in _txt(domain) if "v=spf1" in t.lower()]
    dmarc_records = [t for t in _txt(f"_dmarc.{domain}") if "v=dmarc1" in t.lower()]

    dkim_found = []
    for selector in ("default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail"):
        records = _txt(f"{selector}._domainkey.{domain}")
        if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in records):
            dkim_found.append(selector)

    score = 0
    findings = []
    if spf_records:
        score += 1
        findings.append(f"SPF présent: {spf_records[0][:120]}")
    else:
        findings.append("SPF absent")

    if dmarc_records:
        score += 1
        policy = "unknown"
        for rec in dmarc_records:
            if "p=reject" in rec.lower():
                policy = "reject"
            elif "p=quarantine" in rec.lower():
                policy = "quarantine"
            elif "p=none" in rec.lower():
                policy = "none"
        findings.append(f"DMARC présent (policy={policy})")
        if policy == "reject":
            score += 1
    else:
        findings.append("DMARC absent")

    if dkim_found:
        score += 1
        findings.append("DKIM détecté (sélecteurs: " + ", ".join(dkim_found[:4]) + ")")
    else:
        findings.append("DKIM non détecté (sélecteurs courants)")

    risk = "low" if score >= 3 else "medium" if score >= 1 else "high"
    return {
        "success": True,
        "domain": domain,
        "spf": spf_records,
        "dmarc": dmarc_records,
        "dkim_selectors": dkim_found,
        "auth_score": score,
        "findings": findings,
        "risk_level": risk,
    }


def run_crtsh(target: str) -> Dict[str, Any]:
    """Certificats Certificate Transparency via crt.sh."""
    domain = _normalize_domain(target)
    if not domain:
        return {"success": False, "error": "Domaine vide"}

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=12,
            headers={"User-Agent": "PhishingGuardian/7"},
        )
        if resp.status_code != 200:
            return {
                "success": False,
                "domain": domain,
                "unavailable": True,
                "error": f"crt.sh HTTP {resp.status_code}",
            }
        rows = resp.json() if resp.text.strip() else []
    except Exception as exc:
        return {
            "success": False,
            "domain": domain,
            "unavailable": True,
            "error": f"crt.sh indisponible ({exc})",
        }

    names: List[str] = []
    for row in rows[:200]:
        name = (row.get("name_value") or "").strip()
        for part in name.split("\n"):
            part = part.strip().lower()
            if part and part not in names:
                names.append(part)

    return {
        "success": True,
        "domain": domain,
        "certificate_count": len(rows) if isinstance(rows, list) else 0,
        "unique_names": names[:40],
        "name_count": len(names),
        "risk_level": "medium" if len(names) > 80 else "low",
    }


def run_phishing_analyze(target: str) -> Dict[str, Any]:
    """Analyse phishing heuristique (email / URL / domaine)."""
    from phishing_guardian import PhishingGuardian, analyze_email_domains

    raw = (target or "").strip()
    if not raw:
        return {"success": False, "error": "Cible vide"}

    guardian = PhishingGuardian()
    email_text = None
    urls: List[str] = []

    if raw.startswith("http://") or raw.startswith("https://"):
        urls = [raw]
    elif "@" in raw and " " not in raw.split("@", 1)[0]:
        email_text = f"From: {raw}\nMessage concernant un compte lié à {raw}"
    else:
        # Domaine seul : évaluer comme URL https
        urls = [f"https://{raw}"]

    report = guardian.analyze(email_text=email_text, urls=urls or None)
    payload = report.as_dict()
    domain_info = analyze_email_domains(email_text or raw)

    email = payload.get("email") or {}
    url_results = payload.get("urls") or []
    synth = payload.get("synthetique") or {}

    return {
        "success": True,
        "target": raw,
        "email": email,
        "urls": url_results,
        "synthetique": synth,
        "domain_analysis": domain_info,
        "label": (email.get("label") if email else None)
        or (url_results[0].get("label") if url_results else "unknown"),
        "score": synth.get("score", 0),
        "risk_level": {
            "critique": "critical",
            "eleve": "high",
            "modere": "medium",
            "faible": "low",
        }.get(synth.get("niveau", "faible"), "low"),
    }


def run_hibp_osint(query: str) -> Dict[str, Any]:
    """OSINT léger (ex-Skiptracer) : HIBP + pivots basiques."""
    q = (query or "").strip()
    results: Dict[str, Any] = {
        "query": q,
        "sources": [],
        "data": {},
        "module": "hibp_osint",
    }

    if "@" in q:
        try:
            sha1 = hashlib.sha1(q.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=8,
                headers={"User-Agent": "PhishingGuardian"},
            )
            if response.ok and suffix in response.text:
                count = [
                    line.split(":")[1]
                    for line in response.text.splitlines()
                    if line.startswith(suffix)
                ]
                results["sources"].append("HaveIBeenPwned-Passwords")
                results["data"]["password_pwned"] = True
                results["data"]["breach_count"] = int(count[0]) if count else 0
            else:
                results["data"]["password_pwned"] = False
                results["sources"].append("HaveIBeenPwned-Passwords")
        except Exception as exc:
            results["data"]["hibp_error"] = str(exc)

        # LeakCheck / HIBP account via existing helper if available
        try:
            leak = run_leakcheck(q)
            if leak.get("success"):
                results["sources"].append("LeakCheck/HIBP-Accounts")
                results["data"]["account_breaches"] = leak
        except Exception:
            pass
    else:
        results["sources"].append("username-hint")
        results["data"]["note"] = (
            "Module OSINT léger : pour un username, utilisez Sherlock / Person OSINT. "
            "Pour un email, la vérif HIBP est appliquée."
        )

    return {
        "success": True,
        "query": q,
        "output": f"OSINT léger pour: {q}",
        "raw": [
            f"Query: {q}",
            f"Sources: {', '.join(results['sources']) if results['sources'] else 'Aucune'}",
        ],
        "results": results,
    }
