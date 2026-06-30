from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
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


def run_sherlock(username: str) -> Dict[str, Any]:
    username = username.strip()
    if not username:
        return {"success": False, "error": "Nom d'utilisateur vide"}

    sherlock_cmd = None
    for cmd in [["sherlock"], ["python", "-m", "sherlock"]]:
        try:
            result = subprocess.run(
                cmd + ["--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if (
                result.returncode == 0
                or "sherlock" in result.stdout.lower()
                or "sherlock" in result.stderr.lower()
            ):
                sherlock_cmd = cmd
                break
        except FileNotFoundError:
            continue

    if not sherlock_cmd:
        return {"success": False, "error": "Sherlock non installé", "unavailable": True}

    result = subprocess.run(
        sherlock_cmd + ["--no-color", "--json", username],
        capture_output=True,
        text=True,
        timeout=120,
    )

    profiles = {}
    for line in (result.stdout or "").split("\n"):
        line = line.strip()
        if line and (line.startswith("{") or line.startswith("[")):
            try:
                profiles = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    count = len(profiles) if isinstance(profiles, dict) else 0
    return {
        "success": True,
        "username": username,
        "profiles": profiles if isinstance(profiles, dict) else {},
        "count": count,
        "risk_level": "high" if count > 5 else "medium" if count > 0 else "low",
    }


def run_virustotal(query: str) -> Dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "Clé API VirusTotal non configurée",
            "unavailable": True,
        }

    query = query.strip()
    if query.startswith("http"):
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"
        report_params = {"apikey": api_key, "resource": query}
        data = requests.get(report_url, params=report_params, timeout=10).json()
        query_type = "url"
    elif len(query) in (32, 64):
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        data = requests.get(url, params={"apikey": api_key, "resource": query}, timeout=10).json()
        query_type = "hash"
    elif "." in query and not query.replace(".", "").replace(":", "").isdigit():
        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        data = requests.get(url, params={"apikey": api_key, "domain": query}, timeout=10).json()
        query_type = "domain"
    else:
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        data = requests.get(url, params={"apikey": api_key, "ip": query}, timeout=10).json()
        query_type = "ip"

    detections = data.get("positives", 0) if isinstance(data, dict) else 0
    total = data.get("total", 0) if isinstance(data, dict) else 0
    ratio = (detections / total * 100) if total > 0 else 0

    return {
        "success": True,
        "query": query,
        "type": query_type,
        "detections": detections,
        "total": total,
        "ratio": round(ratio, 2),
        "risk_level": (
            "critical"
            if ratio > 50
            else "high"
            if ratio > 25
            else "medium"
            if ratio > 10
            else "low"
        ),
        "data": data,
    }


def run_abuseipdb(ip: str) -> Dict[str, Any]:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "Clé API AbuseIPDB non configurée",
            "unavailable": True,
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
    response = requests.get(url, headers=headers, params=params, timeout=10)
    response.raise_for_status()
    check_data = response.json().get("data", {})
    abuse_confidence = check_data.get("abuseConfidencePercentage", 0)

    return {
        "success": True,
        "ip": ip,
        "abuseConfidence": abuse_confidence,
        "country": check_data.get("countryCode", "N/A"),
        "domain": check_data.get("domain", "N/A"),
        "totalReports": check_data.get("totalReports", 0),
        "risk_level": (
            "critical"
            if abuse_confidence > 75
            else "high"
            if abuse_confidence > 50
            else "medium"
            if abuse_confidence > 25
            else "low"
        ),
        "data": check_data,
    }


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
