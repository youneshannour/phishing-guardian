"""Feeds anti-phishing locaux + lookups URLHaus / OpenPhish."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"
OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
OPENPHISH_TTL_SEC = 6 * 3600
USER_AGENT = "PhishingGuardian/7"


def _ensure_cache_dir() -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def _normalize_target(target: str) -> Tuple[str, str, str]:
    """Retourne (raw, host, url_or_empty)."""
    raw = (target or "").strip()
    if not raw:
        return "", "", ""

    host = raw
    url = ""

    if "@" in raw and " " not in raw.split("@", 1)[0]:
        host = raw.split("@", 1)[1].strip().lower().rstrip(".")
        return raw, host, ""

    if re.match(r"^https?://", raw, re.I):
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        url = raw
        return raw, host, url

    # Domaine nu → URL synthétique pour lookup
    host = raw.lower().rstrip(".")
    if "/" in host:
        parsed = urlparse("http://" + host)
        host = (parsed.hostname or host.split("/")[0]).lower().rstrip(".")
        url = "http://" + raw.lstrip("/")
    return raw, host, url


def _load_openphish_cache() -> Tuple[Set[str], Dict[str, Any]]:
    path = _ensure_cache_dir() / "openphish.json"
    meta: Dict[str, Any] = {"source": "openphish", "cached": False, "count": 0}
    if not path.exists():
        return set(), meta
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        fetched_at = float(data.get("fetched_at") or 0)
        if time.time() - fetched_at > OPENPHISH_TTL_SEC:
            return set(), meta
        hosts = set(data.get("hosts") or [])
        urls = set(data.get("urls") or [])
        meta.update(
            {
                "cached": True,
                "count": len(hosts) + len(urls),
                "fetched_at": fetched_at,
                "age_sec": int(time.time() - fetched_at),
            }
        )
        return hosts | urls, meta
    except Exception:
        return set(), meta


def refresh_openphish(force: bool = False) -> Dict[str, Any]:
    """Télécharge / rafraîchit le feed OpenPhish (liste d'URLs)."""
    path = _ensure_cache_dir() / "openphish.json"
    if not force and path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - float(data.get("fetched_at") or 0) < OPENPHISH_TTL_SEC:
                return {
                    "success": True,
                    "refreshed": False,
                    "count": len(data.get("hosts") or []),
                    "message": "Cache OpenPhish encore valide",
                }
        except Exception:
            pass

    try:
        resp = requests.get(
            OPENPHISH_URL,
            timeout=25,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
    except Exception as exc:
        return {"success": False, "error": f"OpenPhish inaccessible ({exc})"}

    hosts: Set[str] = set()
    urls: List[str] = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line.startswith("http"):
            continue
        urls.append(line)
        host = urlparse(line).hostname
        if host:
            hosts.add(host.lower().rstrip("."))

    payload = {
        "fetched_at": time.time(),
        "hosts": sorted(hosts),
        "urls": urls[:5000],
        "source_url": OPENPHISH_URL,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return {
        "success": True,
        "refreshed": True,
        "count": len(hosts),
        "url_count": len(urls),
    }


def _check_openphish(host: str, url: str) -> Dict[str, Any]:
    entries, meta = _load_openphish_cache()
    if not entries:
        refreshed = refresh_openphish()
        if refreshed.get("success"):
            entries, meta = _load_openphish_cache()
        else:
            return {
                "listed": False,
                "source": "openphish",
                "unavailable": True,
                "error": refreshed.get("error"),
                "meta": meta,
            }

    listed = False
    match = None
    if host and host in entries:
        listed = True
        match = host
    elif url:
        # match exact URL or host substring in cached urls
        if url in entries:
            listed = True
            match = url
        else:
            for item in entries:
                if isinstance(item, str) and host and host in item:
                    listed = True
                    match = item
                    break

    return {
        "listed": listed,
        "source": "openphish",
        "match": match,
        "meta": meta,
    }


def _check_urlhaus_host(host: str) -> Dict[str, Any]:
    if not host:
        return {"listed": False, "source": "urlhaus", "error": "host vide"}
    try:
        resp = requests.post(
            URLHAUS_HOST_API,
            data={"host": host},
            timeout=12,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            return {
                "listed": False,
                "source": "urlhaus",
                "unavailable": True,
                "error": f"URLHaus HTTP {resp.status_code}",
            }
        data = resp.json()
    except Exception as exc:
        return {
            "listed": False,
            "source": "urlhaus",
            "unavailable": True,
            "error": str(exc),
        }

    query_status = (data.get("query_status") or "").lower()
    if query_status == "no_results":
        return {"listed": False, "source": "urlhaus", "query_status": query_status}

    if query_status != "ok":
        return {
            "listed": False,
            "source": "urlhaus",
            "unavailable": True,
            "error": f"URLHaus status={query_status}",
            "query_status": query_status,
        }

    urls = data.get("urls") or []
    online = [u for u in urls if (u.get("url_status") or "").lower() == "online"]
    return {
        "listed": True,
        "source": "urlhaus",
        "query_status": query_status,
        "url_count": len(urls),
        "online_count": len(online),
        "threat": data.get("threat") or (urls[0].get("threat") if urls else None),
        "sample_urls": [u.get("url") for u in urls[:5] if u.get("url")],
        "raw": {
            "urlhaus_reference": data.get("urlhaus_reference"),
            "firstseen": data.get("firstseen"),
        },
    }


def _check_urlhaus_url(url: str) -> Dict[str, Any]:
    if not url:
        return {"listed": False, "source": "urlhaus_url", "skipped": True}
    try:
        resp = requests.post(
            URLHAUS_URL_API,
            data={"url": url},
            timeout=12,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            return {
                "listed": False,
                "source": "urlhaus_url",
                "unavailable": True,
                "error": f"URLHaus URL HTTP {resp.status_code}",
            }
        data = resp.json()
    except Exception as exc:
        return {
            "listed": False,
            "source": "urlhaus_url",
            "unavailable": True,
            "error": str(exc),
        }

    status = (data.get("query_status") or "").lower()
    if status == "no_results":
        return {"listed": False, "source": "urlhaus_url", "query_status": status}
    if status != "ok":
        return {
            "listed": False,
            "source": "urlhaus_url",
            "unavailable": True,
            "error": f"status={status}",
        }
    return {
        "listed": True,
        "source": "urlhaus_url",
        "query_status": status,
        "threat": data.get("threat"),
        "url_status": data.get("url_status"),
        "tags": data.get("tags") or [],
        "urlhaus_reference": data.get("urlhaus_reference"),
    }


def run_blocklist_check(target: str) -> Dict[str, Any]:
    """Vérifie une cible contre URLHaus + OpenPhish."""
    raw, host, url = _normalize_target(target)
    if not host and not url:
        return {"success": False, "error": "Cible vide"}

    checks: List[Dict[str, Any]] = []
    if host:
        checks.append(_check_urlhaus_host(host))
    if url:
        checks.append(_check_urlhaus_url(url))
    checks.append(_check_openphish(host, url))

    hits = [c for c in checks if c.get("listed")]
    unavailable = [c for c in checks if c.get("unavailable")]

    if hits:
        risk = "critical"
    elif unavailable and len(unavailable) == len(checks):
        risk = "low"
    else:
        risk = "low"

    sources_hit = sorted({c.get("source") for c in hits if c.get("source")})
    findings: List[str] = []
    for hit in hits:
        src = hit.get("source")
        threat = hit.get("threat")
        if src == "urlhaus":
            findings.append(
                f"URLHaus: hôte listé ({hit.get('online_count', 0)} URL online"
                + (f", threat={threat}" if threat else "")
                + ")"
            )
        elif src == "urlhaus_url":
            findings.append(
                f"URLHaus: URL listée"
                + (f" ({threat})" if threat else "")
                + (f" status={hit.get('url_status')}" if hit.get("url_status") else "")
            )
        elif src == "openphish":
            findings.append(f"OpenPhish: correspondance {hit.get('match')}")

    if not hits:
        findings.append("Aucune entrée blocklist connue (URLHaus / OpenPhish)")

    return {
        "success": True,
        "query": raw,
        "host": host,
        "url": url or None,
        "listed": bool(hits),
        "hit_count": len(hits),
        "sources_hit": sources_hit,
        "checks": checks,
        "findings": findings,
        "risk_level": risk,
        "unavailable_sources": [c.get("source") for c in unavailable],
    }
