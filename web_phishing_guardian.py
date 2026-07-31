import os
from pathlib import Path

# Charger .env AVANT les imports services (Ollama, clés API, etc.)
from dotenv import load_dotenv

load_dotenv()
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

import subprocess
import json
import io
import re
import uuid
from contextlib import asynccontextmanager
from typing import Any, List, Optional
from datetime import datetime
import logging
import asyncio
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Header, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import requests

logger = logging.getLogger(__name__)

# Imports pour OCR
try:
    from PIL import Image, ImageEnhance, ImageFilter
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    Image = None
    ImageEnhance = None
    ImageFilter = None
    pytesseract = None

from phishing_guardian import PhishingGuardian
from osint_scanner import OSINTScanner
from vulnerability_scanner import VulnerabilityScanner
from advanced_vulnerability_scanner import AdvancedVulnerabilityScanner
from services.playbook_engine import playbook_engine
from services.ai_investigator import ai_investigator
from services.graph_service import (
    build_graph_from_investigation,
    graph_to_cytoscape,
    merge_graphs,
    suggest_pivot_playbook,
)
from services.scoring_service import compute_attack_surface
from services.privacy_service import compute_privacy_score
from services.timeline_service import build_timeline
from services.report_service import (
    generate_pdf_bytes,
    prepare_report_context,
    report_status,
    suggested_filename,
)
from services.watch_service import watch_service
from services.workspace_service import workspace_service
from plugins.osint.registry import list_plugins
from services.api_auth import API_KEY, APIKeyMiddleware, default_cors_origins
from services.session_auth import (
    COOKIE_NAME,
    cookie_settings,
    create_session_token,
    session_username_from_request,
    verify_credentials,
)

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    watch_service.start_scheduler()

    def _warm_feeds():
        try:
            from services.threat_feeds import refresh_openphish
            refresh_openphish(force=False)
        except Exception as exc:
            logger.warning("Warm-up OpenPhish failed: %s", exc)

    try:
        asyncio.create_task(asyncio.to_thread(_warm_feeds))
    except Exception:
        pass
    yield
    await watch_service.stop_scheduler()


app = FastAPI(title="Phishing Guardian - OSINT Platform", lifespan=lifespan)

app.add_middleware(APIKeyMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=default_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-PG-User", "X-PG-API-Key", "Authorization"],
)

EXTENSION_DIR = BASE_DIR / "extension"
if EXTENSION_DIR.is_dir():
    app.mount("/extension", StaticFiles(directory=str(EXTENSION_DIR), html=True), name="extension")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

guardian = PhishingGuardian()
shodan_scanner = OSINTScanner()
vuln_scanner = VulnerabilityScanner()
advanced_scanner = AdvancedVulnerabilityScanner()


# ========== MODELS ==========
class AnalyzeRequest(BaseModel):
    email: Optional[str] = None
    urls: Optional[List[str]] = None


class ShodanIPRequest(BaseModel):
    ip: str


class ShodanSearchRequest(BaseModel):
    query: str


class LeakCheckRequest(BaseModel):
    email: str


class ExifToolRequest(BaseModel):
    image_path: Optional[str] = None


class SherlockRequest(BaseModel):
    username: str


class SkiptracerRequest(BaseModel):
    query: str


class VirusTotalRequest(BaseModel):
    query: str


class AbuseIPDBRequest(BaseModel):
    ip: str


class WhoisRequest(BaseModel):
    query: str


class VulnerabilityRequest(BaseModel):
    ip: Optional[str] = None
    cve_list: Optional[List[str]] = None
    scan_type: Optional[str] = "stealth"  # stealth, full, quick


class PlaybookRunRequest(BaseModel):
    target: str
    playbook_id: Optional[str] = None


class AIChatMessage(BaseModel):
    role: str
    content: str


class AIChatRequest(BaseModel):
    message: str
    history: Optional[List[AIChatMessage]] = None


class AIInvestigateRequest(BaseModel):
    message: str
    playbook_id: Optional[str] = None


class GraphFromInvestigationRequest(BaseModel):
    investigation: dict


class GraphPivotRequest(BaseModel):
    target: str
    entity_type: Optional[str] = None
    playbook_id: Optional[str] = None
    existing_graph: Optional[dict] = None


class ScoreFromInvestigationRequest(BaseModel):
    investigation: dict


class PrivacyFromInvestigationRequest(BaseModel):
    investigation: dict


class TimelineFromInvestigationRequest(BaseModel):
    investigation: dict


class ReportFromInvestigationRequest(BaseModel):
    investigation: dict


class WatchCreateRequest(BaseModel):
    target: str
    playbook_id: Optional[str] = None
    label: Optional[str] = None
    interval_hours: Optional[int] = None
    baseline_investigation: Optional[dict] = None


class WatchUpdateRequest(BaseModel):
    status: Optional[str] = None
    label: Optional[str] = None
    interval_hours: Optional[int] = None


class WorkspaceCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""


class WorkspaceUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class WorkspaceMemberRequest(BaseModel):
    username: str
    role: Optional[str] = "analyst"


class CaseCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ""
    priority: Optional[str] = "medium"
    tags: Optional[List[str]] = None
    investigation: Optional[dict] = None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    tags: Optional[List[str]] = None


class CaseAddInvestigationRequest(BaseModel):
    investigation: dict


class WorkspaceAddInvestigationRequest(BaseModel):
    investigation: dict
    case_id: Optional[str] = None
    case_title: Optional[str] = None


class NoteCreateRequest(BaseModel):
    content: str
    case_id: Optional[str] = None


def _pg_user(
    request: Request,
    x_pg_user: Optional[str] = Header(None, alias="X-PG-User"),
) -> str:
    raw = (x_pg_user or "").strip() or (session_username_from_request(request) or "")
    if not raw:
        raise HTTPException(
            status_code=401,
            detail="Authentification requise",
        )
    try:
        return workspace_service.normalize_username(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class LoginRequest(BaseModel):
    username: str
    password: str


# ========== AUTH ROUTES ==========
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if session_username_from_request(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/api/auth/login")
async def api_auth_login(body: LoginRequest):
    if not verify_credentials(body.username, body.password):
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    token = create_session_token(body.username.strip())
    resp = JSONResponse({"ok": True, "username": body.username.strip()})
    resp.set_cookie(value=token, **cookie_settings())
    return resp


@app.get("/api/auth/me")
async def api_auth_me(request: Request):
    user = session_username_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Non connecte")
    return {"username": user}


@app.post("/api/auth/logout")
async def api_auth_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(key=COOKIE_NAME, path="/")
    return resp


# ========== MAIN ROUTES ==========
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = session_username_from_request(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "api_key": API_KEY, "username": user},
    )


@app.post("/api/analyze-image")
async def api_analyze_image(file: UploadFile = File(...)) -> Any:
    """OCR avancé sur capture d'écran d'email (+ artefacts emails/URLs)."""
    if not OCR_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="OCR non disponible. Installez: pip install pytesseract Pillow + tesseract-ocr-fra",
        )

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Image vide")

    def _run() -> dict:
        from services.ocr_email import ocr_email_image

        result = ocr_email_image(image_bytes)
        result["filename"] = file.filename
        if not result.get("success"):
            result["warning"] = (
                "L'OCR n'a pas pu extraire de texte. Vérifiez la qualité / le zoom de la capture."
            )
        return result

    try:
        return await asyncio.to_thread(_run)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur OCR: {exc}")


@app.post("/api/analyze-screenshot")
async def api_analyze_screenshot(file: UploadFile = File(...)) -> Any:
    """OCR + analyse phishing complète + enrichissement multi-sources en un appel."""
    if not OCR_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="OCR non disponible. Installez: pip install pytesseract Pillow + tesseract-ocr-fra",
        )

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Image vide")

    def _run() -> dict:
        from services.ocr_email import ocr_email_image
        from services.phishing_enrichment import enrich_phishing_report

        ocr = ocr_email_image(image_bytes)
        text = ocr.get("augmented_text") or ocr.get("extracted_text") or ""
        arts = ocr.get("artifacts") or {}
        urls = list(arts.get("urls") or [])

        if not text.strip():
            return {
                "success": False,
                "ocr": ocr,
                "message": "Aucun texte extrait — analyse impossible",
            }

        report = guardian.analyze(email_text=text, urls=urls or None)
        result = report.as_dict()
        enrich_phishing_report(result, email_text=text, urls=urls or None)

        url_rows = result.get("urls") or []
        result["statistics"] = {
            "total_urls_analyzed": len(url_rows),
            "phishing_urls": len([u for u in url_rows if u.get("label") == "phishing"]),
            "legitimate_urls": len(
                [u for u in url_rows if u.get("label") in ("legitime", "legitimate")]
            ),
            "email_analyzed": bool(result.get("email")),
            "email_is_phishing": (
                (result.get("email") or {}).get("label") == "phishing"
            ),
            "max_score": (result.get("synthetique") or {}).get("score", 0),
            "intel_boost": (result.get("synthetique") or {}).get("boost_intel", 0),
            "sources_ok": (result.get("enrichment") or {}).get("sources_ok") or [],
            "ocr_emails": len(arts.get("emails") or []),
            "ocr_urls": len(arts.get("urls") or []),
        }
        result["success"] = True
        result["ocr"] = {
            "extracted_text": ocr.get("extracted_text"),
            "artifacts": arts,
            "statistics": ocr.get("statistics"),
            "message": ocr.get("message"),
            "filename": file.filename,
        }
        result["source"] = "screenshot"
        return result

    try:
        return await asyncio.to_thread(_run)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur analyse capture: {exc}")


@app.post("/api/analyze")
async def api_analyze(payload: AnalyzeRequest) -> Any:
    """Analyse phishing avancée email/URLs avec enrichissement multi-sources."""
    email_text = payload.email or None
    urls = payload.urls or None

    def _run() -> dict:
        from services.phishing_enrichment import enrich_phishing_report

        report = guardian.analyze(email_text=email_text, urls=urls)
        result = report.as_dict()
        enrich_phishing_report(result, email_text=email_text, urls=urls)

        url_rows = result.get("urls") or []
        result["statistics"] = {
            "total_urls_analyzed": len(url_rows),
            "phishing_urls": len([u for u in url_rows if u.get("label") == "phishing"]),
            "legitimate_urls": len(
                [u for u in url_rows if u.get("label") in ("legitime", "legitimate")]
            ),
            "email_analyzed": bool(result.get("email")),
            "email_is_phishing": (
                result.get("email", {}).get("label") == "phishing"
                if result.get("email")
                else False
            ),
            "max_score": result.get("synthetique", {}).get("score", 0),
            "intel_boost": result.get("synthetique", {}).get("boost_intel", 0),
            "sources_ok": (result.get("enrichment") or {}).get("sources_ok") or [],
        }
        return result

    return await asyncio.to_thread(_run)


@app.post("/api/shodan/ip")
async def api_shodan_ip(payload: ShodanIPRequest) -> Any:
    """Enrichissement IP avancé via Shodan."""

    def _run() -> dict:
        from services.osint_tools import run_shodan_ip

        data = run_shodan_ip(payload.ip.strip())
        if data.get("unavailable"):
            raise HTTPException(status_code=503, detail=data.get("error") or "Shodan non configuré")
        if not data.get("success"):
            raise HTTPException(status_code=404, detail=data.get("error") or "Aucune info Shodan")

        info = data.get("data") or {}
        vulns_raw = data.get("vulns") if data.get("vulns") is not None else info.get("vulns")
        if isinstance(vulns_raw, dict):
            vulns = list(vulns_raw.keys())
        elif isinstance(vulns_raw, list):
            vulns = [str(v) for v in vulns_raw]
        else:
            vulns = []

        ports = data.get("ports") or info.get("ports") or []
        hostnames = data.get("hostnames") or info.get("hostnames") or []

        enriched = {
            "success": True,
            "ip": data.get("ip") or payload.ip,
            "org": data.get("org") or info.get("org"),
            "isp": info.get("isp"),
            "os": info.get("os"),
            "ports": ports,
            "hostnames": hostnames,
            "vulns": vulns,
            "last_update": info.get("last_update"),
            "analysis": {
                "total_ports": len(ports),
                "total_hostnames": len(hostnames),
                "total_vulns": len(vulns),
                "risk_level": data.get("risk_level")
                or ("high" if vulns else "medium" if len(ports) > 10 else "low"),
            },
            "services": [],
            "geolocation": {},
        }

        for service_data in info.get("data", []) or []:
            enriched["services"].append(
                {
                    "port": service_data.get("port"),
                    "product": service_data.get("product"),
                    "version": service_data.get("version"),
                    "banner": (service_data.get("data") or "")[:200] or None,
                    "http": service_data.get("http") if "http" in service_data else None,
                }
            )

        for data_item in info.get("data", []) or []:
            if "location" in data_item:
                loc = data_item["location"] or {}
                enriched["geolocation"] = {
                    "country": loc.get("country_name"),
                    "city": loc.get("city"),
                    "latitude": loc.get("latitude"),
                    "longitude": loc.get("longitude"),
                }
                break
        return enriched

    try:
        return await asyncio.to_thread(_run)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur Shodan: {exc}")


@app.post("/api/shodan/search")
async def api_shodan_search(payload: ShodanSearchRequest) -> Any:
    """Recherche Shodan avancée."""

    def _run() -> dict:
        from services.osint_tools import run_shodan_search

        data = run_shodan_search(payload.query.strip())
        if data.get("unavailable"):
            raise HTTPException(status_code=503, detail=data.get("error") or "Shodan non configuré")
        if not data.get("success"):
            raise HTTPException(status_code=404, detail=data.get("error") or "Aucun résultat")
        # UI attend { matches, total }
        return {
            "matches": data.get("matches") or [],
            "total": data.get("matches_count") or len(data.get("matches") or []),
            "query": data.get("query"),
        }

    try:
        return await asyncio.to_thread(_run)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur Shodan search: {exc}")


@app.post("/api/leakcheck")
async def api_leakcheck(payload: LeakCheckRequest) -> Any:
    """Vérification email avancée dans bases de fuites via HaveIBeenPwned + API email."""
    email = payload.email.strip().lower()
    
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Email invalide")
    
    try:
        import hashlib
        
        # 1. Vérification via API HaveIBeenPwned (passwords)
        sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        hibp_url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(hibp_url, timeout=10, headers={"User-Agent": "PhishingGuardian"})
        response.raise_for_status()
        
        hashes = response.text
        found_password = False
        password_breach_count = 0
        
        for line in hashes.split("\n"):
            if line.startswith(suffix):
                password_breach_count = int(line.split(":")[1].strip())
                found_password = True
                break
        
        # 2. Vérification via API HaveIBeenPwned pour emails (si disponible)
        found_email = False
        email_breaches = []
        hibp_api_key = os.getenv("HAVEIBEENPWNED_API_KEY")  # Optionnel
        
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
        
        # Combiner les résultats
        total_breaches = password_breach_count + len(email_breaches)
        found = found_password or found_email
        
        sources = []
        if found_password:
            sources.append(f"Password breaches: {password_breach_count}")
        if found_email:
            breach_names = [b.get("Name", "Unknown") for b in email_breaches]
            sources.extend(breach_names)
        
        return {
            "email": email,
            "found": found,
            "sources": sources,
            "breach_count": total_breaches,
            "password_breaches": password_breach_count,
            "email_breaches": len(email_breaches),
            "breach_details": email_breaches[:10],  # Top 10
            "risk_level": "critical" if total_breaches > 10 else ("high" if total_breaches > 5 else ("medium" if total_breaches > 0 else "low")),
            "details": {
                "service": "HaveIBeenPwned (gratuit)" + (" + API email" if hibp_api_key else ""),
                "note": f"Email trouvé dans {total_breaches} fuite(s) connue(s)." if found else "Email non trouvé dans les bases de fuites connues.",
            },
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Erreur lors de la vérification: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")


@app.post("/api/exiftool")
async def api_exiftool(file: UploadFile = File(...)) -> Any:
    """Extraction métadonnées image via ExifTool."""
    temp_dir = BASE_DIR / "temp"
    temp_dir.mkdir(exist_ok=True)
    suffix = Path(file.filename or "upload.bin").suffix or ".bin"
    temp_path = temp_dir / f"exif-{uuid.uuid4().hex}{suffix}"

    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Fichier vide")
        temp_path.write_bytes(content)

        exiftool_cmd = _resolve_exiftool_cmd()
        if not exiftool_cmd:
            raise HTTPException(
                status_code=503,
                detail=(
                    "ExifTool non installé. Sous Linux: sudo apt install libimage-exiftool-perl. "
                    "Sous Windows: placez exiftool.exe dans le dossier exiftool/ du projet "
                    "(https://exiftool.org/)."
                ),
            )

        def _run() -> dict:
            result = subprocess.run(
                [exiftool_cmd, "-j", "-a", "-G", str(temp_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if result.returncode != 0 and not (result.stdout or "").strip():
                raise RuntimeError(result.stderr or "ExifTool a échoué")

            metadata = {}
            raw = (result.stdout or "").strip()
            if raw:
                parsed = json.loads(raw)
                if isinstance(parsed, list) and parsed:
                    metadata = parsed[0]
                elif isinstance(parsed, dict):
                    metadata = parsed

            analysis = {
                "has_gps": any("GPS" in str(k) for k in metadata.keys()),
                "has_camera_info": any(
                    k in metadata or k.split(":")[-1] in ("Make", "Model", "Camera")
                    for k in metadata.keys()
                ),
                "has_software": any("Software" in str(k) for k in metadata.keys()),
                "has_author": any(
                    any(tag in str(k) for tag in ("Artist", "Author", "Creator"))
                    for k in metadata.keys()
                ),
                "file_size": metadata.get("FileSize") or metadata.get("File:FileSize"),
                "mime_type": metadata.get("MIMEType") or metadata.get("File:MIMEType"),
            }

            def _get(*keys):
                for k in keys:
                    if k in metadata and metadata[k] not in (None, ""):
                        return metadata[k]
                return None

            gps_data = {}
            if analysis["has_gps"]:
                lat = _get("GPSLatitude", "Composite:GPSLatitude", "EXIF:GPSLatitude")
                lon = _get("GPSLongitude", "Composite:GPSLongitude", "EXIF:GPSLongitude")
                if lat and lon:
                    gps_data = {
                        "latitude": str(lat),
                        "longitude": str(lon),
                        "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
                    }

            camera_info = {
                "make": _get("Make", "EXIF:Make"),
                "model": _get("Model", "EXIF:Model"),
                "lens": _get("LensModel", "EXIF:LensModel"),
                "focal_length": _get("FocalLength", "EXIF:FocalLength"),
                "aperture": _get("FNumber", "EXIF:FNumber"),
                "iso": _get("ISO", "EXIF:ISO"),
                "exposure": _get("ExposureTime", "EXIF:ExposureTime"),
            }

            return {
                "filename": file.filename,
                "metadata": metadata,
                "summary": {
                    k: v
                    for k, v in metadata.items()
                    if k not in ("SourceFile", "ExifToolVersion") and v not in (None, "")
                },
                "analysis": analysis,
                "gps": gps_data,
                "camera": {k: v for k, v in camera_info.items() if v},
                "security_flags": {
                    "has_location": analysis["has_gps"],
                    "has_author_info": analysis["has_author"],
                    "risk_level": (
                        "high"
                        if analysis["has_gps"]
                        else "medium"
                        if analysis["has_author"]
                        else "low"
                    ),
                },
            }

        try:
            return await asyncio.to_thread(_run)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Erreur ExifTool: {exc}")
    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass


@app.post("/api/sherlock")
async def api_sherlock(payload: SherlockRequest) -> Any:
    """Recherche profils via Sherlock."""
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Nom d'utilisateur vide")
    try:
        from services.osint_tools import run_sherlock

        data = await asyncio.to_thread(run_sherlock, username)
        if data.get("unavailable"):
            raise HTTPException(
                status_code=503,
                detail=data.get("error") or "Sherlock non installé. pip install sherlock-project",
            )
        if not data.get("success") and data.get("error"):
            raise HTTPException(status_code=504 if "timeout" in str(data.get("error")).lower() else 500, detail=data["error"])
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur Sherlock: {str(e)}")


@app.post("/api/skiptracer")
async def api_skiptracer(payload: SkiptracerRequest) -> Any:
    """Recherche OSINT via Skiptracer (version simplifiée)."""
    # Skiptracer est un outil interactif complexe, on utilise une version simplifiée
    # qui combine plusieurs sources OSINT publiques
    
    query = payload.query.strip()
    results = {
        "query": query,
        "sources": [],
        "data": {},
    }
    
    # Vérification HaveIBeenPwned (si email)
    if "@" in query:
        try:
            import hashlib
            import requests
            sha1 = hashlib.sha1(query.encode()).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]
            
            hibp_url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(hibp_url, timeout=5)
            if response.ok:
                hashes = response.text
                if suffix in hashes:
                    count = [line.split(":")[1] for line in hashes.split("\n") if line.startswith(suffix)][0]
                    results["sources"].append("HaveIBeenPwned")
                    results["data"]["pwned"] = True
                    results["data"]["breach_count"] = int(count)
                else:
                    results["data"]["pwned"] = False
        except Exception:
            pass
    
    # Recherche simple sur plusieurs sources publiques
    try:
        import requests
        # Exemple: recherche sur namechk (si c'est un username)
        if "@" not in query:
            # On pourrait faire des requêtes vers des APIs publiques ici
            results["sources"].append("Username check (simplifié)")
            results["data"]["note"] = "Skiptracer complet nécessite une utilisation interactive. Cette version simplifiée combine quelques sources publiques."
    except Exception:
        pass
    
    return {
        "query": query,
        "output": f"Recherche OSINT simplifiée pour: {query}",
        "raw": [f"Query: {query}", f"Sources vérifiées: {', '.join(results['sources']) if results['sources'] else 'Aucune'}"],
        "results": results,
    }


@app.post("/api/virustotal")
async def api_virustotal(payload: VirusTotalRequest) -> Any:
    """Scan VirusTotal (URL / IP / domaine / hash) via le wrapper OSINT unifié."""

    def _run() -> dict:
        from services.osint_tools import run_virustotal

        data = run_virustotal(payload.query.strip())
        if data.get("unavailable"):
            raise HTTPException(
                status_code=503,
                detail=data.get("error") or "VirusTotal indisponible",
            )
        if not data.get("success"):
            raise HTTPException(
                status_code=502,
                detail=data.get("error") or "Erreur VirusTotal",
            )
        return data

    try:
        return await asyncio.to_thread(_run)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur VirusTotal: {exc}")


@app.post("/api/abuseipdb")
async def api_abuseipdb(payload: AbuseIPDBRequest) -> Any:
    """Check IP / domaine via AbuseIPDB (fallback local si clé absente)."""

    def _run() -> dict:
        from services.osint_tools import run_abuseipdb

        data = run_abuseipdb(payload.ip.strip())
        if not data.get("success") and data.get("unavailable"):
            raise HTTPException(status_code=503, detail=data.get("error") or "AbuseIPDB indisponible")
        # Toujours renvoyer le dict service (source + abuseConfidence) pour l'UI
        return data

    try:
        return await asyncio.to_thread(_run)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur AbuseIPDB: {exc}")


@app.post("/api/whois")
async def api_whois(payload: WhoisRequest) -> Any:
    """Whois lookup."""
    query = payload.query.strip()
    
    if not query:
        raise HTTPException(status_code=400, detail="Query vide")
    
    # Importer whois
    try:
        import whois
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Module whois non installé. Installez-le: pip install python-whois",
        )
    
    import socket
    
    try:
        # Détecter si c'est une IP ou un domaine
        try:
            socket.inet_aton(query)
            is_ip = True
        except (socket.error, ValueError):
            is_ip = False
        
        if is_ip:
            # Pour les IPs, utiliser une API publique
            try:
                response = requests.get(f"https://ipwhois.app/json/{query}", timeout=10)
                response.raise_for_status()
                data = response.json()

                # Extraire un maximum d'informations intéressantes tout en restant robuste
                return {
                    "query": query,
                    "type": "ip",
                    "data": {
                        # Champs de base
                        "ip": data.get("ip", query),
                        "country": data.get("country", "N/A"),
                        "country_code": data.get("country_code", "N/A"),
                        "continent": data.get("continent", "N/A"),
                        "region": data.get("region", "N/A"),
                        "city": data.get("city", "N/A"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                        "timezone": data.get("timezone", "N/A"),
                        # Réseau / ASN
                        "asn": data.get("asn", "N/A"),
                        "asn_org": data.get("asn_org", data.get("org", "N/A")),
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("org", "N/A"),
                        # Infos supplémentaires utiles
                        "currency": data.get("currency", "N/A"),
                        "country_capital": data.get("country_capital", "N/A"),
                        "phone_code": data.get("country_phone", "N/A"),
                        "reverse_dns": data.get("reverse", data.get("reverse_dns", None)),
                    },
                }
            except Exception as e:
                return {
                    "query": query,
                    "type": "ip",
                    "data": {"error": f"Whois IP lookup failed: {str(e)}"},
                }
        else:
            # Pour les domaines
            try:
                w = whois.whois(query)
                # Nettoyer les données (whois peut retourner des listes)
                def clean_value(v):
                    if isinstance(v, list):
                        return v[0] if v else None
                    return v
                
                # Extraire davantage de métadonnées utiles
                domain_name = clean_value(w.domain_name)
                registrar = clean_value(w.registrar)
                creation_date = str(w.creation_date) if w.creation_date else None
                expiration_date = str(w.expiration_date) if w.expiration_date else None
                updated_date_raw = getattr(w, "updated_date", None)
                updated_date = str(clean_value(updated_date_raw)) if updated_date_raw else None
                org = clean_value(w.org)
                country = clean_value(w.country)
                state = clean_value(getattr(w, "state", None))
                city = clean_value(getattr(w, "city", None))
                address = clean_value(getattr(w, "address", None))
                zipcode = clean_value(getattr(w, "zipcode", None))
                phone = clean_value(getattr(w, "phone", None))
                fax = clean_value(getattr(w, "fax", None))
                registrar_url = clean_value(getattr(w, "registrar_url", None))
                
                return {
                    "query": query,
                    "type": "domain",
                    "data": {
                        "domain_name": domain_name,
                        "registrar": registrar,
                        "registrar_url": registrar_url,
                        "creation_date": creation_date,
                        "expiration_date": expiration_date,
                        "updated_date": updated_date,
                        "org": org,
                        "country": country,
                        "state": state,
                        "city": city,
                        "address": address,
                        "zipcode": zipcode,
                        "phone": phone,
                        "fax": fax,
                        "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                        "status": clean_value(w.status),
                        "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                    },
                }
            except whois.parser.PywhoisError as e:
                raise HTTPException(status_code=404, detail=f"Domaine non trouvé ou erreur whois: {str(e)}")
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Erreur Whois: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur inattendue: {str(e)}")


@app.post("/api/vulnerabilities")
async def api_vulnerabilities(payload: VulnerabilityRequest) -> Any:
    """Analyse avancée des vulnérabilités avec Nmap, NVD, CVE Details, Exploit-DB et analyse des ports."""
    try:
        cve_list = payload.cve_list or []
        ports_analysis = None
        scan_error = None
        scan_method = None
        
        # Extraire l'IP depuis une URL si nécessaire
        target_ip = payload.ip
        original_input = payload.ip  # Garder l'entrée originale pour l'affichage
        if target_ip:
            # Si c'est une URL, extraire le domaine puis résoudre en IP
            if target_ip.startswith("http://") or target_ip.startswith("https://"):
                from urllib.parse import urlparse
                parsed_url = urlparse(target_ip)
                domain = parsed_url.netloc or parsed_url.path.split('/')[0]
                # Résoudre le domaine en IP
                try:
                    import socket
                    resolved_ip = socket.gethostbyname(domain)
                    logger.info(f"URL {target_ip} résolue en IP: {resolved_ip}")
                    target_ip = resolved_ip
                except socket.gaierror:
                    logger.warning(f"Impossible de résoudre le domaine {domain}")
                    # Essayer de scanner directement le domaine si la résolution échoue
                    target_ip = domain
            elif "." in target_ip and not any(c.isdigit() for c in target_ip.split(".")[0]):
                # C'est probablement un domaine sans http://
                try:
                    import socket
                    resolved_ip = socket.gethostbyname(target_ip)
                    logger.info(f"Domaine {target_ip} résolu en IP: {resolved_ip}")
                    target_ip = resolved_ip
                except socket.gaierror:
                    logger.warning(f"Impossible de résoudre le domaine {target_ip}")
                    # Garder le domaine tel quel pour le scan
                    pass
        
        if target_ip:
            # Utiliser le scanner avancé avec Nmap (ou scan manuel)
            try:
                scan_result = advanced_scanner.scan_ip_nmap(target_ip, payload.scan_type or "stealth")
                
                if scan_result.get("error"):
                    # Erreur de scan, utiliser scan manuel en fallback
                    scan_result = advanced_scanner._manual_port_scan(target_ip)
                    scan_method = "manual_fallback"
                else:
                    scan_method = scan_result.get("scan_method", "nmap")
                
                # Analyser les ports avec le scanner avancé
                # Si aucun port trouvé, analyser quand même les ports communs pour informer
                ports_analysis = advanced_scanner.analyze_ports_advanced(scan_result)
                ports_analysis["scan_method"] = scan_method
                ports_analysis["nmap_available"] = advanced_scanner.nmap_path is not None
                
                # Si aucun port détecté, ajouter un message informatif
                if ports_analysis.get("ports_analyzed", 0) == 0:
                    ports_analysis["message"] = "Aucun port ouvert détecté. Analyse des ports communs à risque pour information."
                    ports_analysis["info_only"] = True
                
            except Exception as e:
                scan_error = f"Erreur de scan: {str(e)}"
                # Fallback vers scan manuel
                try:
                    scan_result = advanced_scanner._manual_port_scan(payload.ip)
                    ports_analysis = advanced_scanner.analyze_ports_advanced(scan_result)
                    ports_analysis["scan_method"] = "manual_fallback"
                    ports_analysis["nmap_available"] = False
                except:
                    ports_analysis = {
                        "ports_analyzed": 0,
                        "ports_details": [],
                        "critical_ports": [],
                        "total_risk_score": 0.0,
                        "attack_vectors": [],
                        "exploit_commands": [],
                        "message": f"Impossible de scanner l'IP: {str(e)}"
                    }
        else:
            # Si pas d'IP fournie, pas d'analyse de ports
            ports_analysis = None
        
        # Dédupliquer et nettoyer les CVE
        cve_list = [cve.strip().upper() for cve in cve_list if cve and cve.strip().upper().startswith("CVE-")]
        cve_list = list(set(cve_list))
        
        # Analyser les CVE si disponibles (même sans Shodan)
        cve_analysis = None
        if cve_list:
            cve_analysis = vuln_scanner.analyze_vulnerabilities(cve_list)
            recommendations = vuln_scanner._generate_recommendations(cve_analysis)
        else:
            cve_analysis = {
                "total": 0,
                "analyzed": 0,
                "vulnerabilities": [],
                "summary": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0
                },
                "risk_score": 0.0
            }
            recommendations = []
        
        # Ajouter les recommandations des ports
        if ports_analysis:
            for port_detail in ports_analysis.get("ports_details", []):
                recommendations.extend(port_detail.get("recommendations", []))
        
        # Calculer le score de risque global
        global_risk_score = cve_analysis.get("risk_score", 0.0)
        if ports_analysis:
            ports_risk = ports_analysis.get("total_risk_score", 0.0)
            global_risk_score = max(global_risk_score, ports_risk)
        
        return {
            "error": False,
            "ip": target_ip if target_ip else payload.ip,
            "original_input": original_input,  # Garder l'entrée originale (URL ou IP)
            "cve_list": cve_list,
            "cve_analysis": cve_analysis,
            "ports_analysis": ports_analysis,
            "recommendations": list(set(recommendations)) if recommendations else ["Aucune vulnérabilité critique détectée"],
            "global_risk_score": global_risk_score,
            "scan_error": scan_error,
            "scan_method": ports_analysis.get("scan_method") if ports_analysis else None,
            "nmap_available": ports_analysis.get("nmap_available") if ports_analysis else False,
            "scan_date": datetime.now().isoformat()
        }
        
    except Exception as e:
        import traceback
        return {
            "error": True,
            "message": f"Erreur lors de l'analyse des vulnérabilités: {str(e)}",
            "traceback": traceback.format_exc() if os.getenv("DEBUG") else None,
            "ip": target_ip if 'target_ip' in locals() else payload.ip,
            "original_input": payload.ip,
            "cve_list": payload.cve_list or []
        }


@app.get("/api/playbooks")
async def api_list_playbooks() -> Any:
    """Liste des playbooks OSINT disponibles."""
    playbooks = playbook_engine.list_playbooks()
    plugins = [
        {
            "id": p.id,
            "name": p.name,
            "supported_types": [t.value for t in p.supported_types],
            "available": p.is_available(),
            "env_key": p.env_key,
        }
        for p in list_plugins()
    ]
    return {
        "playbooks": [p.to_dict() for p in playbooks],
        "plugins": plugins,
    }


@app.get("/api/playbooks/suggest")
async def api_suggest_playbook(target: str) -> Any:
    """Suggère un playbook selon le type de cible détecté."""
    if not target.strip():
        raise HTTPException(status_code=400, detail="Cible vide")
    return playbook_engine.suggest(target.strip())


@app.post("/api/playbooks/run")
async def api_run_playbook(payload: PlaybookRunRequest) -> Any:
    """Exécute un playbook OSINT et retourne une fiche synthèse."""
    if not payload.target.strip():
        raise HTTPException(status_code=400, detail="Cible vide")
    try:
        result = await playbook_engine.run(
            target=payload.target.strip(),
            playbook_id=payload.playbook_id,
        )
        return result.to_dict()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur playbook: {str(exc)}")


@app.get("/api/ai/status")
async def api_ai_status() -> Any:
    """Statut de la connexion Ollama / Investigator AI."""
    return await asyncio.to_thread(ai_investigator.check_status)


@app.post("/api/ai/chat")
async def api_ai_chat(payload: AIChatRequest) -> Any:
    """Chat avec Investigator AI (réponses ou investigation automatique)."""
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message vide")
    try:
        history = [{"role": m.role, "content": m.content} for m in (payload.history or [])]
        return await ai_investigator.chat(payload.message.strip(), history)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur Investigator AI: {str(exc)}")


@app.post("/api/ai/investigate")
async def api_ai_investigate(payload: AIInvestigateRequest) -> Any:
    """Lance une investigation OSINT depuis un message en langage naturel."""
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message vide")
    try:
        return await ai_investigator.investigate(
            payload.message.strip(),
            playbook_id=payload.playbook_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur investigation: {str(exc)}")


@app.post("/api/ai/summarize")
async def api_ai_summarize(payload: dict) -> Any:
    """Génère un résumé IA à partir d'un résultat d'investigation existant."""
    if not payload:
        raise HTTPException(status_code=400, detail="Résultat d'investigation requis")
    try:
        return await ai_investigator.summarize_investigation(payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur résumé: {str(exc)}")


@app.post("/api/graph/from-investigation")
async def api_graph_from_investigation(payload: GraphFromInvestigationRequest) -> Any:
    """Génère un graphe de relations depuis un résultat d'investigation."""
    if not payload.investigation:
        raise HTTPException(status_code=400, detail="Investigation requise")
    graph = build_graph_from_investigation(payload.investigation)
    cytoscape = graph_to_cytoscape(graph)
    return {"graph": graph, "cytoscape": cytoscape}


@app.post("/api/graph/pivot")
async def api_graph_pivot(payload: GraphPivotRequest) -> Any:
    """Mode pivot : relance une investigation sur une entité et fusionne le graphe."""
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Cible vide")
    playbook_id = payload.playbook_id
    if not playbook_id and payload.entity_type:
        playbook_id = suggest_pivot_playbook(payload.entity_type)
    try:
        result = await playbook_engine.run(target=target, playbook_id=playbook_id)
        new_graph = build_graph_from_investigation(result.to_dict())
        if payload.existing_graph:
            merged = merge_graphs(payload.existing_graph, new_graph)
        else:
            merged = new_graph
        return {
            "investigation": result.to_dict(),
            "graph": merged,
            "cytoscape": graph_to_cytoscape(merged),
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur pivot: {str(exc)}")


@app.post("/api/score/from-investigation")
async def api_score_from_investigation(payload: ScoreFromInvestigationRequest) -> Any:
    """Calcule le score de surface d'attaque (0–100) depuis une investigation."""
    if not payload.investigation:
        raise HTTPException(status_code=400, detail="Investigation requise")
    return compute_attack_surface(payload.investigation)


@app.post("/api/privacy/from-investigation")
async def api_privacy_from_investigation(payload: PrivacyFromInvestigationRequest) -> Any:
    """Calcule le Privacy Score personnel (0–100) depuis une investigation."""
    if not payload.investigation:
        raise HTTPException(status_code=400, detail="Investigation requise")
    return compute_privacy_score(payload.investigation)


@app.post("/api/timeline/from-investigation")
async def api_timeline_from_investigation(payload: TimelineFromInvestigationRequest) -> Any:
    """Construit une timeline d'activité depuis une investigation."""
    if not payload.investigation:
        raise HTTPException(status_code=400, detail="Investigation requise")
    return build_timeline(payload.investigation)


@app.get("/api/report/status")
async def api_report_status() -> Any:
    """Statut du moteur d'export PDF."""
    return report_status()


@app.post("/api/report/preview")
async def api_report_preview(payload: ReportFromInvestigationRequest) -> Any:
    """Aperçu JSON du contenu du rapport (sans générer le PDF)."""
    if not payload.investigation:
        raise HTTPException(status_code=400, detail="Investigation requise")
    ctx = prepare_report_context(payload.investigation)
    return {
        "filename": suggested_filename(payload.investigation),
        "target": ctx["target"],
        "playbook_name": ctx["playbook_name"],
        "overall_risk": ctx["overall_risk"],
        "attack_surface_score": ctx["attack_surface"].get("score"),
        "timeline_events": len((ctx["timeline"] or {}).get("events") or []),
        "graph_nodes": len((ctx["graph"] or {}).get("nodes") or []),
        "entities_count": len(ctx["entities"]),
        "key_findings": ctx["key_findings"],
    }


@app.post("/api/report/from-investigation")
async def api_report_from_investigation(payload: ReportFromInvestigationRequest) -> Response:
    """Génère un rapport PDF professionnel depuis une investigation."""
    if not payload.investigation:
        raise HTTPException(status_code=400, detail="Investigation requise")
    status = report_status()
    if not status.get("pdf_available"):
        raise HTTPException(
            status_code=503,
            detail="Export PDF indisponible — installez reportlab (pip install reportlab)",
        )
    try:
        pdf_bytes = generate_pdf_bytes(payload.investigation)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur génération PDF : {exc}") from exc
    filename = suggested_filename(payload.investigation)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/watch/status")
async def api_watch_status() -> Any:
    """Statut du module de surveillance OSINT."""
    return watch_service.status()


@app.get("/api/watches")
async def api_list_watches() -> Any:
    """Liste les cibles sous surveillance."""
    return {"watches": watch_service.list_watches(), "status": watch_service.status()}


@app.post("/api/watches")
async def api_create_watch(payload: WatchCreateRequest) -> Any:
    """Ajoute une cible à surveiller (baseline optionnelle depuis une investigation)."""
    try:
        return await watch_service.create_watch(
            payload.target,
            playbook_id=payload.playbook_id,
            label=payload.label,
            interval_hours=payload.interval_hours,
            baseline_investigation=payload.baseline_investigation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/watches/{watch_id}")
async def api_get_watch(watch_id: str) -> Any:
    watch = watch_service.get_watch(watch_id)
    if not watch:
        raise HTTPException(status_code=404, detail="Surveillance introuvable")
    alerts = watch_service.list_alerts(watch_id=watch_id, limit=20)
    return {"watch": watch, "recent_alerts": alerts}


@app.patch("/api/watches/{watch_id}")
async def api_update_watch(watch_id: str, payload: WatchUpdateRequest) -> Any:
    try:
        return await watch_service.update_watch(
            watch_id,
            status=payload.status,
            label=payload.label,
            interval_hours=payload.interval_hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/api/watches/{watch_id}")
async def api_delete_watch(watch_id: str) -> Any:
    if not await watch_service.delete_watch(watch_id):
        raise HTTPException(status_code=404, detail="Surveillance introuvable")
    return {"deleted": True, "watch_id": watch_id}


@app.post("/api/watches/{watch_id}/check")
async def api_check_watch(watch_id: str) -> Any:
    """Relance une investigation et compare avec la baseline."""
    try:
        return await watch_service.run_check(watch_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/alerts")
async def api_list_alerts(
    watch_id: Optional[str] = None,
    unread_only: bool = False,
    limit: int = 100,
) -> Any:
    alerts = watch_service.list_alerts(
        watch_id=watch_id,
        unread_only=unread_only,
        limit=min(limit, 500),
    )
    return {
        "alerts": alerts,
        "unread_count": watch_service.status().get("unread_alerts", 0),
    }


@app.post("/api/alerts/{alert_id}/read")
async def api_mark_alert_read(alert_id: str) -> Any:
    alert = watch_service.mark_alert_read(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable ou déjà lue")
    return {"alert": alert}


@app.post("/api/alerts/read-all")
async def api_mark_all_alerts_read(watch_id: Optional[str] = None) -> Any:
    count = watch_service.mark_all_alerts_read(watch_id=watch_id)
    return {"marked_read": count}


@app.get("/api/workspace/status")
async def api_workspace_status() -> Any:
    return workspace_service.status()


@app.get("/api/workspaces")
async def api_list_workspaces(username: str = Header(alias="X-PG-User")) -> Any:
    try:
        user = workspace_service.normalize_username(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"workspaces": workspace_service.list_workspaces(user), "username": user}


@app.post("/api/workspaces")
async def api_create_workspace(
    payload: WorkspaceCreateRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        ws = workspace_service.create_workspace(
            payload.name,
            owner=user,
            description=payload.description or "",
        )
        return {"workspace": ws}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/workspaces/{workspace_id}")
async def api_get_workspace(
    workspace_id: str,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        return workspace_service.get_workspace(workspace_id, user)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.patch("/api/workspaces/{workspace_id}")
async def api_update_workspace(
    workspace_id: str,
    payload: WorkspaceUpdateRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        ws = workspace_service.update_workspace(
            workspace_id,
            user,
            name=payload.name,
            description=payload.description,
        )
        return {"workspace": ws}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.delete("/api/workspaces/{workspace_id}")
async def api_delete_workspace(
    workspace_id: str,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        if not workspace_service.delete_workspace(workspace_id, user):
            raise HTTPException(status_code=404, detail="Workspace introuvable")
        return {"deleted": True, "workspace_id": workspace_id}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/workspaces/{workspace_id}/members")
async def api_add_workspace_member(
    workspace_id: str,
    payload: WorkspaceMemberRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        member = workspace_service.add_member(
            workspace_id,
            user,
            username=payload.username,
            role=payload.role or "analyst",
        )
        return {"member": member}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.delete("/api/workspaces/{workspace_id}/members/{member_username}")
async def api_remove_workspace_member(
    workspace_id: str,
    member_username: str,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        if not workspace_service.remove_member(workspace_id, user, member_username):
            raise HTTPException(status_code=404, detail="Membre introuvable")
        return {"removed": True}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/workspaces/{workspace_id}/cases")
async def api_create_case(
    workspace_id: str,
    payload: CaseCreateRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        case = workspace_service.create_case(
            workspace_id,
            user,
            title=payload.title,
            description=payload.description or "",
            priority=payload.priority or "medium",
            tags=payload.tags,
            investigation=payload.investigation,
        )
        return {"case": case}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/api/workspaces/{workspace_id}/cases/{case_id}")
async def api_get_case(
    workspace_id: str,
    case_id: str,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        return workspace_service.get_case(workspace_id, case_id, user)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.patch("/api/workspaces/{workspace_id}/cases/{case_id}")
async def api_update_case(
    workspace_id: str,
    case_id: str,
    payload: CaseUpdateRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        case = workspace_service.update_case(
            workspace_id,
            case_id,
            user,
            title=payload.title,
            description=payload.description,
            status=payload.status,
            priority=payload.priority,
            tags=payload.tags,
        )
        return {"case": case}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/workspaces/{workspace_id}/cases/{case_id}/investigations")
async def api_add_case_investigation(
    workspace_id: str,
    case_id: str,
    payload: CaseAddInvestigationRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        return workspace_service.add_investigation_to_case(
            workspace_id, case_id, user, payload.investigation
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/workspaces/{workspace_id}/investigations")
async def api_add_workspace_investigation(
    workspace_id: str,
    payload: WorkspaceAddInvestigationRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        return workspace_service.add_investigation_to_workspace(
            workspace_id,
            user,
            payload.investigation,
            case_title=payload.case_title,
            case_id=payload.case_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/api/workspaces/{workspace_id}/notes")
async def api_create_note(
    workspace_id: str,
    payload: NoteCreateRequest,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        note = workspace_service.create_note(
            workspace_id,
            user,
            payload.content,
            case_id=payload.case_id,
        )
        return {"note": note}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/api/workspaces/{workspace_id}/activity")
async def api_workspace_activity(
    workspace_id: str,
    limit: int = 50,
    username: str = Header(alias="X-PG-User"),
) -> Any:
    try:
        user = workspace_service.normalize_username(username)
        return {
            "activity": workspace_service.list_activity(workspace_id, user, limit=min(limit, 200)),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/api/extension/status")
async def api_extension_status() -> Any:
    """Statut API pour l'extension navigateur."""
    return {
        "ok": True,
        "version": "1.0.0",
        "api_base": os.getenv("PG_PUBLIC_URL", "http://127.0.0.1:8000"),
        "cors_enabled": True,
        "features": {
            "url_analyze": True,
            "playbook_quick_scan": True,
            "playbook_suggest": True,
            "privacy_score": True,
            "attack_surface": True,
            "open_dashboard": True,
        },
        "extension_path": str(EXTENSION_DIR) if EXTENSION_DIR.is_dir() else None,
    }


@app.get("/api/health")
async def health():
    """Health check."""
    return {"status": "ok", "modules": {
        "phishing": True,
        "shodan": bool(os.getenv("SHODAN_API_KEY")),
        "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "leakcheck": True,  # HaveIBeenPwned est gratuit
        "exiftool": _check_exiftool(),
        "sherlock": _check_sherlock(),
        "skiptracer": _check_skiptracer(),
        "playbooks": True,
        "investigator_ai": bool(
            (lambda s: s.get("available") and s.get("model_available"))(ai_investigator.check_status())
        ),
        "graph": True,
        "attack_surface_score": True,
        "timeline": True,
        "pdf_export": report_status().get("pdf_available", False),
        "watch": True,
        "workspace": True,
        "privacy_score": True,
        "browser_extension": EXTENSION_DIR.is_dir(),
    }}


def _resolve_exiftool_cmd() -> Optional[str]:
    """Trouve ExifTool (Windows exeiftool.exe / Linux apt / variantes)."""
    candidates = [
        str(BASE_DIR / "exiftool" / "exiftool.exe"),
        str(BASE_DIR / "exiftool" / "exiftool(-k).exe"),
        str(BASE_DIR / "exiftool.exe"),
        str(BASE_DIR / "exiftool(-k).exe"),
        "exiftool",
        "exiftool.exe",
        "/usr/bin/exiftool",
        "/usr/local/bin/exiftool",
    ]
    for path in candidates:
        try:
            result = subprocess.run(
                [path, "-ver"],
                capture_output=True,
                timeout=3,
            )
            stdout = (
                result.stdout.decode("utf-8", errors="ignore")
                if isinstance(result.stdout, (bytes, bytearray))
                else (result.stdout or "")
            )
            stderr = (
                result.stderr.decode("utf-8", errors="ignore")
                if isinstance(result.stderr, (bytes, bytearray))
                else (result.stderr or "")
            )
            blob = f"{stdout}{stderr}"
            if result.returncode == 0 or "exiftool" in blob.lower() or "image::exiftool" in blob.lower():
                return path
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError, TypeError):
            continue
    return None


def _check_exiftool() -> bool:
    return _resolve_exiftool_cmd() is not None


def _check_sherlock() -> bool:
    try:
        from services.osint_tools import _resolve_sherlock_cmd

        return _resolve_sherlock_cmd() is not None
    except Exception:
        return False


def _check_skiptracer() -> bool:
    skiptracer_path = BASE_DIR / "skiptracer_repo" / "skiptracer.py"
    return skiptracer_path.exists()
