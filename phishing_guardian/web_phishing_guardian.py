import os
import subprocess
import json
import io
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, List, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Header
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import requests
from dotenv import load_dotenv

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

load_dotenv()

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    watch_service.start_scheduler()
    yield
    await watch_service.stop_scheduler()


app = FastAPI(title="Phishing Guardian - OSINT Platform", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*", "X-PG-User"],
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


def _pg_user(x_pg_user: Optional[str] = Header(None, alias="X-PG-User")) -> str:
    if not x_pg_user or not x_pg_user.strip():
        raise HTTPException(
            status_code=401,
            detail="En-tête X-PG-User requis — définissez votre nom dans l'onglet Workspace",
        )
    try:
        return workspace_service.normalize_username(x_pg_user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ========== ROUTES ==========
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze-image")
async def api_analyze_image(file: UploadFile = File(...)) -> Any:
    """Analyse d'image avec OCR pour extraire le texte d'un email."""
    if not OCR_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="OCR non disponible. Installez les dépendances: pip install pytesseract Pillow"
        )
    
    try:
        # Lire l'image
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))
        
        # Vérifier si Tesseract est installé
        try:
            pytesseract.get_tesseract_version()
        except Exception:
            # Essayer de configurer le chemin Tesseract automatiquement
            tesseract_paths = [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                r"C:\Tesseract-OCR\tesseract.exe",
                "tesseract",
                "tesseract.exe"
            ]
            
            tesseract_found = False
            for path in tesseract_paths:
                try:
                    if os.path.exists(path) or path in ["tesseract", "tesseract.exe"]:
                        pytesseract.pytesseract.tesseract_cmd = path
                        pytesseract.get_tesseract_version()
                        tesseract_found = True
                        break
                except:
                    continue
            
            if not tesseract_found:
                raise HTTPException(
                    status_code=503,
                    detail="Tesseract OCR non trouvé. Téléchargez-le depuis https://github.com/UB-Mannheim/tesseract/wiki et installez-le. Puis configurez le chemin dans pytesseract.pytesseract.tesseract_cmd"
                )
        
        # Améliorer la qualité de l'image pour un meilleur OCR
        # 1. Convertir en RGB si nécessaire
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # 2. Redimensionner si l'image est trop petite (minimum 300px de largeur)
        width, height = image.size
        if width < 300:
            scale_factor = 300 / width
            new_width = int(width * scale_factor)
            new_height = int(height * scale_factor)
            image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # 3. Convertir en niveaux de gris pour améliorer la précision
        gray_image = image.convert('L')
        
        # 4. Améliorer le contraste
        enhancer = ImageEnhance.Contrast(gray_image)
        gray_image = enhancer.enhance(2.0)  # Augmenter le contraste de 2x
        
        # 5. Améliorer la netteté
        enhancer_sharp = ImageEnhance.Sharpness(gray_image)
        gray_image = enhancer_sharp.enhance(2.0)  # Augmenter la netteté de 2x
        
        # 6. Améliorer la luminosité si nécessaire
        enhancer_bright = ImageEnhance.Brightness(gray_image)
        gray_image = enhancer_bright.enhance(1.1)  # Légèrement plus lumineux
        
        # 7. Appliquer un filtre pour réduire le bruit
        gray_image = gray_image.filter(ImageFilter.MedianFilter(size=3))
        
        # Configuration OCR optimisée pour les captures d'écran
        # PSM 6 = Bloc uniforme de texte
        # PSM 11 = Texte clairsemé (meilleur pour les emails)
        # PSM 12 = Image avec texte aligné OSD
        custom_config = r'--oem 3 --psm 6 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@.,!?;:()[]{}/\-_=+*&%$#<>|"\' '
        
        # Extraire le texte avec OCR (essayer plusieurs langues et configurations)
        extracted_text = ""
        ocr_errors = []
        
        # Essai 1: Français + Anglais avec configuration optimisée
        try:
            extracted_text = pytesseract.image_to_string(gray_image, lang='fra+eng', config=custom_config)
            if extracted_text.strip():
                pass  # Succès
        except Exception as e:
            ocr_errors.append(f"fra+eng: {str(e)}")
        
        # Essai 2: Seulement anglais si échec
        if not extracted_text.strip():
            try:
                extracted_text = pytesseract.image_to_string(gray_image, lang='eng', config=custom_config)
            except Exception as e:
                ocr_errors.append(f"eng: {str(e)}")
        
        # Essai 3: Sans langue spécifiée (fallback)
        if not extracted_text.strip():
            try:
                extracted_text = pytesseract.image_to_string(gray_image, config=custom_config)
            except Exception as e:
                ocr_errors.append(f"default: {str(e)}")
        
        # Essai 4: Mode PSM 11 (texte clairsemé) si toujours rien
        if not extracted_text.strip():
            try:
                custom_config_psm11 = r'--oem 3 --psm 11'
                extracted_text = pytesseract.image_to_string(gray_image, lang='fra+eng', config=custom_config_psm11)
            except Exception as e:
                ocr_errors.append(f"PSM11: {str(e)}")
        
        # Nettoyer et corriger le texte extrait
        cleaned_text = extracted_text.strip()
        
        # Post-traitement : corriger les erreurs OCR communes
        if cleaned_text:
            # Remplacer les caractères mal reconnus
            corrections = {
                '|': 'I',  # Pipe mal reconnu comme I
                '0': 'O',  # 0 mal reconnu comme O (dans certains contextes)
                '1': 'I',  # 1 mal reconnu comme I (dans certains contextes)
                '5': 'S',  # 5 mal reconnu comme S (dans certains contextes)
            }
            
            # Nettoyer les espaces multiples
            cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
            
            # Nettoyer les sauts de ligne multiples
            cleaned_text = re.sub(r'\n{3,}', '\n\n', cleaned_text)
            
            # Supprimer les caractères de contrôle invisibles
            cleaned_text = ''.join(char for char in cleaned_text if ord(char) >= 32 or char in '\n\t')
            
            # Corriger les emails mal reconnus (ex: @ mal reconnu)
            cleaned_text = re.sub(r'\s*@\s*', '@', cleaned_text)
            cleaned_text = re.sub(r'(\w+)\s+@\s+(\w+)', r'\1@\2', cleaned_text)
            
            # Corriger les URLs mal reconnues
            cleaned_text = re.sub(r'https?\s*:\s*/\s*/', lambda m: m.group(0).replace(' ', ''), cleaned_text)
            
            # Nettoyer les espaces autour de la ponctuation
            cleaned_text = re.sub(r'\s+([.,!?;:])', r'\1', cleaned_text)
            cleaned_text = re.sub(r'([.,!?;:])\s+', r'\1 ', cleaned_text)
        
        # Statistiques sur le texte extrait
        word_count = len(cleaned_text.split()) if cleaned_text else 0
        line_count = len(cleaned_text.split('\n')) if cleaned_text else 0
        has_email = bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', cleaned_text)) if cleaned_text else False
        has_url = bool(re.search(r'https?://[^\s]+', cleaned_text)) if cleaned_text else False
        
        if not cleaned_text:
            return {
                "success": False,
                "extracted_text": "",
                "filename": file.filename,
                "message": "Aucun texte détecté dans l'image. Vérifiez que l'image contient du texte lisible.",
                "warning": "L'OCR n'a pas pu extraire de texte. L'image peut être de mauvaise qualité ou ne contenir aucun texte.",
                "ocr_errors": ocr_errors if ocr_errors else [],
                "image_info": {
                    "original_size": f"{width}x{height}",
                    "processed_size": f"{gray_image.size[0]}x{gray_image.size[1]}" if 'gray_image' in locals() else "N/A"
                }
            }
        
        return {
            "success": True,
            "extracted_text": cleaned_text,
            "filename": file.filename,
            "message": f"Texte extrait avec succès ({len(cleaned_text)} caractères, {word_count} mots, {line_count} lignes)",
            "statistics": {
                "characters": len(cleaned_text),
                "words": word_count,
                "lines": line_count,
                "has_email": has_email,
                "has_url": has_url
            },
            "image_info": {
                "original_size": f"{width}x{height}",
                "processed_size": f"{gray_image.size[0]}x{gray_image.size[1]}"
            },
            "ocr_errors": ocr_errors if ocr_errors else []
        }
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        if "tesseract" in error_msg.lower() or "not found" in error_msg.lower():
            raise HTTPException(
                status_code=503,
                detail=f"Tesseract OCR non trouvé. Installez Tesseract depuis https://github.com/UB-Mannheim/tesseract/wiki. Erreur: {error_msg}"
            )
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de l'extraction OCR: {error_msg}"
        )


@app.post("/api/analyze")
async def api_analyze(payload: AnalyzeRequest) -> Any:
    """Analyse phishing avancée email/URLs avec enrichissement."""
    report = guardian.analyze(
        email_text=payload.email or None,
        urls=payload.urls or None,
    )
    
    result = report.as_dict()
    
    # Enrichir avec des statistiques avancées
    result["statistics"] = {
        "total_urls_analyzed": len(result.get("urls", [])),
        "phishing_urls": len([u for u in result.get("urls", []) if u.get("label") == "phishing"]),
        "legitimate_urls": len([u for u in result.get("urls", []) if u.get("label") == "legitimate"]),
        "email_analyzed": bool(result.get("email")),
        "email_is_phishing": result.get("email", {}).get("label") == "phishing" if result.get("email") else False,
        "max_score": result.get("synthetique", {}).get("score", 0),
    }
    
    return result


@app.post("/api/shodan/ip")
async def api_shodan_ip(payload: ShodanIPRequest) -> Any:
    """Enrichissement IP avancé via Shodan avec analyse détaillée."""
    info = shodan_scanner.check_ip_shodan(payload.ip)
    if not info:
        raise HTTPException(status_code=404, detail="Aucune information trouvée pour cette IP.")
    
    # Enrichir avec plus de détails
    enriched = {
        **info,
        "analysis": {
            "total_ports": len(info.get("ports", [])),
            "total_hostnames": len(info.get("hostnames", [])),
            "total_vulns": len(info.get("vulns", [])),
            "risk_level": "high" if len(info.get("vulns", [])) > 0 else ("medium" if len(info.get("ports", [])) > 10 else "low"),
        },
        "services": [],
        "geolocation": {},
    }
    
    # Extraire les services détaillés
    for service_data in info.get("data", []):
        service = {
            "port": service_data.get("port"),
            "product": service_data.get("product"),
            "version": service_data.get("version"),
            "banner": service_data.get("data", "")[:200] if service_data.get("data") else None,
            "http": service_data.get("http") if "http" in service_data else None,
        }
        enriched["services"].append(service)
    
    # Géolocalisation si disponible
    if info.get("data"):
        for data_item in info.get("data", []):
            if "location" in data_item:
                enriched["geolocation"] = {
                    "country": data_item["location"].get("country_name"),
                    "city": data_item["location"].get("city"),
                    "latitude": data_item["location"].get("latitude"),
                    "longitude": data_item["location"].get("longitude"),
                }
                break
    
    return enriched


@app.post("/api/shodan/search")
async def api_shodan_search(payload: ShodanSearchRequest) -> Any:
    """Recherche Shodan avancée."""
    results = shodan_scanner.search_shodan(payload.query)
    if results is None:
        raise HTTPException(
            status_code=502,
            detail="Erreur lors de l'appel à l'API Shodan (clé, quota ou réseau).",
        )
    return results


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
    # Sauvegarder temporairement
    temp_dir = BASE_DIR / "temp"
    temp_dir.mkdir(exist_ok=True)
    temp_path = temp_dir / file.filename
    
    try:
        with open(temp_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Appel ExifTool - chercher dans plusieurs emplacements
        exiftool_paths = [
            str(BASE_DIR / "exiftool" / "exiftool.exe"),  # Dossier local (priorité)
            str(BASE_DIR / "exiftool.exe"),  # Racine du projet
            "exiftool",  # Dans le PATH
            "exiftool.exe",  # Windows PATH
            "C:\\Windows\\exiftool.exe",  # Windows system
        ]
        
        exiftool_cmd = None
        for path in exiftool_paths:
            try:
                result = subprocess.run(
                    [path, "-ver"],
                    capture_output=True,
                    timeout=2,
                )
                if result.returncode == 0 or "ExifTool" in (result.stdout or result.stderr or ""):
                    exiftool_cmd = path
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        if not exiftool_cmd:
            raise HTTPException(
                status_code=503,
                detail="ExifTool non installé. Téléchargez-le depuis https://exiftool.org/ et placez exiftool.exe dans le PATH ou dans le dossier du projet.",
            )
        
        try:
            result = subprocess.run(
                [exiftool_cmd, "-j", "-a", str(temp_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise HTTPException(status_code=500, detail=f"ExifTool error: {result.stderr}")
            
            metadata = json.loads(result.stdout)[0] if result.stdout else {}
            
            # Analyse avancée des métadonnées
            analysis = {
                "has_gps": any("GPS" in k for k in metadata.keys()),
                "has_camera_info": any(k in metadata for k in ["Make", "Model", "Camera"]),
                "has_software": "Software" in metadata or "ProcessingSoftware" in metadata,
                "has_author": any(k in metadata for k in ["Artist", "Author", "Creator"]),
                "file_size": metadata.get("FileSize"),
                "mime_type": metadata.get("MIMEType"),
            }
            
            # Extraire GPS si présent
            gps_data = {}
            if analysis["has_gps"]:
                lat = metadata.get("GPSLatitude")
                lon = metadata.get("GPSLongitude")
                if lat and lon:
                    gps_data = {
                        "latitude": str(lat),
                        "longitude": str(lon),
                        "google_maps": f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else None,
                    }
            
            # Extraire informations caméra
            camera_info = {}
            if analysis["has_camera_info"]:
                camera_info = {
                    "make": metadata.get("Make"),
                    "model": metadata.get("Model"),
                    "lens": metadata.get("LensModel"),
                    "focal_length": metadata.get("FocalLength"),
                    "aperture": metadata.get("FNumber"),
                    "iso": metadata.get("ISO"),
                    "exposure": metadata.get("ExposureTime"),
                }
            
            return {
                "filename": file.filename,
                "metadata": metadata,
                "summary": {
                    k: v for k, v in metadata.items() 
                    if k not in ["SourceFile", "ExifToolVersion"] and v
                },
                "analysis": analysis,
                "gps": gps_data,
                "camera": camera_info,
                "security_flags": {
                    "has_location": analysis["has_gps"],
                    "has_author_info": analysis["has_author"],
                    "risk_level": "high" if analysis["has_gps"] else ("medium" if analysis["has_author"] else "low"),
                },
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erreur ExifTool: {str(e)}")
    finally:
        if temp_path.exists():
            temp_path.unlink()


@app.post("/api/sherlock")
async def api_sherlock(payload: SherlockRequest) -> Any:
    """Recherche profils via Sherlock."""
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Nom d'utilisateur vide")
    
    # Essayer d'abord avec la commande directe, puis avec python -m
    sherlock_cmd = None
    for cmd in [["sherlock"], ["python", "-m", "sherlock"]]:
        try:
            result = subprocess.run(
                cmd + ["--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 or "sherlock" in result.stdout.lower() or "sherlock" in result.stderr.lower():
                sherlock_cmd = cmd
                break
        except FileNotFoundError:
            continue
    
    if not sherlock_cmd:
        raise HTTPException(
            status_code=503,
            detail="Sherlock non installé. Installez-le: pip install sherlock-project",
        )
    
    try:
        # Lancer sherlock avec JSON output
        result = subprocess.run(
            sherlock_cmd + ["--no-color", "--json", username],
            capture_output=True,
            text=True,
            timeout=120,  # Sherlock peut prendre du temps
        )
        
        # Parser JSON (même si returncode != 0, il peut y avoir des résultats)
        profiles = {}
        output_lines = result.stdout.split("\n") if result.stdout else []
        
        # Chercher la ligne JSON dans la sortie
        for line in output_lines:
            line = line.strip()
            if line and (line.startswith("{") or line.startswith("[")):
                try:
                    profiles = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        
        # Si pas de JSON, essayer de parser manuellement les résultats
        if not profiles and result.stdout:
            # Format alternatif: chercher les URLs dans la sortie
            for line in output_lines:
                if "http" in line.lower() or "https" in line.lower():
                    # Essayer d'extraire des infos
                    pass
        
        return {
            "username": username,
            "profiles": profiles if isinstance(profiles, dict) else {},
            "count": len(profiles) if isinstance(profiles, dict) else 0,
            "raw_output": result.stdout[:500] if result.stdout else "",  # Limiter la taille
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Sherlock timeout (>120s)")
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
    """Scan avancé via VirusTotal API avec analyse détaillée."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Clé API VirusTotal non configurée. Ajoutez VIRUSTOTAL_API_KEY dans .env",
        )
    
    query = payload.query.strip()
    
    try:
        # Détecter le type (URL, IP, domain, hash)
        if query.startswith("http"):
            # URL scan
            url = "https://www.virustotal.com/vtapi/v2/url/scan"
            params = {"apikey": api_key, "url": query}
            response = requests.post(url, data=params, timeout=10)
            response.raise_for_status()
            scan_data = response.json()
            
            # Attendre un peu puis récupérer le rapport
            import time
            time.sleep(2)
            report_url = "https://www.virustotal.com/vtapi/v2/url/report"
            report_params = {"apikey": api_key, "resource": query}
            report_response = requests.get(report_url, params=report_params, timeout=10)
            report_response.raise_for_status()
            data = report_response.json()
            
        elif len(query) == 32 or len(query) == 64:
            # Hash (MD5 ou SHA256)
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {"apikey": api_key, "resource": query}
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
        elif "." in query and not query.replace(".", "").replace(":", "").isdigit():
            # Domain
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": api_key, "domain": query}
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
        else:
            # IP
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {"apikey": api_key, "ip": query}
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
        
        # Analyse avancée
        detections = data.get("positives", 0) if isinstance(data, dict) else 0
        total = data.get("total", 0) if isinstance(data, dict) else 0
        ratio = (detections / total * 100) if total > 0 else 0
        
        # Extraire les scanners qui ont détecté
        scans = {}
        if isinstance(data, dict) and "scans" in data:
            scans = {k: v for k, v in data["scans"].items() if v.get("detected", False)}
        
        return {
            "query": query,
            "type": "url" if query.startswith("http") else ("hash" if len(query) in [32, 64] else ("domain" if "." in query else "ip")),
            "data": data,
            "detections": detections,
            "total": total,
            "ratio": round(ratio, 2),
            "risk_level": "critical" if ratio > 50 else ("high" if ratio > 25 else ("medium" if ratio > 10 else "low")),
            "detecting_engines": list(scans.keys())[:10],  # Top 10
            "scan_date": data.get("scan_date") if isinstance(data, dict) else None,
            "permalink": data.get("permalink") if isinstance(data, dict) else None,
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Erreur VirusTotal: {str(e)}")


@app.post("/api/abuseipdb")
async def api_abuseipdb(payload: AbuseIPDBRequest) -> Any:
    """Check IP reputation avancé via AbuseIPDB avec historique."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Clé API AbuseIPDB non configurée. Ajoutez ABUSEIPDB_API_KEY dans .env",
        )
    
    try:
        # Check de base
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": payload.ip, "maxAgeInDays": 90, "verbose": ""}
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        check_data = data.get("data", {})
        abuse_confidence = check_data.get("abuseConfidencePercentage", 0)
        
        # Récupérer l'historique des rapports
        reports = []
        try:
            reports_url = "https://api.abuseipdb.com/api/v2/check-block"
            reports_params = {"network": f"{payload.ip}/32", "maxAgeInDays": 90}
            reports_response = requests.get(reports_url, headers=headers, params=reports_params, timeout=10)
            if reports_response.status_code == 200:
                reports_data = reports_response.json()
                reports = reports_data.get("data", {}).get("reportedAddress", [])[:10]  # Top 10
        except Exception:
            pass  # Historique optionnel
        
        return {
            "ip": payload.ip,
            "data": check_data,
            "isPublic": check_data.get("isPublic", False),
            "abuseConfidence": abuse_confidence,
            "usageType": check_data.get("usageType", "N/A"),
            "country": check_data.get("countryCode", "N/A"),
            "domain": check_data.get("domain", "N/A"),
            "hostnames": check_data.get("hostnames", []),
            "totalReports": check_data.get("totalReports", 0),
            "numDistinctUsers": check_data.get("numDistinctUsers", 0),
            "lastReportedAt": check_data.get("lastReportedAt"),
            "risk_level": "critical" if abuse_confidence > 75 else ("high" if abuse_confidence > 50 else ("medium" if abuse_confidence > 25 else "low")),
            "recent_reports": reports,
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Erreur AbuseIPDB: {str(e)}")


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
            "recommendations": list(set(recommendations)) if recommendations else ["✅ Aucune vulnérabilité critique détectée"],
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
    return ai_investigator.check_status()


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
        "investigator_ai": ai_investigator.check_status().get("available", False),
        "graph": True,
        "attack_surface_score": True,
        "timeline": True,
        "pdf_export": report_status().get("pdf_available", False),
        "watch": True,
        "workspace": True,
        "privacy_score": True,
        "browser_extension": EXTENSION_DIR.is_dir(),
    }}


def _check_exiftool() -> bool:
    exiftool_paths = [
        "exiftool",
        "exiftool.exe",
        str(BASE_DIR / "exiftool" / "exiftool.exe"),
        str(BASE_DIR / "exiftool.exe"),
    ]
    for path in exiftool_paths:
        try:
            result = subprocess.run([path, "-ver"], capture_output=True, timeout=2)
            if result.returncode == 0 or "ExifTool" in (result.stdout or result.stderr or ""):
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _check_sherlock() -> bool:
    for cmd in [["sherlock"], ["python", "-m", "sherlock"]]:
        try:
            result = subprocess.run(cmd + ["--version"], capture_output=True, timeout=2)
            if result.returncode == 0 or "sherlock" in (result.stdout or "").lower() or "sherlock" in (result.stderr or "").lower():
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _check_skiptracer() -> bool:
    skiptracer_path = BASE_DIR / "skiptracer_repo" / "skiptracer.py"
    return skiptracer_path.exists()
