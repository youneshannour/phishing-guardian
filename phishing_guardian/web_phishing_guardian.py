import os
import subprocess
import json
import io
import re
from pathlib import Path
from typing import Any, List, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
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

load_dotenv()

BASE_DIR = Path(__file__).parent

app = FastAPI(title="Phishing Guardian - OSINT Platform")

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
