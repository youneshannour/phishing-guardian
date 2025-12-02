from pathlib import Path
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from phishing_guardian import PhishingGuardian
from osint_scanner import OSINTScanner


BASE_DIR = Path(__file__).parent

app = FastAPI(title="Phishing Guardian Web")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

guardian = PhishingGuardian()
shodan_scanner = OSINTScanner()


class AnalyzeRequest(BaseModel):
    email: Optional[str] = None
    urls: Optional[List[str]] = None


class ShodanIPRequest(BaseModel):
    ip: str


class ShodanSearchRequest(BaseModel):
    query: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
async def api_analyze(payload: AnalyzeRequest) -> Any:
    report = guardian.analyze(
        email_text=payload.email or None,
        urls=payload.urls or None,
    )
    return report.as_dict()


@app.post("/api/shodan/ip")
async def api_shodan_ip(payload: ShodanIPRequest) -> Any:
    """Enrichissement OSINT pour une IP via Shodan."""
    info = shodan_scanner.check_ip_shodan(payload.ip)
    if not info:
        raise HTTPException(status_code=404, detail="Aucune information trouvée pour cette IP.")
    return info


@app.post("/api/shodan/search")
async def api_shodan_search(payload: ShodanSearchRequest) -> Any:
    """Recherche Shodan libre (requête avancée)."""
    results = shodan_scanner.search_shodan(payload.query)
    # Si None -> erreur côté Shodan ou réseau
    if results is None:
        raise HTTPException(
            status_code=502,
            detail="Erreur lors de l'appel à l'API Shodan (clé, quota ou réseau).",
        )
    # Sinon on renvoie la réponse brute, même si total == 0 / matches == []
    return results


