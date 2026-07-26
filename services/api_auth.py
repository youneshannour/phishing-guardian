"""Authentification locale légère pour l'API Phishing Guardian."""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from services.session_auth import session_username_from_request

ENV_PATHS = [
    Path(__file__).resolve().parent.parent.parent / ".env",  # repo root
    Path(__file__).resolve().parent.parent / ".env",  # phishing_guardian/
]

for _env in ENV_PATHS:
    load_dotenv(_env, override=False)
load_dotenv(override=False)

PUBLIC_EXACT = {
    "/login",
    "/api/health",
    "/api/auth/bootstrap",
    "/api/auth/login",
    "/api/auth/me",
    "/api/auth/logout",
    "/favicon.ico",
    "/docs",
    "/openapi.json",
    "/redoc",
}
PUBLIC_PREFIXES = ("/static", "/extension")


def _ensure_api_key() -> str:
    key = (os.getenv("PG_API_KEY") or "").strip()
    if key:
        return key

    key = secrets.token_hex(24)
    os.environ["PG_API_KEY"] = key

    for env_path in ENV_PATHS:
        try:
            env_path.parent.mkdir(parents=True, exist_ok=True)
            existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
            if "PG_API_KEY=" in existing:
                lines = []
                for line in existing.splitlines():
                    if line.strip().startswith("PG_API_KEY="):
                        lines.append(f"PG_API_KEY={key}")
                    else:
                        lines.append(line)
                env_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
            else:
                with env_path.open("a", encoding="utf-8") as fh:
                    fh.write(f"\n# Token API local (ne pas partager)\nPG_API_KEY={key}\n")
            break
        except OSError:
            continue
    return key


API_KEY = _ensure_api_key()


def extract_api_key(request: Request) -> Optional[str]:
    header = request.headers.get("X-PG-API-Key")
    if header:
        return header.strip()
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.query_params.get("api_key") or "").strip() or None


def is_public_path(path: str) -> bool:
    if path in PUBLIC_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method == "OPTIONS" or is_public_path(path) or not path.startswith("/api/"):
            return await call_next(request)

        provided = extract_api_key(request)
        if provided and provided == API_KEY:
            return await call_next(request)

        # Session web (cookie HttpOnly) acceptée comme alternative à la clé API
        if session_username_from_request(request):
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={
                "detail": "Authentification requise. Connectez-vous ou fournissez X-PG-API-Key.",
            },
        )


def default_cors_origins() -> list:
    raw = os.getenv("CORS_ORIGINS", "").strip()
    if raw and raw != "*":
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "null",  # extension chrome:// / file origin sometimes
    ]
