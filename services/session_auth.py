"""Authentification session (login web) pour Phishing Guardian."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv

ENV_PATHS = [
    Path(__file__).resolve().parent.parent.parent / ".env",
    Path(__file__).resolve().parent.parent / ".env",
]

for _env in ENV_PATHS:
    load_dotenv(_env, override=False)
load_dotenv(override=False)

COOKIE_NAME = "pg_session"
SESSION_TTL_SEC = 7 * 24 * 3600  # 7 jours


def _persist_env(key: str, value: str) -> None:
    for env_path in ENV_PATHS:
        try:
            env_path.parent.mkdir(parents=True, exist_ok=True)
            existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
            if f"{key}=" in existing:
                lines = []
                for line in existing.splitlines():
                    if line.strip().startswith(f"{key}="):
                        lines.append(f"{key}={value}")
                    else:
                        lines.append(line)
                env_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
            else:
                with env_path.open("a", encoding="utf-8") as fh:
                    fh.write(f"\n{key}={value}\n")
            break
        except OSError:
            continue


def _ensure_secret() -> str:
    secret = (os.getenv("PG_SESSION_SECRET") or "").strip()
    if secret:
        return secret
    secret = secrets.token_hex(32)
    os.environ["PG_SESSION_SECRET"] = secret
    _persist_env("PG_SESSION_SECRET", secret)
    return secret


def _ensure_credentials() -> Tuple[str, str]:
    username = (os.getenv("PG_USERNAME") or "").strip() or "admin"
    password = (os.getenv("PG_PASSWORD") or "").strip()
    if not password:
        password = "guardian"
        os.environ["PG_PASSWORD"] = password
        if not (os.getenv("PG_USERNAME") or "").strip():
            os.environ["PG_USERNAME"] = username
            _persist_env("PG_USERNAME", username)
        _persist_env("PG_PASSWORD", password)
    else:
        os.environ.setdefault("PG_USERNAME", username)
    return username, password


SESSION_SECRET = _ensure_secret()
DEFAULT_USERNAME, DEFAULT_PASSWORD = _ensure_credentials()


def get_login_credentials() -> Tuple[str, str]:
    user = (os.getenv("PG_USERNAME") or DEFAULT_USERNAME).strip() or "admin"
    pwd = (os.getenv("PG_PASSWORD") or DEFAULT_PASSWORD).strip() or "guardian"
    return user, pwd


def verify_credentials(username: str, password: str) -> bool:
    expected_user, expected_pwd = get_login_credentials()
    user_ok = hmac.compare_digest(
        (username or "").strip().encode("utf-8"),
        expected_user.encode("utf-8"),
    )
    pwd_ok = hmac.compare_digest(
        (password or "").encode("utf-8"),
        expected_pwd.encode("utf-8"),
    )
    return user_ok and pwd_ok


def _b64encode(raw: bytes) -> str:
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(raw: str) -> bytes:
    pad = "=" * (-len(raw) % 4)
    return urlsafe_b64decode(raw + pad)


def create_session_token(username: str, ttl: int = SESSION_TTL_SEC) -> str:
    payload = {
        "u": username.strip(),
        "exp": int(time.time()) + int(ttl),
        "iat": int(time.time()),
        "jti": secrets.token_hex(8),
    }
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        body.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{body}.{sig}"


def parse_session_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expected = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        body.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64decode(body).decode("utf-8"))
    except Exception:
        return None
    if int(payload.get("exp") or 0) < int(time.time()):
        return None
    username = (payload.get("u") or "").strip()
    if not username:
        return None
    return payload


def session_username_from_request(request) -> Optional[str]:
    token = request.cookies.get(COOKIE_NAME)
    payload = parse_session_token(token or "")
    if not payload:
        return None
    return str(payload.get("u") or "").strip() or None


def cookie_settings() -> Dict[str, Any]:
    return {
        "key": COOKIE_NAME,
        "httponly": True,
        "samesite": "lax",
        "path": "/",
        "max_age": SESSION_TTL_SEC,
    }
