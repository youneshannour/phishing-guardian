from __future__ import annotations

import re
from typing import List, Optional

from models.playbook import EntityType
from services.entity_resolver import resolve_entity_type

EMAIL_INLINE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)
URL_INLINE = re.compile(r"https?://[^\s,;\"'<>]+", re.IGNORECASE)
IP_INLINE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_INLINE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

INVESTIGATE_KEYWORDS = re.compile(
    r"\b(investigu(?:e|er|ation)|analys(?:e|er)|recherch(?:e|er)|"
    r"scan(?:ner)?|vérifi(?:e|er)|verifi(?:e|er)|check|osint|trace|"
    r"qui est|trouve|cherche)\b",
    re.IGNORECASE,
)

USERNAME_INLINE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")

PSEUDO_PATTERNS = (
    re.compile(
        r"\b(?:pseudo(?:nyme)?|utilisateur|compte|profil|username|nick(?:name)?|handle)"
        r"\s+[\"']?([A-Za-z0-9._-]{2,32})[\"']?",
        re.IGNORECASE,
    ),
    re.compile(r"@([A-Za-z0-9._]{2,32})\b"),
)

USERNAME_STOPWORDS = frozenset({
    "sur", "les", "des", "une", "un", "le", "la", "du", "de", "et", "ou",
    "pour", "dans", "avec", "sans", "tous", "tout", "son", "ses", "mon",
    "reseaux", "réseaux", "reseau", "réseau", "social", "sociaux",
    "email", "domaine", "adresse", "cible", "investigation", "analyse",
    "the", "and", "for", "from", "this", "that", "check", "scan",
})


def _valid_username(value: str) -> bool:
    candidate = value.strip().lstrip("@")
    if not USERNAME_INLINE.match(candidate):
        return False
    if candidate.lower() in USERNAME_STOPWORDS:
        return False
    if resolve_entity_type(candidate) != EntityType.USERNAME:
        return False
    return True


def _extract_usernames(text: str) -> List[str]:
    found: List[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        candidate = value.strip().lstrip("@")
        key = candidate.lower()
        if key and key not in seen and _valid_username(candidate):
            seen.add(key)
            found.append(candidate)

    for pattern in PSEUDO_PATTERNS:
        for match in pattern.finditer(text):
            add(match.group(1))

    return found


def _valid_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_targets(text: str) -> List[str]:
    """Extrait les cibles OSINT candidates d'un message en langage naturel."""
    if not text or not text.strip():
        return []

    found: List[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        key = value.strip().lower()
        if key and key not in seen:
            seen.add(key)
            found.append(value.strip())

    for match in EMAIL_INLINE.finditer(text):
        add(match.group(0))

    for match in URL_INLINE.finditer(text):
        add(match.group(0).rstrip(".,;:)"))

    for match in IP_INLINE.finditer(text):
        ip = match.group(0)
        if _valid_ip(ip):
            add(ip)

    skip_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
    for match in DOMAIN_INLINE.finditer(text):
        domain = match.group(0).lower()
        if domain in skip_domains:
            continue
        if "@" in text:
            email_domains = {e.split("@", 1)[1].lower() for e in EMAIL_INLINE.findall(text)}
            if domain in email_domains:
                continue
        if resolve_entity_type(domain) == EntityType.DOMAIN:
            add(match.group(0))

    for username in _extract_usernames(text):
        add(username)

    return found


def pick_best_target(text: str) -> Optional[str]:
    """Choisit la cible la plus pertinente dans un message."""
    candidates = extract_targets(text)
    if not candidates:
        return None

    priority = {"email": 0, "url": 1, "ip": 2, "domain": 3, "username": 4, "unknown": 5}
    return min(
        candidates,
        key=lambda c: priority.get(resolve_entity_type(c).value, 99),
    )


def wants_investigation(text: str) -> bool:
    """Détecte si l'utilisateur demande une investigation OSINT."""
    if INVESTIGATE_KEYWORDS.search(text):
        return True
    return bool(extract_targets(text))
