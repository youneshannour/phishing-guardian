from __future__ import annotations

import re
import socket
from typing import Optional
from urllib.parse import urlparse

from models.playbook import EntityType, TargetTransform

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def resolve_entity_type(target: str) -> EntityType:
    value = target.strip()
    if not value:
        return EntityType.UNKNOWN

    if value.startswith(("http://", "https://")):
        return EntityType.URL

    if EMAIL_RE.match(value):
        return EntityType.EMAIL

    if IP_RE.match(value):
        octets = value.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return EntityType.IP

    if DOMAIN_RE.match(value):
        return EntityType.DOMAIN

    if USERNAME_RE.match(value):
        return EntityType.USERNAME

    return EntityType.UNKNOWN


def transform_target(target: str, transform: TargetTransform) -> Optional[str]:
    value = target.strip()
    if not value:
        return None

    if transform == TargetTransform.SAME:
        return value

    if transform == TargetTransform.USERNAME_FROM_EMAIL:
        if "@" not in value:
            return None
        return value.split("@", 1)[0]

    if transform == TargetTransform.DOMAIN_FROM_EMAIL:
        if "@" not in value:
            return None
        return value.split("@", 1)[1]

    if transform == TargetTransform.DOMAIN_FROM_URL:
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            return parsed.netloc or None
        return value if DOMAIN_RE.match(value) else None

    if transform == TargetTransform.IP_FROM_DOMAIN:
        domain = value
        if value.startswith(("http://", "https://")):
            domain = urlparse(value).netloc
        if not domain:
            return None
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    return value


def suggest_playbook_id(entity_type: EntityType) -> str:
    mapping = {
        EntityType.EMAIL: "person_osint",
        EntityType.USERNAME: "social_media_osint",
        EntityType.DOMAIN: "domain_osint",
        EntityType.IP: "ip_osint",
        EntityType.URL: "domain_osint",
        EntityType.COMPANY: "company_osint",
        EntityType.UNKNOWN: "breach_check",
    }
    return mapping.get(entity_type, "breach_check")
