from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class EntityType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    COMPANY = "company"
    UNKNOWN = "unknown"


class PluginStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


class TargetTransform(str, Enum):
    SAME = "same"
    USERNAME_FROM_EMAIL = "username_from_email"
    DOMAIN_FROM_EMAIL = "domain_from_email"
    DOMAIN_FROM_URL = "domain_from_url"
    IP_FROM_DOMAIN = "ip_from_domain"


@dataclass
class Entity:
    type: EntityType
    value: str
    source: str
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class PluginResult:
    plugin_id: str
    plugin_name: str
    status: PluginStatus
    duration_ms: int
    data: Dict[str, Any] = field(default_factory=dict)
    entities: List[Entity] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "data": self.data,
            "entities": [e.to_dict() for e in self.entities],
            "error": self.error,
        }


@dataclass
class PlaybookStep:
    plugin_id: str
    transform: TargetTransform = TargetTransform.SAME


@dataclass
class PlaybookDefinition:
    id: str
    name: str
    description: str
    icon: str
    target_types: List[EntityType]
    steps: List[PlaybookStep]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "icon": self.icon,
            "target_types": [t.value for t in self.target_types],
            "steps": [
                {"plugin_id": s.plugin_id, "transform": s.transform.value}
                for s in self.steps
            ],
        }


@dataclass
class InvestigationResult:
    id: str
    playbook_id: str
    playbook_name: str
    target: str
    target_type: EntityType
    started_at: datetime
    completed_at: datetime
    duration_ms: int
    steps: List[PluginResult]
    entities: List[Entity]
    synthesis: Dict[str, Any]

    @staticmethod
    def new_id() -> str:
        return str(uuid4())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "target": self.target,
            "target_type": self.target_type.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": self.duration_ms,
            "steps": [s.to_dict() for s in self.steps],
            "entities": [e.to_dict() for e in self.entities],
            "synthesis": self.synthesis,
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
