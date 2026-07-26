from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class WatchStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertType(str, Enum):
    RISK_INCREASE = "risk_increase"
    SCORE_INCREASE = "score_increase"
    NEW_BREACH = "new_breach"
    NEW_ENTITY = "new_entity"
    VT_DETECTIONS = "vt_detections"
    REPUTATION_CHANGE = "reputation_change"
    NETWORK_EXPOSURE = "network_exposure"
    NEW_FINDING = "new_finding"
    CHECK_ERROR = "check_error"
    FIRST_BASELINE = "first_baseline"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_watch_id() -> str:
    return f"watch_{uuid4().hex[:12]}"


def new_alert_id() -> str:
    return f"alert_{uuid4().hex[:12]}"


@dataclass
class Watch:
    id: str
    target: str
    target_type: str
    playbook_id: str
    label: str
    status: WatchStatus
    interval_hours: int
    created_at: str
    updated_at: str
    last_check_at: Optional[str] = None
    next_check_at: Optional[str] = None
    baseline_investigation_id: Optional[str] = None
    last_investigation_id: Optional[str] = None
    unread_alerts: int = 0
    total_alerts: int = 0
    last_risk: str = "low"
    last_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "target_type": self.target_type,
            "playbook_id": self.playbook_id,
            "label": self.label,
            "status": self.status.value,
            "interval_hours": self.interval_hours,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_check_at": self.last_check_at,
            "next_check_at": self.next_check_at,
            "baseline_investigation_id": self.baseline_investigation_id,
            "last_investigation_id": self.last_investigation_id,
            "unread_alerts": self.unread_alerts,
            "total_alerts": self.total_alerts,
            "last_risk": self.last_risk,
            "last_score": self.last_score,
        }


@dataclass
class Alert:
    id: str
    watch_id: str
    target: str
    severity: AlertSeverity
    alert_type: AlertType
    title: str
    message: str
    created_at: str
    read: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "watch_id": self.watch_id,
            "target": self.target,
            "severity": self.severity.value,
            "alert_type": self.alert_type.value,
            "title": self.title,
            "message": self.message,
            "created_at": self.created_at,
            "read": self.read,
            "details": self.details,
        }
