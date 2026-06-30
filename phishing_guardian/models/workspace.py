from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class MemberRole(str, Enum):
    OWNER = "owner"
    ANALYST = "analyst"
    VIEWER = "viewer"


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ARCHIVED = "archived"


ROLE_RANK = {
    MemberRole.VIEWER.value: 1,
    MemberRole.ANALYST.value: 2,
    MemberRole.OWNER.value: 3,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_workspace_id() -> str:
    return f"ws_{uuid4().hex[:12]}"


def new_case_id() -> str:
    return f"case_{uuid4().hex[:12]}"


def new_note_id() -> str:
    return f"note_{uuid4().hex[:12]}"


def new_activity_id() -> str:
    return f"act_{uuid4().hex[:12]}"


@dataclass
class WorkspaceMember:
    username: str
    role: MemberRole
    joined_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role.value,
            "joined_at": self.joined_at,
        }


@dataclass
class Workspace:
    id: str
    name: str
    description: str
    owner: str
    created_at: str
    updated_at: str
    members: List[WorkspaceMember] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner": self.owner,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "members": [m.to_dict() for m in self.members],
            "member_count": len(self.members),
        }
