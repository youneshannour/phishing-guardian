from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.workspace import (
    CaseStatus,
    MemberRole,
    ROLE_RANK,
    new_activity_id,
    new_case_id,
    new_note_id,
    new_workspace_id,
    utc_now,
)

DEFAULT_STORE = Path(__file__).resolve().parent.parent / "data" / "workspace_store.json"
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,32}$")


class WorkspaceService:
    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._store_path = Path(store_path or os.getenv("WORKSPACE_STORE_PATH", str(DEFAULT_STORE)))

    def store_path(self) -> Path:
        return self._store_path

    def _load(self) -> Dict[str, Any]:
        if not self._store_path.exists():
            return {
                "workspaces": [],
                "cases": [],
                "notes": [],
                "activity": [],
                "investigations": {},
            }
        try:
            with open(self._store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {
                "workspaces": [],
                "cases": [],
                "notes": [],
                "activity": [],
                "investigations": {},
            }
        for key in ("workspaces", "cases", "notes", "activity", "investigations"):
            data.setdefault(key, [] if key != "investigations" else {})
        if isinstance(data["investigations"], list):
            data["investigations"] = {}
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._store_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._store_path)

    def _iso(self, dt: Optional[datetime] = None) -> str:
        return (dt or utc_now()).isoformat()

    @staticmethod
    def normalize_username(username: str) -> str:
        name = (username or "").strip().lower()
        if not USERNAME_RE.match(name):
            raise ValueError("Nom d'utilisateur invalide (2–32 car., alphanum ._-)")
        return name

    def status(self) -> Dict[str, Any]:
        data = self._load()
        return {
            "store_path": str(self._store_path),
            "workspace_count": len(data["workspaces"]),
            "case_count": len(data["cases"]),
            "note_count": len(data["notes"]),
            "activity_count": len(data["activity"]),
            "investigation_count": len(data.get("investigations", {})),
        }

    def _get_workspace_raw(self, data: Dict[str, Any], workspace_id: str) -> Optional[Dict[str, Any]]:
        return next((w for w in data["workspaces"] if w["id"] == workspace_id), None)

    def _member_role(self, workspace: Dict[str, Any], username: str) -> Optional[str]:
        for m in workspace.get("members") or []:
            if m.get("username") == username:
                return m.get("role")
        return None

    def _require_member(self, workspace: Dict[str, Any], username: str) -> str:
        role = self._member_role(workspace, username)
        if not role:
            raise PermissionError("Accès refusé — vous n'êtes pas membre de ce workspace")
        return role

    def _require_role(self, workspace: Dict[str, Any], username: str, min_role: str) -> str:
        role = self._require_member(workspace, username)
        if ROLE_RANK.get(role, 0) < ROLE_RANK.get(min_role, 0):
            raise PermissionError(f"Rôle insuffisant — {min_role} requis")
        return role

    def _log_activity(
        self,
        data: Dict[str, Any],
        *,
        workspace_id: str,
        actor: str,
        action: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        entry = {
            "id": new_activity_id(),
            "workspace_id": workspace_id,
            "actor": actor,
            "action": action,
            "message": message,
            "metadata": metadata or {},
            "created_at": self._iso(),
        }
        data["activity"].append(entry)
        if len(data["activity"]) > 500:
            data["activity"] = data["activity"][-500:]
        return entry

    def _store_investigation(self, data: Dict[str, Any], investigation: Dict[str, Any]) -> str:
        inv_id = investigation.get("id") or new_case_id().replace("case_", "inv_")
        investigation = {**investigation, "id": inv_id}
        investigations = data.setdefault("investigations", {})
        investigations[inv_id] = investigation
        if len(investigations) > 300:
            oldest = sorted(investigations.keys())[: len(investigations) - 300]
            for key in oldest:
                investigations.pop(key, None)
        return inv_id

    def _investigation_summary(self, investigation: Dict[str, Any]) -> Dict[str, Any]:
        synth = investigation.get("synthesis") or {}
        as_data = synth.get("attack_surface") or {}
        return {
            "id": investigation.get("id"),
            "target": investigation.get("target"),
            "target_type": investigation.get("target_type"),
            "playbook_name": investigation.get("playbook_name"),
            "completed_at": investigation.get("completed_at"),
            "overall_risk": synth.get("overall_risk", "low"),
            "attack_surface_score": as_data.get("score"),
            "entities_found": synth.get("entities_found", 0),
            "key_findings": (synth.get("key_findings") or [])[:3],
        }

    def list_workspaces(self, username: Optional[str] = None) -> List[Dict[str, Any]]:
        data = self._load()
        workspaces = data["workspaces"]
        if username:
            workspaces = [
                w for w in workspaces
                if self._member_role(w, username) is not None
            ]
        result = []
        for w in sorted(workspaces, key=lambda x: x.get("updated_at", ""), reverse=True):
            cases = [c for c in data["cases"] if c.get("workspace_id") == w["id"]]
            open_cases = sum(1 for c in cases if c.get("status") not in ("closed", "archived"))
            item = dict(w)
            item["case_count"] = len(cases)
            item["open_cases"] = open_cases
            result.append(item)
        return result

    def get_workspace(self, workspace_id: str, username: Optional[str] = None) -> Dict[str, Any]:
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        if username:
            self._require_member(ws, username)
        cases = [c for c in data["cases"] if c.get("workspace_id") == workspace_id]
        notes = [n for n in data["notes"] if n.get("workspace_id") == workspace_id]
        activity = [
            a for a in data["activity"]
            if a.get("workspace_id") == workspace_id
        ][-30:]
        return {
            "workspace": ws,
            "cases": sorted(cases, key=lambda c: c.get("updated_at", ""), reverse=True),
            "notes": sorted(notes, key=lambda n: n.get("created_at", ""), reverse=True)[:20],
            "recent_activity": list(reversed(activity)),
        }

    def create_workspace(
        self,
        name: str,
        *,
        owner: str,
        description: str = "",
    ) -> Dict[str, Any]:
        owner = self.normalize_username(owner)
        name = name.strip()
        if not name:
            raise ValueError("Nom du workspace requis")

        now = self._iso()
        ws = {
            "id": new_workspace_id(),
            "name": name,
            "description": description.strip(),
            "owner": owner,
            "created_at": now,
            "updated_at": now,
            "members": [{"username": owner, "role": MemberRole.OWNER.value, "joined_at": now}],
        }

        data = self._load()
        data["workspaces"].append(ws)
        self._log_activity(
            data,
            workspace_id=ws["id"],
            actor=owner,
            action="workspace_created",
            message=f"Workspace « {name} » créé",
        )
        self._save(data)
        return ws

    def update_workspace(
        self,
        workspace_id: str,
        username: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        username = self.normalize_username(username)
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        self._require_role(ws, username, MemberRole.ANALYST.value)

        if name is not None:
            ws["name"] = name.strip() or ws["name"]
        if description is not None:
            ws["description"] = description.strip()
        ws["updated_at"] = self._iso()
        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=username,
            action="workspace_updated",
            message=f"Workspace mis à jour",
        )
        self._save(data)
        return ws

    def delete_workspace(self, workspace_id: str, username: str) -> bool:
        username = self.normalize_username(username)
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            return False
        self._require_role(ws, username, MemberRole.OWNER.value)

        data["workspaces"] = [w for w in data["workspaces"] if w["id"] != workspace_id]
        data["cases"] = [c for c in data["cases"] if c.get("workspace_id") != workspace_id]
        data["notes"] = [n for n in data["notes"] if n.get("workspace_id") != workspace_id]
        data["activity"] = [a for a in data["activity"] if a.get("workspace_id") != workspace_id]
        self._save(data)
        return True

    def add_member(
        self,
        workspace_id: str,
        actor: str,
        *,
        username: str,
        role: str = MemberRole.ANALYST.value,
    ) -> Dict[str, Any]:
        actor = self.normalize_username(actor)
        username = self.normalize_username(username)
        if role not in ROLE_RANK:
            raise ValueError("Rôle invalide")

        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        self._require_role(ws, actor, MemberRole.OWNER.value)

        if self._member_role(ws, username):
            raise ValueError(f"{username} est déjà membre")

        member = {
            "username": username,
            "role": role,
            "joined_at": self._iso(),
        }
        ws.setdefault("members", []).append(member)
        ws["updated_at"] = self._iso()
        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=actor,
            action="member_added",
            message=f"{username} ajouté comme {role}",
            metadata={"username": username, "role": role},
        )
        self._save(data)
        return member

    def remove_member(self, workspace_id: str, actor: str, username: str) -> bool:
        actor = self.normalize_username(actor)
        username = self.normalize_username(username)

        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            return False

        if username == ws.get("owner") and actor != username:
            raise PermissionError("Impossible de retirer le propriétaire")

        if actor != username:
            self._require_role(ws, actor, MemberRole.OWNER.value)

        members = ws.get("members") or []
        before = len(members)
        ws["members"] = [m for m in members if m.get("username") != username]
        if len(ws["members"]) == before:
            return False

        ws["updated_at"] = self._iso()
        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=actor,
            action="member_removed",
            message=f"{username} retiré du workspace",
        )
        self._save(data)
        return True

    def create_case(
        self,
        workspace_id: str,
        username: str,
        *,
        title: str,
        description: str = "",
        priority: str = "medium",
        tags: Optional[List[str]] = None,
        investigation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        username = self.normalize_username(username)
        title = title.strip()
        if not title:
            raise ValueError("Titre du dossier requis")

        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        self._require_role(ws, username, MemberRole.ANALYST.value)

        now = self._iso()
        inv_refs: List[Dict[str, Any]] = []
        if investigation:
            inv_id = self._store_investigation(data, investigation)
            inv_refs.append(self._investigation_summary(data["investigations"][inv_id]))

        case = {
            "id": new_case_id(),
            "workspace_id": workspace_id,
            "title": title,
            "description": description.strip(),
            "status": CaseStatus.OPEN.value,
            "priority": priority if priority in ("low", "medium", "high", "critical") else "medium",
            "tags": tags or [],
            "created_by": username,
            "created_at": now,
            "updated_at": now,
            "investigation_ids": [r["id"] for r in inv_refs if r.get("id")],
            "investigations": inv_refs,
        }
        data["cases"].append(case)
        ws["updated_at"] = now
        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=username,
            action="case_created",
            message=f"Dossier « {title} » créé",
            metadata={"case_id": case["id"]},
        )
        self._save(data)
        return case

    def add_investigation_to_case(
        self,
        workspace_id: str,
        case_id: str,
        username: str,
        investigation: Dict[str, Any],
    ) -> Dict[str, Any]:
        username = self.normalize_username(username)
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        self._require_role(ws, username, MemberRole.ANALYST.value)

        case = next((c for c in data["cases"] if c["id"] == case_id and c["workspace_id"] == workspace_id), None)
        if not case:
            raise ValueError("Dossier introuvable")

        inv_id = self._store_investigation(data, investigation)
        summary = self._investigation_summary(data["investigations"][inv_id])

        case.setdefault("investigation_ids", [])
        case.setdefault("investigations", [])
        if inv_id not in case["investigation_ids"]:
            case["investigation_ids"].append(inv_id)
            case["investigations"].append(summary)
        case["updated_at"] = self._iso()
        ws["updated_at"] = case["updated_at"]

        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=username,
            action="investigation_added",
            message=f"Investigation {summary.get('target')} ajoutée au dossier « {case['title']} »",
            metadata={"case_id": case_id, "investigation_id": inv_id},
        )
        self._save(data)
        return {"case": case, "investigation": summary}

    def add_investigation_to_workspace(
        self,
        workspace_id: str,
        username: str,
        investigation: Dict[str, Any],
        *,
        case_title: Optional[str] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if case_id:
            return self.add_investigation_to_case(workspace_id, case_id, username, investigation)

        target = investigation.get("target", "Cible")
        title = case_title or f"Investigation — {target}"
        return {
            "case": self.create_case(
                workspace_id,
                username,
                title=title,
                investigation=investigation,
            )
        }

    def update_case(
        self,
        workspace_id: str,
        case_id: str,
        username: str,
        *,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        username = self.normalize_username(username)
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        self._require_role(ws, username, MemberRole.ANALYST.value)

        case = next((c for c in data["cases"] if c["id"] == case_id and c["workspace_id"] == workspace_id), None)
        if not case:
            raise ValueError("Dossier introuvable")

        if title is not None:
            case["title"] = title.strip() or case["title"]
        if description is not None:
            case["description"] = description.strip()
        if status is not None and status in {s.value for s in CaseStatus}:
            case["status"] = status
        if priority is not None and priority in ("low", "medium", "high", "critical"):
            case["priority"] = priority
        if tags is not None:
            case["tags"] = tags
        case["updated_at"] = self._iso()
        ws["updated_at"] = case["updated_at"]

        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=username,
            action="case_updated",
            message=f"Dossier « {case['title']} » mis à jour",
            metadata={"case_id": case_id},
        )
        self._save(data)
        return case

    def get_case(self, workspace_id: str, case_id: str, username: Optional[str] = None) -> Dict[str, Any]:
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        if username:
            self._require_member(ws, username)

        case = next((c for c in data["cases"] if c["id"] == case_id and c["workspace_id"] == workspace_id), None)
        if not case:
            raise ValueError("Dossier introuvable")

        full_investigations = []
        for inv_id in case.get("investigation_ids") or []:
            inv = data.get("investigations", {}).get(inv_id)
            if inv:
                full_investigations.append(inv)

        case_notes = [n for n in data["notes"] if n.get("case_id") == case_id]
        return {
            "case": case,
            "investigations_full": full_investigations,
            "notes": sorted(case_notes, key=lambda n: n.get("created_at", ""), reverse=True),
        }

    def create_note(
        self,
        workspace_id: str,
        username: str,
        content: str,
        *,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        username = self.normalize_username(username)
        content = content.strip()
        if not content:
            raise ValueError("Contenu de la note requis")

        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        self._require_role(ws, username, MemberRole.ANALYST.value)

        if case_id:
            case = next((c for c in data["cases"] if c["id"] == case_id and c["workspace_id"] == workspace_id), None)
            if not case:
                raise ValueError("Dossier introuvable")

        now = self._iso()
        note = {
            "id": new_note_id(),
            "workspace_id": workspace_id,
            "case_id": case_id,
            "author": username,
            "content": content,
            "created_at": now,
            "updated_at": now,
        }
        data["notes"].append(note)
        ws["updated_at"] = now
        self._log_activity(
            data,
            workspace_id=workspace_id,
            actor=username,
            action="note_created",
            message=f"Note ajoutée par {username}",
            metadata={"note_id": note["id"], "case_id": case_id},
        )
        self._save(data)
        return note

    def list_activity(self, workspace_id: str, username: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        data = self._load()
        ws = self._get_workspace_raw(data, workspace_id)
        if not ws:
            raise ValueError("Workspace introuvable")
        if username:
            self._require_member(ws, username)

        items = [a for a in data["activity"] if a.get("workspace_id") == workspace_id]
        items = sorted(items, key=lambda a: a.get("created_at", ""), reverse=True)
        return items[:limit]

    def get_investigation(self, inv_id: str) -> Optional[Dict[str, Any]]:
        return self._load().get("investigations", {}).get(inv_id)


workspace_service = WorkspaceService()
