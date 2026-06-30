from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from models.watch import (
    Alert,
    AlertSeverity,
    AlertType,
    Watch,
    WatchStatus,
    new_alert_id,
    new_watch_id,
    utc_now,
)
from services.entity_resolver import resolve_entity_type, suggest_playbook_id
from services.playbook_engine import playbook_engine
from services.scoring_service import compute_attack_surface

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

DEFAULT_STORE = Path(__file__).resolve().parent.parent / "data" / "watch_store.json"
DEFAULT_INTERVAL_HOURS = int(os.getenv("WATCH_DEFAULT_INTERVAL_HOURS", "24"))
AUTO_CHECK_ENABLED = os.getenv("WATCH_AUTO_CHECK", "true").lower() in ("1", "true", "yes")
AUTO_CHECK_POLL_MINUTES = int(os.getenv("WATCH_POLL_MINUTES", "15"))


class WatchService:
    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._store_path = Path(store_path or os.getenv("WATCH_STORE_PATH", str(DEFAULT_STORE)))
        self._lock = asyncio.Lock()
        self._scheduler_task: Optional[asyncio.Task] = None

    def store_path(self) -> Path:
        return self._store_path

    def _load(self) -> Dict[str, Any]:
        if not self._store_path.exists():
            return {"watches": [], "alerts": [], "investigations": {}}
        try:
            with open(self._store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"watches": [], "alerts": [], "investigations": {}}
        data.setdefault("watches", [])
        data.setdefault("alerts", [])
        data.setdefault("investigations", {})
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._store_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._store_path)

    def _iso(self, dt: Optional[datetime] = None) -> str:
        return (dt or utc_now()).isoformat()

    def _parse_iso(self, value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _watch_from_dict(self, raw: Dict[str, Any]) -> Watch:
        return Watch(
            id=raw["id"],
            target=raw["target"],
            target_type=raw.get("target_type", "unknown"),
            playbook_id=raw.get("playbook_id", ""),
            label=raw.get("label") or raw["target"],
            status=WatchStatus(raw.get("status", WatchStatus.ACTIVE.value)),
            interval_hours=int(raw.get("interval_hours", DEFAULT_INTERVAL_HOURS)),
            created_at=raw.get("created_at", self._iso()),
            updated_at=raw.get("updated_at", self._iso()),
            last_check_at=raw.get("last_check_at"),
            next_check_at=raw.get("next_check_at"),
            baseline_investigation_id=raw.get("baseline_investigation_id"),
            last_investigation_id=raw.get("last_investigation_id"),
            unread_alerts=int(raw.get("unread_alerts", 0)),
            total_alerts=int(raw.get("total_alerts", 0)),
            last_risk=raw.get("last_risk", "low"),
            last_score=float(raw.get("last_score", 0)),
        )

    def _alert_from_dict(self, raw: Dict[str, Any]) -> Alert:
        return Alert(
            id=raw["id"],
            watch_id=raw["watch_id"],
            target=raw.get("target", ""),
            severity=AlertSeverity(raw.get("severity", AlertSeverity.INFO.value)),
            alert_type=AlertType(raw.get("alert_type", AlertType.NEW_FINDING.value)),
            title=raw.get("title", "Alerte"),
            message=raw.get("message", ""),
            created_at=raw.get("created_at", self._iso()),
            read=bool(raw.get("read", False)),
            details=raw.get("details") or {},
        )

    def status(self) -> Dict[str, Any]:
        data = self._load()
        watches = data["watches"]
        alerts = data["alerts"]
        unread = sum(1 for a in alerts if not a.get("read"))
        active = sum(1 for w in watches if w.get("status") == WatchStatus.ACTIVE.value)
        return {
            "store_path": str(self._store_path),
            "watch_count": len(watches),
            "active_watches": active,
            "alert_count": len(alerts),
            "unread_alerts": unread,
            "auto_check_enabled": AUTO_CHECK_ENABLED,
            "poll_interval_minutes": AUTO_CHECK_POLL_MINUTES,
            "default_interval_hours": DEFAULT_INTERVAL_HOURS,
        }

    def list_watches(self) -> List[Dict[str, Any]]:
        data = self._load()
        return sorted(data["watches"], key=lambda w: w.get("updated_at", ""), reverse=True)

    def get_watch(self, watch_id: str) -> Optional[Dict[str, Any]]:
        for w in self._load()["watches"]:
            if w["id"] == watch_id:
                return w
        return None

    def list_alerts(
        self,
        *,
        watch_id: Optional[str] = None,
        unread_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        alerts = self._load()["alerts"]
        if watch_id:
            alerts = [a for a in alerts if a.get("watch_id") == watch_id]
        if unread_only:
            alerts = [a for a in alerts if not a.get("read")]
        alerts = sorted(alerts, key=lambda a: a.get("created_at", ""), reverse=True)
        return alerts[:limit]

    def _store_investigation(self, data: Dict[str, Any], investigation: Dict[str, Any]) -> None:
        inv_id = investigation.get("id")
        if not inv_id:
            return
        investigations = data.setdefault("investigations", {})
        investigations[inv_id] = investigation
        if len(investigations) > 200:
            oldest = sorted(investigations.keys())[: len(investigations) - 200]
            for key in oldest:
                investigations.pop(key, None)

    def get_investigation(self, inv_id: str) -> Optional[Dict[str, Any]]:
        return self._load().get("investigations", {}).get(inv_id)

    async def create_watch(
        self,
        target: str,
        *,
        playbook_id: Optional[str] = None,
        label: Optional[str] = None,
        interval_hours: Optional[int] = None,
        baseline_investigation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        target = target.strip()
        if not target:
            raise ValueError("Cible vide")

        entity_type = resolve_entity_type(target)
        pb_id = playbook_id or suggest_playbook_id(entity_type)
        hours = max(1, min(int(interval_hours or DEFAULT_INTERVAL_HOURS), 168))
        now = utc_now()

        if baseline_investigation:
            investigation = baseline_investigation
        else:
            result = await playbook_engine.run(target=target, playbook_id=pb_id)
            investigation = result.to_dict()

        synth = investigation.get("synthesis") or {}
        as_data = synth.get("attack_surface") or compute_attack_surface(investigation)
        watch_id = new_watch_id()
        inv_id = investigation.get("id", "")

        watch = Watch(
            id=watch_id,
            target=target,
            target_type=entity_type.value,
            playbook_id=pb_id,
            label=(label or target).strip() or target,
            status=WatchStatus.ACTIVE,
            interval_hours=hours,
            created_at=self._iso(now),
            updated_at=self._iso(now),
            last_check_at=self._iso(now),
            next_check_at=self._iso(now + timedelta(hours=hours)),
            baseline_investigation_id=inv_id,
            last_investigation_id=inv_id,
            unread_alerts=0,
            total_alerts=0,
            last_risk=synth.get("overall_risk", "low"),
            last_score=float(as_data.get("score", 0)),
        )

        async with self._lock:
            data = self._load()
            if any(w["target"].lower() == target.lower() and w.get("status") == WatchStatus.ACTIVE.value for w in data["watches"]):
                raise ValueError(f"Une surveillance active existe déjà pour {target}")
            self._store_investigation(data, investigation)
            data["watches"].append(watch.to_dict())
            self._save(data)

        return {
            "watch": watch.to_dict(),
            "baseline_investigation": investigation,
        }

    async def update_watch(
        self,
        watch_id: str,
        *,
        status: Optional[str] = None,
        label: Optional[str] = None,
        interval_hours: Optional[int] = None,
    ) -> Dict[str, Any]:
        async with self._lock:
            data = self._load()
            watch_raw = None
            for w in data["watches"]:
                if w["id"] == watch_id:
                    watch_raw = w
                    break
            if not watch_raw:
                raise ValueError("Surveillance introuvable")

            if status is not None:
                watch_raw["status"] = WatchStatus(status).value
            if label is not None:
                watch_raw["label"] = label.strip() or watch_raw["target"]
            if interval_hours is not None:
                watch_raw["interval_hours"] = max(1, min(int(interval_hours), 168))
                last = self._parse_iso(watch_raw.get("last_check_at"))
                if last:
                    watch_raw["next_check_at"] = self._iso(
                        last + timedelta(hours=watch_raw["interval_hours"])
                    )
            watch_raw["updated_at"] = self._iso()
            self._save(data)
            return watch_raw

    async def delete_watch(self, watch_id: str) -> bool:
        async with self._lock:
            data = self._load()
            before = len(data["watches"])
            data["watches"] = [w for w in data["watches"] if w["id"] != watch_id]
            if len(data["watches"]) == before:
                return False
            self._save(data)
            return True

    def compare_investigations(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
        *,
        watch_id: str,
        target: str,
    ) -> List[Alert]:
        alerts: List[Alert] = []
        now = self._iso()
        b_synth = baseline.get("synthesis") or {}
        c_synth = current.get("synthesis") or {}

        b_risk = b_synth.get("overall_risk", "low")
        c_risk = c_synth.get("overall_risk", "low")
        if RISK_ORDER.get(c_risk, 0) > RISK_ORDER.get(b_risk, 0):
            alerts.append(
                Alert(
                    id=new_alert_id(),
                    watch_id=watch_id,
                    target=target,
                    severity=AlertSeverity.HIGH if c_risk in ("high", "critical") else AlertSeverity.MEDIUM,
                    alert_type=AlertType.RISK_INCREASE,
                    title="Risque global augmenté",
                    message=f"{b_risk.upper()} → {c_risk.upper()}",
                    created_at=now,
                    details={"previous": b_risk, "current": c_risk},
                )
            )

        b_as = b_synth.get("attack_surface") or compute_attack_surface(baseline)
        c_as = c_synth.get("attack_surface") or compute_attack_surface(current)
        b_score = float(b_as.get("score", 0))
        c_score = float(c_as.get("score", 0))
        delta = round(c_score - b_score, 1)
        if delta >= 5:
            alerts.append(
                Alert(
                    id=new_alert_id(),
                    watch_id=watch_id,
                    target=target,
                    severity=AlertSeverity.HIGH if delta >= 15 else AlertSeverity.MEDIUM,
                    alert_type=AlertType.SCORE_INCREASE,
                    title="Attack Surface Score en hausse",
                    message=f"+{delta} pts ({b_score} → {c_score}/100)",
                    created_at=now,
                    details={"previous": b_score, "current": c_score, "delta": delta},
                )
            )

        b_breaches = _leakcheck_count(baseline)
        c_breaches = _leakcheck_count(current)
        if c_breaches > b_breaches:
            alerts.append(
                Alert(
                    id=new_alert_id(),
                    watch_id=watch_id,
                    target=target,
                    severity=AlertSeverity.CRITICAL if c_breaches - b_breaches >= 2 else AlertSeverity.HIGH,
                    alert_type=AlertType.NEW_BREACH,
                    title="Nouvelle(s) fuite(s) de données",
                    message=f"{b_breaches} → {c_breaches} fuite(s) HIBP",
                    created_at=now,
                    details={"previous": b_breaches, "current": c_breaches},
                )
            )

        b_vt, c_vt = _vt_detections(baseline), _vt_detections(current)
        if c_vt > b_vt:
            alerts.append(
                Alert(
                    id=new_alert_id(),
                    watch_id=watch_id,
                    target=target,
                    severity=AlertSeverity.HIGH,
                    alert_type=AlertType.VT_DETECTIONS,
                    title="Détections VirusTotal en hausse",
                    message=f"{b_vt} → {c_vt} détection(s)",
                    created_at=now,
                    details={"previous": b_vt, "current": c_vt},
                )
            )

        b_rep, c_rep = _abuse_score(baseline), _abuse_score(current)
        if c_rep > b_rep and c_rep - b_rep >= 10:
            alerts.append(
                Alert(
                    id=new_alert_id(),
                    watch_id=watch_id,
                    target=target,
                    severity=AlertSeverity.MEDIUM,
                    alert_type=AlertType.REPUTATION_CHANGE,
                    title="Réputation IP dégradée",
                    message=f"AbuseIPDB {b_rep}% → {c_rep}%",
                    created_at=now,
                    details={"previous": b_rep, "current": c_rep},
                )
            )

        b_ports, c_ports = _shodan_ports(baseline), _shodan_ports(current)
        new_ports = sorted(c_ports - b_ports)
        if new_ports:
            alerts.append(
                Alert(
                    id=new_alert_id(),
                    watch_id=watch_id,
                    target=target,
                    severity=AlertSeverity.MEDIUM,
                    alert_type=AlertType.NETWORK_EXPOSURE,
                    title="Nouveaux ports exposés (Shodan)",
                    message=f"Ports : {', '.join(str(p) for p in new_ports[:8])}",
                    created_at=now,
                    details={"new_ports": new_ports},
                )
            )

        b_entities = _entity_keys(baseline)
        for ent in current.get("entities") or []:
            key = (ent.get("type", ""), str(ent.get("value", "")).lower())
            if key not in b_entities:
                alerts.append(
                    Alert(
                        id=new_alert_id(),
                        watch_id=watch_id,
                        target=target,
                        severity=AlertSeverity.LOW,
                        alert_type=AlertType.NEW_ENTITY,
                        title="Nouvelle entité découverte",
                        message=f"{ent.get('type')}: {ent.get('value')}",
                        created_at=now,
                        details={"entity": ent},
                    )
                )

        b_findings: Set[str] = set(b_synth.get("key_findings") or [])
        for finding in c_synth.get("key_findings") or []:
            if finding not in b_findings:
                alerts.append(
                    Alert(
                        id=new_alert_id(),
                        watch_id=watch_id,
                        target=target,
                        severity=AlertSeverity.INFO,
                        alert_type=AlertType.NEW_FINDING,
                        title="Nouveau constat OSINT",
                        message=finding[:200],
                        created_at=now,
                        details={"finding": finding},
                    )
                )

        return alerts

    async def run_check(self, watch_id: str) -> Dict[str, Any]:
        async with self._lock:
            data = self._load()
            watch_raw = next((w for w in data["watches"] if w["id"] == watch_id), None)
            if not watch_raw:
                raise ValueError("Surveillance introuvable")
            watch = self._watch_from_dict(watch_raw)

        result = await playbook_engine.run(target=watch.target, playbook_id=watch.playbook_id)
        investigation = result.to_dict()

        baseline_id = watch.baseline_investigation_id
        baseline = self.get_investigation(baseline_id) if baseline_id else None
        if not baseline:
            baseline = investigation

        new_alerts = self.compare_investigations(
            baseline, investigation, watch_id=watch_id, target=watch.target
        )

        synth = investigation.get("synthesis") or {}
        as_data = synth.get("attack_surface") or compute_attack_surface(investigation)
        now = utc_now()

        async with self._lock:
            data = self._load()
            watch_raw = next((w for w in data["watches"] if w["id"] == watch_id), None)
            if not watch_raw:
                raise ValueError("Surveillance introuvable")

            self._store_investigation(data, investigation)
            watch_raw["last_check_at"] = self._iso(now)
            watch_raw["next_check_at"] = self._iso(now + timedelta(hours=watch_raw.get("interval_hours", DEFAULT_INTERVAL_HOURS)))
            watch_raw["last_investigation_id"] = investigation.get("id")
            watch_raw["last_risk"] = synth.get("overall_risk", "low")
            watch_raw["last_score"] = float(as_data.get("score", 0))
            watch_raw["updated_at"] = self._iso(now)

            alert_dicts = [a.to_dict() for a in new_alerts]
            if alert_dicts:
                data["alerts"].extend(alert_dicts)
                watch_raw["unread_alerts"] = int(watch_raw.get("unread_alerts", 0)) + len(alert_dicts)
                watch_raw["total_alerts"] = int(watch_raw.get("total_alerts", 0)) + len(alert_dicts)

            self._save(data)

        return {
            "watch": watch_raw,
            "investigation": investigation,
            "alerts": alert_dicts,
            "changes_detected": len(alert_dicts),
        }

    async def run_due_checks(self) -> List[Dict[str, Any]]:
        if not AUTO_CHECK_ENABLED:
            return []
        now = utc_now()
        due: List[str] = []
        for w in self.list_watches():
            if w.get("status") != WatchStatus.ACTIVE.value:
                continue
            nxt = self._parse_iso(w.get("next_check_at"))
            if nxt is None or nxt <= now:
                due.append(w["id"])

        results = []
        for watch_id in due:
            try:
                results.append(await self.run_check(watch_id))
            except Exception as exc:
                results.append({"watch_id": watch_id, "error": str(exc)})
        return results

    def mark_alert_read(self, alert_id: str) -> Optional[Dict[str, Any]]:
        data = self._load()
        alert_raw = None
        for a in data["alerts"]:
            if a["id"] == alert_id and not a.get("read"):
                a["read"] = True
                alert_raw = a
                break
        if not alert_raw:
            return None

        watch_id = alert_raw.get("watch_id")
        for w in data["watches"]:
            if w["id"] == watch_id and w.get("unread_alerts", 0) > 0:
                w["unread_alerts"] = int(w["unread_alerts"]) - 1
                break
        self._save(data)
        return alert_raw

    def mark_all_alerts_read(self, watch_id: Optional[str] = None) -> int:
        data = self._load()
        count = 0
        for a in data["alerts"]:
            if a.get("read"):
                continue
            if watch_id and a.get("watch_id") != watch_id:
                continue
            a["read"] = True
            count += 1

        if watch_id:
            for w in data["watches"]:
                if w["id"] == watch_id:
                    w["unread_alerts"] = 0
        else:
            for w in data["watches"]:
                w["unread_alerts"] = 0

        if count:
            self._save(data)
        return count

    def start_scheduler(self) -> None:
        if self._scheduler_task is None or self._scheduler_task.done():
            self._scheduler_task = asyncio.create_task(self._scheduler_loop())

    async def stop_scheduler(self) -> None:
        if self._scheduler_task and not self._scheduler_task.done():
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
            self._scheduler_task = None

    async def _scheduler_loop(self) -> None:
        while True:
            try:
                await self.run_due_checks()
            except Exception:
                pass
            await asyncio.sleep(max(60, AUTO_CHECK_POLL_MINUTES * 60))


def _step_data(investigation: Dict[str, Any], plugin_id: str) -> Dict[str, Any]:
    for step in investigation.get("steps") or []:
        if step.get("plugin_id") == plugin_id and step.get("status") == "success":
            return step.get("data") or {}
    return {}


def _leakcheck_count(investigation: Dict[str, Any]) -> int:
    data = _step_data(investigation, "leakcheck")
    return int(data.get("breach_count") or 0)


def _vt_detections(investigation: Dict[str, Any]) -> int:
    return int(_step_data(investigation, "virustotal").get("detections") or 0)


def _abuse_score(investigation: Dict[str, Any]) -> int:
    return int(_step_data(investigation, "abuseipdb").get("abuseConfidence") or 0)


def _shodan_ports(investigation: Dict[str, Any]) -> Set[int]:
    ports: Set[int] = set()
    for pid in ("shodan_ip", "shodan_search"):
        for p in _step_data(investigation, pid).get("ports") or []:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                pass
    return ports


def _entity_keys(investigation: Dict[str, Any]) -> Set[Tuple[str, str]]:
    return {
        (e.get("type", ""), str(e.get("value", "")).lower())
        for e in (investigation.get("entities") or [])
    }


watch_service = WatchService()
