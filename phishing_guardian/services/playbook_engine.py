from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Set

from models.playbook import (
    Entity,
    EntityType,
    InvestigationResult,
    PlaybookDefinition,
    PluginResult,
    PluginStatus,
    utc_now,
)
from playbooks.definitions import get_playbook, list_playbooks
from plugins.osint.base_plugin import InvestigationContext
from plugins.osint.registry import get_plugin
from services.entity_resolver import (
    resolve_entity_type,
    suggest_playbook_id,
    transform_target,
)
from services.scoring_service import compute_attack_surface
from services.privacy_service import compute_privacy_score
from services.timeline_service import build_timeline


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PlaybookEngine:
    def list_playbooks(self) -> List[PlaybookDefinition]:
        return list_playbooks()

    def suggest(self, target: str) -> Dict[str, object]:
        entity_type = resolve_entity_type(target)
        playbook_id = suggest_playbook_id(entity_type)
        playbook = get_playbook(playbook_id)
        return {
            "target": target,
            "target_type": entity_type.value,
            "suggested_playbook_id": playbook_id,
            "suggested_playbook": playbook.to_dict(),
        }

    async def run(
        self,
        target: str,
        playbook_id: Optional[str] = None,
    ) -> InvestigationResult:
        target = target.strip()
        if not target:
            raise ValueError("Cible vide")

        entity_type = resolve_entity_type(target)
        if not playbook_id:
            playbook_id = suggest_playbook_id(entity_type)

        playbook = get_playbook(playbook_id)
        started_at = utc_now()
        context = InvestigationContext(target, entity_type, playbook_id)
        steps: List[PluginResult] = []

        for step in playbook.steps:
            plugin = get_plugin(step.plugin_id)
            step_target = transform_target(target, step.transform)

            if not step_target:
                steps.append(
                    PluginResult(
                        plugin_id=plugin.id,
                        plugin_name=plugin.name,
                        status=PluginStatus.SKIPPED,
                        duration_ms=0,
                        error=f"Transformation '{step.transform.value}' impossible pour '{target}'",
                    )
                )
                continue

            effective_type = resolve_entity_type(step_target)
            if effective_type == EntityType.UNKNOWN and entity_type != EntityType.UNKNOWN:
                effective_type = entity_type

            if not plugin.supports(effective_type) and not plugin.supports(entity_type):
                steps.append(
                    PluginResult(
                        plugin_id=plugin.id,
                        plugin_name=plugin.name,
                        status=PluginStatus.SKIPPED,
                        duration_ms=0,
                        error=f"Plugin non compatible avec le type '{effective_type.value}'",
                    )
                )
                continue

            if plugin.env_key and not plugin.is_available():
                steps.append(
                    PluginResult(
                        plugin_id=plugin.id,
                        plugin_name=plugin.name,
                        status=PluginStatus.UNAVAILABLE,
                        duration_ms=0,
                        error=f"Clé API manquante ({plugin.env_key})",
                    )
                )
                continue

            result = await asyncio.to_thread(plugin.run, step_target, context)
            context.register_result(result)
            steps.append(result)

        completed_at = utc_now()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)
        entities = self._merge_entities(steps)
        inv_id = InvestigationResult.new_id()
        synthesis = self._build_synthesis(target, entity_type, playbook, steps, entities)
        synthesis["timeline"] = build_timeline({
            "id": inv_id,
            "target": target,
            "target_type": entity_type.value,
            "steps": [s.to_dict() for s in steps],
            "entities": [e.to_dict() for e in entities],
            "completed_at": completed_at.isoformat(),
        })

        return InvestigationResult(
            id=inv_id,
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            target=target,
            target_type=entity_type,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            steps=steps,
            entities=entities,
            synthesis=synthesis,
        )

    def _merge_entities(self, steps: List[PluginResult]) -> List[Entity]:
        seen: Set[str] = set()
        merged: List[Entity] = []
        for step in steps:
            for entity in step.entities:
                key = f"{entity.type.value}:{entity.value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                merged.append(entity)
        return merged

    def _build_synthesis(
        self,
        target: str,
        entity_type: EntityType,
        playbook: PlaybookDefinition,
        steps: List[PluginResult],
        entities: List[Entity],
    ) -> Dict[str, object]:
        status_counts = {s.value: 0 for s in PluginStatus}
        for step in steps:
            status_counts[step.status.value] += 1

        risk_levels = []
        key_findings: List[str] = []

        for step in steps:
            if step.status != PluginStatus.SUCCESS:
                continue
            risk = step.data.get("risk_level")
            if risk:
                risk_levels.append(risk)

            if step.plugin_id == "leakcheck" and step.data.get("found"):
                key_findings.append(
                    f"Email trouvé dans {step.data.get('breach_count', 0)} fuite(s) connue(s)"
                )
            if step.plugin_id == "sherlock" and step.data.get("count", 0) > 0:
                key_findings.append(
                    f"{step.data['count']} profil(s) social(aux) détecté(s)"
                )
            if step.plugin_id == "virustotal" and step.data.get("detections", 0) > 0:
                key_findings.append(
                    f"VirusTotal: {step.data['detections']}/{step.data.get('total', 0)} détections"
                )
            if step.plugin_id == "abuseipdb":
                score = step.data.get("abuseConfidence", 0)
                if score > 25:
                    key_findings.append(f"IP signalée AbuseIPDB ({score}% confiance)")
            if step.plugin_id == "shodan_ip" and step.data.get("vuln_count", 0) > 0:
                key_findings.append(
                    f"{step.data['vuln_count']} vulnérabilité(s) Shodan détectée(s)"
                )
            if step.plugin_id == "whois" and step.data.get("type") == "domain":
                org = step.data.get("data", {}).get("org")
                if org:
                    key_findings.append(f"Organisation WHOIS: {org}")

        overall_risk = "low"
        if risk_levels:
            overall_risk = max(risk_levels, key=lambda r: RISK_ORDER.get(r, 0))

        synthesis_base = {
            "target": target,
            "target_type": entity_type.value,
            "playbook": playbook.name,
            "tools_run": len(steps),
            "tools_success": status_counts[PluginStatus.SUCCESS.value],
            "tools_failed": status_counts[PluginStatus.ERROR.value],
            "tools_skipped": status_counts[PluginStatus.SKIPPED.value],
            "tools_unavailable": status_counts[PluginStatus.UNAVAILABLE.value],
            "entities_found": len(entities),
            "overall_risk": overall_risk,
            "key_findings": key_findings,
            "entity_breakdown": self._entity_breakdown(entities),
        }

        inv_stub = {
            "target": target,
            "target_type": entity_type.value,
            "steps": [s.to_dict() for s in steps],
            "entities": [e.to_dict() for e in entities],
        }
        synthesis_base["attack_surface"] = compute_attack_surface(inv_stub)
        synthesis_base["privacy_score"] = compute_privacy_score(inv_stub)
        return synthesis_base

    def _entity_breakdown(self, entities: List[Entity]) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        for entity in entities:
            breakdown[entity.type.value] = breakdown.get(entity.type.value, 0) + 1
        return breakdown


playbook_engine = PlaybookEngine()
