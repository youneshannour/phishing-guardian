from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set

from models.playbook import Entity, EntityType, PluginResult, PluginStatus


class InvestigationContext:
    def __init__(self, target: str, target_type: EntityType, playbook_id: str):
        self.target = target
        self.target_type = target_type
        self.playbook_id = playbook_id
        self._results: Dict[str, PluginResult] = {}

    def register_result(self, result: PluginResult) -> None:
        self._results[result.plugin_id] = result

    def get_result(self, plugin_id: str) -> Optional[PluginResult]:
        return self._results.get(plugin_id)


class OSINTPlugin(ABC):
    id: str
    name: str
    supported_types: Set[EntityType]
    env_key: Optional[str] = None

    def is_available(self) -> bool:
        if self.env_key:
            import os
            return bool(os.getenv(self.env_key))
        return True

    def supports(self, entity_type: EntityType) -> bool:
        return entity_type in self.supported_types

    @abstractmethod
    def run(self, target: str, context: InvestigationContext) -> PluginResult:
        pass

    def _build_result(
        self,
        status: PluginStatus,
        duration_ms: int,
        data: dict,
        entities: Optional[List[Entity]] = None,
        error: Optional[str] = None,
    ) -> PluginResult:
        return PluginResult(
            plugin_id=self.id,
            plugin_name=self.name,
            status=status,
            duration_ms=duration_ms,
            data=data,
            entities=entities or [],
            error=error,
        )
