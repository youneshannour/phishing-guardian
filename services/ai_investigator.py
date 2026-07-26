from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import requests

from services.entity_resolver import resolve_entity_type, suggest_playbook_id
from services.nl_target_extractor import extract_targets, pick_best_target, wants_investigation
from services.playbook_engine import playbook_engine

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

PREFERRED_MODELS = (
    "mistral",
    "llama3.2",
    "llama3",
    "llama3.1",
    "llama2",
    "phi3",
    "gemma2",
    "qwen2.5",
    "mixtral",
)

SYSTEM_PROMPT = """Tu es Investigator AI, analyste OSINT expert intégré à la plateforme Phishing Guardian.
Tu aides les enquêteurs à comprendre les résultats d'investigations en source ouverte.

Règles :
- Réponds en français, de façon concise et professionnelle (style rapport de renseignement).
- Structure tes réponses : Résumé exécutif, Constats clés, Niveau de risque, Recommandations.
- Ne invente jamais de données absentes des résultats fournis.
- Si une information manque, indique-le clairement.
- Pour les investigations, cite les outils utilisés (LeakCheck, WHOIS, Shodan, etc.).
"""


class AIInvestigator:
    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._active_model: Optional[str] = None

    def _resolve_model(self, models: List[str]) -> Optional[str]:
        if not models:
            return None

        normalized = [m for m in models if m]
        for preferred in (self.model, *PREFERRED_MODELS):
            for name in normalized:
                base = name.split(":", 1)[0]
                if base == preferred or name.startswith(f"{preferred}:"):
                    return name

        for name in normalized:
            if self.model in name:
                return name

        return normalized[0]

    def _effective_model(self) -> str:
        return self._active_model or self.model

    def check_status(self) -> Dict[str, Any]:
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            resolved = self._resolve_model(models)
            self._active_model = resolved
            model_available = resolved is not None
            return {
                "available": True,
                "ollama_url": self.base_url,
                "configured_model": self.model,
                "active_model": resolved,
                "model_available": model_available,
                "models": models,
            }
        except Exception as exc:
            self._active_model = None
            return {
                "available": False,
                "ollama_url": self.base_url,
                "configured_model": self.model,
                "active_model": None,
                "model_available": False,
                "models": [],
                "error": str(exc),
            }

    def _generate(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        payload = {
            "model": self._effective_model(),
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 1024},
        }
        if system:
            payload["system"] = system

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except requests.RequestException:
            return None

    def _chat_generate(self, messages: List[Dict[str, str]]) -> Optional[str]:
        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self._effective_model(),
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0.4, "num_predict": 1024},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content", "").strip()
        except requests.RequestException:
            return None

    def build_investigation_context(self, result: Dict[str, Any]) -> str:
        synth = result.get("synthesis", {})
        steps = result.get("steps", [])
        entities = result.get("entities", [])

        lines = [
            f"Cible: {result.get('target')} ({result.get('target_type')})",
            f"Playbook: {result.get('playbook_name')}",
            f"Durée: {result.get('duration_ms')}ms",
            f"Risque global: {synth.get('overall_risk', 'N/A')}",
            f"Outils réussis: {synth.get('tools_success', 0)}/{synth.get('tools_run', 0)}",
            f"Entités découvertes: {synth.get('entities_found', 0)}",
            "",
            "Constats automatiques:",
        ]
        for finding in synth.get("key_findings", []):
            lines.append(f"- {finding}")

        lines.append("\nPipeline:")
        for step in steps:
            status = step.get("status", "?")
            name = step.get("plugin_name", step.get("plugin_id", "?"))
            dur = step.get("duration_ms", 0)
            lines.append(f"- [{status}] {name} ({dur}ms)")
            if step.get("error"):
                lines.append(f"  Erreur: {step['error']}")

        if entities:
            lines.append("\nEntités:")
            for ent in entities[:25]:
                lines.append(f"- {ent.get('type')}: {ent.get('value')} (source: {ent.get('source')})")

        return "\n".join(lines)

    def fallback_summary(self, result: Dict[str, Any]) -> str:
        synth = result.get("synthesis", {})
        risk = synth.get("overall_risk", "low").upper()
        findings = synth.get("key_findings", [])

        lines = [
            "## Rapport d'investigation OSINT",
            "",
            f"**Cible analysée :** `{result.get('target')}` ({result.get('target_type')})",
            f"**Playbook exécuté :** {result.get('playbook_name')}",
            f"**Niveau de risque :** {risk}",
            f"**Durée :** {result.get('duration_ms', 0)} ms",
            "",
            "### Résumé exécutif",
            f"L'investigation a exécuté {synth.get('tools_run', 0)} outil(s) OSINT, "
            f"dont {synth.get('tools_success', 0)} avec succès. "
            f"{synth.get('entities_found', 0)} entité(s) ont été identifiée(s).",
            "",
            "### Constats clés",
        ]
        if findings:
            lines.extend(f"- {f}" for f in findings)
        else:
            lines.append("- Aucun signal critique détecté dans les données disponibles.")

        lines.extend([
            "",
            "### Recommandations",
            "- Explorer les entités via le module Graphe OSINT.",
            "- Vérifier manuellement les sources à haut risque.",
            "",
            "_Rapport généré sans LLM (Ollama indisponible)._",
        ])
        return "\n".join(lines)

    async def summarize_investigation(self, result: Dict[str, Any]) -> Dict[str, Any]:
        context = self.build_investigation_context(result)
        status = self.check_status()

        if status.get("available") and status.get("model_available"):
            prompt = (
                "Analyse les résultats OSINT suivants et rédige un rapport de renseignement structuré "
                "en français (Résumé exécutif, Constats clés, Évaluation du risque, Recommandations).\n\n"
                f"{context}"
            )
            summary = self._generate(prompt, system=SYSTEM_PROMPT)
            if summary:
                return {
                    "summary": summary,
                    "ai_powered": True,
                    "model": self._effective_model(),
                }

        return {
            "summary": self.fallback_summary(result),
            "ai_powered": False,
            "model": None,
        }

    async def investigate(self, message: str, playbook_id: Optional[str] = None) -> Dict[str, Any]:
        message = message.strip()
        if not message:
            raise ValueError("Message vide")

        target = pick_best_target(message)
        if not target:
            return {
                "action": "clarify",
                "reply": (
                    "Je n'ai pas détecté de cible OSINT dans votre message. "
                    "Précisez un email, domaine, IP, URL ou pseudo — par exemple :\n"
                    "• *Investigue john@company.com*\n"
                    "• *Analyse le domaine example.com*\n"
                    "• *OSINT sur 8.8.8.8*"
                ),
                "targets_found": [],
                "investigation": None,
            }

        entity_type = resolve_entity_type(target)
        suggested_playbook = playbook_id or suggest_playbook_id(entity_type)
        suggestion = playbook_engine.suggest(target)

        result = await playbook_engine.run(target=target, playbook_id=suggested_playbook)
        result_dict = result.to_dict()
        summary_data = await self.summarize_investigation(result_dict)

        reply = summary_data["summary"]
        if summary_data["ai_powered"]:
            reply = f"✅ Investigation terminée sur `{target}`.\n\n{reply}"
        else:
            reply = f"✅ Investigation terminée sur `{target}` (mode sans IA).\n\n{reply}"

        return {
            "action": "investigation_complete",
            "reply": reply,
            "target": target,
            "target_type": entity_type.value,
            "suggested_playbook_id": suggestion["suggested_playbook_id"],
            "playbook_id": result_dict["playbook_id"],
            "targets_found": extract_targets(message),
            "investigation": result_dict,
            "ai_powered": summary_data["ai_powered"],
            "model": summary_data.get("model"),
        }

    async def chat(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        message = message.strip()
        if not message:
            raise ValueError("Message vide")

        history = history or []

        if wants_investigation(message):
            inv = await self.investigate(message)
            return {
                "reply": inv["reply"],
                "action": inv["action"],
                "investigation": inv.get("investigation"),
                "target": inv.get("target"),
                "ai_powered": inv.get("ai_powered", False),
            }

        status = self.check_status()
        if status.get("available") and status.get("model_available"):
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            for item in history[-10:]:
                role = item.get("role", "user")
                if role in ("user", "assistant"):
                    messages.append({"role": role, "content": item.get("content", "")})
            messages.append({"role": "user", "content": message})

            reply = self._chat_generate(messages)
            if reply:
                return {"reply": reply, "action": "chat", "ai_powered": True}

        targets = extract_targets(message)
        reply = (
            "Investigator AI (mode hors-ligne) — Ollama n'est pas disponible.\n\n"
            "Je peux lancer des investigations OSINT si vous incluez une cible concrète :\n"
            "email, domaine, IP, URL ou pseudo.\n\n"
            "Exemple : *Investigue suspect@domain.com*"
        )
        if targets:
            reply += f"\n\nCibles détectées : {', '.join(targets)}"

        return {"reply": reply, "action": "chat", "ai_powered": False}


ai_investigator = AIInvestigator()
