from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

import requests

from services.entity_resolver import resolve_entity_type, suggest_playbook_id
from services.nl_target_extractor import extract_targets, pick_best_target, wants_investigation
from services.playbook_engine import playbook_engine

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "90"))
OLLAMA_CHAT_TOKENS = int(os.getenv("OLLAMA_CHAT_TOKENS", "384"))
OLLAMA_REPORT_TOKENS = int(os.getenv("OLLAMA_REPORT_TOKENS", "768"))

PREFERRED_MODELS = (
    "tinyllama",
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


KNOWN_CONTEXT = {
    "8.8.8.8": (
        "**8.8.8.8** est le DNS public de **Google** (Google Public DNS).\n\n"
        "Ce n’est ni un VPN, ni un proxy, ni un service d’anonymat.\n"
        "Usage typique : résoudre des noms de domaine en adresses IP.\n\n"
        "Pour une investigation OSINT complète (Shodan, AbuseIPDB, VirusTotal…), écrivez :\n"
        "*Investigue 8.8.8.8*"
    ),
    "8.8.4.4": (
        "**8.8.4.4** est le DNS secondaire public de **Google**.\n\n"
        "Pour une investigation OSINT : *Investigue 8.8.4.4*"
    ),
    "1.1.1.1": (
        "**1.1.1.1** est le DNS public de **Cloudflare**.\n\n"
        "Pour une investigation OSINT : *Investigue 1.1.1.1*"
    ),
}


class AIInvestigator:
    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self._active_model: Optional[str] = None
        self.reload_config(base_url=base_url, model=model, timeout=timeout)

    def reload_config(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Relit OLLAMA_* depuis l'environnement (après load_dotenv)."""
        self.base_url = (
            base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        ).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "tinyllama")
        self.timeout = int(
            timeout if timeout is not None else os.getenv("OLLAMA_TIMEOUT", "90")
        )

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
        self.reload_config()
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
                "base_url": self.base_url,
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
                "base_url": self.base_url,
                "configured_model": self.model,
                "active_model": None,
                "model_available": False,
                "models": [],
                "error": str(exc),
            }

    def _is_tiny_model(self) -> bool:
        name = (self._effective_model() or "").lower()
        return any(tag in name for tag in ("tinyllama", "tiny", "phi", "gemma:2b", "1b", "2b"))

    def _system_prompt(self) -> str:
        if self._is_tiny_model():
            return (
                "Tu es Investigator AI (OSINT). Réponds en français, court et concret. "
                "Ne invente pas de faits."
            )
        return SYSTEM_PROMPT

    def _generate(self, prompt: str, system: Optional[str] = None) -> Optional[str]:
        payload = {
            "model": self._effective_model(),
            "prompt": prompt,
            "stream": False,
            "keep_alive": "10m",
            "options": {
                "temperature": 0.3,
                "num_predict": OLLAMA_REPORT_TOKENS,
            },
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
            return (resp.json().get("response") or "").strip() or None
        except (requests.RequestException, ValueError, KeyError):
            return None

    def _chat_generate(self, messages: List[Dict[str, str]]) -> Optional[str]:
        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self._effective_model(),
                    "messages": messages,
                    "stream": False,
                    "keep_alive": "10m",
                    "options": {
                        "temperature": 0.4,
                        "num_predict": OLLAMA_CHAT_TOKENS,
                    },
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return (resp.json().get("message", {}) or {}).get("content", "").strip() or None
        except (requests.RequestException, ValueError, KeyError, TypeError):
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
        status = await asyncio.to_thread(self.check_status)

        # tinyllama invente souvent des faits → rapport déterministe préféré
        if self._is_tiny_model() or not (
            status.get("available") and status.get("model_available")
        ):
            return {
                "summary": self.fallback_summary(result),
                "ai_powered": False,
                "model": None,
            }

        if status.get("available") and status.get("model_available"):
            prompt = (
                "Analyse les résultats OSINT suivants et rédige un rapport de renseignement structuré "
                "en français (Résumé exécutif, Constats clés, Évaluation du risque, Recommandations).\n\n"
                "N'invente aucune information absente du contexte.\n\n"
                f"{context}"
            )
            summary = await asyncio.to_thread(
                self._generate, prompt, self._system_prompt()
            )
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

    def _quick_target_reply(self, message: str) -> Optional[Dict[str, Any]]:
        """Réponse rapide pour une cible seule — évite Ollama + évite playbook long."""
        stripped = message.strip().strip(".,;:!?\"'")
        known = KNOWN_CONTEXT.get(stripped)
        if known:
            return {"reply": known, "action": "chat", "ai_powered": False}

        targets = extract_targets(message)
        if not targets:
            return None
        if stripped.lower() not in {t.lower() for t in targets}:
            return None

        target = pick_best_target(message) or targets[0]
        entity_type = resolve_entity_type(target)
        playbook = suggest_playbook_id(entity_type)
        reply = (
            f"Cible détectée : `{target}` (type **{entity_type.value}**).\n\n"
            "Pour lancer l’investigation OSINT (playbooks + outils), écrivez par exemple :\n"
            f"*Investigue {target}*\n\n"
            f"Playbook suggéré : `{playbook}`.\n"
            "Astuce : vous pouvez aussi utiliser le panneau **Playbooks** "
            "(plus fiable si l’investigation est longue)."
        )
        return {"reply": reply, "action": "clarify", "ai_powered": False, "target": target}

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

        quick = self._quick_target_reply(message)
        if quick:
            return quick

        status = await asyncio.to_thread(self.check_status)
        if status.get("available") and status.get("model_available") and not self._is_tiny_model():
            messages = [{"role": "system", "content": self._system_prompt()}]
            for item in history[-6:]:
                role = item.get("role", "user")
                if role in ("user", "assistant"):
                    messages.append({"role": role, "content": item.get("content", "")})
            messages.append({"role": "user", "content": message})

            reply = await asyncio.to_thread(self._chat_generate, messages)
            if reply:
                return {
                    "reply": reply,
                    "action": "chat",
                    "ai_powered": True,
                    "model": self._effective_model(),
                }

        targets = extract_targets(message)
        reply = (
            "Investigator AI — pour une investigation OSINT, précisez un mot-clé "
            "(Investigue / Analyse / OSINT) + une cible.\n\n"
            "Exemples :\n"
            "• *Investigue 8.8.8.8*\n"
            "• *Analyse suspect@domain.com*\n"
            "• *OSINT sur le pseudo johndoe*\n\n"
            "Sinon utilisez le panneau **Playbooks** (recommandé pour les scans longs)."
        )
        if targets:
            reply += f"\n\nCibles détectées : {', '.join(targets)}"

        return {"reply": reply, "action": "chat", "ai_powered": False}


ai_investigator = AIInvestigator()
