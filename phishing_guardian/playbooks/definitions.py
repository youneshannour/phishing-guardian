from __future__ import annotations

from models.playbook import EntityType, PlaybookDefinition, PlaybookStep, TargetTransform

PLAYBOOKS: dict[str, PlaybookDefinition] = {
    "person_osint": PlaybookDefinition(
        id="person_osint",
        name="Person OSINT",
        description="Investigation complète sur une personne (email, fuites, profils sociaux).",
        icon="👤",
        target_types=[EntityType.EMAIL, EntityType.USERNAME],
        steps=[
            PlaybookStep("leakcheck", TargetTransform.SAME),
            PlaybookStep("sherlock", TargetTransform.USERNAME_FROM_EMAIL),
            PlaybookStep("whois", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("virustotal", TargetTransform.DOMAIN_FROM_EMAIL),
        ],
    ),
    "company_osint": PlaybookDefinition(
        id="company_osint",
        name="Company OSINT",
        description="Analyse d'une entreprise via son domaine et son exposition réseau.",
        icon="🏢",
        target_types=[EntityType.DOMAIN, EntityType.COMPANY],
        steps=[
            PlaybookStep("whois", TargetTransform.SAME),
            PlaybookStep("virustotal", TargetTransform.SAME),
            PlaybookStep("shodan_search", TargetTransform.SAME),
        ],
    ),
    "domain_osint": PlaybookDefinition(
        id="domain_osint",
        name="Domain OSINT",
        description="WHOIS, réputation et exposition Shodan d'un domaine.",
        icon="🌐",
        target_types=[EntityType.DOMAIN, EntityType.URL],
        steps=[
            PlaybookStep("whois", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("virustotal", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("shodan_search", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("shodan_ip", TargetTransform.IP_FROM_DOMAIN),
        ],
    ),
    "social_media_osint": PlaybookDefinition(
        id="social_media_osint",
        name="Social Media OSINT",
        description="Recherche de profils sur les réseaux sociaux via Sherlock.",
        icon="📱",
        target_types=[EntityType.USERNAME, EntityType.EMAIL],
        steps=[
            PlaybookStep("sherlock", TargetTransform.USERNAME_FROM_EMAIL),
        ],
    ),
    "breach_check": PlaybookDefinition(
        id="breach_check",
        name="Breach Check",
        description="Vérification rapide des fuites de données (HaveIBeenPwned).",
        icon="🔓",
        target_types=[EntityType.EMAIL],
        steps=[
            PlaybookStep("leakcheck", TargetTransform.SAME),
        ],
    ),
    "ip_osint": PlaybookDefinition(
        id="ip_osint",
        name="IP OSINT",
        description="Enrichissement IP : Shodan, réputation AbuseIPDB, VirusTotal.",
        icon="📡",
        target_types=[EntityType.IP],
        steps=[
            PlaybookStep("shodan_ip", TargetTransform.SAME),
            PlaybookStep("abuseipdb", TargetTransform.SAME),
            PlaybookStep("virustotal", TargetTransform.SAME),
            PlaybookStep("whois", TargetTransform.SAME),
        ],
    ),
}


def get_playbook(playbook_id: str) -> PlaybookDefinition:
    playbook = PLAYBOOKS.get(playbook_id)
    if not playbook:
        raise KeyError(f"Playbook inconnu: {playbook_id}")
    return playbook


def list_playbooks() -> list[PlaybookDefinition]:
    return list(PLAYBOOKS.values())
