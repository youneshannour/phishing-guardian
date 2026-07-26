from __future__ import annotations

from models.playbook import EntityType, PlaybookDefinition, PlaybookStep, TargetTransform

PLAYBOOKS: dict[str, PlaybookDefinition] = {
    "phishing_triage": PlaybookDefinition(
        id="phishing_triage",
        name="Phishing Triage",
        description="Triage phishing : heuristiques, SPF/DKIM/DMARC, DNS, VirusTotal, certificats.",
        icon="PH",
        target_types=[EntityType.EMAIL, EntityType.URL, EntityType.DOMAIN],
        steps=[
            PlaybookStep("phishing_analyze", TargetTransform.SAME),
            PlaybookStep("blocklist_check", TargetTransform.SAME),
            PlaybookStep("email_auth", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("dns_lookup", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("virustotal", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("crtsh", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("abuseipdb", TargetTransform.IP_FROM_DOMAIN),
            PlaybookStep("leakcheck", TargetTransform.SAME),
        ],
    ),
    "person_osint": PlaybookDefinition(
        id="person_osint",
        name="Person OSINT",
        description="Investigation complète sur une personne (email, fuites, profils sociaux).",
        icon="PE",
        target_types=[EntityType.EMAIL, EntityType.USERNAME],
        steps=[
            PlaybookStep("leakcheck", TargetTransform.SAME),
            PlaybookStep("sherlock", TargetTransform.USERNAME_FROM_EMAIL),
            PlaybookStep("whois", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("virustotal", TargetTransform.DOMAIN_FROM_EMAIL),
            PlaybookStep("email_auth", TargetTransform.DOMAIN_FROM_EMAIL),
        ],
    ),
    "company_osint": PlaybookDefinition(
        id="company_osint",
        name="Company OSINT",
        description="Analyse d'une entreprise via son domaine et son exposition réseau.",
        icon="CO",
        target_types=[EntityType.DOMAIN, EntityType.COMPANY],
        steps=[
            PlaybookStep("whois", TargetTransform.SAME),
            PlaybookStep("dns_lookup", TargetTransform.SAME),
            PlaybookStep("email_auth", TargetTransform.SAME),
            PlaybookStep("virustotal", TargetTransform.SAME),
            PlaybookStep("crtsh", TargetTransform.SAME),
            PlaybookStep("shodan_search", TargetTransform.SAME),
        ],
    ),
    "domain_osint": PlaybookDefinition(
        id="domain_osint",
        name="Domain OSINT",
        description="WHOIS, DNS, auth email, réputation et exposition Shodan d'un domaine.",
        icon="DM",
        target_types=[EntityType.DOMAIN, EntityType.URL],
        steps=[
            PlaybookStep("whois", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("dns_lookup", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("email_auth", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("virustotal", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("crtsh", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("shodan_search", TargetTransform.DOMAIN_FROM_URL),
            PlaybookStep("shodan_ip", TargetTransform.IP_FROM_DOMAIN),
        ],
    ),
    "social_media_osint": PlaybookDefinition(
        id="social_media_osint",
        name="Social Media OSINT",
        description="Recherche de profils sur les réseaux sociaux via Sherlock.",
        icon="SM",
        target_types=[EntityType.USERNAME, EntityType.EMAIL],
        steps=[
            PlaybookStep("sherlock", TargetTransform.USERNAME_FROM_EMAIL),
        ],
    ),
    "breach_check": PlaybookDefinition(
        id="breach_check",
        name="Breach Check",
        description="Vérification rapide des fuites de données (HaveIBeenPwned).",
        icon="BR",
        target_types=[EntityType.EMAIL],
        steps=[
            PlaybookStep("leakcheck", TargetTransform.SAME),
            PlaybookStep("hibp_osint", TargetTransform.SAME),
        ],
    ),
    "ip_osint": PlaybookDefinition(
        id="ip_osint",
        name="IP OSINT",
        description="Enrichissement IP : Shodan, réputation AbuseIPDB, VirusTotal.",
        icon="IP",
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
