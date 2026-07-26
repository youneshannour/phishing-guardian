from __future__ import annotations

import time
from typing import Dict, List

from models.playbook import Entity, EntityType, PluginStatus
from plugins.osint.base_plugin import InvestigationContext, OSINTPlugin
from services import osint_tools


class LeakCheckPlugin(OSINTPlugin):
  id = "leakcheck"
  name = "Leak Check (HIBP)"
  supported_types = {EntityType.EMAIL}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_leakcheck(target)
      duration = int((time.perf_counter() - start) * 1000)
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(EntityType.EMAIL, data["email"], self.id)]
      if data.get("found"):
        for source in data.get("sources", [])[:5]:
          entities.append(
            Entity(
              EntityType.UNKNOWN,
              source,
              self.id,
              metadata={"kind": "breach"},
            )
          )
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


class WhoisPlugin(OSINTPlugin):
  id = "whois"
  name = "WHOIS Lookup"
  supported_types = {EntityType.DOMAIN, EntityType.IP, EntityType.URL}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_whois(target)
      duration = int((time.perf_counter() - start) * 1000)
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities: List[Entity] = []
      record = data.get("data", {})
      if data.get("type") == "domain":
        entities.append(Entity(EntityType.DOMAIN, target, self.id))
        if record.get("org"):
          entities.append(
            Entity(
              EntityType.COMPANY,
              str(record["org"]),
              self.id,
              metadata={"source_field": "org"},
            )
          )
      else:
        entities.append(Entity(EntityType.IP, target, self.id))
        if record.get("asn_org"):
          entities.append(
            Entity(
              EntityType.COMPANY,
              str(record["asn_org"]),
              self.id,
              metadata={"source_field": "asn_org"},
            )
          )
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


class SherlockPlugin(OSINTPlugin):
  id = "sherlock"
  name = "Sherlock (Social Profiles)"
  supported_types = {EntityType.USERNAME, EntityType.EMAIL}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_sherlock(target)
      duration = int((time.perf_counter() - start) * 1000)
      if data.get("unavailable"):
        return self._build_result(
          PluginStatus.UNAVAILABLE,
          duration,
          data,
          error=data.get("error"),
        )
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [
        Entity(EntityType.USERNAME, data["username"], self.id),
      ]
      for site, info in (data.get("profiles") or {}).items():
        url = info.get("url_main") or info.get("url_user")
        if url:
          entities.append(
            Entity(
              EntityType.URL,
              url,
              self.id,
              metadata={"platform": site},
            )
          )
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


class VirusTotalPlugin(OSINTPlugin):
  id = "virustotal"
  name = "VirusTotal"
  supported_types = {
    EntityType.DOMAIN,
    EntityType.IP,
    EntityType.URL,
    EntityType.EMAIL,
  }
  # Pas de env_key : fallback local si clé absente

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_virustotal(target)
      duration = int((time.perf_counter() - start) * 1000)
      if data.get("unavailable"):
        return self._build_result(
          PluginStatus.UNAVAILABLE,
          duration,
          data,
          error=data.get("error"),
        )
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entity_type = {
        "domain": EntityType.DOMAIN,
        "ip": EntityType.IP,
        "url": EntityType.URL,
      }.get(data.get("type", ""), EntityType.UNKNOWN)
      entities = [Entity(entity_type, data.get("query") or target, self.id)]
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


class AbuseIPDBPlugin(OSINTPlugin):
  id = "abuseipdb"
  name = "AbuseIPDB"
  supported_types = {EntityType.IP, EntityType.DOMAIN, EntityType.EMAIL}
  # Fallback local si clé absente

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_abuseipdb(target)
      duration = int((time.perf_counter() - start) * 1000)
      if data.get("unavailable"):
        return self._build_result(
          PluginStatus.UNAVAILABLE,
          duration,
          data,
          error=data.get("error"),
        )
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = []
      if data.get("ip"):
        entities.append(Entity(EntityType.IP, str(data["ip"]), self.id))
      if data.get("domain") and data["domain"] not in ("N/A", None, data.get("ip")):
        entities.append(Entity(EntityType.DOMAIN, str(data["domain"]), self.id))
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


class DnsLookupPlugin(OSINTPlugin):
  id = "dns_lookup"
  name = "DNS Lookup"
  supported_types = {EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_dns_lookup(target)
      duration = int((time.perf_counter() - start) * 1000)
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(EntityType.DOMAIN, data["domain"], self.id)]
      for ip in (data.get("records") or {}).get("A", [])[:5]:
        entities.append(Entity(EntityType.IP, ip, self.id))
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(PluginStatus.ERROR, duration, {}, error=str(exc))


class EmailAuthPlugin(OSINTPlugin):
  id = "email_auth"
  name = "Email Auth (SPF/DKIM/DMARC)"
  supported_types = {EntityType.DOMAIN, EntityType.EMAIL, EntityType.URL}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_email_auth(target)
      duration = int((time.perf_counter() - start) * 1000)
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(EntityType.DOMAIN, data["domain"], self.id)]
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(PluginStatus.ERROR, duration, {}, error=str(exc))


class CrtShPlugin(OSINTPlugin):
  id = "crtsh"
  name = "Certificate Transparency (crt.sh)"
  supported_types = {EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_crtsh(target)
      duration = int((time.perf_counter() - start) * 1000)
      if data.get("unavailable"):
        return self._build_result(
          PluginStatus.UNAVAILABLE, duration, data, error=data.get("error")
        )
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(EntityType.DOMAIN, data["domain"], self.id)]
      for name in (data.get("unique_names") or [])[:10]:
        if name.startswith("*."):
          name = name[2:]
        if name and name != data["domain"]:
          entities.append(Entity(EntityType.DOMAIN, name, self.id))
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(PluginStatus.ERROR, duration, {}, error=str(exc))


class PhishingAnalyzePlugin(OSINTPlugin):
  id = "phishing_analyze"
  name = "Phishing Analyze"
  supported_types = {
    EntityType.EMAIL,
    EntityType.URL,
    EntityType.DOMAIN,
  }

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_phishing_analyze(target)
      duration = int((time.perf_counter() - start) * 1000)
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(context.target_type, target, self.id)]
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(PluginStatus.ERROR, duration, {}, error=str(exc))


class HibpOsintPlugin(OSINTPlugin):
  id = "hibp_osint"
  name = "OSINT léger (HIBP)"
  supported_types = {EntityType.EMAIL, EntityType.USERNAME}

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_hibp_osint(target)
      duration = int((time.perf_counter() - start) * 1000)
      entities = [Entity(context.target_type, target, self.id)]
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(PluginStatus.ERROR, duration, {}, error=str(exc))


class BlocklistCheckPlugin(OSINTPlugin):
  id = "blocklist_check"
  name = "Blocklists (URLHaus / OpenPhish)"
  supported_types = {
    EntityType.URL,
    EntityType.DOMAIN,
    EntityType.EMAIL,
  }

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      from services.threat_feeds import run_blocklist_check

      data = run_blocklist_check(target)
      duration = int((time.perf_counter() - start) * 1000)
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = []
      if data.get("host"):
        entities.append(Entity(EntityType.DOMAIN, data["host"], self.id))
      if data.get("url"):
        entities.append(Entity(EntityType.URL, data["url"], self.id))
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(PluginStatus.ERROR, duration, {}, error=str(exc))


class ShodanIPPlugin(OSINTPlugin):
  id = "shodan_ip"
  name = "Shodan IP"
  supported_types = {EntityType.IP}
  env_key = "SHODAN_API_KEY"

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_shodan_ip(target)
      duration = int((time.perf_counter() - start) * 1000)
      if data.get("unavailable"):
        return self._build_result(
          PluginStatus.UNAVAILABLE,
          duration,
          data,
          error=data.get("error"),
        )
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(EntityType.IP, target, self.id)]
      for hostname in data.get("hostnames", [])[:5]:
        entities.append(Entity(EntityType.DOMAIN, hostname, self.id))
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


class ShodanSearchPlugin(OSINTPlugin):
  id = "shodan_search"
  name = "Shodan Search"
  supported_types = {EntityType.DOMAIN, EntityType.COMPANY}
  env_key = "SHODAN_API_KEY"

  def run(self, target: str, context: InvestigationContext):
    start = time.perf_counter()
    try:
      data = osint_tools.run_shodan_search(target)
      duration = int((time.perf_counter() - start) * 1000)
      if data.get("unavailable"):
        return self._build_result(
          PluginStatus.UNAVAILABLE,
          duration,
          data,
          error=data.get("error"),
        )
      if not data.get("success"):
        return self._build_result(
          PluginStatus.ERROR, duration, data, error=data.get("error")
        )
      entities = [Entity(context.target_type, target, self.id)]
      for match in data.get("matches", []):
        ip = match.get("ip_str")
        if ip:
          entities.append(Entity(EntityType.IP, ip, self.id))
      return self._build_result(PluginStatus.SUCCESS, duration, data, entities)
    except Exception as exc:
      duration = int((time.perf_counter() - start) * 1000)
      return self._build_result(
        PluginStatus.ERROR, duration, {}, error=str(exc)
      )


PLUGIN_REGISTRY: Dict[str, OSINTPlugin] = {
  p.id: p
  for p in [
    LeakCheckPlugin(),
    WhoisPlugin(),
    SherlockPlugin(),
    VirusTotalPlugin(),
    AbuseIPDBPlugin(),
    ShodanIPPlugin(),
    ShodanSearchPlugin(),
    DnsLookupPlugin(),
    EmailAuthPlugin(),
    CrtShPlugin(),
    PhishingAnalyzePlugin(),
    HibpOsintPlugin(),
    BlocklistCheckPlugin(),
  ]
}


def get_plugin(plugin_id: str) -> OSINTPlugin:
  plugin = PLUGIN_REGISTRY.get(plugin_id)
  if not plugin:
    raise KeyError(f"Plugin inconnu: {plugin_id}")
  return plugin


def list_plugins() -> List[OSINTPlugin]:
  return list(PLUGIN_REGISTRY.values())
