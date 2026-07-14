#!/usr/bin/env python3
import os
import re
import logging
import requests
from typing import Optional

log = logging.getLogger("context_assembler")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RCE_KEYWORDS = [
    "remote code execution", "execute arbitrary code",
    "arbitrary command", "code injection", "command injection",
    "remote command execution", "unauthenticated rce",
]

_kev_cache: Optional[dict] = None


def load_kev_catalogue() -> dict:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        log.info(f"CISA KEV catalogue loaded: {len(_kev_cache)} entries")
    except Exception as e:
        log.warning(f"Failed to load CISA KEV catalogue: {e}")
        _kev_cache = {}
    return _kev_cache


def fetch_advisory_summary(url: str) -> str:
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "ThreatForge/1.0"})
        resp.raise_for_status()
        plain = re.sub(r"<[^>]+>", " ", resp.text)
        plain = re.sub(r"\s+", " ", plain).strip()
        return plain[:1500]
    except Exception as e:
        log.debug(f"Advisory fetch failed for {url}: {e}")
        return ""


def detect_rce_in_kev(kev_entry: dict) -> bool:
    desc = kev_entry.get("shortDescription", "").lower()
    return any(kw in desc for kw in RCE_KEYWORDS)


def parse_cvss_vector(vector: str) -> dict:
    components = {}
    if not vector:
        return components
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            components[k] = v
    return components


class ContextAssembler:
    def __init__(self):
        self.kev = load_kev_catalogue()

    def assemble(self, cve_data: dict) -> dict:
        cve_id = cve_data.get("cve_id", "")
        context = {
            "cve_id": cve_id,
            "description": cve_data.get("cve_description", ""),
            "cvss_score": cve_data.get("cvss_score", 0),
            "severity": cve_data.get("severity", "unknown"),
            "is_kev": cve_data.get("is_kev", False),
            "age_in_days": cve_data.get("age_in_days", 0),
            "kev_short_description": "",
            "kev_required_action": "",
            "rce_in_kev": False,
            "advisory_summary": "",
            "cvss_vector": cve_data.get("cvss_vector", ""),
            "cvss_components": {},
            "allows_rce": False,
            "rce_vector": "unknown",
        }

        if context["is_kev"] and cve_id in self.kev:
            kev_entry = self.kev[cve_id]
            context["kev_short_description"] = kev_entry.get("shortDescription", "")
            context["kev_required_action"] = kev_entry.get("requiredAction", "")
            context["rce_in_kev"] = detect_rce_in_kev(kev_entry)
            log.debug(f"{cve_id}: KEV entry found, rce_in_kev={context['rce_in_kev']}")

        if context["cvss_vector"]:
            components = parse_cvss_vector(context["cvss_vector"])
            context["cvss_components"] = components
            if (components.get("AV") == "N" and
                    components.get("PR") == "N" and
                    components.get("UI") == "N"):
                context["allows_rce"] = True
                context["rce_vector"] = "network"
                log.debug(f"{cve_id}: Network RCE detected via CVSS vector")

        return context

    def enrich_advisory(self, context: dict, cve_data: dict) -> dict:
        """Fetch advisory reference summaries (network I/O). Call only for the
        final, already-trimmed CVE set — not every scoring candidate."""
        references = cve_data.get("references", [])
        for ref in references[:2]:
            summary = fetch_advisory_summary(ref)
            if summary:
                context["advisory_summary"] += summary[:500] + " "
        return context

    def format_for_prompt(self, context: dict) -> str:
        lines = [
            f"CVE: {context['cve_id']}",
            f"Description: {context['description']}",
            f"CVSS Score: {context['cvss_score']} ({context['severity'].upper()})",
            f"Age: {context['age_in_days']} days old",
        ]
        if context["is_kev"]:
            lines.append("CISA KEV Status: ACTIVELY EXPLOITED IN THE WILD")
            if context["kev_short_description"]:
                lines.append(f"CISA KEV Description: {context['kev_short_description']}")
            if context["kev_required_action"]:
                lines.append(f"CISA KEV Required Action: {context['kev_required_action']}")
        if context["allows_rce"]:
            lines.append("RCE: YES — network-exploitable (AV:N/PR:N/UI:N)")
        if context["advisory_summary"]:
            lines.append(f"Advisory Context: {context['advisory_summary'][:800]}")
        return "\n".join(lines)
