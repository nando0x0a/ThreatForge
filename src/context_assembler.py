#!/usr/bin/env python3
import os
import re
import logging
import requests
from typing import Optional
from urllib.parse import urlparse

import cve_org_lookup

log = logging.getLogger("context_assembler")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
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
            "description": cve_data.get("description", ""),
            "cvss_score": cve_data.get("cvss_score", 0),
            "severity": cve_data.get("severity", "unknown"),
            "is_kev": cve_data.get("is_kev", False),
            "age_in_days": cve_data.get("age_in_days", 0),
            "kev_short_description": "",
            "kev_required_action": "",
            "rce_in_kev": False,
            "advisory_summary": "",
            "cvss_vector": cve_data.get("cvss_metrics", ""),
            "cvss_components": {},
            "allows_rce": False,
            "rce_vector": "unknown",
            "severity_discrepancy": {},
            "sources": [],
            "poc_available": cve_data.get("is_poc", False),
            "poc_count": cve_data.get("poc_count") or 0,
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
        """Fetch advisory reference summaries and cross-check severity against
        cve.org (network I/O). Call only for the final, already-trimmed CVE
        set — not every scoring candidate. Builds the numbered source list
        every produced output cites from, in the order sources are added."""
        cve_id = context["cve_id"]
        sources = [{"label": "NVD", "url": NVD_URL.format(cve_id=cve_id)}]

        if context["is_kev"]:
            sources.append({"label": "CISA Known Exploited Vulnerabilities Catalog", "url": CISA_KEV_CATALOG_URL})

        references = [c.get("url") for c in cve_data.get("citations", []) if c.get("url")]
        for ref in references[:2]:
            summary = fetch_advisory_summary(ref)
            if summary:
                context["advisory_summary"] += summary[:500] + " "
                domain = urlparse(ref).netloc or ref
                sources.append({"label": domain, "url": ref})

        cna_metrics = cve_org_lookup.fetch_cna_metrics(cve_id)
        context["severity_discrepancy"] = cve_org_lookup.check_discrepancy(context["cvss_score"], cna_metrics)
        if cna_metrics:
            sources.append({"label": "CVE.org (CNA-published record)", "url": cna_metrics["source_url"]})

        # PoC availability — vulnx tracks this with per-entry source attribution
        # (is_poc/poc_count/pocs). No packet-capture (PCAP) data is tracked by
        # any source this pipeline has access to — there's no equivalent signal
        # to surface for that, so it's stated as a fixed caveat in the
        # signatures prompt template instead of computed here.
        for poc in (cve_data.get("pocs") or [])[:2]:
            if poc.get("url"):
                sources.append({"label": f"PoC ({poc.get('source', 'unknown')})", "url": poc["url"]})

        context["sources"] = sources
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

        if context.get("poc_available"):
            lines.append(f"PoC Availability: {context['poc_count']} public proof-of-concept(s) known to exist (see PoC sources below).")
        else:
            lines.append("PoC Availability: No public proof-of-concept known.")

        sources = context.get("sources") or []
        if sources:
            lines.append("")
            lines.append(
                "SOURCES — cite specific factual claims inline using [N] matching the "
                "numbers below, and end the output with a \"## Sources\" section listing "
                "them exactly as shown:"
            )
            for i, src in enumerate(sources, 1):
                lines.append(f"[{i}] {src['label']} — {src['url']}")

        disc = context.get("severity_discrepancy")
        if disc and disc.get("has_discrepancy"):
            nvd_idx = next((i for i, s in enumerate(sources, 1) if s["label"] == "NVD"), 1)
            cna_idx = next((i for i, s in enumerate(sources, 1) if "CVE.org" in s["label"]), len(sources))
            lines.append(
                f"\nSEVERITY DISCREPANCY BETWEEN SOURCES [{nvd_idx}] and [{cna_idx}] — cite both explicitly:\n"
                f"  [{nvd_idx}] NVD: CVSS {disc['nvd_score']} ({disc['nvd_severity']})\n"
                f"  [{cna_idx}] CVE.org (CNA-published, CVSS v{disc['cna_version']}): "
                f"{disc['cna_score']} ({disc['cna_severity']})"
            )
        return "\n".join(lines)
