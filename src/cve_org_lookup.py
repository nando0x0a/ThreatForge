#!/usr/bin/env python3
import logging
import requests

log = logging.getLogger("cve_org_lookup")

CVE_ORG_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"


def severity_band(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def fetch_cna_metrics(cve_id: str) -> dict:
    """Fetch the CNA-published CVSS metrics from the official CVE Program
    record (cve.org / cveawg.mitre.org). This is the vendor/CNA's own
    assessment — often factoring in temporal/environmental context like
    exploit maturity — as opposed to NVD's independently recalculated base
    score, which is what vulnx surfaces elsewhere in the pipeline."""
    url = CVE_ORG_API.format(cve_id=cve_id)
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "ThreatForge/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.debug(f"cve.org lookup failed for {cve_id}: {e}")
        return {}

    metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
    for entry in metrics:
        for key, val in entry.items():
            if key.startswith("cvssV") and isinstance(val, dict) and "baseScore" in val:
                score = val["baseScore"]
                return {
                    "cvss_score": score,
                    "cvss_version": val.get("version", key.replace("cvssV", "").replace("_", ".")),
                    "severity": val.get("baseSeverity", severity_band(score)).upper(),
                    "source_url": CVE_ORG_URL.format(cve_id=cve_id),
                }
    return {}


def check_discrepancy(nvd_score: float, cve_id: str) -> dict:
    """Compare vulnx/NVD's CVSS score against cve.org's CNA-published score.
    Returns {} if cve.org has no data for this CVE, or if the two sources
    agree on severity band. Otherwise returns a note with both sources
    attributed, for surfacing in prompts, output headers, and Discord."""
    cna = fetch_cna_metrics(cve_id)
    if not cna:
        return {}

    nvd_band = severity_band(nvd_score)
    if nvd_band == cna["severity"]:
        return {}

    return {
        "has_discrepancy": True,
        "nvd_score": nvd_score,
        "nvd_severity": nvd_band,
        "cna_score": cna["cvss_score"],
        "cna_severity": cna["severity"],
        "cna_version": cna["cvss_version"],
        "cna_source_url": cna["source_url"],
    }
