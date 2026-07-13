#!/usr/bin/env python3
import logging

log = logging.getLogger("scorer")

WIDELY_USED = {
    "nginx", "apache", "apache httpd", "openssl", "openssh",
    "ubuntu", "debian", "windows", "linux kernel", "log4j",
    "spring framework", "jenkins", "docker", "kubernetes",
    "php", "python", "nodejs", "mysql", "postgresql",
}

SCORE_WEIGHTS = {
    "KEV":     50,
    "RCE":     40,
    "RCE-KEV": 25,
    "CRIT":    30,
    "HIGH":    20,
    "EPSS":    15,
    "T1":      20,
    "WIDE":    10,
    "POC":     10,
    "NEW":     10,
}

TIER_LABELS = {
    0: "CRITICAL — ACT NOW",
    1: "HIGH PRIORITY",
    2: "STANDARD",
    3: "MONITOR",
}


class Scorer:
    def score(self, cve_data: dict, context: dict) -> dict:
        tags = []
        score = 0

        if context.get("is_kev"):
            tags.append("KEV")
            score += SCORE_WEIGHTS["KEV"]

        if context.get("allows_rce"):
            tags.append("RCE")
            score += SCORE_WEIGHTS["RCE"]

        if context.get("rce_in_kev"):
            tags.append("RCE-KEV")
            score += SCORE_WEIGHTS["RCE-KEV"]

        cvss = cve_data.get("cvss_score", 0)
        if cvss >= 9.0:
            tags.append("CRIT")
            score += SCORE_WEIGHTS["CRIT"]
        elif cvss >= 7.0:
            tags.append("HIGH")
            score += SCORE_WEIGHTS["HIGH"]

        if cve_data.get("epss_score", 0) > 0.5:
            tags.append("EPSS")
            score += SCORE_WEIGHTS["EPSS"]

        if cve_data.get("tier", 2) == 1:
            tags.append("T1")
            score += SCORE_WEIGHTS["T1"]

        product = cve_data.get("product", "").lower()
        if any(w in product for w in WIDELY_USED):
            tags.append("WIDE")
            score += SCORE_WEIGHTS["WIDE"]

        refs = cve_data.get("references", [])
        poc_domains = ["github.com", "exploit-db.com", "packetstormsecurity.com"]
        if any(d in r for r in refs for d in poc_domains):
            tags.append("POC")
            score += SCORE_WEIGHTS["POC"]

        if cve_data.get("age_in_days", 999) < 3:
            tags.append("NEW")
            score += SCORE_WEIGHTS["NEW"]

        if "KEV" in tags and "RCE" in tags:
            priority_tier = 0
        elif score >= 90:
            priority_tier = 0
        elif score >= 70:
            priority_tier = 1
        elif score >= 40:
            priority_tier = 2
        else:
            priority_tier = 3

        tag_order = list(SCORE_WEIGHTS.keys())
        tags.sort(key=lambda t: tag_order.index(t) if t in tag_order else 99)

        log.debug(f"{cve_data.get('cve_id')}: score={score} tier={priority_tier} tags={tags}")

        return {
            "tags": tags,
            "composite_score": score,
            "priority_tier": priority_tier,
            "tier_label": TIER_LABELS[priority_tier],
        }
