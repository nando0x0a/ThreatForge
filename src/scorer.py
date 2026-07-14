#!/usr/bin/env python3
import logging

from config_loader import load_config

log = logging.getLogger("scorer")


class Scorer:
    def __init__(self):
        cfg = load_config()
        scoring = cfg["scoring"]
        self.weights = scoring["weights"]
        self.widely_used = scoring["widely_used"]
        self.tier_labels = {int(k): v for k, v in scoring["tier_labels"].items()}
        self.tier_thresholds = scoring["tier_thresholds"]
        self.cvss_crit_threshold = scoring["cvss_crit_threshold"]
        self.cvss_high_threshold = cfg["pipeline"]["cvss_threshold"]
        self.epss_threshold = cfg["pipeline"]["epss_threshold"]
        self.new_threshold_days = cfg["pipeline"]["new_threshold_days"]
        self.tag_order = list(self.weights.keys())

    def score(self, cve_data: dict, context: dict) -> dict:
        tags = []
        score = 0
        w = self.weights

        if context.get("is_kev"):
            tags.append("KEV")
            score += w["KEV"]

        if context.get("allows_rce"):
            tags.append("RCE")
            score += w["RCE"]

        if context.get("rce_in_kev"):
            tags.append("RCE-KEV")
            score += w["RCE-KEV"]

        cvss = cve_data.get("cvss_score", 0)
        if cvss >= self.cvss_crit_threshold:
            tags.append("CRIT")
            score += w["CRIT"]
        elif cvss >= self.cvss_high_threshold:
            tags.append("HIGH")
            score += w["HIGH"]

        if cve_data.get("epss_score", 0) > self.epss_threshold:
            tags.append("EPSS")
            score += w["EPSS"]

        if cve_data.get("tier", 2) == 1:
            tags.append("T1")
            score += w["T1"]

        product = cve_data.get("product", "").lower()
        if any(w_ in product for w_ in self.widely_used):
            tags.append("WIDE")
            score += w["WIDE"]

        # vulnx flags PoC availability directly (is_poc) — more reliable than
        # guessing from reference-URL domains, which vulnx doesn't expose anyway.
        if cve_data.get("is_poc", False):
            tags.append("POC")
            score += w["POC"]

        if cve_data.get("age_in_days", 999) < self.new_threshold_days:
            tags.append("NEW")
            score += w["NEW"]

        if "KEV" in tags and "RCE" in tags:
            priority_tier = 0
        elif score >= self.tier_thresholds["tier_0"]:
            priority_tier = 0
        elif score >= self.tier_thresholds["tier_1"]:
            priority_tier = 1
        elif score >= self.tier_thresholds["tier_2"]:
            priority_tier = 2
        else:
            priority_tier = 3

        tags.sort(key=lambda t: self.tag_order.index(t) if t in self.tag_order else 99)

        log.debug(f"{cve_data.get('cve_id')}: score={score} tier={priority_tier} tags={tags}")

        return {
            "tags": tags,
            "composite_score": score,
            "priority_tier": priority_tier,
            "tier_label": self.tier_labels[priority_tier],
        }
