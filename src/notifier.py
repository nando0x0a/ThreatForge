#!/usr/bin/env python3
import os
import logging
import requests
from datetime import datetime

log = logging.getLogger("notifier")

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
DISCORD_USERNAME = "ThreatForge"
# Discord hard limit is 2000 chars; stay under with buffer
_CHUNK = 1900

OUTPUT_LABELS = {
    1: "Security advisory (management)",
    2: "Technical findings (SOC analyst)",
    3: "Suricata signature drafts",
    4: "IoC list",
    5: "Threat hunting queries (CrowdStrike + Netflow)",
    6: "Patch recommendations",
}

OUTPUT_DESCRIPTIONS = {
    1: "Non-technical risk summary for CISO/management. Covers business impact, affected systems, and recommended action with a time-bound remediation timeline.",
    2: "Deep-dive for SOC analysts. Attack vector breakdown, CVSS analysis, observable behaviour on the wire, detection coverage gaps, and immediate response steps.",
    3: "Draft Suricata IDS/IPS rule targeting network-observable behaviour. Includes MITRE ATT&CK tag, KEV status, classtype, and sid. Marked experimental — review before deploying.",
    4: "Structured list of IPs, domains, URLs, file hashes, user-agents, and URI paths extracted from KEV entry, vendor advisory, and OSINT. Confidence-rated per indicator.",
    5: "Ready-to-run CrowdStrike Event Search queries and nfdump Netflow queries. Targets C2 connections, post-exploitation process chains, and protocol anomalies.",
    6: "Upgrade path, rollback risk assessment, and an Ansible playbook (apt module) to patch the affected package across your inventory. Includes dry-run command.",
}


def _post(message: str) -> bool:
    if not DISCORD_WEBHOOK_URL:
        log.error("DISCORD_WEBHOOK_URL not set")
        return False
    chunks = [message[i:i + _CHUNK] for i in range(0, len(message), _CHUNK)]
    for chunk in chunks:
        try:
            resp = requests.post(
                DISCORD_WEBHOOK_URL,
                json={"content": chunk, "username": DISCORD_USERNAME},
                timeout=10,
            )
            resp.raise_for_status()
        except Exception as e:
            log.error(f"Discord post failed: {e}")
            return False
    return True


class DiscordNotifier:
    def post_brief_report(self, enriched_cves: list[dict]) -> None:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"**ThreatForge — Daily Report**",
            f"{now} · {len(enriched_cves)} actionable CVE(s) found",
            "",
        ]
        for i, cve in enumerate(enriched_cves, 1):
            tags_str = " ".join(f"[{t}]" for t in cve.get("tags", []))
            lines += [
                f"**{i}. {cve['cve_id']}** — {cve.get('product', '').upper()}",
                f"   Tags: {tags_str}  Score: {cve.get('composite_score', 0)}",
                f"   **{cve.get('tier_label', 'UNKNOWN')}**",
                f"   {cve.get('context', {}).get('description', '')[:120]}...",
                "",
            ]
        lines += [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "**What would you like me to produce?**",
            "",
        ]
        for num, label in OUTPUT_LABELS.items():
            desc = OUTPUT_DESCRIPTIONS.get(num, "")
            lines += [
                f"**{num}. {label}**",
                f"> {desc}",
                "",
            ]
        lines += [
            "**0. All of the above**",
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "**Produce outputs:**",
            "`docker exec threatforge python3 src/orchestrate.py --produce 1,3,6`",
            "*(comma-separated, no spaces — e.g. `1,3,6` or `0` for all)*",
        ]
        _post("\n".join(lines))
        log.info(f"Brief report posted to Discord: {len(enriched_cves)} CVEs")

    def post_output(self, output_num: int, cve_data: dict, result: dict) -> None:
        """Post a single generated output to Discord with markdown rendering."""
        label = OUTPUT_LABELS.get(output_num, f"Output {output_num}")
        cve_id = cve_data.get("cve_id", "")
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        tier = cve_data.get("tier_label", "")
        banner = (
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🛡️ **{label.upper()}**\n"
            f"**CVE:** {cve_id}  |  **{tier}**  |  Score: {cve_data.get('composite_score', 0)}\n"
            f"**Tags:** {tags_str}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        content = result.get("content", "")
        full = banner + content
        chunks = [full[i:i + _CHUNK] for i in range(0, len(full), _CHUNK)]
        for chunk in chunks:
            _post(chunk)

    def post_outputs_complete(self, enriched_cves: list[dict], selected: list[int]) -> None:
        labels = [OUTPUT_LABELS.get(n, f"Output {n}") for n in selected]
        cve_ids = [c["cve_id"] for c in enriched_cves]
        _post(
            f"**ThreatForge — All outputs posted above** ✓\n"
            f"CVEs: {', '.join(cve_ids)}\n"
            f"Produced: {', '.join(labels)}"
        )

    def post_empty_report(self) -> None:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        _post(f"**ThreatForge — Daily Report**\n{now} · No actionable CVEs found today.")
