# ThreatForge — Source Code Reference

All files live under `src/`. The pipeline entry point is `orchestrate.py`. Every module can be run standalone for testing.

---

## src/orchestrate.py

```python
#!/usr/bin/env python3
"""
ThreatForge — Main orchestration loop.
Reads products.txt, runs vulnx per product, filters CVEs,
assembles context, scores/tags, posts brief report to Slack,
and produces selected outputs on request.
"""

import os
import sys
import json
import subprocess
import logging
import click
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from context_assembler import ContextAssembler
from scorer import Scorer
from slack_notifier import SlackNotifier
from output_router import OutputRouter
from claude_caller import ClaudeCaller

load_dotenv("/opt/threatforge/config/.env")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/opt/threatforge/logs/threatforge.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("orchestrate")

PRODUCTS_FILE = "/opt/threatforge/config/products.txt"
CVE_AGE_DAYS = int(os.getenv("CVE_AGE_DAYS", 7))
CVSS_THRESHOLD = float(os.getenv("CVSS_THRESHOLD", 7.0))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/opt/threatforge/outputs"))


def load_products() -> list[dict]:
    """Load products.txt and return list of {name, tier} dicts."""
    products = []
    with open(PRODUCTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            name = parts[0].strip().lower()
            tier = int(parts[1].strip()) if len(parts) > 1 else 2
            products.append({"name": name, "tier": tier})
    return products


def query_vulnx(product_name: str) -> list[dict]:
    """Run vulnx search for a product and return filtered CVE list."""
    output_file = f"/tmp/vulnx_{product_name.replace(' ', '_')}.json"
    try:
        subprocess.run(
            ["vulnx", "search", product_name, "-j"],
            capture_output=True, text=True, check=True,
            stdout=open(output_file, "w"),
        )
    except subprocess.CalledProcessError as e:
        log.warning(f"vulnx failed for {product_name}: {e.stderr}")
        return []

    with open(output_file) as f:
        raw = json.load(f)

    # jq equivalent filter in Python
    results = raw.get("results", [])
    filtered = [
        r for r in results
        if r.get("age_in_days", 999) < CVE_AGE_DAYS
        and (r.get("cvss_score", 0) >= CVSS_THRESHOLD or r.get("is_kev", False))
    ]
    log.info(f"{product_name}: {len(results)} CVEs found, {len(filtered)} actionable")
    return filtered


def run_pipeline(
    products: list[dict] = None,
    single_cve: str = None,
    dry_run: bool = False,
) -> list[dict]:
    """
    Run the full intelligence pipeline.
    Returns a list of enriched, scored CVE dicts.
    """
    assembler = ContextAssembler()
    scorer = Scorer()
    enriched_cves = []

    if single_cve:
        # Force-process a specific CVE regardless of age/CVSS
        log.info(f"Processing single CVE: {single_cve}")
        cve_data = {"cve_id": single_cve, "product": "manual", "tier": 2}
        context = assembler.assemble(cve_data)
        scored = scorer.score(cve_data, context)
        enriched_cves.append({**cve_data, "context": context, **scored})
    else:
        products = products or load_products()
        for product in products:
            cves = query_vulnx(product["name"])
            for cve in cves:
                cve["product"] = product["name"]
                cve["tier"] = product["tier"]
                context = assembler.assemble(cve)
                scored = scorer.score(cve, context)
                enriched_cves.append({**cve, "context": context, **scored})

    # Sort: Tier 0 first, then by composite score descending
    enriched_cves.sort(key=lambda x: x.get("composite_score", 0), reverse=True)

    log.info(f"Pipeline complete: {len(enriched_cves)} actionable CVEs")
    return enriched_cves


@click.command()
@click.option("--product", default=None, help="Run pipeline for a single product")
@click.option("--cve", default=None, help="Force-process a specific CVE ID")
@click.option("--produce", default=None, help="Produce outputs: numbers 1-6 or 0 for all")
@click.option("--scheduled", is_flag=True, help="Scheduled run mode (cron trigger)")
@click.option("--dry-run", is_flag=True, help="Run pipeline without Claude calls or Slack posts")
def main(product, cve, produce, scheduled, dry_run):
    log.info(f"ThreatForge starting — mode: {'scheduled' if scheduled else 'manual'}")

    products = None
    if product:
        products = [{"name": product.lower(), "tier": 2}]

    enriched_cves = run_pipeline(
        products=products,
        single_cve=cve,
        dry_run=dry_run,
    )

    if not enriched_cves:
        log.info("No actionable CVEs found. Exiting.")
        if not dry_run:
            SlackNotifier().post_empty_report()
        return

    if dry_run:
        log.info("Dry run — skipping Slack post and output production.")
        for c in enriched_cves:
            print(f"  {c['cve_id']} | Score: {c['composite_score']} | Tags: {' '.join(c['tags'])}")
        return

    # Post brief findings report + output menu to Slack
    notifier = SlackNotifier()
    notifier.post_brief_report(enriched_cves)

    if produce:
        # Produce selected outputs
        selected = list(range(1, 7)) if produce == "0" else [int(x) for x in produce.split()]
        caller = ClaudeCaller()
        router = OutputRouter(OUTPUT_DIR)

        for cve_data in enriched_cves:
            for output_num in selected:
                log.info(f"Producing output {output_num} for {cve_data['cve_id']}")
                result = caller.produce(output_num, cve_data)
                router.save(output_num, cve_data, result)

        notifier.post_outputs_complete(enriched_cves, selected)

    log.info("ThreatForge run complete.")


if __name__ == "__main__":
    main()
```

---

## src/context_assembler.py

```python
#!/usr/bin/env python3
"""
ThreatForge — Context Assembler.
Enriches each CVE with CISA KEV detail, vendor advisory summary,
and OSINT context before the Claude call.
"""

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

# Cache the KEV catalogue for the duration of a run
_kev_cache: Optional[dict] = None


def load_kev_catalogue() -> dict:
    """Load and cache the CISA KEV JSON catalogue."""
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
    """Fetch a vendor advisory URL and return a plain-text summary."""
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "ThreatForge/1.0"})
        resp.raise_for_status()
        text = resp.text
        # Strip HTML tags for a rough plain-text extract (max 1500 chars)
        plain = re.sub(r"<[^>]+>", " ", text)
        plain = re.sub(r"\s+", " ", plain).strip()
        return plain[:1500]
    except Exception as e:
        log.debug(f"Advisory fetch failed for {url}: {e}")
        return ""


def detect_rce_in_kev(kev_entry: dict) -> bool:
    """Check if the KEV shortDescription contains RCE language."""
    desc = kev_entry.get("shortDescription", "").lower()
    return any(kw in desc for kw in RCE_KEYWORDS)


def parse_cvss_vector(vector: str) -> dict:
    """Parse a CVSS vector string into component fields."""
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
        """
        Assemble all threat-intel context for a CVE.
        Returns a context dict to be included in the Claude prompt.
        """
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

        # ── CISA KEV enrichment ──────────────────────
        if context["is_kev"] and cve_id in self.kev:
            kev_entry = self.kev[cve_id]
            context["kev_short_description"] = kev_entry.get("shortDescription", "")
            context["kev_required_action"] = kev_entry.get("requiredAction", "")
            context["rce_in_kev"] = detect_rce_in_kev(kev_entry)
            log.debug(f"{cve_id}: KEV entry found, rce_in_kev={context['rce_in_kev']}")

        # ── CVSS vector parsing ──────────────────────
        if context["cvss_vector"]:
            components = parse_cvss_vector(context["cvss_vector"])
            context["cvss_components"] = components
            # Network RCE: AV:N + PR:N + UI:N
            if (components.get("AV") == "N" and
                    components.get("PR") == "N" and
                    components.get("UI") == "N"):
                context["allows_rce"] = True
                context["rce_vector"] = "network"
                log.debug(f"{cve_id}: Network RCE detected via CVSS vector")

        # ── Advisory enrichment ──────────────────────
        references = cve_data.get("references", [])
        for ref in references[:2]:  # fetch max 2 advisories
            summary = fetch_advisory_summary(ref)
            if summary:
                context["advisory_summary"] += summary[:500] + " "

        return context

    def format_for_prompt(self, context: dict) -> str:
        """Format the context dict into a prompt-ready string."""
        lines = [
            f"CVE: {context['cve_id']}",
            f"Description: {context['description']}",
            f"CVSS Score: {context['cvss_score']} ({context['severity'].upper()})",
            f"Age: {context['age_in_days']} days old",
        ]
        if context["is_kev"]:
            lines.append(f"CISA KEV Status: ACTIVELY EXPLOITED IN THE WILD")
            if context["kev_short_description"]:
                lines.append(f"CISA KEV Description: {context['kev_short_description']}")
            if context["kev_required_action"]:
                lines.append(f"CISA KEV Required Action: {context['kev_required_action']}")
        if context["allows_rce"]:
            lines.append(f"RCE: YES — network-exploitable (AV:N/PR:N/UI:N)")
        if context["advisory_summary"]:
            lines.append(f"Advisory Context: {context['advisory_summary'][:800]}")
        return "\n".join(lines)
```

---

## src/scorer.py

```python
#!/usr/bin/env python3
"""
ThreatForge — Scorer.
Assigns tags and computes composite priority score for each CVE.
"""

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
        """
        Assign tags and compute composite score for a CVE.
        Returns a dict with keys: tags, composite_score, priority_tier, tier_label.
        """
        tags = []
        score = 0

        # [KEV] — CISA Known Exploited Vulnerabilities
        if context.get("is_kev"):
            tags.append("KEV")
            score += SCORE_WEIGHTS["KEV"]

        # [RCE] — Network-exploitable RCE via CVSS vector
        if context.get("allows_rce"):
            tags.append("RCE")
            score += SCORE_WEIGHTS["RCE"]

        # [RCE-KEV] — RCE language in CISA KEV shortDescription
        if context.get("rce_in_kev"):
            tags.append("RCE-KEV")
            score += SCORE_WEIGHTS["RCE-KEV"]

        # [CRIT] / [HIGH] — CVSS severity (mutually exclusive)
        cvss = cve_data.get("cvss_score", 0)
        if cvss >= 9.0:
            tags.append("CRIT")
            score += SCORE_WEIGHTS["CRIT"]
        elif cvss >= 7.0:
            tags.append("HIGH")
            score += SCORE_WEIGHTS["HIGH"]

        # [EPSS] — Exploit prediction score > threshold
        epss = cve_data.get("epss_score", 0)
        if epss > 0.5:
            tags.append("EPSS")
            score += SCORE_WEIGHTS["EPSS"]

        # [T1] — Tier 1 asset
        if cve_data.get("tier", 2) == 1:
            tags.append("T1")
            score += SCORE_WEIGHTS["T1"]

        # [WIDE] — Widely-used software
        product = cve_data.get("product", "").lower()
        if any(w in product for w in WIDELY_USED):
            tags.append("WIDE")
            score += SCORE_WEIGHTS["WIDE"]

        # [POC] — Public PoC available (check references)
        refs = cve_data.get("references", [])
        poc_domains = ["github.com", "exploit-db.com", "packetstormsecurity.com"]
        if any(d in r for r in refs for d in poc_domains):
            tags.append("POC")
            score += SCORE_WEIGHTS["POC"]

        # [NEW] — Published within last 3 days
        if cve_data.get("age_in_days", 999) < 3:
            tags.append("NEW")
            score += SCORE_WEIGHTS["NEW"]

        # Override: [KEV] + [RCE] always = Tier 0
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

        # Sort tags by rank order
        tag_order = list(SCORE_WEIGHTS.keys())
        tags.sort(key=lambda t: tag_order.index(t) if t in tag_order else 99)

        log.debug(f"{cve_data.get('cve_id')}: score={score} tier={priority_tier} tags={tags}")

        return {
            "tags": tags,
            "composite_score": score,
            "priority_tier": priority_tier,
            "tier_label": TIER_LABELS[priority_tier],
        }
```

---

## src/claude_caller.py

```python
#!/usr/bin/env python3
"""
ThreatForge — Claude API caller.
Sends assembled context + system prompt to Claude and returns output.
Handles self-repair retry on validation failure.
"""

import os
import re
import logging
from pathlib import Path
import anthropic

from context_assembler import ContextAssembler

log = logging.getLogger("claude_caller")

CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
PROMPTS_DIR = Path("/opt/threatforge/prompts")

OUTPUT_MODULES = {
    1: "advisory",
    2: "technical_findings",
    3: "signatures",
    4: "ioc_list",
    5: "hunting_queries",
    6: "patch_recs",
}


def load_prompt(filename: str) -> str:
    path = PROMPTS_DIR / filename
    if path.exists():
        return path.read_text()
    log.warning(f"Prompt file not found: {path}")
    return ""


class ClaudeCaller:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.assembler = ContextAssembler()
        self.system_prompt = load_prompt("system_prompt.txt")
        self.few_shot = load_prompt("few_shot_rules.txt")

    def produce(self, output_num: int, cve_data: dict) -> dict:
        """
        Produce a specific output type for a CVE.
        Returns dict with keys: output_type, content, cve_id, success, error.
        """
        output_type = OUTPUT_MODULES.get(output_num, "unknown")
        template = load_prompt(f"output_templates/{output_type}.txt")
        context = cve_data.get("context", {})
        context_block = self.assembler.format_for_prompt(context)
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))

        user_message = f"""
{context_block}

Priority Score: {cve_data.get('composite_score', 0)}
Priority Tags: {tags_str}
Priority Tier: {cve_data.get('tier_label', 'UNKNOWN')}

{self.few_shot if output_num == 3 else ''}

{template}
"""

        result = self._call(user_message, output_type)

        # Self-repair retry on failure
        if not result["success"] and result.get("error"):
            log.info(f"Self-repair retry for {cve_data['cve_id']} output {output_num}")
            user_message_retry = user_message + f"\n\nPrevious attempt failed with error:\n{result['error']}\nPlease fix and try again."
            result = self._call(user_message_retry, output_type)
            if not result["success"]:
                result["review_needed"] = True
                log.warning(f"Self-repair failed for {cve_data['cve_id']} output {output_num}")

        result["output_type"] = output_type
        result["cve_id"] = cve_data.get("cve_id", "")
        return result

    def _call(self, user_message: str, output_type: str) -> dict:
        """Make a single Claude API call and return the result."""
        try:
            response = self.client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=2048,
                system=self.system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            content = response.content[0].text
            # Strip markdown fences if present
            content = re.sub(r"^```[a-z]*\n?", "", content, flags=re.MULTILINE)
            content = re.sub(r"\n?```$", "", content, flags=re.MULTILINE)
            return {"success": True, "content": content.strip(), "error": None}
        except anthropic.APIError as e:
            log.error(f"Claude API error: {e}")
            return {"success": False, "content": "", "error": str(e)}
```

---

## src/slack_notifier.py

```python
#!/usr/bin/env python3
"""
ThreatForge — Slack notifier.
Posts the brief findings report and output menu via notify CLI.
"""

import os
import subprocess
import logging
import json
from datetime import datetime

log = logging.getLogger("slack_notifier")

OUTPUT_LABELS = {
    1: "Security advisory (management)",
    2: "Technical findings (SOC analyst)",
    3: "Suricata signature drafts",
    4: "IoC list",
    5: "Threat hunting queries (CrowdStrike + Netflow)",
    6: "Patch recommendations",
}


def _post(message: str) -> bool:
    """Post a message to Slack via notify."""
    try:
        result = subprocess.run(
            ["notify", "-silent", "-bulk"],
            input=message,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            log.warning(f"notify returned non-zero: {result.stderr}")
            return False
        return True
    except Exception as e:
        log.error(f"Slack post failed: {e}")
        return False


class SlackNotifier:
    def post_brief_report(self, enriched_cves: list[dict]) -> None:
        """Post the brief findings report and interactive menu."""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"*ThreatForge — Daily Report*",
            f"{now} · {len(enriched_cves)} actionable CVE(s) found",
            "",
        ]

        for i, cve in enumerate(enriched_cves, 1):
            tags_str = " ".join(f"[{t}]" for t in cve.get("tags", []))
            lines += [
                f"*{i}. {cve['cve_id']}* — {cve.get('product', '').upper()}",
                f"   Tags: {tags_str}  Score: {cve.get('composite_score', 0)}",
                f"   *{cve.get('tier_label', 'UNKNOWN')}*",
                f"   {cve.get('context', {}).get('description', '')[:120]}...",
                "",
            ]

        lines += [
            "---",
            "*What would you like me to produce?*",
            "Reply with numbers or run the command below:",
            "",
        ]
        for num, label in OUTPUT_LABELS.items():
            lines.append(f"  {num}. {label}")
        lines.append("  0. All of the above")
        lines += [
            "",
            "*To produce outputs:*",
            "`docker exec threatforge python3 src/orchestrate.py --produce <numbers>`",
            "Example: `docker exec threatforge python3 src/orchestrate.py --produce 1 3 6`",
            "",
            "_No reply by 08:00 → brief report only. Menu stays available._",
        ]

        message = "\n".join(lines)
        _post(message)
        log.info(f"Brief report posted to Slack: {len(enriched_cves)} CVEs")

    def post_outputs_complete(self, enriched_cves: list[dict], selected: list[int]) -> None:
        """Post a summary when output production is complete."""
        labels = [OUTPUT_LABELS.get(n, f"Output {n}") for n in selected]
        cve_ids = [c["cve_id"] for c in enriched_cves]
        message = (
            f"*ThreatForge — Outputs Ready*\n"
            f"CVEs: {', '.join(cve_ids)}\n"
            f"Produced: {', '.join(labels)}\n"
            f"Location: /opt/threatforge/outputs/"
        )
        _post(message)

    def post_empty_report(self) -> None:
        """Post a message when no actionable CVEs are found."""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        _post(f"*ThreatForge — Daily Report*\n{now} · No actionable CVEs found today.")
```

---

## src/output_router.py

```python
#!/usr/bin/env python3
"""
ThreatForge — Output router.
Saves generated outputs to the correct folder, logs results,
and sets REVIEW_NEEDED flags on failures.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime

log = logging.getLogger("output_router")

OUTPUT_DIRS = {
    1: "advisories",
    2: "advisories",
    3: "rules",
    4: "iocs",
    5: "hunting",
    6: "patches",
}

OUTPUT_EXTENSIONS = {
    1: ".md",
    2: ".md",
    3: ".rules",
    4: ".txt",
    5: ".txt",
    6: ".yml",
}


class OutputRouter:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def save(self, output_num: int, cve_data: dict, result: dict) -> Path:
        """Save a generated output to the appropriate folder."""
        cve_id = cve_data.get("cve_id", "UNKNOWN").replace("-", "_")
        output_type = result.get("output_type", f"output_{output_num}")
        ext = OUTPUT_EXTENSIONS.get(output_num, ".txt")
        subdir = OUTPUT_DIRS.get(output_num, "misc")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        folder = self.base_dir / subdir
        folder.mkdir(parents=True, exist_ok=True)

        filename = f"{cve_id}_{output_type}_{timestamp}{ext}"
        filepath = folder / filename

        # Build file content with header metadata
        header = self._build_header(cve_data, result, output_num)
        content = header + "\n\n" + result.get("content", "")

        if result.get("review_needed"):
            content += f"\n\n# REVIEW_NEEDED\n# Error: {result.get('error', 'unknown')}"
            filename = "REVIEW_NEEDED_" + filename
            filepath = folder / filename

        filepath.write_text(content)
        log.info(f"Saved: {filepath}")

        # Append to run log
        self._log_run(cve_data, output_num, result, filepath)
        return filepath

    def _build_header(self, cve_data: dict, result: dict, output_num: int) -> str:
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        return (
            f"# ThreatForge Output — {result.get('output_type', '').upper()}\n"
            f"# CVE:       {cve_data.get('cve_id', '')}\n"
            f"# Product:   {cve_data.get('product', '')}\n"
            f"# Tags:      {tags_str}\n"
            f"# Score:     {cve_data.get('composite_score', 0)}\n"
            f"# Tier:      {cve_data.get('tier_label', '')}\n"
            f"# Generated: {datetime.utcnow().isoformat()}Z\n"
            f"# Status:    {'REVIEW_NEEDED' if result.get('review_needed') else 'OK'}\n"
            f"# ---"
        )

    def _log_run(self, cve_data: dict, output_num: int, result: dict, filepath: Path) -> None:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cve_id": cve_data.get("cve_id"),
            "product": cve_data.get("product"),
            "output_num": output_num,
            "output_type": result.get("output_type"),
            "composite_score": cve_data.get("composite_score"),
            "tags": cve_data.get("tags"),
            "success": result.get("success"),
            "review_needed": result.get("review_needed", False),
            "filepath": str(filepath),
        }
        log_path = Path("/opt/threatforge/logs/runs.jsonl")
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
```

---

## src/modules/advisory.py

```python
#!/usr/bin/env python3
"""Output module 1 — Management security advisory."""

TEMPLATE = """
You are a cybersecurity communications specialist writing a security advisory
for a non-technical management audience.

Write a security advisory in Markdown format with the following sections:

## Executive Summary
One paragraph. What is affected, how severe, and what action is required.
No technical jargon.

## Business Impact
What could happen if this is not addressed. Focus on business risk:
data breach, service disruption, regulatory exposure.

## Affected Systems
List the affected products and versions in plain language.

## Recommended Action
What management needs to approve or communicate. Specific, time-bound.

## Timeline
Recommended remediation timeline based on priority tier.

Write for a CISO or VP-level audience. Avoid CVE numbers in the summary.
Use the priority tier to set the urgency tone.
"""
```

---

## src/modules/technical_findings.py

```python
#!/usr/bin/env python3
"""Output module 2 — Technical findings for SOC analyst."""

TEMPLATE = """
You are a senior security analyst writing a technical findings report
for a SOC analyst audience.

Write a technical findings report in Markdown format:

## CVE Summary
CVE ID, affected product, CVSS score, KEV status, age.

## Attack Vector
How the vulnerability is exploited. Network path, required conditions,
authentication requirements. Reference the CVSS vector components.

## Observable Behaviour
What this attack looks like on the wire or in endpoint telemetry.
Specific indicators: HTTP paths, payload patterns, process chains,
network connections.

## Detection Coverage
What signatures or queries would catch this. Reference the Suricata
rule or hunting query if produced.

## Affected Assets
Which assets in the inventory are affected based on the product list.

## Recommended Response
Immediate containment actions, investigation steps, escalation criteria.

Write with technical precision. Include specific field values, protocol
details, and command examples where relevant.
"""
```

---

## src/modules/signatures.py

```python
#!/usr/bin/env python3
"""Output module 3 — Suricata signature drafts (SigForge module)."""

TEMPLATE = """
You are a detection engineer writing a Suricata IDS/IPS rule.

Using the CVE metadata, CISA KEV context, and advisory detail provided,
draft one Suricata rule targeting the network-observable behaviour of
this vulnerability.

Requirements:
- Action: alert
- Include msg with CVE ID and product name
- Use appropriate flow keywords
- Include content and/or pcre match targeting the observable behaviour
- Include reference:cve tag
- Include metadata with mitre_technique_id, is_kev status, status experimental
- Include appropriate classtype
- Assign a unique sid in the range 9000000-9999999
- Set rev:1

Return ONLY the rule text. No explanation, no markdown fencing.

Example format:
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"THREATFORGE CVE-XXXX-XXXX product exploit attempt";
  flow:established,to_server; http.uri; content:"/exploit/path";
  pcre:"/exploit_pattern/i";
  reference:cve,XXXX-XXXX;
  metadata:mitre_technique_id T1190, is_kev true, status experimental;
  classtype:attempted-admin; sid:9000001; rev:1; )
"""
```

---

## src/modules/ioc_list.py

```python
#!/usr/bin/env python3
"""Output module 4 — IoC list."""

TEMPLATE = """
You are a threat intelligence analyst extracting indicators of compromise.

Based on the CVE metadata, CISA KEV entry, advisory context, and OSINT
provided, produce a structured IoC list in the following format:

# IoC List — CVE-XXXX-XXXX
# Generated: [date]
# Confidence: HIGH / MEDIUM / LOW per indicator

## Network Indicators
# IP addresses associated with exploitation
IP: x.x.x.x  # source / description

## Domain Indicators
DOMAIN: malicious.example.com  # description

## URL Indicators
URL: http://example.com/exploit/path  # description

## File Indicators
HASH_SHA256: abc123...  # filename / description
HASH_MD5: abc123...     # filename / description

## User-Agent Indicators
UA: ExploitScanner/1.0

## URI Path Indicators
URI: /vulnerable/endpoint

## Notes
Any caveats, confidence levels, or context about these indicators.

If no specific IoCs are available from the provided context, state that
clearly and list the observable behaviour patterns instead.
Only include indicators with reasonable confidence from the provided context.
"""
```

---

## src/modules/hunting_queries.py

```python
#!/usr/bin/env python3
"""Output module 5 — Threat hunting queries (CrowdStrike + nfdump)."""

TEMPLATE = """
You are a threat hunter writing detection queries for two platforms.

Based on the CVE metadata, observable behaviour, and IoC context provided,
write threat hunting queries for:

## CrowdStrike Event Search

Write 2-3 CrowdStrike Event Search queries targeting:
1. Network connections to known malicious IPs/domains
2. Process execution patterns associated with post-exploitation
3. File system artefacts if applicable

Format:
```
event_simpleName=NetworkConnect RemotePort=443 RemoteIP IN ("x.x.x.x")
| stats count by ComputerName, UserName, RemoteIP, RemotePort
| sort -count
```

## nfdump Netflow Queries

Write 2-3 nfdump queries targeting:
1. Traffic to known malicious IPs on exploit-relevant ports
2. Anomalous traffic volumes or patterns
3. Protocol anomalies associated with the exploit

Format:
```
nfdump -r /var/log/netflow/nfcapd.current \
  -f 'proto tcp and dst port 8080 and dst ip x.x.x.x' \
  -s record/bytes -n 20
```

## Hunting Notes
What to look for, false positive considerations, and escalation criteria.

Write queries that are ready to run. Use placeholder values
(x.x.x.x, malicious.example.com) where specific IoCs are not available.
"""
```

---

## src/modules/patch_recs.py

```python
#!/usr/bin/env python3
"""Output module 6 — Patch recommendations and Ansible playbook (PatchForge module)."""

TEMPLATE = """
You are a systems engineer writing a patch recommendation and remediation playbook.

Based on the CVE metadata and advisory context provided, produce:

## Patch Recommendation

**CVE:** [CVE ID]
**Affected Product:** [product and affected versions]
**Fixed Version:** [version that resolves the CVE]
**Urgency:** [based on priority tier — immediate / within 24h / within 7 days]
**Rollback Risk:** [what could break, how to revert]

## Ansible Remediation Playbook

Write an Ansible playbook using the apt module to upgrade the affected package:

```yaml
---
- name: "Remediate [CVE ID] on {{ target_group }}"
  hosts: "{{ target_group }}"
  become: true
  vars:
    cve_id: "[CVE ID]"
    affected_package: "[package name]"

  tasks:
    - name: Update apt cache
      ansible.builtin.apt:
        update_cache: true
        cache_valid_time: 3600

    - name: Upgrade affected package
      ansible.builtin.apt:
        name: "{{ affected_package }}"
        state: latest
      register: patch_result

    - name: Restart service if package was upgraded
      ansible.builtin.service:
        name: "[service name]"
        state: restarted
      when: patch_result.changed

    - name: Audit log
      ansible.builtin.debug:
        msg: "{{ cve_id }} patched on {{ inventory_hostname }} at {{ ansible_date_time.iso8601 }}"
```

## Validation Steps
How to confirm the patch was applied successfully.

## Dry Run Command
```
ansible-playbook remediate_[cve_id].yml --check --diff -i inventory.ini
```

Return the playbook as valid YAML. No markdown explanation outside the
designated sections.
"""
```

---

## prompts/system_prompt.txt

```
You are ThreatForge, a cybersecurity automation assistant.
Your role is to produce structured security outputs for analyst review.

Rules:
- Produce ONLY the requested output type. No preamble, no explanation outside
  the requested format.
- Never produce exploit code, attack tools, or instructions for offensive use.
- Every output is a proposed draft for analyst review. State this where
  appropriate within the output.
- Use the assembled CVE context, CISA KEV detail, and advisory information
  provided to produce accurate, specific outputs rather than generic ones.
- If specific technical detail is unavailable, note that clearly rather than
  fabricating indicators or patterns.
- Tag all rule metadata and output headers with the CVE ID for traceability.
```

---

## prompts/few_shot_rules.txt

```
# Example Suricata rules for few-shot context (signatures module only)
# These are structural examples — do not copy match logic verbatim

alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"THREATFORGE CVE-2021-44228 Log4j JNDI injection attempt";
  flow:established,to_server; http.header; content:"${jndi:";
  nocase; reference:cve,2021-44228;
  metadata:mitre_technique_id T1190, is_kev true, status experimental;
  classtype:attempted-admin; sid:9000001; rev:1; )

alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
  msg:"THREATFORGE CVE-2024-6387 OpenSSH regreSSHion exploit attempt";
  flow:established,to_server; dsize:>1400;
  threshold:type both, track by_src, count 5, seconds 10;
  reference:cve,2024-6387;
  metadata:mitre_technique_id T1190, is_kev true, status experimental;
  classtype:attempted-admin; sid:9000002; rev:1; )

alert dns $HOME_NET any -> any 53 (
  msg:"THREATFORGE CVE-2020-1350 SIGRed DNS exploit attempt";
  flow:established; dns.query; content:"|00 ff|"; offset:2;
  reference:cve,2020-1350;
  metadata:mitre_technique_id T1190, is_kev true, status experimental;
  classtype:attempted-admin; sid:9000003; rev:1; )
```

---

## prompts/output_templates/advisory.txt

```
Write a management security advisory as described in the system prompt.
Use the CVE context and priority tier provided to set urgency and tone.
Format output as Markdown. No CVE numbers in the executive summary.
```

---

## prompts/output_templates/technical_findings.txt

```
Write a technical findings report as described in the system prompt.
Include specific observable behaviour, CVSS vector analysis, and
recommended SOC response actions.
```

---

## prompts/output_templates/signatures.txt

```
Write one Suricata rule as described in the system prompt.
Use the observable behaviour from the advisory and KEV context
to populate content and pcre match fields.
Return ONLY the rule text.
```

---

## prompts/output_templates/ioc_list.txt

```
Extract IoCs from the provided context as described in the system prompt.
Only include indicators you can support from the provided context.
State confidence levels clearly.
```

---

## prompts/output_templates/hunting_queries.txt

```
Write CrowdStrike Event Search and nfdump queries as described in the
system prompt. Queries should be ready to run with placeholder values
clearly marked.
```

---

## prompts/output_templates/patch_recs.txt

```
Write a patch recommendation and Ansible playbook as described in the
system prompt. Return the playbook as valid YAML.
```
