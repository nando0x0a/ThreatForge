#!/usr/bin/env python3
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
from notifier import DiscordNotifier
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
    output_file = f"/tmp/vulnx_{product_name.replace(' ', '_')}.json"
    try:
        with open(output_file, "w") as out_f:
            subprocess.run(
                ["vulnx", "search", product_name, "-j"],
                stdout=out_f,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
    except subprocess.CalledProcessError as e:
        log.warning(f"vulnx failed for {product_name}: {e.stderr}")
        return []

    with open(output_file) as f:
        raw = json.load(f)

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
    assembler = ContextAssembler()
    scorer = Scorer()
    enriched_cves = []

    if single_cve:
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

    enriched_cves.sort(key=lambda x: x.get("composite_score", 0), reverse=True)
    log.info(f"Pipeline complete: {len(enriched_cves)} actionable CVEs")
    return enriched_cves


@click.command()
@click.option("--product", default=None, help="Run pipeline for a single product")
@click.option("--cve", default=None, help="Force-process a specific CVE ID")
@click.option("--produce", default=None, help="Comma-separated output numbers 1-6, or 0 for all. Example: --produce 1,3,6")
@click.option("--scheduled", is_flag=True, help="Scheduled run mode (cron trigger)")
@click.option("--dry-run", is_flag=True, help="Run pipeline without Claude calls or Discord posts")
def main(product, cve, produce, scheduled, dry_run):
    log.info(f"ThreatForge starting — mode: {'scheduled' if scheduled else 'manual'}")

    products = None
    if product:
        products = [{"name": product.lower(), "tier": 2}]

    enriched_cves = run_pipeline(products=products, single_cve=cve, dry_run=dry_run)

    if not enriched_cves:
        log.info("No actionable CVEs found. Exiting.")
        if not dry_run:
            DiscordNotifier().post_empty_report()
        return

    if dry_run:
        log.info("Dry run — skipping Discord post and output production.")
        for c in enriched_cves:
            print(f"  {c['cve_id']} | Score: {c['composite_score']} | Tags: {' '.join(c['tags'])}")
        return

    notifier = DiscordNotifier()
    notifier.post_brief_report(enriched_cves)

    if produce:
        selected = list(range(1, 7)) if produce == "0" else [int(x) for x in produce.replace(",", " ").split()]
        caller = ClaudeCaller()
        router = OutputRouter(OUTPUT_DIR)

        for cve_data in enriched_cves:
            for output_num in selected:
                log.info(f"Producing output {output_num} for {cve_data['cve_id']}")
                result = caller.produce(output_num, cve_data)
                router.save(output_num, cve_data, result)
                notifier.post_output(output_num, cve_data, result)

        notifier.post_outputs_complete(enriched_cves, selected)

    log.info("ThreatForge run complete.")


if __name__ == "__main__":
    main()
