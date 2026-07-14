#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import tempfile
import logging
import click
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from context_assembler import ContextAssembler
from scorer import Scorer
from notifier import DiscordNotifier
from output_router import OutputRouter
from ai_caller import AICaller
from config_loader import load_config

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

_cfg = load_config()
PRODUCTS_FILE = "/opt/threatforge/config/products.txt"
CVE_AGE_DAYS = _cfg["pipeline"]["cve_age_days"]
CVSS_THRESHOLD = _cfg["pipeline"]["cvss_threshold"]
TEST_DEFAULT_COUNT = _cfg["test_mode"]["default_count"]
TEST_QUERY_LIMIT = _cfg["test_mode"]["query_limit"]
TEST_GLOBAL_LIMIT = _cfg["test_mode"]["global_limit"]
CLEAN_BEFORE_RUN = _cfg["output_management"]["clean_before_run"]
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/opt/threatforge/outputs"))


def clean_outputs(output_dir: Path) -> None:
    """Wipe previously generated drafts before writing new ones. Outputs are
    ephemeral review artifacts, not a permanent record — runs.jsonl already
    logs every generation regardless of whether the file itself survives."""
    if not output_dir.exists():
        return
    removed = 0
    for f in output_dir.rglob("*"):
        if f.is_file():
            f.unlink()
            removed += 1
    log.info(f"Cleaned outputs/: removed {removed} file(s)")


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


def _run_vulnx(product_name: str, extra_args: list[str]) -> list[dict]:
    fd, output_file = tempfile.mkstemp(prefix=f"vulnx_{product_name.replace(' ', '_')}_", suffix=".json")
    os.close(fd)
    try:
        with open(output_file, "w") as out_f:
            subprocess.run(
                ["vulnx", "search", product_name, "-j"] + extra_args,
                stdout=out_f,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
        with open(output_file) as f:
            content = f.read().strip()
        # vulnx exits 0 and writes nothing to stdout when a query matches zero
        # results — that's a normal outcome, not a failure.
        if not content:
            return []
        raw = json.loads(content)
        return raw.get("results", [])
    except subprocess.CalledProcessError as e:
        log.warning(f"vulnx failed for {product_name} {extra_args}: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        log.warning(f"vulnx returned unparseable output for {product_name} {extra_args}: {e}")
        return []
    finally:
        Path(output_file).unlink(missing_ok=True)


def query_vulnx(product_name: str, test_mode: bool = False) -> list[dict]:
    if test_mode:
        # Test mode: search broadly for the CVEs that check the most boxes —
        # KEV-listed or high-CVSS — with no age cutoff, so genuinely critical
        # older CVEs aren't excluded just for missing the "actionable this week" window.
        kev_results = _run_vulnx(product_name, ["--kev=true", "--limit", str(TEST_QUERY_LIMIT)])
        crit_results = _run_vulnx(
            product_name,
            ["--cvss-score", f">={CVSS_THRESHOLD}", "--sort-desc", "cvss_score", "--limit", str(TEST_QUERY_LIMIT)],
        )
        by_id = {r["cve_id"]: r for r in kev_results + crit_results if r.get("cve_id")}
        results = list(by_id.values())
        log.info(f"{product_name} [test mode]: {len(results)} candidate CVE(s) (KEV or CVSS>={CVSS_THRESHOLD}, any age)")
        return results

    results = _run_vulnx(product_name, ["--limit", "10"])
    filtered = [
        r for r in results
        if r.get("age_in_days", 999) < CVE_AGE_DAYS
        and (r.get("cvss_score", 0) >= CVSS_THRESHOLD or r.get("is_kev", False))
    ]
    log.info(f"{product_name}: {len(results)} CVEs found, {len(filtered)} actionable")
    return filtered


def query_vulnx_global() -> list[dict]:
    """Test-mode only: an unscoped sweep across ALL products, not just products.txt —
    catches genuinely critical/KEV CVEs for software nobody's gotten around to
    listing yet."""
    kev_results = _run_vulnx("is_kev:true", ["--limit", str(TEST_GLOBAL_LIMIT)])
    crit_results = _run_vulnx(
        f"cvss_score:>={CVSS_THRESHOLD}",
        ["--sort-desc", "cvss_score", "--limit", str(TEST_GLOBAL_LIMIT)],
    )
    by_id = {r["cve_id"]: r for r in kev_results + crit_results if r.get("cve_id")}
    results = list(by_id.values())
    log.info(f"global sweep [test mode]: {len(results)} candidate CVE(s) (KEV or CVSS>={CVSS_THRESHOLD}, any product, any age)")
    return results


def _derive_product_label(cve_raw: dict) -> str:
    affected = cve_raw.get("affected_products") or []
    products = sorted({p.get("product") for p in affected if p.get("product")})
    if products:
        return ", ".join(products[:3])
    name = cve_raw.get("name", "")
    return name.split(" - ")[0].strip().lower() if name else "unknown"


def run_pipeline(
    products: list[dict] = None,
    single_cve: str = None,
    dry_run: bool = False,
    test_mode: bool = False,
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
            cves = query_vulnx(product["name"], test_mode=test_mode)
            for cve in cves:
                cve["product"] = product["name"]
                cve["tier"] = product["tier"]
                context = assembler.assemble(cve)
                scored = scorer.score(cve, context)
                enriched_cves.append({**cve, "context": context, **scored})

        if test_mode:
            for cve in query_vulnx_global():
                cve["product"] = _derive_product_label(cve)
                cve["tier"] = 2  # not in products.txt — no tier info, don't assume T1
                context = assembler.assemble(cve)
                scored = scorer.score(cve, context)
                enriched_cves.append({**cve, "context": context, **scored})

    # Dedup by CVE ID — the same CVE can surface from both a per-product search
    # and the global sweep in test mode.
    enriched_cves = list({c["cve_id"]: c for c in enriched_cves}.values())

    # Primary: composite score descending. Tiebreaker: newest first — many CVEs
    # tie at the same score (KEV+RCE-KEV+CRIT+EPSS+T1+WIDE all cap out together),
    # so without this the most recent of an equally-critical set isn't favoured.
    enriched_cves.sort(key=lambda x: (x.get("composite_score", 0), -x.get("age_in_days", 999)), reverse=True)
    log.info(f"Pipeline complete: {len(enriched_cves)} candidate CVEs")
    return enriched_cves


@click.command()
@click.option("--product", default=None, help="Run pipeline for a single product")
@click.option("--cve", default=None, help="Force-process a specific CVE ID")
@click.option("--produce", default=None, help="Comma-separated output numbers 1-6, or 0 for all. Example: --produce 1,3,6")
@click.option("--scheduled", is_flag=True, help="Scheduled run mode (cron trigger)")
@click.option("--dry-run", is_flag=True, help="Run pipeline without Claude calls or Discord posts")
@click.option(
    "--test", "test_count", is_flag=False, flag_value=-1, default=None, type=int, metavar="[N]",
    help="Test mode: search broadly for KEV-listed or high-CVSS CVEs regardless of age (ignores "
         "cve_age_days) across products.txt PLUS an unscoped global sweep (any product, not just "
         "products.txt), score everything the same way as production, and keep only the top N by "
         "composite score — for spot-checking against cve.org / CISA KEV. Bare --test uses the "
         "configured default count (test_mode.default_count). Combine with --produce to also "
         "generate drafts for just this set. Mutually exclusive with --recent.",
)
@click.option(
    "--recent", "recent_count", is_flag=False, flag_value=-1, default=None, type=int, metavar="[N]",
    help="Same broad search as --test (KEV or high-CVSS, any age, products.txt + global sweep), but "
         "ranks by recency (newest first) instead of composite score — for spotting brand-new "
         "critical/KEV activity that hasn't accumulated EPSS/WIDE signal yet to compete on score. "
         "Bare --recent uses the configured default count (test_mode.default_count). Mutually "
         "exclusive with --test.",
)
def main(product, cve, produce, scheduled, dry_run, test_count, recent_count):
    if test_count is not None and recent_count is not None:
        raise click.UsageError("--test and --recent are mutually exclusive — pick one.")

    log.info(f"ThreatForge starting — mode: {'scheduled' if scheduled else 'manual'}")
    broad_search = test_count is not None or recent_count is not None

    products = None
    if product:
        products = [{"name": product.lower(), "tier": 2}]

    enriched_cves = run_pipeline(products=products, single_cve=cve, dry_run=dry_run, test_mode=broad_search)

    if recent_count is not None:
        n = TEST_DEFAULT_COUNT if recent_count == -1 else recent_count
        enriched_cves = sorted(enriched_cves, key=lambda c: c.get("age_in_days", 999))[:n]
        log.info(f"Recent mode: limited to the {n} newest CVE(s) (KEV or high-CVSS, any score)")
    elif test_count is not None:
        n = TEST_DEFAULT_COUNT if test_count == -1 else test_count
        enriched_cves = enriched_cves[:n]
        log.info(f"Test mode: limited to top {n} CVE(s) by score")

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

    # Advisory reference fetching is network I/O — only do it for the final,
    # already-trimmed set, not every scoring candidate (test mode can pull many).
    assembler = ContextAssembler()
    for c in enriched_cves:
        assembler.enrich_advisory(c["context"], c)

    notifier = DiscordNotifier()
    notifier.post_brief_report(enriched_cves)

    if produce:
        if CLEAN_BEFORE_RUN:
            clean_outputs(OUTPUT_DIR)

        selected = list(range(1, 7)) if produce == "0" else [int(x) for x in produce.replace(",", " ").split()]
        caller = AICaller()
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
