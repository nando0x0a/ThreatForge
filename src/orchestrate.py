#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import tempfile
import logging
import click
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

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
QUERY_LIMIT = _cfg["pipeline"]["query_limit"]
TEST_DEFAULT_COUNT = _cfg["test_mode"]["default_count"]
TEST_QUERY_LIMIT = _cfg["test_mode"]["query_limit"]
TEST_GLOBAL_LIMIT = _cfg["test_mode"]["global_limit"]
CLEAN_BEFORE_RUN = _cfg["output_management"]["clean_before_run"]
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/opt/threatforge/outputs"))


def print_summary_table(produced: list[dict]) -> None:
    """One row per produced item — CVE, output type, product, tier, score,
    status, and where it was saved. Shown at the end of any --produce run.
    Width is forced (not auto-detected) since this often runs without a real
    TTY (docker exec -i / cli.py), where Rich would otherwise default to 80
    columns and wrap every row across multiple lines."""
    if not produced:
        return
    table = Table(title="ThreatForge — Outputs Produced")
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Output Type", no_wrap=True)
    table.add_column("Product", no_wrap=True)
    table.add_column("Tier", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("KEV Source (added)", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("File", no_wrap=True)
    for i, item in enumerate(produced, 1):
        status = item["status"]
        status_markup = f"[green]{status}[/green]" if status == "OK" else f"[red]{status}[/red]"
        table.add_row(
            str(i), item["cve_id"], item["output_type"], item["product"], item["tier"],
            str(item["score"]), _format_kev_sources(item.get("kev_sources", [])), status_markup, item["file"],
        )
    Console(width=200).print(table)


def _format_kev_sources(kev_sources: list[dict]) -> str:
    if not kev_sources:
        return ""
    return ", ".join(
        f"{s['source']} ({s['added_date'][:10]})" if s.get("added_date") else s["source"]
        for s in kev_sources
    )


def print_candidate_table(enriched_cves: list[dict]) -> None:
    """Same numbered-table format as print_summary_table, shown before any
    produce decision — the CVE-selection prompt refers to CVEs by this same
    '#' position, so an analyst can answer it directly from what's on screen."""
    table = Table(title="ThreatForge — CVEs Found")
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Product", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Tags", no_wrap=True)
    table.add_column("KEV Source (added)", no_wrap=True)
    for i, c in enumerate(enriched_cves, 1):
        kev_sources = c.get("context", {}).get("kev_sources", [])
        table.add_row(
            str(i), c["cve_id"], c.get("product", "unknown"), str(c["composite_score"]),
            " ".join(c["tags"]), _format_kev_sources(kev_sources),
        )
    Console(width=200).print(table)


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


def _days_since(iso_ts: str) -> int:
    dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


def _kev_recency_days(r: dict) -> int | None:
    """Days since this CVE last became actionable via KEV: either newly added
    to the KEV catalog or the underlying CVE record was updated. Returns None
    if vulnx supplied neither timestamp, so the caller can fall back to
    age_in_days instead of treating it as automatically recent."""
    candidates = []
    for entry in r.get("kev") or []:
        added = entry.get("added_date")
        if added:
            candidates.append(_days_since(added))
    updated = r.get("cve_updated_at")
    if updated:
        candidates.append(_days_since(updated))
    return min(candidates) if candidates else None


# A CVE whose KEV listing itself (not just the underlying CVE record) was
# added within this many days gets called out separately as a "just entered
# KEV" alert, on top of whatever the normal candidate filters already
# decided about it. First cut of KEV-on-entry re-alerting: checked once per
# web-UI pipeline run (see web.py), not yet a standalone frequent poll.
KEV_RECENT_ENTRY_DAYS = 7


def _kev_added_days(kev_sources: list[dict]) -> int | None:
    """Days since the most recent KEV 'added' date across all sources for a
    candidate's already-enriched kev_sources (the same data the "KEV Source
    (added)" column already displays) — deliberately independent of
    _kev_recency_days's fallback to the CVE's updated-at timestamp, since
    this is specifically about the KEV listing itself being new."""
    added_dates = [s["added_date"] for s in (kev_sources or []) if s.get("added_date")]
    return min((_days_since(d) for d in added_dates), default=None)


def annotate_recent_kev_entries(enriched_cves: list[dict], days: int = KEV_RECENT_ENTRY_DAYS) -> list[dict]:
    """Mutates each candidate in place with kev_added_days (int|None) and
    recent_kev_entry (bool), then returns just the subset flagged True —
    CVEs whose KEV listing was added within `days`. The web UI shows these
    separately from (in addition to) the normal candidate list, since a
    fresh KEV entry means CISA just confirmed active exploitation,
    regardless of what the rest of scoring/filtering already decided."""
    recent = []
    for c in enriched_cves:
        kev_sources = c.get("context", {}).get("kev_sources", [])
        added_days = _kev_added_days(kev_sources)
        c["kev_added_days"] = added_days
        c["recent_kev_entry"] = added_days is not None and added_days <= days
        if c["recent_kev_entry"]:
            recent.append(c)
    return recent


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

    # Two targeted queries instead of one unsorted fetch — a plain `--limit N`
    # fetch (previously --limit 10) returns whatever the index gives, roughly
    # most-recently-indexed first. For high-volume products (e.g. wordpress,
    # with constant plugin-CVE churn) that silently crowds out older-but-still-
    # actionable CVEs before the filter below ever sees them. Querying with
    # the filter baked in (like test mode's kev_results/crit_results) guarantees
    # anything KEV-listed or high-CVSS for this product actually gets fetched.
    kev_results = _run_vulnx(product_name, ["--kev=true", "--limit", str(QUERY_LIMIT)])
    crit_results = _run_vulnx(
        product_name,
        ["--cvss-score", f">={CVSS_THRESHOLD}", "--sort-desc", "cve_created_at", "--limit", str(QUERY_LIMIT)],
    )
    by_id = {r["cve_id"]: r for r in kev_results + crit_results if r.get("cve_id")}
    results = list(by_id.values())

    # KEV-listed CVEs are actionable when the KEV listing itself is recent —
    # newly added to the catalog, or the CVE record was recently updated —
    # not simply because the underlying CVE is KEV-listed. A CVE added to KEV
    # years ago is stale: almost certainly already patched, not worth fresh
    # advisories/signatures. Falls back to age_in_days if vulnx supplies
    # neither KEV-added nor updated timestamp.
    def _actionable(r: dict) -> bool:
        if r.get("is_kev", False):
            recency = _kev_recency_days(r)
            recency = recency if recency is not None else r.get("age_in_days", 999)
        else:
            recency = r.get("age_in_days", 999)
        return recency < CVE_AGE_DAYS

    filtered = [r for r in results if _actionable(r)]
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


def query_vulnx_id(cve_id: str) -> dict:
    """Fetch a specific CVE's real record via `vulnx id` — used by --cve.
    Unlike `vulnx search`, this returns a single object, not {"results": [...]}."""
    fd, output_file = tempfile.mkstemp(prefix=f"vulnx_id_{cve_id}_", suffix=".json")
    os.close(fd)
    try:
        with open(output_file, "w") as out_f:
            subprocess.run(
                ["vulnx", "id", cve_id, "-j"],
                stdout=out_f,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
        with open(output_file) as f:
            content = f.read().strip()
        if not content:
            log.warning(f"vulnx id {cve_id}: no data found")
            return {}
        return json.loads(content)
    except subprocess.CalledProcessError as e:
        log.warning(f"vulnx id failed for {cve_id}: {e.stderr}")
        return {}
    except json.JSONDecodeError as e:
        log.warning(f"vulnx id returned unparseable output for {cve_id}: {e}")
        return {}
    finally:
        Path(output_file).unlink(missing_ok=True)


def _parse_cve_selection(choice: str, enriched_cves: list[dict]) -> list[dict]:
    """Parse an analyst's numbered CVE selection against the printed, 1-indexed
    list. Blank input or a selection with nothing valid in range both mean
    "skip production" — the caller treats any empty return the same way."""
    choice = choice.strip()
    if not choice:
        return []
    if choice == "0":
        return enriched_cves
    try:
        indices = [int(x) for x in choice.replace(",", " ").split()]
    except ValueError:
        log.warning(f"Could not parse CVE selection {choice!r} — skipping production.")
        return []
    in_range = [enriched_cves[i - 1] for i in indices if 1 <= i <= len(enriched_cves)]
    if len(in_range) != len(indices):
        log.warning(f"Some selected numbers were outside 1-{len(enriched_cves)} and were ignored.")
    return in_range


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
        cve_ids = [c.strip() for c in single_cve.split(",") if c.strip()]
        log.info(f"Processing {len(cve_ids)} CVE(s): {', '.join(cve_ids)}")
        for cve_id in cve_ids:
            cve_data = query_vulnx_id(cve_id)
            if not cve_data:
                log.warning(f"No data found for {cve_id} — skipping")
                continue
            cve_data["cve_id"] = cve_data.get("cve_id", cve_id)
            cve_data["product"] = _derive_product_label(cve_data)
            cve_data["tier"] = 2
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
@click.option("--cve", default=None, help="Force-process specific CVE ID(s), comma-separated")
@click.option(
    "--produce", default=None,
    help="Comma-separated output numbers 1-6 (7=post to Discord), or 0 for all file outputs. "
         "Example: --produce 1,3,6. Pass --produce ask to defer the output-type prompt until "
         "after the CVE list is printed (interactive terminals only).",
)
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

    # Show what the pipeline found before anything gets produced — same
    # numbered-table format as the outputs-produced summary, so an analyst
    # attached to a terminal can select a subset by position before any
    # produce decision is made.
    print_candidate_table(enriched_cves)

    if dry_run:
        log.info("Dry run — skipping Discord post and output production.")
        return

    notifier = DiscordNotifier()
    assembler = ContextAssembler()

    if not produce:
        # No production requested — the "brief and wait" path (README step 4):
        # enrich and post the full candidate list so an analyst watching
        # Discord, not this terminal, can decide what to produce later via
        # `--cve`/`--produce`. No prompt exists here to defer enrichment past.
        for c in enriched_cves:
            assembler.enrich_advisory(c["context"], c)
        notifier.post_brief_report(enriched_cves)
        log.info("ThreatForge run complete.")
        return

    # Scheduled/cron runs and non-interactive invocations must never block on
    # input — only prompt when a human is actually attached and watching.
    interactive = not scheduled and sys.stdin.isatty()

    if produce == "ask":
        # Defers "which outputs?" until after the CVE table above is on
        # screen, instead of cli.py asking it blind before the pipeline runs.
        if not interactive:
            log.warning("--produce ask requires an interactive terminal — nothing to produce.")
            return
        which = click.prompt(
            "Which outputs? 1=advisory 2=technical 3=signatures 4=iocs 5=hunting "
            "6=patches 7=post to Discord (comma-separated, 0=all file outputs, "
            "blank to skip production — 7 is opt-in and not included by 0)",
            default="", show_default=False,
        )
        if not which.strip():
            log.info("Production skipped by analyst.")
            return
        produce = which.strip()

    raw_selected = list(range(1, 7)) if produce == "0" else [int(x) for x in produce.replace(",", " ").split()]
    # 7 is a reserved toggle ("post produced drafts to Discord"), not an
    # output_menu entry — ai_caller/output_router only know about 1-6
    # (real prompts with a save location), so it's split out here rather
    # than treated as a 7th produce-able draft type. "0" (all outputs)
    # never implies it — posting to Discord is always opt-in.
    post_to_discord = 7 in raw_selected
    selected = [n for n in raw_selected if n != 7]

    if not selected:
        log.info("No output types selected (only the Discord toggle) — nothing to produce.")
        return

    # Interactive prompt runs BEFORE any network I/O (enrich_advisory is a
    # per-CVE HTTP round trip — advisory fetch + cve.org cross-check — so
    # running it against the full candidate list first could mean minutes of
    # silent work standing between the printed list and the prompt).
    target_cves = enriched_cves
    if interactive:
        choice = click.prompt(
            f"Produce outputs {selected} for which CVE(s)? "
            f"(Discord post: {'on' if post_to_discord else 'off'}) "
            "(comma-separated numbers from the list above, 0 for all, blank to skip)",
            default="", show_default=False,
        )
        target_cves = _parse_cve_selection(choice, enriched_cves)
        if not target_cves:
            log.info("Production skipped by analyst.")
            return

    # Only now — after the analyst has narrowed the list, or immediately for
    # non-interactive/scheduled runs — enrich and brief just the CVEs that
    # are actually about to be produced. Unlike post_output/post_outputs_complete
    # below, this brief always posts regardless of the item-7 toggle — it's
    # the "here's what's about to happen" notification, not produced content.
    for c in target_cves:
        assembler.enrich_advisory(c["context"], c)
    notifier.post_brief_report(target_cves)

    router = OutputRouter(OUTPUT_DIR)

    if CLEAN_BEFORE_RUN:
        clean_outputs(OUTPUT_DIR)
        router.clean_remote()

    caller = AICaller()
    produced = []

    for cve_data in target_cves:
        for output_num in selected:
            log.info(f"Producing output {output_num} for {cve_data['cve_id']}")
            result = caller.produce(output_num, cve_data)
            filepath = router.save(output_num, cve_data, result)
            if post_to_discord:
                notifier.post_output(output_num, cve_data, result)
            produced.append({
                "cve_id": cve_data.get("cve_id", ""),
                "output_type": result.get("output_type", f"output_{output_num}"),
                "product": cve_data.get("product", ""),
                "tier": cve_data.get("tier_label", ""),
                "score": cve_data.get("composite_score", 0),
                "kev_sources": cve_data.get("context", {}).get("kev_sources", []),
                "status": "REVIEW_NEEDED" if result.get("review_needed") else "OK",
                # filename only — Output Type column already implies the subdirectory
                "file": filepath.name,
            })

    if post_to_discord:
        notifier.post_outputs_complete(target_cves, selected)
    print_summary_table(produced)

    log.info("ThreatForge run complete.")


if __name__ == "__main__":
    main()
