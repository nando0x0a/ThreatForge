#!/usr/bin/env python3
"""Interactive menu for ThreatForge — wraps orchestrate.py's CLI so an analyst
can pick a run mode without memorizing flags. Every action here maps directly
to an `orchestrate.py` invocation; run `python3 src/orchestrate.py --help`
for the flag-level reference."""
import sys

from orchestrate import main as orchestrate_main, load_config

CFG = load_config()


def ask(prompt_text: str, default: str = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{prompt_text}{suffix}: ").strip()
    return val if val else default


def ask_yn(prompt_text: str, default: bool = False) -> bool:
    suffix = " (Y/n)" if default else " (y/N)"
    val = input(f"{prompt_text}{suffix}: ").strip().lower()
    if not val:
        return default
    return val.startswith("y")


def run_orchestrate(args: list[str]) -> None:
    print(f"\n$ orchestrate.py {' '.join(args)}\n")
    try:
        orchestrate_main(args, standalone_mode=False)
    except SystemExit:
        pass
    except Exception as e:
        print(f"\n[cli] Run failed: {e}\n")
    print()


def build_produce_args() -> list[str]:
    if not ask_yn("Produce output drafts for these results?"):
        return []
    which = ask(
        "Which outputs? 1=advisory 2=technical 3=signatures 4=iocs 5=hunting "
        "6=patches (comma-separated, or 0 for all)",
        "0",
    )
    return ["--produce", which]


def wizard_daily():
    args = build_produce_args()
    run_orchestrate(args)


def wizard_test():
    n = ask("How many CVEs?", str(CFG["test_mode"]["default_count"]))
    args = ["--test", n] + build_produce_args()
    run_orchestrate(args)


def wizard_recent():
    n = ask("How many CVEs?", str(CFG["test_mode"]["default_count"]))
    args = ["--recent", n] + build_produce_args()
    run_orchestrate(args)


def wizard_product():
    name = ask("Product name (e.g. nginx)")
    if not name:
        print("No product given, cancelled.")
        return
    args = ["--product", name] + build_produce_args()
    run_orchestrate(args)


def wizard_cve():
    cve_id = ask("CVE ID (e.g. CVE-2024-12345)")
    if not cve_id:
        print("No CVE given, cancelled.")
        return
    args = ["--cve", cve_id] + build_produce_args()
    run_orchestrate(args)


def wizard_dry_run():
    print("Dry run against: 1) production filters  2) test mode  3) recent mode")
    choice = ask("Choice", "1")
    args = ["--dry-run"]
    if choice in ("2", "3"):
        n = ask("How many CVEs?", str(CFG["test_mode"]["default_count"]))
        args += (["--test", n] if choice == "2" else ["--recent", n])
    run_orchestrate(args)


def show_scheduler_status():
    sched = CFG.get("scheduler", {})
    enabled = sched.get("enabled", False)
    cron = sched.get("cron", "?")
    print(f"\nScheduler: {'ENABLED' if enabled else 'DISABLED'}")
    print(f"Cron expression: {cron}")
    print("To change: edit scheduler.enabled / scheduler.cron in config/threatforge.yaml,")
    print("then: docker compose -f docker/docker-compose.yml up -d --force-recreate\n")


MAIN_MENU = """
================================
 ThreatForge — Interactive CLI
================================
 1) Daily pipeline   (production filters: KEV or CVSS>=threshold, age<cve_age_days)
 2) Test mode        (broad search, top N by score, any age)
 3) Recent mode      (broad search, newest N, any age)
 4) Single product
 5) Single CVE
 6) Dry run          (preview only — no Discord post, no AI calls)
 7) Scheduler status
 0) Exit
"""

ACTIONS = {
    "1": wizard_daily,
    "2": wizard_test,
    "3": wizard_recent,
    "4": wizard_product,
    "5": wizard_cve,
    "6": wizard_dry_run,
    "7": show_scheduler_status,
}


def main():
    while True:
        print(MAIN_MENU)
        choice = ask("Choice", "0")
        if choice == "0":
            print("Bye.")
            break
        action = ACTIONS.get(choice)
        if action:
            action()
        else:
            print("Invalid choice.\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
        sys.exit(0)
