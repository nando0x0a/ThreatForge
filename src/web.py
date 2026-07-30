#!/usr/bin/env python3
"""FastAPI web app for ThreatForge — mirrors the CLI wizard's flow (run
pipeline, pick outputs, produce, browse results) plus config editing and run
history. Auth (HTTP Basic) and TLS terminate at nginx in front of this — this
app assumes it's already behind that gate and adds no auth of its own."""
import json
import logging
import threading
from datetime import datetime
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from config_loader import load_config, CONFIG_PATH
from context_assembler import ContextAssembler
from ai_caller import AICaller
from output_router import OutputRouter
import github_publisher
import orchestrate

log = logging.getLogger("web")

APP_DIR = Path(__file__).parent
PRODUCTS_FILE = Path(orchestrate.PRODUCTS_FILE)
RUNS_LOG = Path("/opt/threatforge/logs/runs.jsonl")


def _github_url(subdir: str, filename: str) -> str | None:
    """Outputs are published to GitHub by OutputRouter.save() (via
    github_publisher) whenever GITHUB_TOKEN/GITHUB_REPO are set — same repo
    ThreatForge's own automation already commits to. Since that repo is
    public, linking there lets anyone view a produced draft without needing
    this site's Basic Auth password at all."""
    if not github_publisher.GITHUB_REPO:
        return None
    branch = github_publisher.GITHUB_BRANCH
    return f"https://github.com/{github_publisher.GITHUB_REPO}/blob/{branch}/outputs/{subdir}/{filename}"

app = FastAPI(title="ThreatForge")
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")

# In-memory state for the current candidate list — single-operator tool, no
# need for per-session complexity. Reset every time the pipeline runs.
# "last_run" records what produced the currently-displayed candidates (mode,
# params, when, how many) so the page never shows a candidate table with no
# indication of where that data came from or whether a run is in progress.
_state: dict = {"enriched_cves": [], "last_run": None}

# Guards writes to _state only — NOT held across the pipeline run itself
# (which calls slow external APIs) so a page load during a run isn't blocked
# waiting on it. See the "shared in-memory state needs a lock" lesson in the
# cli-to-web-ui-deploy skill for why this exists at all.
_state_lock = threading.Lock()


def _output_menu() -> dict:
    return {int(k): v for k, v in load_config()["output_menu"].items()}


def _describe_run(mode: str, product: str, cve: str, count: int) -> str:
    if mode == "product" and product.strip():
        return f"Single product: {product.strip()}"
    if mode == "cve" and cve.strip():
        return f"Single CVE: {cve.strip()}"
    if mode == "test":
        return f"Test mode ({count} candidates)"
    if mode == "recent":
        return f"Recent mode ({count} candidates)"
    return "Daily (production filters)"


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    for c in _state["enriched_cves"]:
        kev_sources = c.get("context", {}).get("kev_sources", [])
        c["kev_source_display"] = orchestrate._format_kev_sources(kev_sources)
    last_run = _state["last_run"]
    return templates.TemplateResponse(request, "index.html", {
        "cves": _state["enriched_cves"],
        "output_menu": _output_menu(),
        "last_run": last_run,
        "pipeline_running": bool(last_run and last_run.get("status") == "running"),
    })


@app.post("/run")
def run_pipeline_route(
    mode: str = Form("daily"),
    product: str = Form(""),
    cve: str = Form(""),
    count: int = Form(5),
):
    description = _describe_run(mode, product, cve, count)
    with _state_lock:
        # Clear immediately, before the (potentially slow) pipeline call —
        # so a page load while this run is in progress never shows the
        # previous run's candidates looking current.
        _state["enriched_cves"] = []
        _state["last_run"] = {"description": description, "status": "running", "started_at": datetime.utcnow().isoformat() + "Z"}

    if mode == "product" and product.strip():
        enriched = orchestrate.run_pipeline(products=[{"name": product.strip().lower(), "tier": 2}])
    elif mode == "cve" and cve.strip():
        enriched = orchestrate.run_pipeline(single_cve=cve.strip())
    elif mode == "test":
        enriched = orchestrate.run_pipeline(test_mode=True)[:count]
    elif mode == "recent":
        enriched = sorted(orchestrate.run_pipeline(test_mode=True), key=lambda c: c.get("age_in_days", 999))[:count]
    else:
        enriched = orchestrate.run_pipeline()

    with _state_lock:
        _state["enriched_cves"] = enriched
        _state["last_run"] = {
            "description": description,
            "status": "OK",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "count": len(enriched),
        }
    return RedirectResponse("/", status_code=303)


@app.post("/produce", response_class=HTMLResponse)
def produce_route(
    request: Request,
    cve_ids: list[str] = Form([]),
    output_nums: list[int] = Form([]),
):
    by_id = {c["cve_id"]: c for c in _state["enriched_cves"]}
    target_cves = [by_id[cid] for cid in cve_ids if cid in by_id]

    if not target_cves or not output_nums:
        return templates.TemplateResponse(request, "produced.html", {"produced": [], "skipped": True})

    assembler = ContextAssembler()
    for c in target_cves:
        assembler.enrich_advisory(c["context"], c)

    router = OutputRouter(orchestrate.OUTPUT_DIR)
    if orchestrate.CLEAN_BEFORE_RUN:
        orchestrate.clean_outputs(orchestrate.OUTPUT_DIR)
        router.clean_remote()

    caller = AICaller()
    menu = _output_menu()
    produced = []
    for cve_data in target_cves:
        for output_num in output_nums:
            log.info(f"[web] Producing output {output_num} for {cve_data['cve_id']}")
            result = caller.produce(output_num, cve_data)
            filepath = router.save(output_num, cve_data, result)
            subdir = menu.get(output_num, {}).get("output_dir", "")
            produced.append({
                "cve_id": cve_data.get("cve_id", ""),
                "output_type": result.get("output_type", f"output_{output_num}"),
                "status": "REVIEW_NEEDED" if result.get("review_needed") else "OK",
                "error": result.get("error") if result.get("review_needed") else None,
                "file": filepath.name,
                "github_url": _github_url(subdir, filepath.name),
            })

    return templates.TemplateResponse(request, "produced.html", {"produced": produced, "skipped": False})


@app.get("/outputs", response_class=HTMLResponse)
def outputs_route(request: Request):
    base = orchestrate.OUTPUT_DIR
    by_dir = {}
    if base.exists():
        for f in sorted(base.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file():
                subdir = f.parent.name
                by_dir.setdefault(subdir, []).append({
                    "name": f.name,
                    "github_url": _github_url(subdir, f.name),
                })
    github_configured = bool(github_publisher.GITHUB_REPO)
    return templates.TemplateResponse(request, "outputs.html", {
        "by_dir": by_dir,
        "github_configured": github_configured,
        "github_repo": github_publisher.GITHUB_REPO,
    })


@app.get("/outputs/{subdir}/{filename}")
def download_output(subdir: str, filename: str):
    """Fallback only — outputs are normally viewed via their GitHub link
    (no auth needed there, repo is public). This stays available in case
    GitHub publishing is ever disabled or a push fails."""
    path = (orchestrate.OUTPUT_DIR / subdir / filename).resolve()
    if orchestrate.OUTPUT_DIR.resolve() not in path.parents or not path.is_file():
        return PlainTextResponse("Not found", status_code=404)
    return FileResponse(path)


@app.get("/runs", response_class=HTMLResponse)
def runs_route(request: Request):
    runs = []
    if RUNS_LOG.exists():
        with open(RUNS_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        runs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    runs.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return templates.TemplateResponse(request, "runs.html", {"runs": runs[:200]})


@app.get("/config/products", response_class=HTMLResponse)
def products_get(request: Request):
    content = PRODUCTS_FILE.read_text() if PRODUCTS_FILE.exists() else ""
    return templates.TemplateResponse(request, "products.html", {"content": content})


@app.post("/config/products")
def products_post(content: str = Form("")):
    PRODUCTS_FILE.write_text(content)
    return RedirectResponse("/config/products", status_code=303)


class _BlockStyleDumper(yaml.Dumper):
    """Preserves the `|` block-literal style for multi-line strings (the AI
    prompts) on write — plain yaml.dump would otherwise flatten them into an
    unreadable single line with escaped \\n, defeating SSH-editability."""
    pass


def _str_presenter(dumper: yaml.Dumper, data: str):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_BlockStyleDumper.add_representer(str, _str_presenter)


# Only these config.tunables are exposed for editing — prompts and the
# output menu stay file/SSH-only, per the security decision in the AWS
# migration plan (they govern what the AI is instructed to do).
_EDITABLE_PIPELINE_FIELDS = ["cve_age_days", "cvss_threshold", "epss_threshold", "new_threshold_days", "query_limit"]


@app.get("/config/pipeline", response_class=HTMLResponse)
def pipeline_config_get(request: Request):
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)
    return templates.TemplateResponse(request, "pipeline_config.html", {
        "pipeline": {k: cfg["pipeline"].get(k) for k in _EDITABLE_PIPELINE_FIELDS},
        "weights": cfg["scoring"]["weights"],
        "cvss_crit_threshold": cfg["scoring"]["cvss_crit_threshold"],
        "scheduler": cfg["scheduler"],
    })


@app.post("/config/pipeline")
def pipeline_config_post(
    cve_age_days: int = Form(...),
    cvss_threshold: float = Form(...),
    epss_threshold: float = Form(...),
    new_threshold_days: int = Form(...),
    query_limit: int = Form(...),
    cvss_crit_threshold: float = Form(...),
    scheduler_enabled: bool = Form(False),
    scheduler_cron: str = Form(...),
):
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)

    cfg["pipeline"]["cve_age_days"] = cve_age_days
    cfg["pipeline"]["cvss_threshold"] = cvss_threshold
    cfg["pipeline"]["epss_threshold"] = epss_threshold
    cfg["pipeline"]["new_threshold_days"] = new_threshold_days
    cfg["pipeline"]["query_limit"] = query_limit
    cfg["scoring"]["cvss_crit_threshold"] = cvss_crit_threshold
    cfg["scheduler"]["enabled"] = scheduler_enabled
    cfg["scheduler"]["cron"] = scheduler_cron

    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f, Dumper=_BlockStyleDumper, sort_keys=False, default_flow_style=False)

    # Config module caches on first load — clear it so the next pipeline run
    # (and this page's next GET) picks up the change without a restart.
    import config_loader
    config_loader._config = None

    return RedirectResponse("/config/pipeline", status_code=303)
