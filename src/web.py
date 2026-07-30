#!/usr/bin/env python3
"""FastAPI web app for ThreatForge — mirrors the CLI wizard's flow (run
pipeline, pick outputs, produce, browse results) plus config editing and run
history. Auth (HTTP Basic) and TLS terminate at nginx in front of this — this
app assumes it's already behind that gate and adds no auth of its own."""
import json
import logging
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
import orchestrate

log = logging.getLogger("web")

APP_DIR = Path(__file__).parent
PRODUCTS_FILE = Path(orchestrate.PRODUCTS_FILE)
RUNS_LOG = Path("/opt/threatforge/logs/runs.jsonl")

app = FastAPI(title="ThreatForge")
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
templates = Jinja2Templates(directory=APP_DIR / "templates")

# In-memory state for the current candidate list — single-operator tool, no
# need for per-session complexity. Reset every time the pipeline runs.
_state: dict = {"enriched_cves": []}


def _output_menu() -> dict:
    return {int(k): v for k, v in load_config()["output_menu"].items()}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "cves": _state["enriched_cves"],
        "output_menu": _output_menu(),
    })


@app.post("/run")
def run_pipeline_route(
    mode: str = Form("daily"),
    product: str = Form(""),
    cve: str = Form(""),
    count: int = Form(5),
):
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
    _state["enriched_cves"] = enriched
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
    produced = []
    for cve_data in target_cves:
        for output_num in output_nums:
            log.info(f"[web] Producing output {output_num} for {cve_data['cve_id']}")
            result = caller.produce(output_num, cve_data)
            filepath = router.save(output_num, cve_data, result)
            produced.append({
                "cve_id": cve_data.get("cve_id", ""),
                "output_type": result.get("output_type", f"output_{output_num}"),
                "status": "REVIEW_NEEDED" if result.get("review_needed") else "OK",
                "file": filepath.name,
            })

    return templates.TemplateResponse(request, "produced.html", {"produced": produced, "skipped": False})


@app.get("/outputs", response_class=HTMLResponse)
def outputs_route(request: Request):
    base = orchestrate.OUTPUT_DIR
    by_dir = {}
    if base.exists():
        for f in sorted(base.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file():
                by_dir.setdefault(f.parent.name, []).append(f.name)
    return templates.TemplateResponse(request, "outputs.html", {"by_dir": by_dir})


@app.get("/outputs/{subdir}/{filename}")
def download_output(subdir: str, filename: str):
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
