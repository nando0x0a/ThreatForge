# ThreatForge — Implementation Guide

## Prerequisites

The Dockerfile is self-contained (`python:3.12-slim` base — no host-side Python/build deps needed). The host only needs Docker itself:

| Requirement | Check |
|---|---|
| Docker Engine 24.0+ | `docker --version` |
| Docker Compose v2 | `docker compose version` |
| curl | `curl --version` |
| git | `git --version` |

Deployed at `/opt/docker/threatforge` on the host, connected to an existing external Docker network named `infra` (created separately — `docker network create infra` if it doesn't already exist).

If Docker itself isn't installed yet (Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

---

## Project structure

```
ThreatForge/
├── 01_ThreatForge_Overview.md
├── 02_ThreatForge_Implementation.md
├── 03_ThreatForge_Code.md
├── setup.sh                          # installer — targets /opt/docker/threatforge
├── requirements.txt
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── entrypoint.sh                 # reads scheduler.enabled at container start
├── src/
│   ├── cli.py                        # interactive wizard, wraps orchestrate.py
│   ├── orchestrate.py                # main pipeline + CLI entry point
│   ├── config_loader.py              # loads/caches threatforge.yaml
│   ├── context_assembler.py          # KEV + advisory + cve.org + PoC enrichment, sources list
│   ├── cve_org_lookup.py             # CNA-published CVSS cross-check (severity discrepancy)
│   ├── scorer.py                     # tag assignment + composite scoring
│   ├── ai_caller.py                  # Anthropic / OpenAI-compatible caller with self-repair
│   ├── notifier.py                   # Discord webhook — brief report, per-output post
│   ├── output_router.py              # save locally + publish to GitHub + log + REVIEW_NEEDED
│   └── github_publisher.py           # GitHub Contents/Git Data API — create/update/clean
├── config/
│   ├── threatforge.yaml              # single source of truth: filters, scoring, prompts, menu
│   ├── products.txt                  # one product per line, with asset tier
│   ├── .env.example                  # safe template (secrets + deployment paths only)
│   └── .env                          # actual secrets — gitignored, never commit
├── outputs/                          # generated artifacts — gitignored, host-only
│   ├── rules/
│   ├── advisories/
│   ├── iocs/
│   ├── hunting/
│   └── patches/
└── logs/
    ├── threatforge.log
    └── runs.jsonl                    # one JSON line per produced output, permanent record
```

There is no `prompts/` directory — every prompt (system prompt, few-shot Suricata examples, and all six output templates) lives inline under `prompts:` in `threatforge.yaml`, alongside the filters and scoring config it's paired with. Editing a prompt is a YAML edit, not a code or file-layout change.

---

## setup.sh

Idempotent — safe to re-run after config changes. Installs to `/opt/docker/threatforge`, walks the operator through the three required secrets interactively (rather than failing with a generic error), then builds and starts the container.

```bash
#!/usr/bin/env bash
# ThreatForge — Setup Script
# Run once on aiserver. Idempotent — safe to re-run after changes.
set -euo pipefail

INSTALL_DIR="/opt/docker/threatforge"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="threatforge"

echo "================================================"
echo " ThreatForge — Setup"
echo "================================================"

# 1. Prerequisites
echo "[1/6] Checking prerequisites..."
for cmd in docker curl git; do
  command -v "$cmd" &>/dev/null || { echo "ERROR: $cmd not found. Aborting."; exit 1; }
done
docker compose version &>/dev/null || { echo "ERROR: Docker Compose v2 required. Aborting."; exit 1; }
echo "  OK."

# 2. Directory structure
echo "[2/6] Creating /opt/docker/threatforge/..."
sudo mkdir -p "$INSTALL_DIR"/{config,outputs/{rules,advisories,iocs,hunting,patches},logs}
sudo chown -R "$USER:$USER" "$INSTALL_DIR"
echo "  Done."

# 3. Config templates
echo "[3/6] Copying config templates..."
cp --update=none "$SCRIPT_DIR/config/.env.example" "$INSTALL_DIR/config/.env.example" 2>/dev/null || \
  cp -n           "$SCRIPT_DIR/config/.env.example" "$INSTALL_DIR/config/.env.example"
cp "$SCRIPT_DIR/config/products.txt" "$INSTALL_DIR/config/products.txt"
cp "$SCRIPT_DIR/config/threatforge.yaml" "$INSTALL_DIR/config/threatforge.yaml"

[ ! -f "$INSTALL_DIR/config/.env" ] && \
  cp "$INSTALL_DIR/config/.env.example" "$INSTALL_DIR/config/.env"

# Prompt whenever any required value is still a placeholder
_needs_keys=0
for _var in ANTHROPIC_API_KEY PDTM_API_KEY DISCORD_WEBHOOK_URL; do
  _val=$(grep "^${_var}=" "$INSTALL_DIR/config/.env" 2>/dev/null | cut -d= -f2-)
  if [ -z "$_val" ] || [[ "$_val" == *"your_"* ]]; then
    _needs_keys=1; break
  fi
done

if [ "$_needs_keys" -eq 1 ]; then
  echo ""
  echo "  ┌─ API KEYS REQUIRED ──────────────────────────────────────────────┐"
  echo "  │                                                                    │"
  echo "  │  Open a NEW terminal and edit:                                     │"
  echo "  │    nano $INSTALL_DIR/config/.env"
  echo "  │                                                                    │"
  echo "  │  Fill in these 3 values:                                           │"
  echo "  │                                                                    │"
  echo "  │  1. ANTHROPIC_API_KEY                                              │"
  echo "  │     Your Claude API key.                                           │"
  echo "  │     Get it at: https://console.anthropic.com → API Keys           │"
  echo "  │     Starts with: sk-ant-...                                        │"
  echo "  │                                                                    │"
  echo "  │  2. PDTM_API_KEY                                                   │"
  echo "  │     ProjectDiscovery API key — needed to use vulnx,               │"
  echo "  │     the CVE search tool that powers the pipeline.                  │"
  echo "  │     Get it at: https://cloud.projectdiscovery.io → API Key        │"
  echo "  │                                                                    │"
  echo "  │  3. DISCORD_WEBHOOK_URL                                            │"
  echo "  │     The URL ThreatForge posts daily CVE reports to.               │"
  echo "  │     How to create one:                                             │"
  echo "  │       Discord → Server Settings → Integrations → Webhooks         │"
  echo "  │       → New Webhook → Copy Webhook URL                            │"
  echo "  │     Starts with: https://discord.com/api/webhooks/...             │"
  echo "  │                                                                    │"
  echo "  │  Come back here and press ENTER when done.                         │"
  echo "  └────────────────────────────────────────────────────────────────────┘"

  # Loop until all keys are actually set
  while true; do
    echo ""
    read -rp "  Press ENTER when the .env file is saved > "
    _all_set=1
    for _var in ANTHROPIC_API_KEY PDTM_API_KEY DISCORD_WEBHOOK_URL; do
      _val=$(grep "^${_var}=" "$INSTALL_DIR/config/.env" 2>/dev/null | cut -d= -f2-)
      if [ -z "$_val" ] || [[ "$_val" == *"your_"* ]]; then
        echo "  ✗ $_var is still empty or contains a placeholder. Edit the file and try again."
        _all_set=0
      fi
    done
    [ "$_all_set" -eq 1 ] && break
  done
  echo "  ✓ All keys detected."
fi

# 4. Validate keys
echo "[4/6] Validating environment variables..."
# shellcheck disable=SC1090
source "$INSTALL_DIR/config/.env"
for var in ANTHROPIC_API_KEY PDTM_API_KEY DISCORD_WEBHOOK_URL; do
  if [ -z "${!var:-}" ] || [[ "${!var}" == *"your_"* ]]; then
    echo "ERROR: $var not set in .env. Aborting."
    exit 1
  fi
done
echo "  Keys OK."

# 5. Build image
echo "[5/6] Building Docker image..."
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR" \
  -f "$SCRIPT_DIR/docker/Dockerfile"
echo "  Image built: $IMAGE_NAME"

# 6. Start container
echo "[6/6] Starting container..."
docker compose -f "$SCRIPT_DIR/docker/docker-compose.yml" \
  --env-file "$INSTALL_DIR/config/.env" up -d

echo ""
echo "  Waiting for healthy status..."
for i in $(seq 1 10); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' threatforge 2>/dev/null || echo "starting")
  [ "$STATUS" = "healthy" ] && { echo "  Healthy."; break; }
  sleep 3
done

echo ""
echo "================================================"
echo " ThreatForge deployed."
echo ""
echo " Logs:      docker logs -f threatforge"
echo " Test run:  docker exec threatforge python3 src/orchestrate.py --dry-run"
echo " Produce:   docker exec threatforge python3 src/orchestrate.py --produce 1 3 6"
echo " Outputs:   $INSTALL_DIR/outputs/"
echo " Destroy:   docker compose -f $SCRIPT_DIR/docker/docker-compose.yml down -v && docker rmi threatforge"
echo "================================================"
```

Note ANTHROPIC_API_KEY is validated at install time even though the AI backend is swappable post-install — it's the default `ai_provider.provider` in `threatforge.yaml`. Switching to a local Ollama/LM Studio backend later doesn't require re-running setup.sh, just editing `threatforge.yaml` and (if needed) `.env`.

Make it executable and run it:

```bash
chmod +x setup.sh
./setup.sh
```

---

## Dockerfile

```dockerfile
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    jq \
    git \
    unzip \
    ca-certificates \
    tzdata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64
ENV SUPERCRONIC=/usr/local/bin/supercronic
RUN curl -fsSLo "$SUPERCRONIC" "$SUPERCRONIC_URL" && chmod +x "$SUPERCRONIC"

RUN curl -fsSL "https://api.github.com/repos/projectdiscovery/pdtm/releases/latest" \
    | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url' \
    | xargs curl -fsSL -o /tmp/pdtm.zip \
    && unzip /tmp/pdtm.zip pdtm -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/pdtm \
    && rm /tmp/pdtm.zip
ENV PATH="/root/.pdtm/go/bin:$PATH"
RUN pdtm -install vulnx

# vulnx auth is handled at runtime via PDCP_API_KEY env var

WORKDIR /opt/threatforge

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/products.txt ./config/products.txt
COPY config/threatforge.yaml ./config/threatforge.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p outputs/{rules,advisories,iocs,hunting,patches} logs

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import anthropic, openai; print('ok')" || exit 1

# entrypoint.sh reads config/threatforge.yaml's scheduler section at startup —
# it decides between running supercronic or idling. See that file for details.
CMD ["/usr/local/bin/entrypoint.sh"]
```

Notable changes from an Ubuntu-base image: `pdtm` is fetched directly from its latest GitHub release asset (not the `pdtm.sh` installer script), only `vulnx` is installed (not `notify` — Discord posting goes through `notifier.py`'s own webhook call, not the ProjectDiscovery `notify` CLI), and `vulnx auth` happens at **container runtime** via `PDCP_API_KEY` (set from `docker-compose.yml`), not baked into the image at build time — so rotating the ProjectDiscovery key doesn't require a rebuild.

---

## docker/entrypoint.sh

Reads `scheduler.enabled` from `threatforge.yaml` at container start and either launches supercronic or idles, ready for `docker exec`:

```bash
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/opt/threatforge/config/threatforge.yaml
CRON_FILE=/etc/threatforge.cron

ENABLED=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['scheduler']['enabled'])")
CRON_EXPR=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['scheduler']['cron'])")

if [ "$ENABLED" = "True" ]; then
    echo "$CRON_EXPR python3 /opt/threatforge/src/orchestrate.py --scheduled" > "$CRON_FILE"
    echo "[entrypoint] Scheduler ENABLED — cron: $CRON_EXPR"
    exec /usr/local/bin/supercronic "$CRON_FILE"
else
    echo "[entrypoint] Scheduler DISABLED (scheduler.enabled: false in threatforge.yaml)."
    echo "[entrypoint] Container idle. Run manually with:"
    echo "[entrypoint]   docker exec -it threatforge python3 src/cli.py"
    echo "[entrypoint]   docker exec threatforge python3 src/orchestrate.py [options]"
    exec tail -f /dev/null
fi
```

---

## requirements.txt

```
anthropic>=0.40.0
openai>=1.50.0
requests>=2.31.0
python-dotenv>=1.0.0
pyyaml>=6.0.1
jinja2>=3.1.2
rich>=13.7.0
click>=8.1.7
```

`openai` is required unconditionally (not just for `openai_compatible` mode) because `ai_caller.py` imports it lazily but the healthcheck imports both `anthropic` and `openai` up front.

---

## docker-compose.yml

```yaml
services:
  threatforge:
    image: threatforge
    container_name: threatforge
    restart: unless-stopped

    env_file:
      - /opt/docker/threatforge/config/.env

    volumes:
      - /opt/docker/threatforge/outputs:/opt/threatforge/outputs
      - /opt/docker/threatforge/logs:/opt/threatforge/logs
      # Directory-level mount, not per-file — a per-file bind mount pins to
      # the inode at container-creation time, so editors/scripts that replace
      # rather than truncate-in-place (sed -i, cp of a new file, etc.) silently
      # orphan it. Mounting the directory resolves by path on every access.
      - /opt/docker/threatforge/config:/opt/threatforge/config:ro

    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONPATH=/opt/threatforge/src
      - PDCP_API_KEY=${PDTM_API_KEY}
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - GITHUB_REPO=${GITHUB_REPO}
      - GITHUB_BRANCH=${GITHUB_BRANCH:-main}

    networks:
      - infra

    healthcheck:
      test: ["CMD", "python3", "-c", "import anthropic, openai; print('ok')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"

networks:
  infra:
    external: true
```

`infra` is an externally-managed Docker network shared with other homelab containers — it must already exist (`docker network create infra`) before `docker compose up`.

---

## Configuration

### threatforge.yaml — single source of truth

Bind-mounted read-only; edits take effect on the **next run** without a rebuild, *except* the `scheduler` block (its cron expression is only read once, at container start — see entrypoint.sh above). Top-level sections:

| Section | Controls |
|---|---|
| `pipeline` | `cve_age_days`, `cvss_threshold`, `epss_threshold`, `new_threshold_days` — the daily-mode filter and `[HIGH]`/`[EPSS]`/`[NEW]` tag boundaries |
| `scheduler` | `enabled` (default `false`), `cron` — requires container recreate to change |
| `output_management` | `clean_before_run` — wipe local + GitHub `outputs/` before each `--produce` |
| `ai_provider` | `provider` (`anthropic` / `openai_compatible`), `model`, `base_url`, `api_key_env`, `max_tokens` |
| `test_mode` | `default_count`, `query_limit`, `global_limit` — used by `--test [N]` / `--recent [N]` |
| `scoring` | tag weights, `cvss_crit_threshold`, `tier_thresholds`, `tier_labels`, `widely_used` product list |
| `output_menu` | the 6 output types — key, label, description (shown in the Discord menu), `output_dir`, file `extension` |
| `prompts` | `system_prompt`, `few_shot_rules`, and all 6 `output_templates` — every AI prompt in the system, in one place |

See `03_ThreatForge_Code.md` for the full file.

### products.txt

One product per line, `product_name,tier` (tier 1 = internet-facing/production, tier 2 = internal; omitted tier defaults to 2). The live inventory covers the actual homelab stack plus a broad enterprise-vendor watchlist:

```
# ThreatForge product inventory
# One product per line. Format: product_name,tier
# tier: 1 = internet-facing/auth/production, 2 = internal, 3 = dev/test

# Original baseline
apache httpd,1
nginx,1
openssh,1
jenkins,2
ubuntu,1
windows,1

# aiserver homelab stack (confirmed running via `docker ps`, 2026-07-14)
grafana,2
prometheus,2
portainer,2
netdata,2
jupyterlab,2
open webui,2
ollama,2
comfyui,2
docker engine,2
nvidia driver,2

# Enterprise-grade vendors — common high-value targets
cisco ios,1
vmware esxi,1
vmware vcenter,2
citrix netscaler,1
fortios,1
palo alto pan-os,1
f5 big-ip,1
oracle weblogic,1
sap netweaver,2
atlassian confluence,1
gitlab,2
ivanti connect secure,1
moveit,1
apache struts,1
apache tomcat,1
log4j,1
splunk,2
kubernetes,2
microsoft exchange,1
microsoft sharepoint,1
microsoft active directory,1
mysql server,2
postgresql server,2
mongodb server,2
```

### .env

Secrets and deployment paths only — everything tunable lives in `threatforge.yaml` instead:

```bash
ANTHROPIC_API_KEY=your_anthropic_api_key_here
PDTM_API_KEY=your_projectdiscovery_api_key_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook/url

# AI provider key — which var is actually used is set by ai_provider.api_key_env
# in config/threatforge.yaml. Only fill in the one your active provider needs;
# a local Ollama/LM Studio setup needs no key at all — leave it blank.
OPENAI_API_KEY=
OLLAMA_API_KEY=

# Enables GitHub publishing of generated outputs — every saved draft is also
# pushed as a commit to GITHUB_REPO. Needs a fine-grained PAT scoped to that
# repo with Contents: Read and write.
GITHUB_TOKEN=
GITHUB_REPO=
GITHUB_BRANCH=main

OUTPUT_DIR=/opt/threatforge/outputs
LOG_LEVEL=INFO
```

`GITHUB_TOKEN`/`GITHUB_REPO` are optional — leaving them blank silently disables GitHub publishing and ThreatForge falls back to local-filesystem-only outputs.

---

## Running ThreatForge

### Interactive wizard (recommended for manual/spot-check runs)

```bash
docker exec -it threatforge python3 src/cli.py
```

Menu-driven: daily pipeline, test mode, recent mode, single product, single CVE, dry run, scheduler status. See `01_ThreatForge_Overview.md` for the full menu and what each mode does.

### Scheduled run

Only runs automatically if `scheduler.enabled: true` in `threatforge.yaml` (default: `false`). Check status:

```bash
docker ps | grep threatforge
docker logs -f threatforge
```

### Direct orchestrate.py invocations

```bash
# Full pipeline (all products, production filters)
docker exec threatforge python3 src/orchestrate.py

# Single product / single CVE
docker exec threatforge python3 src/orchestrate.py --product nginx
docker exec threatforge python3 src/orchestrate.py --cve CVE-2021-44228

# Broad spot-check modes — ignore age cutoff, KEV/high-CVSS only, top N
docker exec threatforge python3 src/orchestrate.py --test 10
docker exec threatforge python3 src/orchestrate.py --recent 10

# Produce outputs — comma-separated, no spaces (1=advisory 2=technical 3=signatures 4=iocs 5=hunting 6=patches)
docker exec threatforge python3 src/orchestrate.py --produce 1,3,6
docker exec threatforge python3 src/orchestrate.py --produce 0   # all

# Dry run — pipeline runs, prints scores/tags, no Discord post, no AI calls
docker exec threatforge python3 src/orchestrate.py --dry-run
```

### View outputs

```bash
ls /opt/docker/threatforge/outputs/rules/
ls /opt/docker/threatforge/outputs/advisories/
cat /opt/docker/threatforge/logs/threatforge.log
cat /opt/docker/threatforge/logs/runs.jsonl        # permanent record of every generation
```

If `GITHUB_TOKEN`/`GITHUB_REPO` are set, the same drafts are also committed to that repo under `outputs/` — a versioned copy independent of the host filesystem.

---

## Destroying and rebuilding

```bash
# Stop and remove the container
docker compose -f docker/docker-compose.yml down -v

# Remove the image
docker rmi threatforge

# Remove all local output files (optional — GitHub copy, if configured, is untouched)
rm -rf /opt/docker/threatforge/outputs/*

# Rebuild from scratch
./setup.sh
```

---

## Updating

```bash
cd /path/to/ThreatForge   # the source checkout, not /opt/docker/threatforge

# Rebuild the image
docker build -t threatforge . -f docker/Dockerfile

# Push config changes (products.txt / threatforge.yaml) to the deployed instance
cp config/products.txt config/threatforge.yaml /opt/docker/threatforge/config/

# Restart the container
docker compose -f docker/docker-compose.yml up -d --force-recreate
```

A `--force-recreate` is only strictly required for `scheduler` changes or a new image build — every other `threatforge.yaml` edit takes effect on the next `docker exec` run without any restart.
