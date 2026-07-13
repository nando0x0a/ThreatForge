# ThreatForge — Implementation Guide

## Prerequisites

The following must be present on the Ubuntu Linux host before running `setup.sh`:

| Requirement | Version | Check |
|---|---|---|
| Ubuntu Linux | 22.04 LTS | `lsb_release -a` |
| Docker Engine | 24.0+ | `docker --version` |
| Docker Compose | 2.0+ | `docker compose version` |
| curl | any | `curl --version` |
| git | any | `git --version` |

Install Docker on a fresh Ubuntu 22.04 host:

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
threatforge/
├── setup.sh                          # full installation script
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── src/
│   ├── orchestrate.py                # main pipeline loop
│   ├── context_assembler.py          # KEV + advisory + OSINT enrichment
│   ├── scorer.py                     # tag assignment + composite scoring
│   ├── claude_caller.py              # Claude API caller with self-repair
│   ├── slack_notifier.py             # brief report + menu posting
│   ├── output_router.py              # save + log + flag outputs
│   └── modules/
│       ├── advisory.py               # output 1: management advisory
│       ├── technical_findings.py     # output 2: SOC analyst findings
│       ├── signatures.py             # output 3: Suricata rules (SigForge)
│       ├── ioc_list.py               # output 4: IoC list
│       ├── hunting_queries.py        # output 5: CrowdStrike + nfdump
│       └── patch_recs.py             # output 6: patch recs (PatchForge)
├── prompts/
│   ├── system_prompt.txt             # base system prompt for all calls
│   ├── few_shot_rules.txt            # example Suricata rules (few-shot)
│   └── output_templates/
│       ├── advisory.txt
│       ├── technical_findings.txt
│       ├── signatures.txt
│       ├── ioc_list.txt
│       ├── hunting_queries.txt
│       └── patch_recs.txt
├── config/
│   ├── products.txt                  # one product per line
│   ├── provider.yaml                 # notify Slack webhook config
│   ├── .env                          # API keys (never commit this)
│   └── .env.example                  # safe template to commit
├── outputs/                          # generated artifacts (gitignored)
│   ├── rules/
│   ├── advisories/
│   ├── iocs/
│   ├── hunting/
│   └── patches/
└── logs/
    └── threatforge.log
```

---

## setup.sh

`setup.sh` builds the full environment from scratch. Run it once on a fresh host. It is idempotent — safe to run again after changes.

```bash
#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/threatforge"
IMAGE_NAME="threatforge"

echo "================================================"
echo " ThreatForge — Setup Script"
echo "================================================"

# ── 1. Check prerequisites ──────────────────────────
echo "[1/7] Checking prerequisites..."

for cmd in docker curl git; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is required but not installed. Aborting."
    exit 1
  fi
done

if ! docker compose version &>/dev/null; then
  echo "ERROR: Docker Compose v2 is required. Aborting."
  exit 1
fi

echo "  Prerequisites OK."

# ── 2. Create directory structure ───────────────────
echo "[2/7] Creating directory structure..."

mkdir -p "$INSTALL_DIR"/{docker,src/modules,prompts/output_templates,config,outputs/{rules,advisories,iocs,hunting,patches},logs}

echo "  Directories created at $INSTALL_DIR"

# ── 3. Generate .env.example ────────────────────────
echo "[3/7] Generating configuration templates..."

cat > "$INSTALL_DIR/config/.env.example" << 'EOF'
# ThreatForge environment variables
# Copy this file to .env and fill in your values
# NEVER commit .env to version control

# Anthropic Claude API key
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# ProjectDiscovery API key (vulnx + notify)
PDTM_API_KEY=your_projectdiscovery_api_key_here

# Slack webhook URL for notify
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url

# Slack channel name
SLACK_CHANNEL=#security-alerts

# Model configuration
CLAUDE_MODEL=claude-sonnet-4-6

# Pipeline configuration
CVE_AGE_DAYS=7
CVSS_THRESHOLD=7.0
EPSS_THRESHOLD=0.5

# Output directory inside container
OUTPUT_DIR=/opt/threatforge/outputs

# Log level: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=INFO
EOF

cat > "$INSTALL_DIR/config/products.txt" << 'EOF'
# ThreatForge product inventory
# One product per line. Use lowercase. Format: product_name[,tier]
# tier: 1 = internet-facing/auth/production, 2 = internal, 3 = dev/test
# Example:
apache httpd,1
nginx,1
openssh,1
jenkins,2
ubuntu,1
EOF

cat > "$INSTALL_DIR/config/provider.yaml" << 'EOF'
slack:
  webhook_url: "${SLACK_WEBHOOK_URL}"
  channel: "${SLACK_CHANNEL}"
  username: "ThreatForge"
  icon_emoji: ":shield:"
EOF

echo "  Templates created."

# ── 4. Prompt for .env values ────────────────────────
echo "[4/7] Configuring environment variables..."

if [ ! -f "$INSTALL_DIR/config/.env" ]; then
  cp "$INSTALL_DIR/config/.env.example" "$INSTALL_DIR/config/.env"
  echo ""
  echo "  A .env file has been created at $INSTALL_DIR/config/.env"
  echo "  Please fill in your API keys before continuing."
  echo ""
  read -rp "  Press ENTER when you have filled in your API keys..."
else
  echo "  .env already exists, skipping."
fi

# Validate required keys are set
source "$INSTALL_DIR/config/.env"
for var in ANTHROPIC_API_KEY PDTM_API_KEY SLACK_WEBHOOK_URL; do
  if [ -z "${!var}" ] || [[ "${!var}" == *"your_"* ]]; then
    echo "ERROR: $var is not set in .env. Aborting."
    exit 1
  fi
done
echo "  API keys validated."

# ── 5. Build Docker image ────────────────────────────
echo "[5/7] Building Docker image..."

docker build -t "$IMAGE_NAME" "$INSTALL_DIR/docker/" \
  --build-arg PDTM_API_KEY="$PDTM_API_KEY"

echo "  Image built: $IMAGE_NAME"

# ── 6. Start container ───────────────────────────────
echo "[6/7] Starting ThreatForge container..."

cd "$INSTALL_DIR/docker"
docker compose up -d

# Wait for container to be healthy
echo "  Waiting for container to be healthy..."
for i in $(seq 1 10); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' threatforge 2>/dev/null || echo "starting")
  if [ "$STATUS" = "healthy" ]; then
    echo "  Container is healthy."
    break
  fi
  sleep 3
done

# ── 7. Run test pipeline ─────────────────────────────
echo "[7/7] Running test pipeline against CVE-2021-44228 (Log4Shell)..."

docker exec threatforge python3 /opt/threatforge/src/orchestrate.py \
  --cve CVE-2021-44228 --dry-run

echo ""
echo "================================================"
echo " ThreatForge setup complete."
echo ""
echo " Container:  docker ps | grep threatforge"
echo " Logs:       docker logs -f threatforge"
echo " Test run:   docker exec threatforge python3 src/orchestrate.py --cve CVE-2021-44228"
echo " Produce:    docker exec threatforge python3 src/orchestrate.py --produce 1 3 6"
echo " Destroy:    docker compose -f $INSTALL_DIR/docker/docker-compose.yml down -v && docker rmi threatforge"
echo "================================================"
```

Make it executable and run it:

```bash
chmod +x setup.sh
./setup.sh
```

---

## Dockerfile

```dockerfile
FROM ubuntu:22.04

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Build argument for ProjectDiscovery API key (used during image build to install tools)
ARG PDTM_API_KEY

# ── System packages ──────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-venv \
    python3-pip \
    curl \
    wget \
    jq \
    git \
    ca-certificates \
    tzdata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── supercronic (container-friendly cron) ────────────
ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64
ENV SUPERCRONIC=/usr/local/bin/supercronic
RUN curl -fsSLo "$SUPERCRONIC" "$SUPERCRONIC_URL" \
    && chmod +x "$SUPERCRONIC"

# ── pdtm + vulnx + notify ────────────────────────────
RUN curl -sSfL https://pdtm.sh | sh
ENV PATH="/root/.pdtm/go/bin:$PATH"
RUN pdtm -install vulnx && pdtm -install notify

# Authenticate vulnx with the API key baked in at build time
RUN if [ -n "$PDTM_API_KEY" ]; then \
    echo "$PDTM_API_KEY" | vulnx auth; \
    fi

# ── Python dependencies ──────────────────────────────
WORKDIR /opt/threatforge

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Application source ───────────────────────────────
COPY src/ ./src/
COPY prompts/ ./prompts/
COPY config/products.txt ./config/products.txt
COPY config/provider.yaml ./config/provider.yaml

# ── Crontab for supercronic ──────────────────────────
RUN echo "30 1 * * * python3 /opt/threatforge/src/orchestrate.py --scheduled" \
    > /etc/threatforge.cron

# ── Output and log directories ───────────────────────
RUN mkdir -p outputs/{rules,advisories,iocs,hunting,patches} logs

# ── Health check ─────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import anthropic; print('ok')" || exit 1

# ── Entrypoint ───────────────────────────────────────
CMD ["sh", "-c", "/usr/local/bin/supercronic /etc/threatforge.cron"]
```

---

## requirements.txt

```
anthropic>=0.40.0
requests>=2.31.0
python-dotenv>=1.0.0
pyyaml>=6.0.1
jinja2>=3.1.2
rich>=13.7.0
click>=8.1.7
```

---

## docker-compose.yml

```yaml
version: "3.9"

services:
  threatforge:
    image: threatforge
    container_name: threatforge
    restart: unless-stopped

    env_file:
      - ../config/.env

    volumes:
      # Persistent outputs — survives container restarts
      - ../outputs:/opt/threatforge/outputs
      # Persistent logs
      - ../logs:/opt/threatforge/logs
      # Live config — update products.txt without rebuilding
      - ../config/products.txt:/opt/threatforge/config/products.txt:ro
      # Slack webhook config
      - ../config/provider.yaml:/opt/threatforge/config/provider.yaml:ro

    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONPATH=/opt/threatforge/src

    healthcheck:
      test: ["CMD", "python3", "-c", "import anthropic; print('ok')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## Configuration

### products.txt

One product per line. Optionally append `,1` or `,2` for asset tier (Tier 1 = internet-facing/production, Tier 2 = internal). Products without a tier default to Tier 2.

```
apache httpd,1
nginx,1
openssh,1
jenkins,2
ubuntu,1
log4j,1
spring framework,2
```

### .env

```bash
ANTHROPIC_API_KEY=sk-ant-...
PDTM_API_KEY=...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CHANNEL=#security-alerts
CLAUDE_MODEL=claude-sonnet-4-6
CVE_AGE_DAYS=7
CVSS_THRESHOLD=7.0
EPSS_THRESHOLD=0.5
OUTPUT_DIR=/opt/threatforge/outputs
LOG_LEVEL=INFO
```

### provider.yaml

Used by `notify` to post to Slack. The webhook URL is injected from the environment at runtime:

```yaml
slack:
  webhook_url: "${SLACK_WEBHOOK_URL}"
  channel: "${SLACK_CHANNEL}"
  username: "ThreatForge"
  icon_emoji: ":shield:"
```

---

## Running ThreatForge

### Daily scheduled run

Runs automatically at 01:30 via supercronic. No action required.

```bash
# Check the container is running
docker ps | grep threatforge

# Tail logs
docker logs -f threatforge
```

### On-demand: full pipeline (all products)

```bash
docker exec threatforge python3 src/orchestrate.py
```

### On-demand: single product

```bash
docker exec threatforge python3 src/orchestrate.py --product nginx
```

### On-demand: single CVE

```bash
docker exec threatforge python3 src/orchestrate.py --cve CVE-2021-44228
```

### On-demand: produce outputs

After receiving the Slack brief findings report, produce specific outputs by number:

```bash
# Produce outputs 1 (advisory) + 3 (signatures) + 6 (patches)
docker exec threatforge python3 src/orchestrate.py --produce 1 3 6

# Produce all outputs
docker exec threatforge python3 src/orchestrate.py --produce 0

# Dry run (pipeline runs but no Claude calls, no Slack posts)
docker exec threatforge python3 src/orchestrate.py --dry-run
```

### View outputs

Outputs are saved to the mounted `outputs/` directory on the host:

```bash
ls ~/threatforge/outputs/rules/
ls ~/threatforge/outputs/advisories/
cat ~/threatforge/logs/threatforge.log
```

---

## Destroying and rebuilding

```bash
# Stop and remove the container and its volumes
docker compose -f ~/threatforge/docker/docker-compose.yml down -v

# Remove the image
docker rmi threatforge

# Remove all output files (optional — outputs are on the host volume)
rm -rf ~/threatforge/outputs/*

# Rebuild from scratch
cd ~/threatforge && ./setup.sh
```

---

## Updating

```bash
# Pull latest source changes (when applicable)
cd ~/threatforge

# Rebuild the image
docker build -t threatforge ./docker/

# Restart the container
docker compose -f ./docker/docker-compose.yml up -d --force-recreate
```
