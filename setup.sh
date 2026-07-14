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
