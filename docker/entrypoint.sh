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
