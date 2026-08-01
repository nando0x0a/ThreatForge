#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/opt/vuln-skill/config/vuln-skill.yaml
CRON_FILE=/etc/vuln-skill.cron

ENABLED=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['scheduler']['enabled'])")
CRON_EXPR=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['scheduler']['cron'])")

if [ "$ENABLED" = "True" ]; then
    echo "$CRON_EXPR python3 /opt/vuln-skill/src/orchestrate.py --scheduled" > "$CRON_FILE"
    echo "[entrypoint] Scheduler ENABLED — cron: $CRON_EXPR"
    exec /usr/local/bin/supercronic "$CRON_FILE"
else
    echo "[entrypoint] Scheduler DISABLED (scheduler.enabled: false in vuln-skill.yaml)."
    echo "[entrypoint] Container idle. Run manually with:"
    echo "[entrypoint]   docker exec -it vuln-skill python3 src/cli.py"
    echo "[entrypoint]   docker exec vuln-skill python3 src/orchestrate.py [options]"
    exec tail -f /dev/null
fi
