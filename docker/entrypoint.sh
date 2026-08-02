#!/usr/bin/env bash
set -euo pipefail

# web-bugs-and-tweaks.md #37: the scheduler (supercronic + a
# scheduler.enabled/scheduler.cron config flag) was removed -- always
# disabled by default, and nothing in either deployment (no cron, no
# systemd timer) ever actually enabled it. This container now always
# idles; a run happens via an explicit docker exec or the web UI.
echo "[entrypoint] Container idle. Run manually with:"
echo "[entrypoint]   docker exec -it vuln-skill python3 src/cli.py"
echo "[entrypoint]   docker exec vuln-skill python3 src/orchestrate.py [options]"
exec tail -f /dev/null
