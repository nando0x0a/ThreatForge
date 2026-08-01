# Vuln-Skill — Full Source

Companion to `vuln-skill-overview.md` (description, architecture, setup/usage). This file contains the complete, current source of every code/config/deploy file needed to reconstruct the project elsewhere. Recreate the directory structure below and drop each block into the matching path.

```text
Vuln-Skill/
├── LICENSE
├── .gitignore
├── requirements.txt
├── setup.sh
├── docker/Dockerfile
├── docker/docker-compose.yml
├── docker/entrypoint.sh
├── config/.env.example
├── config/products.txt
├── config/vuln-skill.yaml
└── src/
    ├── config_loader.py
    ├── context_assembler.py
    ├── cve_org_lookup.py
    ├── scorer.py
    ├── ai_caller.py
    ├── output_router.py
    ├── github_publisher.py
    ├── notifier.py
    ├── orchestrate.py
    └── cli.py
```

`config/.env` (real secrets) is intentionally **not** included — only its placeholder template, `.env.example`, is. See `vuln-skill-overview.md` §9 for what each variable is for.

---

## LICENSE

```text
MIT License

Copyright (c) 2026 nando0x0a

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## .gitignore

```gitignore
config/.env
outputs/
logs/
__pycache__/
*.pyc
*.pyo
.DS_Store
/tmp/
```

## requirements.txt

```text
anthropic>=0.40.0
openai>=1.50.0
requests>=2.31.0
python-dotenv>=1.0.0
pyyaml>=6.0.1
jinja2>=3.1.2
rich>=13.7.0
click>=8.1.7
```

## setup.sh

```bash
#!/usr/bin/env bash
# Vuln-Skill — Setup Script
# Run once on aiserver. Idempotent — safe to re-run after changes.
set -euo pipefail

INSTALL_DIR="/opt/docker/vuln-skill"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="vuln-skill"

echo "================================================"
echo " Vuln-Skill — Setup"
echo "================================================"

# 1. Prerequisites
echo "[1/6] Checking prerequisites..."
for cmd in docker curl git; do
  command -v "$cmd" &>/dev/null || { echo "ERROR: $cmd not found. Aborting."; exit 1; }
done
docker compose version &>/dev/null || { echo "ERROR: Docker Compose v2 required. Aborting."; exit 1; }
echo "  OK."

# 2. Directory structure
echo "[2/6] Creating /opt/docker/vuln-skill/..."
sudo mkdir -p "$INSTALL_DIR"/{config,outputs/{rules,advisories,iocs,hunting,patches},logs}
sudo chown -R "$USER:$USER" "$INSTALL_DIR"
echo "  Done."

# 3. Config templates
echo "[3/6] Copying config templates..."
cp --update=none "$SCRIPT_DIR/config/.env.example" "$INSTALL_DIR/config/.env.example" 2>/dev/null || \
  cp -n           "$SCRIPT_DIR/config/.env.example" "$INSTALL_DIR/config/.env.example"
cp "$SCRIPT_DIR/config/products.txt" "$INSTALL_DIR/config/products.txt"
cp "$SCRIPT_DIR/config/vuln-skill.yaml" "$INSTALL_DIR/config/vuln-skill.yaml"

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
  echo "  │     The URL Vuln-Skill posts daily CVE reports to.               │"
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
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' vuln-skill 2>/dev/null || echo "starting")
  [ "$STATUS" = "healthy" ] && { echo "  Healthy."; break; }
  sleep 3
done

echo ""
echo "================================================"
echo " Vuln-Skill deployed."
echo ""
echo " Logs:      docker logs -f vuln-skill"
echo " Test run:  docker exec vuln-skill python3 src/orchestrate.py --dry-run"
echo " Produce:   docker exec vuln-skill python3 src/orchestrate.py --produce 1 3 6"
echo " Outputs:   $INSTALL_DIR/outputs/"
echo " Destroy:   docker compose -f $SCRIPT_DIR/docker/docker-compose.yml down -v && docker rmi vuln-skill"
echo "================================================"
```

## docker/Dockerfile

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

WORKDIR /opt/vuln-skill

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/products.txt ./config/products.txt
COPY config/vuln-skill.yaml ./config/vuln-skill.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p outputs/{rules,advisories,iocs,hunting,patches} logs

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import anthropic, openai; print('ok')" || exit 1

# entrypoint.sh reads config/vuln-skill.yaml's scheduler section at startup —
# it decides between running supercronic or idling. See that file for details.
CMD ["/usr/local/bin/entrypoint.sh"]
```

## docker/docker-compose.yml

```yaml
services:
  vuln-skill:
    image: vuln-skill
    container_name: vuln-skill
    restart: unless-stopped

    env_file:
      - /opt/docker/vuln-skill/config/.env

    volumes:
      - /opt/docker/vuln-skill/outputs:/opt/vuln-skill/outputs
      - /opt/docker/vuln-skill/logs:/opt/vuln-skill/logs
      # Directory-level mount, not per-file — a per-file bind mount pins to
      # the inode at container-creation time, so editors/scripts that replace
      # rather than truncate-in-place (sed -i, cp of a new file, etc.) silently
      # orphan it. Mounting the directory resolves by path on every access.
      - /opt/docker/vuln-skill/config:/opt/vuln-skill/config:ro

    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONPATH=/opt/vuln-skill/src
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

## docker/entrypoint.sh

```bash
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
```

## config/.env.example

```dotenv
# Vuln-Skill environment variables — secrets and deployment paths only.
# Tunable pipeline/scoring/prompt values live in config/vuln-skill.yaml.
# Copy to .env and fill in values. NEVER commit .env to version control.

ANTHROPIC_API_KEY=your_anthropic_api_key_here
PDTM_API_KEY=your_projectdiscovery_api_key_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook/url

# AI provider key — which var is actually used is set by ai_provider.api_key_env
# in config/vuln-skill.yaml. Only fill in the one your active provider needs;
# a local Ollama/LM Studio setup needs no key at all — leave it blank.
OPENAI_API_KEY=
OLLAMA_API_KEY=

# Enables GitHub publishing of generated outputs — every saved draft is also
# pushed as a commit to GITHUB_REPO. Needs a fine-grained PAT scoped to that
# repo with Contents: Read and write.
GITHUB_TOKEN=
GITHUB_REPO=
GITHUB_BRANCH=main

OUTPUT_DIR=/opt/vuln-skill/outputs
LOG_LEVEL=INFO
```

## config/products.txt

```text
# Vuln-Skill product inventory
# One product per line. Format: product_name,tier
# tier: 1 = internet-facing/auth/production, 2 = internal, 3 = dev/test

# Original baseline
apache httpd,1
nginx,1
openssh,1
jenkins,2
ubuntu,1
windows,1
wordpress,1

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

## config/vuln-skill.yaml

```yaml
# Vuln-Skill — single source of truth for pipeline filters, scoring, the
# Discord output menu text, and every Claude prompt.
#
# Secrets (API keys, webhook URLs) stay in config/.env — never put them here.
# This file is bind-mounted read-only into the container, so edits here take
# effect on the next run without rebuilding the image.

pipeline:
  cve_age_days: 7          # only consider CVEs newer than this many days; for KEV-listed CVEs, measured from the KEV-added/CVE-updated date instead of publish date — an old KEV entry does not bypass this
  cvss_threshold: 7.0      # minimum CVSS score to be actionable (unless KEV-listed); also the [HIGH] tag boundary
  epss_threshold: 0.5      # EPSS probability above which the [EPSS] tag applies
  new_threshold_days: 3    # CVE age below which the [NEW] tag applies
  query_limit: 15          # candidates to pull per product per query (KEV, and CVSS-sorted), before filtering — same shape as test_mode.query_limit

# Daily automated run — disabled by default. When disabled, Vuln-Skill only
# runs when triggered manually (via `docker exec ... src/cli.py` or
# `orchestrate.py` directly); the container stays up and healthy either way,
# since manual runs need it alive regardless.
#
# The scheduler is set up once when the container starts, so changing either
# value here requires a container restart to take effect:
#   docker compose -f docker/docker-compose.yml up -d --force-recreate
scheduler:
  enabled: false
  cron: "30 1 * * *"   # cron expression (supercronic syntax), only used when enabled: true

# Local outputs/ folder housekeeping. Outputs are drafts for analyst review
# (see runs.jsonl for a permanent record of every generation, independent of
# whether the file itself still exists) — there's no GitHub publishing, so
# this is the only retention mechanism.
output_management:
  clean_before_run: true   # wipe outputs/{advisories,rules,iocs,hunting,patches} before producing new drafts each run

# Which AI backend produces the 6 output drafts. Two provider modes:
#
#   provider: anthropic         — Claude API. api_key_env must point to a .env
#                                  var holding a real Anthropic key.
#   provider: openai_compatible — anything speaking the OpenAI chat-completions
#                                  API: OpenAI itself, Ollama, LM Studio,
#                                  OpenRouter, Groq, Together, etc. Set base_url
#                                  to the provider's endpoint. For a fully local
#                                  setup with no API key needed (Ollama, LM
#                                  Studio), leave api_key_env pointing at an
#                                  empty/unset .env var — a placeholder is used.
#
# Examples:
#   Anthropic (default):
#     provider: anthropic
#     model: claude-sonnet-4-6
#     base_url: null
#     api_key_env: ANTHROPIC_API_KEY
#
#   Local Ollama on this host (same Docker network, no API key required):
#     provider: openai_compatible
#     model: llama3.2:latest
#     base_url: http://ollama:11434/v1
#     api_key_env: OLLAMA_API_KEY   # fine if unset/empty — no key needed
#
#   OpenAI cloud:
#     provider: openai_compatible
#     model: gpt-4.1
#     base_url: https://api.openai.com/v1
#     api_key_env: OPENAI_API_KEY
ai_provider:
  provider: anthropic
  model: claude-sonnet-4-6
  base_url: null
  api_key_env: ANTHROPIC_API_KEY
  max_tokens: 2048

# Settings for `--test` and `--recent` (orchestrate.py) — both ignore
# cve_age_days and search broadly (KEV or CVSS >= pipeline.cvss_threshold,
# any age) across products.txt PLUS an unscoped global sweep. `--test` ranks
# the results by composite score; `--recent` ranks by age (newest first),
# regardless of score, for spotting brand-new critical/KEV activity that
# hasn't accumulated EPSS/WIDE signal yet.
test_mode:
  default_count: 5    # default N for `--test [N]` / `--recent [N]` when no count is given
  query_limit: 15      # candidates to pull per product per query (KEV, and CVSS-sorted), before scoring
  global_limit: 30     # candidates to pull from the unscoped global sweep (any product, not just products.txt)

scoring:
  weights:
    KEV: 50
    RCE: 40
    RCE-KEV: 25
    CRIT: 30
    HIGH: 20
    EPSS: 15
    T1: 20
    WIDE: 10
    POC: 10
    NEW: 10

  cvss_crit_threshold: 9.0 # CVSS score at/above which [CRIT] applies instead of [HIGH]

  tier_thresholds:
    tier_0: 90
    tier_1: 70
    tier_2: 40

  tier_labels:
    0: "CRITICAL — ACT NOW"
    1: "HIGH PRIORITY"
    2: "STANDARD"
    3: "MONITOR"

  widely_used:
    - nginx
    - apache
    - apache httpd
    - openssl
    - openssh
    - ubuntu
    - debian
    - windows
    - linux kernel
    - log4j
    - spring framework
    - jenkins
    - docker
    - kubernetes
    - php
    - python
    - nodejs
    - mysql
    - postgresql

output_menu:
  1:
    key: advisory
    label: "Security advisory (management)"
    description: "Non-technical risk summary for CISO/management. Covers business impact, affected systems, and recommended action with a time-bound remediation timeline."
    output_dir: advisories
    extension: ".md"
  2:
    key: technical_findings
    label: "Technical findings (SOC analyst)"
    description: "Deep-dive for SOC analysts. Attack vector breakdown, CVSS analysis, observable behaviour on the wire, detection coverage gaps, and immediate response steps."
    output_dir: advisories
    extension: ".md"
  3:
    key: signatures
    label: "Suricata signature drafts"
    description: "Draft Suricata IDS/IPS rule targeting network-observable behaviour. Includes MITRE ATT&CK tag, KEV status, classtype, and sid. Marked experimental — review before deploying."
    output_dir: rules
    extension: ".rules"
  4:
    key: ioc_list
    label: "IoC list"
    description: "Structured list of IPs, domains, URLs, file hashes, user-agents, and URI paths extracted from KEV entry, vendor advisory, and OSINT. Confidence-rated per indicator."
    output_dir: iocs
    extension: ".txt"
  5:
    key: hunting_queries
    label: "Threat hunting queries (CrowdStrike + Netflow)"
    description: "Ready-to-run CrowdStrike Event Search queries and nfdump Netflow queries. Targets C2 connections, post-exploitation process chains, and protocol anomalies."
    output_dir: hunting
    extension: ".txt"
  6:
    key: patch_recs
    label: "Patch recommendations"
    description: "Upgrade path, rollback risk assessment, and an Ansible playbook (apt module) to patch the affected package across your inventory. Includes dry-run command."
    output_dir: patches
    extension: ".yml"

prompts:
  system_prompt: |
    You are Vuln-Skill, a cybersecurity automation assistant.
    Your role is to produce structured security outputs for analyst review.

    Rules:
    - Produce ONLY the requested output type. No preamble, no explanation outside
      the requested format.
    - Never produce exploit code, attack tools, or instructions for offensive use.
    - Every output is a proposed draft for analyst review. State this where
      appropriate within the output.
    - Use the assembled CVE context, CISA KEV detail, and advisory information
      provided to produce accurate, specific outputs rather than generic ones.
    - If specific technical detail is unavailable, note that clearly rather than
      fabricating indicators or patterns.
    - Tag all rule metadata and output headers with the CVE ID for traceability.
    - The context includes a numbered SOURCES list. When you state a specific
      fact drawn from one of them (a CVSS score, a KEV status, a technical
      detail from a vendor advisory), cite it inline with [N] matching that
      source's number. End the output with a "## Sources" section listing
      every source exactly as given — do not renumber or omit any of them,
      even ones you didn't end up citing inline.
    - If the context includes a SEVERITY DISCREPANCY BETWEEN SOURCES block, you
      MUST surface it explicitly in the output, citing both sources by their
      [N] numbers. Never silently pick one score and omit the other — the
      analyst needs to see the disagreement to judge it themselves.

  few_shot_rules: |
    # Example Suricata rules for few-shot context (signatures module only)
    # These are structural examples — do not copy match logic verbatim

    alert http $EXTERNAL_NET any -> $HOME_NET any (
      msg:"VULN-SKILL CVE-2021-44228 Log4j JNDI injection attempt";
      flow:established,to_server; http.header; content:"${jndi:";
      nocase; reference:cve,2021-44228;
      metadata:mitre_technique_id T1190, is_kev true, status experimental;
      classtype:attempted-admin; sid:9000001; rev:1; )

    alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
      msg:"VULN-SKILL CVE-2024-6387 OpenSSH regreSSHion exploit attempt";
      flow:established,to_server; dsize:>1400;
      threshold:type both, track by_src, count 5, seconds 10;
      reference:cve,2024-6387;
      metadata:mitre_technique_id T1190, is_kev true, status experimental;
      classtype:attempted-admin; sid:9000002; rev:1; )

    alert dns $HOME_NET any -> any 53 (
      msg:"VULN-SKILL CVE-2020-1350 SIGRed DNS exploit attempt";
      flow:established; dns.query; content:"|00 ff|"; offset:2;
      reference:cve,2020-1350;
      metadata:mitre_technique_id T1190, is_kev true, status experimental;
      classtype:attempted-admin; sid:9000003; rev:1; )

  output_templates:
    advisory: |
      You are a cybersecurity communications specialist writing a security advisory
      for a non-technical management audience.

      Write a security advisory in Markdown format with the following sections:

      ## Executive Summary
      One paragraph. What is affected, how severe, and what action is required.
      No technical jargon.

      ## Business Impact
      What could happen if this is not addressed. Focus on business risk:
      data breach, service disruption, regulatory exposure.

      ## Affected Systems
      List the affected products and versions in plain language.

      ## Recommended Action
      What management needs to approve or communicate. Specific, time-bound.

      ## Timeline
      Recommended remediation timeline based on priority tier.

      Write for a CISO or VP-level audience. Avoid CVE numbers in the summary.
      Use the priority tier to set the urgency tone.

    technical_findings: |
      You are a senior security analyst writing a technical findings report
      for a SOC analyst audience.

      Write a technical findings report in Markdown format:

      ## CVE Summary
      CVE ID, affected product, CVSS score, KEV status, age.

      ## Attack Vector
      How the vulnerability is exploited. Network path, required conditions,
      authentication requirements. Reference the CVSS vector components.

      ## Observable Behaviour
      What this attack looks like on the wire or in endpoint telemetry.
      Specific indicators: HTTP paths, payload patterns, process chains,
      network connections.

      ## Detection Coverage
      What signatures or queries would catch this. Reference the Suricata
      rule or hunting query if produced.

      ## Affected Assets
      Which assets in the inventory are affected based on the product list.

      ## Recommended Response
      Immediate containment actions, investigation steps, escalation criteria.

      Write with technical precision. Include specific field values, protocol
      details, and command examples where relevant.

    signatures: |
      You are a detection engineer writing a Suricata IDS/IPS rule.

      Using the CVE metadata, CISA KEV context, and advisory detail provided,
      draft one Suricata rule targeting the network-observable behaviour of
      this vulnerability.

      Requirements:
      - Action: alert
      - Include msg with CVE ID and product name
      - Use appropriate flow keywords
      - Include content and/or pcre match targeting the observable behaviour
      - Include reference:cve tag
      - Include metadata with mitre_technique_id, is_kev status, status experimental
      - Include appropriate classtype
      - Assign a unique sid in the range 9000000-9999999
      - Set rev:1
      - Precede the rule with a comment block (# lines, above the alert line)
        stating exactly how confident this pattern is, based on what evidence
        was actually available:
          * PoC status: if the context's PoC Availability line shows known
            proof-of-concept(s), say so and cite the PoC source(s) by [N];
            if none, say "No public PoC known — pattern inferred from the
            CVE/advisory description only."
          * PCAP status: always state "No packet-capture (PCAP) data source
            is available to this pipeline — this pattern is NOT verified
            against captured exploit traffic."
        This block is the single most important signal for how much an
        analyst should trust the match logic before deploying it.

      Return ONLY the rule text (comment block + rule). No explanation outside
      the comment block, no markdown fencing.

      Example format:
      # Confidence: PoC known — see [4]. No PCAP data source available; pattern
      # inferred from PoC + advisory description, not verified against captured
      # exploit traffic.
      alert http $EXTERNAL_NET any -> $HOME_NET any (
        msg:"VULN-SKILL CVE-XXXX-XXXX product exploit attempt";
        flow:established,to_server; http.uri; content:"/exploit/path";
        pcre:"/exploit_pattern/i";
        reference:cve,XXXX-XXXX;
        metadata:mitre_technique_id T1190, is_kev true, status experimental;
        classtype:attempted-admin; sid:9000001; rev:1; )

    ioc_list: |
      You are a threat intelligence analyst extracting indicators of compromise.

      Based on the CVE metadata, CISA KEV entry, advisory context, and OSINT
      provided, produce a structured IoC list in the following format:

      # IoC List — CVE-XXXX-XXXX
      # Generated: [date]
      # Confidence: HIGH / MEDIUM / LOW per indicator

      ## Network Indicators
      IP: x.x.x.x  # source / description

      ## Domain Indicators
      DOMAIN: malicious.example.com  # description

      ## URL Indicators
      URL: http://example.com/exploit/path  # description

      ## File Indicators
      HASH_SHA256: abc123...  # filename / description
      HASH_MD5: abc123...     # filename / description

      ## User-Agent Indicators
      UA: ExploitScanner/1.0

      ## URI Path Indicators
      URI: /vulnerable/endpoint

      ## Notes
      Any caveats, confidence levels, or context about these indicators.

      If no specific IoCs are available from the provided context, state that
      clearly and list the observable behaviour patterns instead.
      Only include indicators with reasonable confidence from the provided context.

    hunting_queries: |
      You are a threat hunter writing detection queries for two platforms.

      Based on the CVE metadata, observable behaviour, and IoC context provided,
      write threat hunting queries for:

      ## CrowdStrike Event Search

      Write 2-3 CrowdStrike Event Search queries targeting:
      1. Network connections to known malicious IPs/domains
      2. Process execution patterns associated with post-exploitation
      3. File system artefacts if applicable

      Format:
      ```
      event_simpleName=NetworkConnect RemotePort=443 RemoteIP IN ("x.x.x.x")
      | stats count by ComputerName, UserName, RemoteIP, RemotePort
      | sort -count
      ```

      ## nfdump Netflow Queries

      Write 2-3 nfdump queries targeting:
      1. Traffic to known malicious IPs on exploit-relevant ports
      2. Anomalous traffic volumes or patterns
      3. Protocol anomalies associated with the exploit

      Format:
      ```
      nfdump -r /var/log/netflow/nfcapd.current \
        -f 'proto tcp and dst port 8080 and dst ip x.x.x.x' \
        -s record/bytes -n 20
      ```

      ## Hunting Notes
      What to look for, false positive considerations, and escalation criteria.

      Write queries that are ready to run. Use placeholder values
      (x.x.x.x, malicious.example.com) where specific IoCs are not available.

    patch_recs: |
      You are a systems engineer writing a patch recommendation and remediation playbook.

      Based on the CVE metadata and advisory context provided, produce:

      ## Patch Recommendation

      **CVE:** [CVE ID]
      **Affected Product:** [product and affected versions]
      **Fixed Version:** [version that resolves the CVE]
      **Urgency:** [based on priority tier — immediate / within 24h / within 7 days]
      **Rollback Risk:** [what could break, how to revert]

      ## Ansible Remediation Playbook

      Write an Ansible playbook using the apt module to upgrade the affected package:

      ```yaml
      ---
      - name: "Remediate [CVE ID] on {{ target_group }}"
        hosts: "{{ target_group }}"
        become: true
        vars:
          cve_id: "[CVE ID]"
          affected_package: "[package name]"

        tasks:
          - name: Update apt cache
            ansible.builtin.apt:
              update_cache: true
              cache_valid_time: 3600

          - name: Upgrade affected package
            ansible.builtin.apt:
              name: "{{ affected_package }}"
              state: latest
            register: patch_result

          - name: Restart service if package was upgraded
            ansible.builtin.service:
              name: "[service name]"
              state: restarted
            when: patch_result.changed

          - name: Audit log
            ansible.builtin.debug:
              msg: "{{ cve_id }} patched on {{ inventory_hostname }} at {{ ansible_date_time.iso8601 }}"
      ```

      ## Validation Steps
      How to confirm the patch was applied successfully.

      ## Dry Run Command
      ```
      ansible-playbook remediate_[cve_id].yml --check --diff -i inventory.ini
      ```

      Return the playbook as valid YAML. No markdown explanation outside the
      designated sections.
```

## src/config_loader.py

```python
#!/usr/bin/env python3
import os
from pathlib import Path

import yaml

CONFIG_PATH = Path(os.getenv("VULN_SKILL_CONFIG", "/opt/vuln-skill/config/vuln-skill.yaml"))

_config = None


def load_config() -> dict:
    global _config
    if _config is not None:
        return _config
    with open(CONFIG_PATH) as f:
        _config = yaml.safe_load(f)
    return _config
```

## src/context_assembler.py

```python
#!/usr/bin/env python3
import os
import re
import logging
import requests
from typing import Optional
from urllib.parse import urlparse

import cve_org_lookup

log = logging.getLogger("context_assembler")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# vulnx's is_kev can come from any catalog it indexes (each kev[] entry carries
# its own "source"), not just CISA — label/link known ones by name, and fall
# back to a generic "KEV (<source>)" label for anything else it reports.
KEV_SOURCE_LABELS = {
    "cisa": "CISA Known Exploited Vulnerabilities Catalog",
    "vulncheck": "VulnCheck KEV",
}
KEV_SOURCE_URLS = {
    "cisa": CISA_KEV_CATALOG_URL,
    "vulncheck": "https://www.vulncheck.com/kev",
}
RCE_KEYWORDS = [
    "remote code execution", "execute arbitrary code",
    "arbitrary command", "code injection", "command injection",
    "remote command execution", "unauthenticated rce",
]

_kev_cache: Optional[dict] = None


def load_kev_catalogue() -> dict:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        log.info(f"CISA KEV catalogue loaded: {len(_kev_cache)} entries")
    except Exception as e:
        log.warning(f"Failed to load CISA KEV catalogue: {e}")
        _kev_cache = {}
    return _kev_cache


def fetch_advisory_summary(url: str) -> str:
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Vuln-Skill/1.0"})
        resp.raise_for_status()
        plain = re.sub(r"<[^>]+>", " ", resp.text)
        plain = re.sub(r"\s+", " ", plain).strip()
        return plain[:1500]
    except Exception as e:
        log.debug(f"Advisory fetch failed for {url}: {e}")
        return ""


def detect_rce_in_kev(kev_entry: dict) -> bool:
    desc = kev_entry.get("shortDescription", "").lower()
    return any(kw in desc for kw in RCE_KEYWORDS)


def parse_cvss_vector(vector: str) -> dict:
    components = {}
    if not vector:
        return components
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            components[k] = v
    return components


class ContextAssembler:
    def __init__(self):
        self.kev = load_kev_catalogue()

    def assemble(self, cve_data: dict) -> dict:
        cve_id = cve_data.get("cve_id", "")
        context = {
            "cve_id": cve_id,
            "description": cve_data.get("description", ""),
            "cvss_score": cve_data.get("cvss_score", 0),
            "severity": cve_data.get("severity", "unknown"),
            "is_kev": cve_data.get("is_kev", False),
            "kev_sources": [],
            "age_in_days": cve_data.get("age_in_days", 0),
            "kev_short_description": "",
            "kev_required_action": "",
            "rce_in_kev": False,
            "advisory_summary": "",
            "cvss_vector": cve_data.get("cvss_metrics", ""),
            "cvss_components": {},
            "allows_rce": False,
            "rce_vector": "unknown",
            "severity_discrepancy": {},
            "sources": [],
            "poc_available": cve_data.get("is_poc", False),
            "poc_count": cve_data.get("poc_count") or 0,
        }

        if context["is_kev"]:
            # vulnx reports its own per-source kev[] entries (e.g. vulncheck) —
            # trust those for source/added-date attribution.
            kev_sources = [
                {"source": e.get("source", "unknown"), "added_date": e.get("added_date", "")}
                for e in (cve_data.get("kev") or [])
            ]
            # Cross-check against Vuln-Skill's own live CISA fetch: vulnx
            # doesn't always tag "cisa" as a kev[] source even when the CVE is
            # genuinely CISA-listed, so add it if our independent check confirms it
            # and vulnx didn't already report it.
            if cve_id in self.kev and not any(s["source"] == "cisa" for s in kev_sources):
                kev_sources.append({"source": "cisa", "added_date": self.kev[cve_id].get("dateAdded", "")})
            context["kev_sources"] = kev_sources

            if cve_id in self.kev:
                kev_entry = self.kev[cve_id]
                context["kev_short_description"] = kev_entry.get("shortDescription", "")
                context["kev_required_action"] = kev_entry.get("requiredAction", "")
                context["rce_in_kev"] = detect_rce_in_kev(kev_entry)
                log.debug(f"{cve_id}: KEV entry found, rce_in_kev={context['rce_in_kev']}")

        if context["cvss_vector"]:
            components = parse_cvss_vector(context["cvss_vector"])
            context["cvss_components"] = components
            if (components.get("AV") == "N" and
                    components.get("PR") == "N" and
                    components.get("UI") == "N"):
                context["allows_rce"] = True
                context["rce_vector"] = "network"
                log.debug(f"{cve_id}: Network RCE detected via CVSS vector")

        return context

    def enrich_advisory(self, context: dict, cve_data: dict) -> dict:
        """Fetch advisory reference summaries and cross-check severity against
        cve.org (network I/O). Call only for the final, already-trimmed CVE
        set — not every scoring candidate. Builds the numbered source list
        every produced output cites from, in the order sources are added."""
        cve_id = context["cve_id"]
        sources = [{"label": "NVD", "url": NVD_URL.format(cve_id=cve_id)}]

        for kev_src in context.get("kev_sources") or []:
            src = kev_src["source"]
            label = KEV_SOURCE_LABELS.get(src, f"KEV ({src})")
            if kev_src.get("added_date"):
                label += f", added {kev_src['added_date'][:10]}"
            sources.append({"label": label, "url": KEV_SOURCE_URLS.get(src, "")})
        if context["is_kev"] and not context.get("kev_sources"):
            sources.append({"label": "KEV (source unspecified)", "url": ""})

        references = [c.get("url") for c in cve_data.get("citations", []) if c.get("url")]
        for ref in references[:2]:
            summary = fetch_advisory_summary(ref)
            if summary:
                context["advisory_summary"] += summary[:500] + " "
                domain = urlparse(ref).netloc or ref
                sources.append({"label": domain, "url": ref})

        cna_metrics = cve_org_lookup.fetch_cna_metrics(cve_id)
        context["severity_discrepancy"] = cve_org_lookup.check_discrepancy(context["cvss_score"], cna_metrics)
        if cna_metrics:
            sources.append({"label": "CVE.org (CNA-published record)", "url": cna_metrics["source_url"]})

        # PoC availability — vulnx tracks this with per-entry source attribution
        # (is_poc/poc_count/pocs). No packet-capture (PCAP) data is tracked by
        # any source this pipeline has access to — there's no equivalent signal
        # to surface for that, so it's stated as a fixed caveat in the
        # signatures prompt template instead of computed here.
        for poc in (cve_data.get("pocs") or [])[:2]:
            if poc.get("url"):
                sources.append({"label": f"PoC ({poc.get('source', 'unknown')})", "url": poc["url"]})

        context["sources"] = sources
        return context

    def format_for_prompt(self, context: dict) -> str:
        lines = [
            f"CVE: {context['cve_id']}",
            f"Description: {context['description']}",
            f"CVSS Score: {context['cvss_score']} ({context['severity'].upper()})",
            f"Age: {context['age_in_days']} days old",
        ]
        if context["is_kev"]:
            kev_sources = context.get("kev_sources") or []
            if kev_sources:
                src_desc = ", ".join(
                    f"{s['source']} (added {s['added_date'][:10]})" if s.get("added_date") else s["source"]
                    for s in kev_sources
                )
                lines.append(f"KEV Status: ACTIVELY EXPLOITED IN THE WILD — listed by {src_desc}")
            else:
                lines.append("KEV Status: ACTIVELY EXPLOITED IN THE WILD (source unspecified)")
            if context["kev_short_description"]:
                lines.append(f"CISA KEV Description: {context['kev_short_description']}")
            if context["kev_required_action"]:
                lines.append(f"CISA KEV Required Action: {context['kev_required_action']}")
        if context["allows_rce"]:
            lines.append("RCE: YES — network-exploitable (AV:N/PR:N/UI:N)")
        if context["advisory_summary"]:
            lines.append(f"Advisory Context: {context['advisory_summary'][:800]}")

        if context.get("poc_available"):
            lines.append(f"PoC Availability: {context['poc_count']} public proof-of-concept(s) known to exist (see PoC sources below).")
        else:
            lines.append("PoC Availability: No public proof-of-concept known.")

        sources = context.get("sources") or []
        if sources:
            lines.append("")
            lines.append(
                "SOURCES — cite specific factual claims inline using [N] matching the "
                "numbers below, and end the output with a \"## Sources\" section listing "
                "them exactly as shown:"
            )
            for i, src in enumerate(sources, 1):
                lines.append(f"[{i}] {src['label']} — {src['url']}")

        disc = context.get("severity_discrepancy")
        if disc and disc.get("has_discrepancy"):
            nvd_idx = next((i for i, s in enumerate(sources, 1) if s["label"] == "NVD"), 1)
            cna_idx = next((i for i, s in enumerate(sources, 1) if "CVE.org" in s["label"]), len(sources))
            lines.append(
                f"\nSEVERITY DISCREPANCY BETWEEN SOURCES [{nvd_idx}] and [{cna_idx}] — cite both explicitly:\n"
                f"  [{nvd_idx}] NVD: CVSS {disc['nvd_score']} ({disc['nvd_severity']})\n"
                f"  [{cna_idx}] CVE.org (CNA-published, CVSS v{disc['cna_version']}): "
                f"{disc['cna_score']} ({disc['cna_severity']})"
            )
        return "\n".join(lines)
```

## src/cve_org_lookup.py

```python
#!/usr/bin/env python3
import logging
import requests

log = logging.getLogger("cve_org_lookup")

CVE_ORG_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"


def severity_band(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def fetch_cna_metrics(cve_id: str) -> dict:
    """Fetch the CNA-published CVSS metrics from the official CVE Program
    record (cve.org / cveawg.mitre.org). This is the vendor/CNA's own
    assessment — often factoring in temporal/environmental context like
    exploit maturity — as opposed to NVD's independently recalculated base
    score, which is what vulnx surfaces elsewhere in the pipeline."""
    url = CVE_ORG_API.format(cve_id=cve_id)
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Vuln-Skill/1.0"})
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.debug(f"cve.org lookup failed for {cve_id}: {e}")
        return {}

    metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
    for entry in metrics:
        for key, val in entry.items():
            if key.startswith("cvssV") and isinstance(val, dict) and "baseScore" in val:
                score = val["baseScore"]
                return {
                    "cvss_score": score,
                    "cvss_version": val.get("version", key.replace("cvssV", "").replace("_", ".")),
                    "severity": val.get("baseSeverity", severity_band(score)).upper(),
                    "source_url": CVE_ORG_URL.format(cve_id=cve_id),
                }
    return {}


def check_discrepancy(nvd_score: float, cna_metrics: dict) -> dict:
    """Compare vulnx/NVD's CVSS score against an already-fetched cve.org CNA
    result (see fetch_cna_metrics). Returns {} if there's no CNA data, or if
    the two sources agree on severity band. Otherwise returns a note with
    both sources attributed, for surfacing in prompts, output headers, and
    Discord."""
    if not cna_metrics:
        return {}

    nvd_band = severity_band(nvd_score)
    if nvd_band == cna_metrics["severity"]:
        return {}

    return {
        "has_discrepancy": True,
        "nvd_score": nvd_score,
        "nvd_severity": nvd_band,
        "cna_score": cna_metrics["cvss_score"],
        "cna_severity": cna_metrics["severity"],
        "cna_version": cna_metrics["cvss_version"],
        "cna_source_url": cna_metrics["source_url"],
    }
```

## src/scorer.py

```python
#!/usr/bin/env python3
import logging

from config_loader import load_config

log = logging.getLogger("scorer")


class Scorer:
    def __init__(self):
        cfg = load_config()
        scoring = cfg["scoring"]
        self.weights = scoring["weights"]
        self.widely_used = scoring["widely_used"]
        self.tier_labels = {int(k): v for k, v in scoring["tier_labels"].items()}
        self.tier_thresholds = scoring["tier_thresholds"]
        self.cvss_crit_threshold = scoring["cvss_crit_threshold"]
        self.cvss_high_threshold = cfg["pipeline"]["cvss_threshold"]
        self.epss_threshold = cfg["pipeline"]["epss_threshold"]
        self.new_threshold_days = cfg["pipeline"]["new_threshold_days"]
        self.tag_order = list(self.weights.keys())

    def score(self, cve_data: dict, context: dict) -> dict:
        tags = []
        score = 0
        w = self.weights

        if context.get("is_kev"):
            tags.append("KEV")
            score += w["KEV"]

        if context.get("allows_rce"):
            tags.append("RCE")
            score += w["RCE"]

        if context.get("rce_in_kev"):
            tags.append("RCE-KEV")
            score += w["RCE-KEV"]

        cvss = cve_data.get("cvss_score", 0)
        if cvss >= self.cvss_crit_threshold:
            tags.append("CRIT")
            score += w["CRIT"]
        elif cvss >= self.cvss_high_threshold:
            tags.append("HIGH")
            score += w["HIGH"]

        if cve_data.get("epss_score", 0) > self.epss_threshold:
            tags.append("EPSS")
            score += w["EPSS"]

        if cve_data.get("tier", 2) == 1:
            tags.append("T1")
            score += w["T1"]

        product = cve_data.get("product", "").lower()
        if any(w_ in product for w_ in self.widely_used):
            tags.append("WIDE")
            score += w["WIDE"]

        # vulnx flags PoC availability directly (is_poc) — more reliable than
        # guessing from reference-URL domains, which vulnx doesn't expose anyway.
        if cve_data.get("is_poc", False):
            tags.append("POC")
            score += w["POC"]

        if cve_data.get("age_in_days", 999) < self.new_threshold_days:
            tags.append("NEW")
            score += w["NEW"]

        if "KEV" in tags and "RCE" in tags:
            priority_tier = 0
        elif score >= self.tier_thresholds["tier_0"]:
            priority_tier = 0
        elif score >= self.tier_thresholds["tier_1"]:
            priority_tier = 1
        elif score >= self.tier_thresholds["tier_2"]:
            priority_tier = 2
        else:
            priority_tier = 3

        tags.sort(key=lambda t: self.tag_order.index(t) if t in self.tag_order else 99)

        log.debug(f"{cve_data.get('cve_id')}: score={score} tier={priority_tier} tags={tags}")

        return {
            "tags": tags,
            "composite_score": score,
            "priority_tier": priority_tier,
            "tier_label": self.tier_labels[priority_tier],
        }
```

## src/ai_caller.py

```python
#!/usr/bin/env python3
import os
import re
import logging

from context_assembler import ContextAssembler
from config_loader import load_config

log = logging.getLogger("ai_caller")


class AICaller:
    def __init__(self):
        cfg = load_config()
        ai_cfg = cfg["ai_provider"]
        self.provider = ai_cfg["provider"]
        self.model = ai_cfg["model"]
        self.max_tokens = ai_cfg.get("max_tokens", 2048)
        self.assembler = ContextAssembler()
        self.system_prompt = cfg["prompts"]["system_prompt"]
        self.few_shot = cfg["prompts"]["few_shot_rules"]
        self.templates = cfg["prompts"]["output_templates"]
        self.output_menu = {int(k): v for k, v in cfg["output_menu"].items()}

        if self.provider == "anthropic":
            import anthropic
            api_key = os.getenv(ai_cfg.get("api_key_env", "ANTHROPIC_API_KEY"), "")
            self.client = anthropic.Anthropic(api_key=api_key)
        elif self.provider == "openai_compatible":
            import openai
            api_key = os.getenv(ai_cfg.get("api_key_env", "OPENAI_API_KEY"), "") or "not-needed"
            self.client = openai.OpenAI(api_key=api_key, base_url=ai_cfg.get("base_url"))
        else:
            raise ValueError(f"Unknown ai_provider.provider: {self.provider!r} (expected 'anthropic' or 'openai_compatible')")

    def produce(self, output_num: int, cve_data: dict) -> dict:
        menu_entry = self.output_menu.get(output_num, {})
        output_type = menu_entry.get("key", "unknown")
        template = self.templates.get(output_type, "")
        context = cve_data.get("context", {})
        context_block = self.assembler.format_for_prompt(context)
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))

        user_message = (
            f"{context_block}\n\n"
            f"Priority Score: {cve_data.get('composite_score', 0)}\n"
            f"Priority Tags: {tags_str}\n"
            f"Priority Tier: {cve_data.get('tier_label', 'UNKNOWN')}\n\n"
            f"{self.few_shot if output_num == 3 else ''}\n\n"
            f"{template}"
        )

        result = self._call(user_message)

        if not result["success"] and result.get("error"):
            log.info(f"Self-repair retry for {cve_data['cve_id']} output {output_num}")
            retry_msg = user_message + f"\n\nPrevious attempt failed:\n{result['error']}\nPlease fix and try again."
            result = self._call(retry_msg)
            if not result["success"]:
                result["review_needed"] = True
                log.warning(f"Self-repair failed for {cve_data['cve_id']} output {output_num}")

        result["output_type"] = output_type
        result["cve_id"] = cve_data.get("cve_id", "")
        return result

    def _call(self, user_message: str) -> dict:
        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=self.system_prompt,
                    messages=[{"role": "user", "content": user_message}],
                )
                content = response.content[0].text
            else:
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                )
                content = response.choices[0].message.content

            content = re.sub(r"^```[a-z]*\n?", "", content, flags=re.MULTILINE)
            content = re.sub(r"\n?```$", "", content, flags=re.MULTILINE)
            return {"success": True, "content": content.strip(), "error": None}
        except Exception as e:
            log.error(f"AI API error ({self.provider}): {e}")
            return {"success": False, "content": "", "error": str(e)}
```

## src/output_router.py

```python
#!/usr/bin/env python3
import json
import logging
from pathlib import Path
from datetime import datetime

import github_publisher
from config_loader import load_config

log = logging.getLogger("output_router")

_OUTPUT_MENU = {int(k): v for k, v in load_config()["output_menu"].items()}


class OutputRouter:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def clean_remote(self) -> int:
        """Wipe every file under outputs/ in the GitHub repo (single commit) —
        the remote-side counterpart to the local outputs/ folder wipe, so
        GitHub never accumulates files across runs."""
        return github_publisher.clean_outputs()

    def save(self, output_num: int, cve_data: dict, result: dict) -> Path:
        cve_id = cve_data.get("cve_id", "UNKNOWN").replace("-", "_")
        output_type = result.get("output_type", f"output_{output_num}")
        menu_entry = _OUTPUT_MENU.get(output_num, {})
        ext = menu_entry.get("extension", ".txt")
        subdir = menu_entry.get("output_dir", "misc")

        folder = self.base_dir / subdir
        folder.mkdir(parents=True, exist_ok=True)

        # One canonical filename per CVE+output-type — no timestamp. Re-running
        # against the same CVE overwrites this file (locally and, via SHA-based
        # update in github_publisher, on GitHub too) instead of piling up a new
        # timestamped file on every run. The generation time still lives in the
        # header below. review_needed status also stays out of the filename —
        # a REVIEW_NEEDED_ prefix would give the same CVE+type two possible
        # paths, defeating the point of a single canonical file.
        filename = f"{cve_id}_{output_type}{ext}"
        filepath = folder / filename

        header = self._build_header(cve_data, result, output_num, ext)
        footer = self._build_sources_footer(cve_data, ext)
        content = header + "\n\n" + result.get("content", "") + footer

        if result.get("review_needed"):
            content += f"\n\n# REVIEW_NEEDED\n# Error: {result.get('error', 'unknown')}"

        filepath.write_text(content)
        log.info(f"Saved: {filepath}")
        self._log_run(cve_data, output_num, result, filepath)

        repo_path = f"outputs/{subdir}/{filename}"
        commit_msg = f"Vuln-Skill: {output_type} for {cve_data.get('cve_id', 'UNKNOWN')}"
        github_publisher.publish(str(filepath), repo_path, commit_msg)

        return filepath

    def _build_header(self, cve_data: dict, result: dict, output_num: int, ext: str) -> str:
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        fields = [
            f"CVE:       {cve_data.get('cve_id', '')}",
            f"Product:   {cve_data.get('product', '')}",
            f"Tags:      {tags_str}",
            f"Score:     {cve_data.get('composite_score', 0)}",
            f"Tier:      {cve_data.get('tier_label', '')}",
        ]

        disc = cve_data.get("context", {}).get("severity_discrepancy") or {}
        if disc.get("has_discrepancy"):
            fields.append(
                f"SEVERITY DISCREPANCY: NVD/vulnx says {disc['nvd_score']} "
                f"({disc['nvd_severity']}) — CVE.org (CNA, v{disc['cna_version']}) says "
                f"{disc['cna_score']} ({disc['cna_severity']}). See {disc['cna_source_url']}"
            )

        fields += [
            f"Generated: {datetime.utcnow().isoformat()}Z",
            f"Status:    {'REVIEW_NEEDED' if result.get('review_needed') else 'OK'}",
        ]

        title = f"Vuln-Skill Output — {result.get('output_type', '').upper()}"
        if ext == ".md":
            # '#'-prefixed lines are H1 headings in Markdown, not comments — each
            # would render as its own giant heading. Use a blockquote instead:
            # normal body-text size, still visually set apart from the content below.
            lines = [f"> **{title}**", ">"] + [f"> {f}" for f in fields]
            return "\n".join(lines)

        lines = [f"# {title}"] + [f"# {f}" for f in fields] + ["# ---"]
        return "\n".join(lines)

    def _build_sources_footer(self, cve_data: dict, ext: str) -> str:
        """Deterministic source list, guaranteed present regardless of whether
        the model's own citations (if any) match or are complete."""
        sources = cve_data.get("context", {}).get("sources") or []
        if not sources:
            return ""

        if ext == ".md":
            # Same heading level and plain list style as the AI's own "## Sources"
            # section, so this reads as the same size/font, not a giant heading
            # per '#'-prefixed line.
            lines = ["", "## Sources (Vuln-Skill-verified)", ""]
            for i, src in enumerate(sources, 1):
                lines.append(f"[{i}] {src['label']} — {src['url']}")
            return "\n".join(lines) + "\n"

        # '#' is a genuine comment character in .txt/.yml/.rules — safe as-is.
        lines = ["", "# --- Sources (Vuln-Skill-verified) ---"]
        for i, src in enumerate(sources, 1):
            lines.append(f"# [{i}] {src['label']} — {src['url']}")
        return "\n".join(lines) + "\n"

    def _log_run(self, cve_data: dict, output_num: int, result: dict, filepath: Path) -> None:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cve_id": cve_data.get("cve_id"),
            "product": cve_data.get("product"),
            "output_num": output_num,
            "output_type": result.get("output_type"),
            "composite_score": cve_data.get("composite_score"),
            "tags": cve_data.get("tags"),
            "success": result.get("success"),
            "review_needed": result.get("review_needed", False),
            "filepath": str(filepath),
        }
        log_path = Path("/opt/vuln-skill/logs/runs.jsonl")
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
```

## src/github_publisher.py

```python
#!/usr/bin/env python3
import os
import base64
import logging
import requests

log = logging.getLogger("github_publisher")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
_API = "https://api.github.com"


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _get_sha(path: str) -> str | None:
    """Return the blob SHA of an existing file, or None if it doesn't exist."""
    url = f"{_API}/repos/{GITHUB_REPO}/contents/{path}"
    try:
        resp = requests.get(url, headers=_headers(), params={"ref": GITHUB_BRANCH}, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("sha")
    except Exception as e:
        log.debug(f"SHA lookup failed for {path}: {e}")
    return None


def clean_outputs(prefix: str = "outputs/") -> int:
    """Delete every file under `prefix` in the repo, in a single commit —
    called once before each --produce run so GitHub never accumulates
    outputs across runs, mirroring the local clean_before_run behavior.
    Uses the Git Data API (tree/commit/ref) rather than one DELETE call per
    file, which would create one commit per file instead of one commit total."""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        log.debug("GitHub cleanup skipped — GITHUB_TOKEN or GITHUB_REPO not set")
        return 0

    ref_url = f"{_API}/repos/{GITHUB_REPO}/git/refs/heads/{GITHUB_BRANCH}"
    try:
        resp = requests.get(ref_url, headers=_headers(), timeout=10)
        resp.raise_for_status()
        base_commit_sha = resp.json()["object"]["sha"]

        resp = requests.get(f"{_API}/repos/{GITHUB_REPO}/git/commits/{base_commit_sha}", headers=_headers(), timeout=10)
        resp.raise_for_status()
        base_tree_sha = resp.json()["tree"]["sha"]

        resp = requests.get(f"{_API}/repos/{GITHUB_REPO}/git/trees/{base_tree_sha}?recursive=1", headers=_headers(), timeout=15)
        resp.raise_for_status()
        tree_items = resp.json().get("tree", [])
    except Exception as e:
        log.error(f"GitHub: failed to read tree for cleanup: {e}")
        return 0

    to_delete = [item for item in tree_items if item.get("type") == "blob" and item["path"].startswith(prefix)]
    if not to_delete:
        return 0

    # base_tree + entries with sha=None removes each path from the resulting tree
    new_tree_entries = [{"path": item["path"], "mode": item["mode"], "type": "blob", "sha": None} for item in to_delete]
    try:
        resp = requests.post(
            f"{_API}/repos/{GITHUB_REPO}/git/trees", headers=_headers(),
            json={"base_tree": base_tree_sha, "tree": new_tree_entries}, timeout=15,
        )
        resp.raise_for_status()
        new_tree_sha = resp.json()["sha"]

        resp = requests.post(
            f"{_API}/repos/{GITHUB_REPO}/git/commits", headers=_headers(),
            json={
                "message": f"Vuln-Skill: clean {len(to_delete)} file(s) under {prefix}",
                "tree": new_tree_sha,
                "parents": [base_commit_sha],
            },
            timeout=15,
        )
        resp.raise_for_status()
        new_commit_sha = resp.json()["sha"]

        resp = requests.patch(ref_url, headers=_headers(), json={"sha": new_commit_sha}, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        log.error(f"GitHub: cleanup commit failed: {e}")
        return 0

    log.info(f"GitHub: cleaned {len(to_delete)} file(s) under {prefix} in one commit")
    return len(to_delete)


def publish(local_path: str, repo_path: str, commit_message: str) -> bool:
    """Push a local file to the GitHub repo. Creates or updates as needed."""
    if not GITHUB_TOKEN or not GITHUB_REPO:
        log.debug("GitHub publishing skipped — GITHUB_TOKEN or GITHUB_REPO not set")
        return False

    try:
        with open(local_path, "rb") as f:
            content_b64 = base64.b64encode(f.read()).decode()
    except Exception as e:
        log.error(f"Failed to read {local_path} for GitHub publish: {e}")
        return False

    sha = _get_sha(repo_path)
    payload = {
        "message": commit_message,
        "content": content_b64,
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    url = f"{_API}/repos/{GITHUB_REPO}/contents/{repo_path}"
    try:
        resp = requests.put(url, headers=_headers(), json=payload, timeout=15)
        resp.raise_for_status()
        action = "updated" if sha else "created"
        log.info(f"GitHub: {action} {repo_path}")
        return True
    except Exception as e:
        log.error(f"GitHub publish failed for {repo_path}: {e}")
        return False
```

## src/notifier.py

```python
#!/usr/bin/env python3
import os
import logging
import requests
from datetime import datetime

from config_loader import load_config

log = logging.getLogger("notifier")

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
DISCORD_USERNAME = "Vuln-Skill"
# Discord hard limit is 2000 chars; stay under with buffer
_CHUNK = 1900

_OUTPUT_MENU = {int(k): v for k, v in load_config()["output_menu"].items()}
OUTPUT_LABELS = {num: entry["label"] for num, entry in _OUTPUT_MENU.items()}
OUTPUT_DESCRIPTIONS = {num: entry["description"] for num, entry in _OUTPUT_MENU.items()}


def _post(message: str) -> bool:
    if not DISCORD_WEBHOOK_URL:
        log.error("DISCORD_WEBHOOK_URL not set")
        return False
    chunks = [message[i:i + _CHUNK] for i in range(0, len(message), _CHUNK)]
    for chunk in chunks:
        try:
            resp = requests.post(
                DISCORD_WEBHOOK_URL,
                json={"content": chunk, "username": DISCORD_USERNAME},
                timeout=10,
            )
            resp.raise_for_status()
        except Exception as e:
            log.error(f"Discord post failed: {e}")
            return False
    return True


class DiscordNotifier:
    def post_brief_report(self, enriched_cves: list[dict]) -> None:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"**Vuln-Skill — Daily Report**",
            f"{now} · {len(enriched_cves)} actionable CVE(s) found",
            "",
        ]
        for i, cve in enumerate(enriched_cves, 1):
            tags_str = " ".join(f"[{t}]" for t in cve.get("tags", []))
            lines += [
                f"**{i}. {cve['cve_id']}** — {cve.get('product', '').upper()}",
                f"   Tags: {tags_str}  Score: {cve.get('composite_score', 0)}",
                f"   **{cve.get('tier_label', 'UNKNOWN')}**",
                f"   {cve.get('context', {}).get('description', '')[:120]}...",
            ]
            disc = cve.get("context", {}).get("severity_discrepancy") or {}
            if disc.get("has_discrepancy"):
                lines.append(
                    f"   ⚠️ **Severity disputed**: NVD says {disc['nvd_severity']} "
                    f"({disc['nvd_score']}) — CVE.org says {disc['cna_severity']} ({disc['cna_score']})"
                )
            lines.append("")
        lines += [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "**What would you like me to produce?**",
            "",
        ]
        for num, label in OUTPUT_LABELS.items():
            desc = OUTPUT_DESCRIPTIONS.get(num, "")
            lines += [
                f"**{num}. {label}**",
                f"> {desc}",
                "",
            ]
        lines += [
            "**0. All of the above**",
            "",
            "**7. Post produced outputs to Discord** (opt-in — `0` does not include this; "
            "outputs are otherwise only saved locally/GitHub)",
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "**Produce outputs:**",
            "`docker exec vuln-skill python3 src/orchestrate.py --produce 1,3,6,7`",
            "*(comma-separated, no spaces — e.g. `1,3,6` or `0` for all file outputs; add `7` to also post to Discord)*",
        ]
        _post("\n".join(lines))
        log.info(f"Brief report posted to Discord: {len(enriched_cves)} CVEs")

    def post_output(self, output_num: int, cve_data: dict, result: dict) -> None:
        """Post a single generated output to Discord with markdown rendering."""
        label = OUTPUT_LABELS.get(output_num, f"Output {output_num}")
        cve_id = cve_data.get("cve_id", "")
        tags_str = " ".join(f"[{t}]" for t in cve_data.get("tags", []))
        tier = cve_data.get("tier_label", "")
        banner = (
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🛡️ **{label.upper()}**\n"
            f"**CVE:** {cve_id}  |  **{tier}**  |  Score: {cve_data.get('composite_score', 0)}\n"
            f"**Tags:** {tags_str}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        content = result.get("content", "")
        full = banner + content
        chunks = [full[i:i + _CHUNK] for i in range(0, len(full), _CHUNK)]
        for chunk in chunks:
            _post(chunk)

    def post_outputs_complete(self, enriched_cves: list[dict], selected: list[int]) -> None:
        labels = [OUTPUT_LABELS.get(n, f"Output {n}") for n in selected]
        cve_ids = [c["cve_id"] for c in enriched_cves]
        _post(
            f"**Vuln-Skill — All outputs posted above** ✓\n"
            f"CVEs: {', '.join(cve_ids)}\n"
            f"Produced: {', '.join(labels)}"
        )

    def post_empty_report(self) -> None:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        _post(f"**Vuln-Skill — Daily Report**\n{now} · No actionable CVEs found today.")
```

## src/orchestrate.py

```python
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

load_dotenv("/opt/vuln-skill/config/.env")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/opt/vuln-skill/logs/vuln-skill.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("orchestrate")

_cfg = load_config()
PRODUCTS_FILE = "/opt/vuln-skill/config/products.txt"
CVE_AGE_DAYS = _cfg["pipeline"]["cve_age_days"]
CVSS_THRESHOLD = _cfg["pipeline"]["cvss_threshold"]
QUERY_LIMIT = _cfg["pipeline"]["query_limit"]
TEST_DEFAULT_COUNT = _cfg["test_mode"]["default_count"]
TEST_QUERY_LIMIT = _cfg["test_mode"]["query_limit"]
TEST_GLOBAL_LIMIT = _cfg["test_mode"]["global_limit"]
CLEAN_BEFORE_RUN = _cfg["output_management"]["clean_before_run"]
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/opt/vuln-skill/outputs"))


def print_summary_table(produced: list[dict]) -> None:
    """One row per produced item — CVE, output type, product, tier, score,
    status, and where it was saved. Shown at the end of any --produce run.
    Width is forced (not auto-detected) since this often runs without a real
    TTY (docker exec -i / cli.py), where Rich would otherwise default to 80
    columns and wrap every row across multiple lines."""
    if not produced:
        return
    table = Table(title="Vuln-Skill — Outputs Produced")
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
    table = Table(title="Vuln-Skill — CVEs Found")
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

    log.info(f"Vuln-Skill starting — mode: {'scheduled' if scheduled else 'manual'}")
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
        log.info("Vuln-Skill run complete.")
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

    log.info("Vuln-Skill run complete.")


if __name__ == "__main__":
    main()
```

## src/cli.py

```python
#!/usr/bin/env python3
"""Interactive menu for Vuln-Skill — wraps orchestrate.py's CLI so an analyst
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
    # "ask" defers the "which outputs?" question to orchestrate.py, which asks
    # it only after the CVE table has printed — asking here, before the
    # pipeline has even run, meant analysts were deciding blind.
    return ["--produce", "ask"]


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
    cve_id = ask("CVE ID(s), comma-separated (e.g. CVE-2024-12345, CVE-2024-12346)")
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
    print("To change: edit scheduler.enabled / scheduler.cron in config/vuln-skill.yaml,")
    print("then: docker compose -f docker/docker-compose.yml up -d --force-recreate\n")


MAIN_MENU = """
================================
 Vuln-Skill — Interactive CLI
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
```
