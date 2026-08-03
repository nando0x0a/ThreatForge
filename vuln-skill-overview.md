# Vuln-Skill — Overview & Usage

**CVE (Common Vulnerabilities and Exposures) intelligence automation platform.** Vuln-Skill ingests vulnerability data, scores and prioritises it against real-world exploitation signals, and produces analyst-ready drafts — advisories, detection rules, IoC (Indicator of Compromise) lists, hunting queries, patch playbooks — only when an analyst asks for them. Every output is a proposed draft, cited back to its sources. Nothing is deployed automatically.

Repository: `git@github.com:nando0x0a/Vuln-Skill.git`
License: All rights reserved

---

## 1. The problem

When a high-severity CVE lands, a detection engineer has to read the advisory, check CISA (Cybersecurity and Infrastructure Security Agency) KEV (Known Exploited Vulnerabilities) for active exploitation, find PoC (Proof of Concept) traffic patterns, and hand-write a Suricata rule, an advisory, a patch recommendation, and hunting queries — per CVE, per product, every day. Vuln-Skill automates the research and first-draft work so the analyst wakes up to a prioritised briefing and picks what to produce.

## 2. How it works

1. **Pipeline** — queries [vulnx](https://github.com/projectdiscovery/vulnx) per product in `products.txt`, filters to what's actionable (recent + high severity, or KEV-listed with a recent KEV addition/update — an old KEV-listed CVE doesn't bypass the age window on its own).
2. **Score & tag** — a composite model combining CISA KEV status, network-exploitable RCE (Remote Code Execution) detection, CVSS (Common Vulnerability Scoring System), EPSS (Exploit Prediction Scoring System), asset tier, PoC availability, and software prevalence. KEV + RCE together always means drop-everything priority.
3. **Verify** — cross-checks NVD (National Vulnerability Database)/vulnx's CVSS score against the CVE Program's own CNA (CVE Numbering Authority)-published record; disagreements are surfaced explicitly, never silently resolved. Every fact-bearing output carries a numbered, deterministic source list.
4. **Brief** — posts a prioritised report to Discord and waits. No output is generated until the analyst selects one.
5. **Produce** — calls the configured AI backend only for the requested output types, saves them locally, and (optionally) commits them to a GitHub repo as a running audit trail.

## 3. Features

- **CISA KEV-aware prioritisation** — confirmed in-the-wild exploitation overrides CVSS severity
- **Composite scoring** with a fully config-driven tag/weight system (`vuln-skill.yaml`, no code changes to retune)
- **Cross-source severity verification** — NVD vs. CVE.org/CNA, discrepancies flagged inline
- **Source-cited outputs** — every draft ends with a verified `## Sources` section, independent of model compliance
- **Pluggable AI backend** — Claude by default, or any OpenAI-compatible endpoint (local Ollama/LM Studio with no API key, OpenRouter, Groq, OpenAI cloud, ...)
- **GitHub-published audit trail** — every draft is committed to a repo, diffable and versioned
- **Interactive CLI (Command Line Interface) wizard** (`src/cli.py`) plus broad spot-check modes (`--test`, `--recent`) for validating against CISA KEV / cve.org
- **Scheduler is opt-in** — fully analyst-driven by default; enable a daily cron run only if you want it

## 4. Output modules

| # | Module | Audience |
|---|---|---|
| 1 | Security advisory | CISO (Chief Information Security Officer) / management |
| 2 | Technical findings | SOC (Security Operations Center) analyst |
| 3 | Suricata signature draft | Detection engineer |
| 4 | IoC list | SOC / threat hunter |
| 5 | Threat hunting queries (CrowdStrike + nfdump) | SOC analyst |
| 6 | Patch recommendation + Ansible playbook | Ops / sysadmin |
| 7 | Post produced outputs to Discord (opt-in toggle, not a real draft type) | — |

## 5. Architecture

```text
Vuln-Skill/
├── setup.sh                    # one-shot install/deploy script
├── requirements.txt            # Python dependencies
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── entrypoint.sh            # decides scheduler vs. idle at container start
├── config/
│   ├── .env.example             # secrets template (copy to .env, never commit)
│   ├── vuln-skill.yaml         # single source of truth: filters, scoring, prompts, output menu
│   └── products.txt             # tracked product/asset inventory (name,tier)
├── src/
│   ├── orchestrate.py           # CLI entrypoint — pipeline, produce flow, click options
│   ├── cli.py                   # interactive wizard wrapping orchestrate.py
│   ├── config_loader.py         # loads/caches vuln-skill.yaml
│   ├── context_assembler.py     # builds per-CVE context: KEV attribution, CVSS parsing, sources
│   ├── cve_org_lookup.py        # CNA-published CVSS cross-check via cve.org
│   ├── scorer.py                # composite scoring model → tags, tier, score
│   ├── ai_caller.py             # calls Claude / OpenAI-compatible backend per output type
│   ├── output_router.py         # writes drafts to disk, builds header/sources footer, logs runs
│   ├── notifier.py               # Discord webhook posts (brief report, per-output, summary)
│   └── github_publisher.py      # commits/cleans outputs/ in the GitHub repo via the Git Data API
└── outputs/                      # generated drafts (gitignored locally; published to GitHub separately)
    ├── advisories/
    ├── rules/
    ├── iocs/
    ├── hunting/
    └── patches/
```

### Data flow

```text
products.txt ──▶ vulnx search ──▶ ContextAssembler ──▶ Scorer ──▶ sorted candidate list
                                        │                              │
                             (KEV catalogue, CVSS               composite_score,
                              vector parsing, cve.org           tags, priority_tier
                              cross-check, sources[])                 │
                                                                       ▼
                                                        Discord brief report (waits)
                                                                       │
                                                     analyst selects CVE(s) + output(s)
                                                                       ▼
                                                     AICaller.produce() per output type
                                                                       │
                                        ┌──────────────────────────────┴─────────────────────────┐
                                        ▼                                                          ▼
                              OutputRouter.save()                                    (optional) Discord post
                              (local file + header/footer)                            per produced output
                                        │
                                        ▼
                              github_publisher.publish()
                              (commit to GITHUB_REPO)
```

## 6. Setup

Requires: Docker + Docker Compose v2, `curl`, `git`, and three secrets — an Anthropic API key, a ProjectDiscovery API key (powers `vulnx`), and a Discord webhook URL.

```bash
git clone git@github.com:nando0x0a/Vuln-Skill.git
cd Vuln-Skill
./setup.sh
```

`setup.sh` is idempotent (safe to re-run). It:

1. Checks prerequisites (`docker`, `curl`, `git`, Docker Compose v2).
2. Creates `/opt/docker/vuln-skill/{config,outputs/{rules,advisories,iocs,hunting,patches},logs}`.
3. Copies config templates, creates `.env` from `.env.example` if missing.
4. Prompts interactively for any of `ANTHROPIC_API_KEY`, `PDTM_API_KEY`, `DISCORD_WEBHOOK_URL` left as placeholders, and loops until all three are filled in.
5. Builds the Docker image.
6. Starts the container via `docker compose up -d` and waits for a healthy status.

Everything else — pipeline filters, scoring weights, AI provider, prompts — lives in `config/vuln-skill.yaml`, which is bind-mounted read-only into the container, so edits take effect on the next run without a rebuild.

## 7. Usage

```bash
# Interactive wizard — pick a run mode, no flags to memorize
docker exec -it vuln-skill python3 src/cli.py

# Or drive orchestrate.py directly:
docker exec vuln-skill python3 src/orchestrate.py --dry-run          # preview only, no AI calls / Discord post
docker exec vuln-skill python3 src/orchestrate.py                    # full pipeline, brief-and-wait
docker exec vuln-skill python3 src/orchestrate.py --produce 1,3,6    # produce advisory + signatures + patch recs for whatever's selected
docker exec vuln-skill python3 src/orchestrate.py --produce 0        # produce all 6 file output types
docker exec vuln-skill python3 src/orchestrate.py --produce 1,3,6,7  # same, plus post each to Discord (7 is opt-in, never implied by 0)
docker exec vuln-skill python3 src/orchestrate.py --product nginx --produce ask
docker exec vuln-skill python3 src/orchestrate.py --cve CVE-2024-12345,CVE-2024-12346 --produce ask
docker exec vuln-skill python3 src/orchestrate.py --test 10          # broad spot-check: top 10 by score, any age, ignores cve_age_days
docker exec vuln-skill python3 src/orchestrate.py --recent 10        # same broad search, newest-first instead of score-ranked
```

CLI wizard menu (`src/cli.py`):

```text
1) Daily pipeline   (production filters: KEV or CVSS>=threshold, age<cve_age_days)
2) Test mode        (broad search, top N by score, any age)
3) Recent mode      (broad search, newest N, any age)
4) Single product
5) Single CVE
6) Dry run          (preview only — no Discord post, no AI calls)
7) Scheduler status
0) Exit
```

### Interactive flow

1. Pipeline runs, prints a numbered candidate table (CVE, product, score, tags, KEV source/added-date).
2. Prompts: *"Which outputs? 1=advisory 2=technical 3=signatures 4=iocs 5=hunting 6=patches 7=post to Discord"*.
3. Prompts: *"Produce outputs [...] for which CVE(s)?"* — numbers refer to the table above, `0` for all, blank to skip.
4. Enrichment (advisory fetch, cve.org cross-check) runs only for the selected CVEs, then a brief posts to Discord.
5. Each selected output is generated, saved to `outputs/<type>/`, optionally posted to Discord, and committed to GitHub if configured.
6. A summary table prints at the end: CVE, output type, product, tier, score, KEV source, status, filename.

### Scheduler (opt-in)

Disabled by default. To enable a daily automated run, edit `config/vuln-skill.yaml`:

```yaml
scheduler:
  enabled: true
  cron: "30 1 * * *"   # supercronic syntax
```

Then recreate the container so `entrypoint.sh` picks up the change:

```bash
docker compose -f docker/docker-compose.yml up -d --force-recreate
```

Scheduled runs never prompt — they always go through the brief-and-wait path (no `--produce`), since `orchestrate.py` only prompts when `sys.stdin.isatty()` and not `--scheduled`.

## 8. Configuration reference (`config/vuln-skill.yaml`)

All tunables live here — no code changes needed to retune.

| Section | Key | Purpose |
|---|---|---|
| `pipeline` | `cve_age_days` | Max CVE age (or KEV-added/updated recency) to be actionable |
| `pipeline` | `cvss_threshold` | Minimum CVSS to be actionable (unless KEV-listed); also `[HIGH]` tag boundary |
| `pipeline` | `epss_threshold` | EPSS probability above which `[EPSS]` tag applies |
| `pipeline` | `new_threshold_days` | CVE age below which `[NEW]` tag applies |
| `pipeline` | `query_limit` | Candidates pulled per product per query, pre-filter |
| `scheduler` | `enabled`, `cron` | Opt-in daily automated run |
| `output_management` | `clean_before_run` | Wipe `outputs/` (local + GitHub) before each `--produce` run |
| `ai_provider` | `provider`, `model`, `base_url`, `api_key_env`, `max_tokens` | AI backend selection — Anthropic or any OpenAI-compatible endpoint |
| `test_mode` | `default_count`, `query_limit`, `global_limit` | Behaviour of `--test` / `--recent` |
| `scoring` | `weights`, `cvss_crit_threshold`, `tier_thresholds`, `tier_labels`, `widely_used` | Composite scoring model |
| `output_menu` | 1–6 | Label, description, output subfolder, file extension per output type |
| `prompts` | `system_prompt`, `few_shot_rules`, `output_templates` | Every Claude/AI prompt, fully editable |

### Composite scoring model

```text
tags checked in order → weight added if present:
  KEV       +50   CISA/VulnCheck KEV-listed (recent addition/update)
  RCE       +40   Network-exploitable via CVSS vector (AV:N/PR:N/UI:N)
  RCE-KEV   +25   RCE explicitly described in the KEV entry itself
  CRIT      +30   CVSS >= cvss_crit_threshold (9.0)         ┐ mutually
  HIGH      +20   CVSS >= cvss_threshold (7.0)               ┘ exclusive
  EPSS      +15   EPSS probability > epss_threshold (0.5)
  T1        +20   Asset tier 1 (internet-facing/auth/production)
  WIDE      +10   Product matches the widely_used list
  POC       +10   Public PoC known (vulnx is_poc)
  NEW       +10   Age < new_threshold_days (3)

priority_tier:
  KEV + RCE together        → tier 0 (CRITICAL — ACT NOW), regardless of score
  else score >= 90           → tier 0
  else score >= 70           → tier 1 (HIGH PRIORITY)
  else score >= 40           → tier 2 (STANDARD)
  else                        → tier 3 (MONITOR)
```

### AI provider examples

```yaml
# Anthropic (default)
ai_provider:
  provider: anthropic
  model: claude-sonnet-4-6
  base_url: null
  api_key_env: ANTHROPIC_API_KEY

# Local Ollama, same Docker network, no API key required
ai_provider:
  provider: openai_compatible
  model: llama3.2:latest
  base_url: http://ollama:11434/v1
  api_key_env: OLLAMA_API_KEY   # fine if unset/empty

# OpenAI cloud
ai_provider:
  provider: openai_compatible
  model: gpt-4.1
  base_url: https://api.openai.com/v1
  api_key_env: OPENAI_API_KEY
```

## 9. Environment variables (`config/.env`, from `.env.example`)

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key (from console.anthropic.com) |
| `PDTM_API_KEY` | ProjectDiscovery API key — powers `vulnx` |
| `DISCORD_WEBHOOK_URL` | Webhook Vuln-Skill posts reports/outputs to |
| `OPENAI_API_KEY` / `OLLAMA_API_KEY` | Only needed if `ai_provider.provider: openai_compatible` points at one of these |
| `GITHUB_TOKEN` | Fine-grained PAT (Personal Access Token), scoped to `GITHUB_REPO`, Contents: Read and write — enables GitHub publishing |
| `GITHUB_REPO` | `owner/repo` to publish generated outputs to |
| `GITHUB_BRANCH` | Defaults to `main` |
| `OUTPUT_DIR` | Defaults to `/opt/vuln-skill/outputs` |
| `LOG_LEVEL` | Defaults to `INFO` |

Never commit `.env` — only `.env.example` (placeholders) is tracked.

## 10. Operational notes

1. **Nothing is deployed automatically.** Every AI-generated draft is explicitly labeled a proposal for analyst review; Ansible playbooks include a `--check --diff` dry-run command before any real apply.
2. **KEV attribution is per-source**, not a single boolean — vulnx reports catalog-specific entries (CISA, VulnCheck, etc.) with their own `added_date`; Vuln-Skill cross-checks its own live CISA KEV feed and adds a `cisa` source if vulnx didn't tag one.
3. **Severity discrepancies are surfaced, never silently resolved** — if NVD/vulnx's CVSS severity band disagrees with the CNA-published record from cve.org, both are cited by number in the output and flagged in Discord/headers.
4. **`clean_before_run: true`** wipes both the local `outputs/` folder and the GitHub `outputs/` path before each `--produce` run, so neither accumulates stale drafts across runs — `logs/runs.jsonl` is the permanent record regardless of whether a given file still exists.
5. **The Discord webhook is separate from the "post to Discord" output toggle (`7`)** — the brief report and the "what would you like to produce" prompt always post; individual produced drafts only post if `7` is explicitly included (never implied by `0` = all file outputs).
