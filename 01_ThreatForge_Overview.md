# ThreatForge
## CVE Intelligence Automation Platform

ThreatForge is a self-hosted automation platform that ingests CVE intelligence, scores and prioritises findings using CISA KEV status, CVSS severity, and RCE indicators, then asks the analyst what to produce before calling an AI backend. Every output is a proposed draft. Nothing is deployed automatically.

---

## The problem it solves

When a high-severity CVE is published, a detection engineer must:

- Read the advisory and understand the attack vector
- Check whether it is actively exploited in the wild (CISA KEV)
- Find public PoC traffic patterns
- Write a Suricata rule, an advisory, a patch recommendation, and threat hunting queries
- Do all of this manually, per CVE, per product, every day

ThreatForge automates every step of the research and first-draft process. The analyst wakes up to a prioritised Discord briefing and selects what to produce.

---

## How it works

### 1. Intelligence pipeline

ThreatForge runs on demand — via `docker exec` or the interactive CLI wizard — and optionally on a schedule (disabled by default; see [Scheduler](#8-scheduler)). For every product in `products.txt` it runs:

```bash
vulnx search "$product" -j > output_${product}.json
```

vulnx (ProjectDiscovery CLI) returns structured JSON for every known CVE affecting that product, including:

| Field | Description |
|---|---|
| `cve_id` | CVE identifier |
| `cve_description` | NVD description |
| `cvss_score` | CVSS base score |
| `severity` | critical / high / medium / low |
| `is_kev` | CISA Known Exploited Vulnerabilities flag |
| `age_in_days` | days since publication |
| `epss_score` | probability of exploitation in next 30 days |
| `cvss_vector` | full CVSS vector string |
| `is_poc` / `poc_count` / `pocs` | public proof-of-concept flag, count, and per-entry source attribution |

The results are filtered in Python to find what is actionable today (the `jq`-equivalent logic):

```python
[r for r in results if r["age_in_days"] < CVE_AGE_DAYS
                    and (r["cvss_score"] >= CVSS_THRESHOLD or r["is_kev"])]
```

Everything outside that window is discarded — for the default daily run. Two additional run modes (`--test`, `--recent`) deliberately ignore this window; see [Run modes](#5-run-modes-and-the-cli-wizard).

A single CVE can also be forced through the pipeline directly via `vulnx id <CVE-ID>`, which returns one canonical record rather than a search result set — used by `--cve`.

---

### 2. CISA KEV — the urgency signal

The `is_kev` flag is the most important field in the pipeline. CISA's Known Exploited Vulnerabilities catalogue lists CVEs for which CISA has confirmed active in-the-wild exploitation by real threat actors. A CVE with `is_kev == true` means:

- Attackers are using this vulnerability **right now**
- It overrides the CVSS threshold entirely
- It goes straight to **Priority 1 — CRITICAL ACT NOW**

A CVSS 7.5 that is KEV-listed is more urgent today than a CVSS 9.8 with no known exploitation. CVSS measures theoretical severity. CISA KEV measures confirmed real-world use.

---

### 3. Scoring and tagging

Every CVE that passes the filter is scored and tagged. Tags are assigned based on detection signals and displayed in every output so the analyst understands exactly why a CVE ranked where it did. Weights, thresholds, and the widely-used-software list all live in `config/threatforge.yaml` — no code change needed to retune scoring.

#### Tag dictionary

| Rank | Tag | Meaning | Detection source | Score |
|---|---|---|---|---|
| 1 | `[KEV]` | Listed in CISA Known Exploited Vulnerabilities | `is_kev == true` from vulnx | +50 |
| 2 | `[RCE]` | Network-exploitable RCE (AV:N + PR:N + UI:N) | CVSS vector from vulnx/NVD | +40 |
| 3 | `[RCE-KEV]` | RCE language found in CISA KEV shortDescription | Keyword match on KEV entry | +25 |
| 4 | `[CRIT]` | CVSS score ≥ 9.0 | `cvss_score` from vulnx | +30 |
| 5 | `[HIGH]` | CVSS score ≥ 7.0 (below CRIT) | `cvss_score` from vulnx | +20 |
| 6 | `[EPSS]` | EPSS probability > 0.5 | `epss_score` from vulnx | +15 |
| 7 | `[T1]` | Affects a Tier 1 asset | Asset tier in products.txt | +20 |
| 8 | `[WIDE]` | Widely-used software | Curated list in config | +10 |
| 9 | `[POC]` | Public PoC available | `is_poc` flag from vulnx (not domain guessing) | +10 |
| 10 | `[NEW]` | Published within `new_threshold_days` (default 3) | `age_in_days` | +10 |

#### Tag rules

- `[KEV]` and `[RCE]` together always produce **Tier 0** regardless of other tags
- `[RCE-KEV]` is a supporting signal — adds weight but never overrides `[KEV]` or `[RCE]`
- `[CRIT]` and `[HIGH]` are mutually exclusive
- Tags are always displayed in rank order

#### Priority tiers

| Score | Tier | Discord label |
|---|---|---|
| 90+ | Tier 0 | `CRITICAL — ACT NOW` |
| 70–89 | Tier 1 | `HIGH PRIORITY` |
| 40–69 | Tier 2 | `STANDARD` |
| < 40 | Tier 3 | `MONITOR` |

---

### 4. Context Assembler & source verification

Before any AI call is made, the Context Assembler enriches each of the final, trimmed CVEs with threat intelligence and builds a **numbered SOURCES list** that every produced output must cite from:

**CISA KEV entry** — where `is_kev == true`, the CISA KEV JSON catalogue is queried for `shortDescription` and `requiredAction`, and the KEV catalogue page itself is added as a source.

**Vendor advisories** — up to two reference URLs are fetched and summarised (network-observable behaviour: URI paths, payload patterns, anomalous headers), each cited by domain.

**CVE.org / CNA cross-check** — the CNA-published record (`cveawg.mitre.org`) is fetched independently of vulnx/NVD and compared by severity band. If the two disagree — e.g. NVD says HIGH but the CNA's own CVSS assessment says CRITICAL — a `SEVERITY DISCREPANCY` block is injected into the prompt, forcing the model to cite **both** sources rather than silently picking one. The same discrepancy is flagged with a ⚠️ warning in the Discord brief report and recorded in the saved output's header.

**PoC availability** — driven by vulnx's own `is_poc`/`poc_count`/`pocs` fields, with each PoC source cited individually. There is no packet-capture (PCAP) data source anywhere in this pipeline — that absence is stated as a fixed caveat wherever it matters (see Suricata signatures, below) rather than silently omitted.

Every fact-bearing output is instructed to cite sources inline as `[N]` and close with a `## Sources` section. The **output router independently appends a deterministic "Sources (ThreatForge-verified)" footer** to every saved file, regardless of how well the model itself complied — so a citation list is always present even if the model's inline citations are incomplete.

---

### 5. Run modes and the CLI wizard

An interactive wizard wraps `orchestrate.py` so an analyst doesn't need to memorize flags:

```bash
docker exec -it threatforge python3 src/cli.py
```

```
================================
 ThreatForge — Interactive CLI
================================
 1) Daily pipeline   (production filters: KEV or CVSS>=threshold, age<cve_age_days)
 2) Test mode        (broad search, top N by score, any age)
 3) Recent mode      (broad search, newest N, any age)
 4) Single product
 5) Single CVE
 6) Dry run          (preview only — no Discord post, no AI calls)
 7) Scheduler status
 0) Exit
```

Every menu path maps 1:1 to a direct `orchestrate.py` invocation, printed before it runs:

| Mode | Flag | What it does |
|---|---|---|
| Daily pipeline | *(default)* | Production filters — actionable-this-week CVEs only |
| Test mode | `--test [N]` | Broad KEV/high-CVSS search, **ignores the age cutoff**, across `products.txt` **plus an unscoped global sweep** (catches critical/KEV CVEs for software not yet in the inventory); ranked by composite score, capped at N (default from config). For spot-checking against CISA KEV / cve.org. |
| Recent mode | `--recent [N]` | Same broad search as test mode, but ranked by **age** (newest first) instead of score — surfaces brand-new KEV/critical activity that hasn't accumulated EPSS/WIDE signal yet to compete on score. |
| Single product | `--product` | Pipeline for one product only |
| Single CVE | `--cve` | Direct `vulnx id` lookup, bypasses all filters |
| Dry run | `--dry-run` | Prints scores/tags to console; no Discord post, no AI calls, no outputs saved |

`--test` and `--recent` are mutually exclusive with each other, and both can be combined with `--produce` to generate real drafts for just that spot-check set.

After the pipeline completes (non-dry-run), ThreatForge posts a brief findings report to Discord via webhook:

```
ThreatForge — Daily Report
2026-07-13 · 01:32 · 3 CVEs found

1. CVE-2024-XXXX — Apache HTTP Server
   Tags: [KEV][RCE][RCE-KEV][CRIT][T1]  Score: 165
   CRITICAL — ACT NOW
   Remote code execution via malformed request header.

2. CVE-2024-YYYY — OpenSSH
   Tags: [KEV][HIGH][EPSS][WIDE]  Score: 85
   HIGH PRIORITY
   Pre-auth heap overflow in the authentication handler.
   ⚠️ Severity disputed: NVD says HIGH (8.1) — CVE.org says CRITICAL (9.0)

3. CVE-2024-ZZZZ — nginx
   Tags: [HIGH][POC][NEW]  Score: 40
   STANDARD
   Directory traversal in request normalisation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What would you like me to produce?

1. Security advisory (management)
   Non-technical risk summary for CISO/management...
2. Technical findings (SOC analyst)
   ...
[... full description per output type ...]

0. All of the above

Produce outputs:
docker exec threatforge python3 src/orchestrate.py --produce 1,3,6
```

The menu remains available for manual triggering at any time; there is no reply-driven bot — the analyst runs the printed command.

---

### 6. Output modules

ThreatForge calls the configured AI backend only for the outputs the analyst selects. Each output is a proposed draft saved to the output folder **and** published to GitHub (see below). Nothing is deployed automatically.

| # | Module | Audience | What's produced |
|---|---|---|---|
| 1 | Security advisory | CISO / management | Non-technical risk summary, business impact, recommended action |
| 2 | Technical findings | SOC analyst | Detailed CVE breakdown, attack vector, observable behaviour |
| 3 | Suricata signature drafts | Detection engineer | Candidate Suricata rule, preceded by a confidence block stating PoC status (cited) and a fixed "no PCAP source available" caveat |
| 4 | IoC list | SOC / threat hunter | IPs, domains, hashes, URLs from KEV + advisory + OSINT, confidence-rated |
| 5 | Threat hunting queries | SOC analyst | CrowdStrike Event Search + nfdump query drafts |
| 6 | Patch recommendations | Ops / sysadmin | Upgrade path + Ansible playbook draft |

Each saved file uses a **canonical, non-timestamped filename** — `{cve_id}_{output_type}{ext}`. Re-running against the same CVE overwrites the file in place, both locally and on GitHub, instead of accumulating timestamped duplicates. `REVIEW_NEEDED` status (self-repair retry failed) is recorded in the file's header/footer, not the filename, so a CVE+output-type always resolves to one path.

---

### 7. GitHub publishing

Every saved draft is also committed to a configured GitHub repository via the Contents API — create-or-update by blob SHA, so reruns update the existing file rather than duplicating it. This turns the repo into a running, versioned, diffable audit trail of every draft ThreatForge has ever proposed, independent of the local filesystem.

When `output_management.clean_before_run` is enabled (default), **both** the local `outputs/` tree and the GitHub `outputs/` tree are wiped before each `--produce` run — the remote wipe uses the Git Data API (tree/commit/ref) to do it in a single commit rather than one deletion per file.

GitHub publishing is entirely optional: if `GITHUB_TOKEN` / `GITHUB_REPO` aren't set in `.env`, publish calls are silently skipped and only the local filesystem is used.

---

### 8. Scheduler

Disabled by default. `config/threatforge.yaml`'s `scheduler.enabled` and `scheduler.cron` control it. When disabled, the container starts, stays healthy, and idles (`tail -f /dev/null`) — ready for on-demand `docker exec` runs at any time. When enabled, `entrypoint.sh` generates the supercronic crontab from the configured cron expression at container start.

Because the crontab is written once at startup, changing either scheduler value requires a container recreate to take effect:

```bash
docker compose -f docker/docker-compose.yml up -d --force-recreate
```

Every other config value in `threatforge.yaml` (pipeline filters, scoring weights, prompts, output menu) is read fresh on every invocation — no rebuild or restart needed.

---

## AI backend

The model is fully pluggable via `ai_provider` in `threatforge.yaml` — no code change to switch:

- **`anthropic`** — Claude API (default: `claude-sonnet-4-6`)
- **`openai_compatible`** — anything speaking the OpenAI chat-completions API: OpenAI cloud, a local Ollama or LM Studio instance (no API key needed), OpenRouter, Groq, Together, etc. — set `base_url` and `model` accordingly.

Every AI call gets a self-repair retry: on failure, the previous error is appended to the prompt and the call is retried once before the output is flagged `REVIEW_NEEDED`.

---

## Platform roadmap

### Phase 1 — Homelab (current scope, in production use)
- Single host running Docker (`python:3.12-slim` base image)
- Discord webhook briefing + local `outputs/` folder + GitHub-committed audit trail
- Analyst triggers runs via `docker exec ... src/cli.py` (interactive wizard) or `orchestrate.py` flags directly
- Scheduler available but off by default — fully analyst-driven
- `setup.sh` handles installation; `config/threatforge.yaml` is the single source of truth for everything but secrets

### Phase 2 — Containerised production
- Reply-driven chat bot (Discord/Slack/Teams) instead of a one-way webhook + manual command
- Persistent output store (S3 or NFS volume) alongside the GitHub audit trail
- Structured logging to a SIEM

### Phase 3 — Enterprise
- Governed LLM endpoint behind an API gateway (the provider abstraction already supports this — same code path as local Ollama)
- RBAC and audit logging
- Auto-deploy signatures to Suricata
- Push IoCs to MISP or a commercial TIP
- Execute patch playbooks via Ansible Automation Platform
- Ticketing system integration (Jira, ServiceNow)
- New telemetry sources (Splunk SPL, Microsoft Sentinel KQL, Elastic EQL)

---

## Design principles

1. **Intelligence first** — the pipeline runs before any AI call. Context quality determines output quality.
2. **Ask before producing** — the model is called only for outputs the analyst requests. This saves tokens and keeps the analyst in control.
3. **Everything is a draft** — no output is deployed or sent without analyst review and promotion.
4. **Every claim is traceable** — outputs cite a deterministic, numbered source list; disagreements between sources (e.g. NVD vs. CNA severity) are surfaced explicitly, never silently resolved.
5. **Pluggable by design** — new output modules are new prompt templates in `threatforge.yaml`; new AI backends are a config change, not a code change. The core pipeline does not change.
6. **Reproducible** — `setup.sh` builds the full environment from scratch. `docker compose down -v && docker rmi threatforge` destroys it completely.
7. **Auditable** — every output links back to the CVE, the tags, the composite score, the assembled context, and — via GitHub publishing — a versioned commit history of every draft ever proposed.

---

## Resume bullet

*Designed and built ThreatForge, a CVE intelligence automation platform that ingests vulnerability data from ProjectDiscovery's vulnx API, cross-verifies severity against both NVD and the CVE Program's own CNA-published records (surfacing disagreements explicitly), correlates findings against the CISA Known Exploited Vulnerabilities catalogue, scores and tags each CVE using a composite model (KEV status, RCE detectability, CVSS score, EPSS probability, asset tier, PoC availability), and uses a pluggable AI backend (Claude or any OpenAI-compatible endpoint, including fully local models) to produce on-demand, source-cited analyst outputs — security advisories, Suricata signature drafts, IoC lists, CrowdStrike and Netflow threat hunting queries, and Ansible patch recommendations — posting a prioritised Discord briefing, publishing every draft to a versioned GitHub audit trail, and waiting for analyst selection before calling the model.*

---

## Enterprise context

The pattern maps directly to enterprise tooling at any scale. vulnx becomes a Tenable, Qualys, or Wiz CVE feed. The CISA KEV feed and CVE.org cross-check become a commercial TIP such as Recorded Future or MISP, plus a governance layer that reconciles conflicting severity scores across vendors. Suricata becomes an enterprise NGFW or managed NIDS. The pluggable AI backend becomes a governed enterprise LLM endpoint — the exact same code path already used for a local Ollama instance in the homelab. The Discord webhook becomes a ticketing system or ChatOps integration (Slack, Teams). The GitHub-committed output audit trail becomes a GRC evidence repository or a PR-based approval workflow — review a draft as a diff, approve by merging. Every component in Phase 1 has a direct enterprise analogue and the core pipeline pattern does not change at scale.
