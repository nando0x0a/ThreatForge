# ThreatForge
## CVE Intelligence Automation Platform

ThreatForge is a self-hosted automation platform that ingests CVE intelligence, scores and prioritises findings using CISA KEV status, CVSS severity, and RCE indicators, then asks the analyst what to produce before calling the Claude API. Every output is a proposed draft. Nothing is deployed automatically.

---

## The problem it solves

When a high-severity CVE is published, a detection engineer must:

- Read the advisory and understand the attack vector
- Check whether it is actively exploited in the wild (CISA KEV)
- Find public PoC traffic patterns
- Write a Suricata rule, an advisory, a patch recommendation, and threat hunting queries
- Do all of this manually, per CVE, per product, every day

ThreatForge automates every step of the research and first-draft process. The analyst wakes up to a prioritised Slack report and selects what to produce.

---

## How it works

### 1. Intelligence pipeline

ThreatForge runs at 01:30 daily via supercronic inside a Docker container on an Ubuntu Linux host. For every product in `products.txt` it runs:

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

The JSON output is filtered with `jq` to find what is actionable today:

```bash
jq '.results[] | select(.age_in_days < 7 and (.cvss_score >= 7.0 or .is_kev == true))'
```

Everything outside that window is discarded.

---

### 2. CISA KEV — the urgency signal

The `is_kev` flag is the most important field in the pipeline. CISA's Known Exploited Vulnerabilities catalogue lists CVEs for which CISA has confirmed active in-the-wild exploitation by real threat actors. A CVE with `is_kev == true` means:

- Attackers are using this vulnerability **right now**
- It overrides the CVSS threshold entirely
- It goes straight to **Priority 1 — CRITICAL ACT NOW**

A CVSS 7.5 that is KEV-listed is more urgent today than a CVSS 9.8 with no known exploitation. CVSS measures theoretical severity. CISA KEV measures confirmed real-world use.

---

### 3. Scoring and tagging

Every CVE that passes the filter is scored and tagged. Tags are assigned based on detection signals and displayed in every output so the analyst understands exactly why a CVE ranked where it did.

#### Tag dictionary

| Rank | Tag | Meaning | Detection source | Score |
|---|---|---|---|---|
| 1 | `[KEV]` | Listed in CISA Known Exploited Vulnerabilities | `is_kev == true` from vulnx | +50 |
| 2 | `[RCE]` | Network-exploitable RCE (AV:N + PR:N + UI:N) | CVSS vector from vulnx/NVD, confirmed by Claude | +40 |
| 3 | `[RCE-KEV]` | RCE language found in CISA KEV shortDescription | Keyword match on KEV entry | +25 |
| 4 | `[CRIT]` | CVSS score 9.0–10.0 | `cvss_score` from vulnx | +30 |
| 5 | `[HIGH]` | CVSS score 7.0–8.9 | `cvss_score` from vulnx | +20 |
| 6 | `[EPSS]` | EPSS probability > 0.5 | `epss_score` from vulnx | +15 |
| 7 | `[T1]` | Affects a Tier 1 asset | Asset tier in products.txt | +20 |
| 8 | `[WIDE]` | Widely-used software | Curated list in config | +10 |
| 9 | `[POC]` | Public PoC available | NVD references + OSINT | +10 |
| 10 | `[NEW]` | Published within last 3 days | `age_in_days < 3` | +10 |

#### Tag rules

- `[KEV]` and `[RCE]` together always produce **Tier 0** regardless of other tags
- `[RCE-KEV]` is a supporting signal — adds weight but never overrides `[KEV]` or `[RCE]`
- `[CRIT]` and `[HIGH]` are mutually exclusive
- Tags are always displayed in rank order

#### Priority tiers

| Score | Tier | Slack label |
|---|---|---|
| 90+ | Tier 0 | `CRITICAL — ACT NOW` |
| 70–89 | Tier 1 | `HIGH PRIORITY` |
| 40–69 | Tier 2 | `STANDARD` |
| < 40 | Tier 3 | `MONITOR` |

---

### 4. Context Assembler

Before any Claude call is made, the Context Assembler enriches each CVE with three categories of threat intelligence:

**CISA KEV entry** — where `is_kev == true`, the CISA KEV JSON catalogue is queried for `shortDescription` and `requiredAction`. These fields describe the attack vector in defender-oriented language.

**Vendor advisories** — NVD reference URLs from the vulnx output are fetched and summarised. The relevant signal is the network-observable behaviour: specific URI paths, payload patterns, anomalous headers.

**OSINT enrichment** — where a public PoC or campaign association exists, that context is added. Campaign associations drive the MITRE ATT&CK technique tag and classtype in the drafted rule.

The assembled context block is what the model receives. Context quality determines output quality.

---

### 5. Brief findings report and interactive menu

After the pipeline completes, ThreatForge posts a brief findings report to Slack via `notify`:

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

3. CVE-2024-ZZZZ — nginx
   Tags: [HIGH][POC][NEW]  Score: 40
   STANDARD
   Directory traversal in request normalisation.

What would you like me to produce?
Reply with numbers (e.g. "1 3 6") or "0" for all:

1. Security advisory (management)
2. Technical findings (SOC analyst)
3. Suricata signature drafts
4. IoC list
5. Threat hunting queries (CrowdStrike + Netflow)
6. Patch recommendations

To produce outputs, run:
docker exec threatforge python3 orchestrate.py --produce <numbers>
Example: docker exec threatforge python3 orchestrate.py --produce 1 3 6
```

If no output is requested, the brief report is the only output. The menu remains available for manual triggering at any time.

---

### 6. Output modules

ThreatForge calls Claude only for the outputs the analyst selects. Each output is a proposed draft saved to the output folder. Nothing is deployed automatically.

| # | Module | Audience | What Claude produces |
|---|---|---|---|
| 1 | Security advisory | CISO / management | Non-technical risk summary, business impact, recommended action |
| 2 | Technical findings | SOC analyst | Detailed CVE breakdown, attack vector, observable behaviour |
| 3 | Suricata signature drafts | Detection engineer | Candidate Suricata rules (SigForge module) |
| 4 | IoC list | SOC / threat hunter | IPs, domains, hashes, URLs from KEV + advisory + OSINT |
| 5 | Threat hunting queries | SOC analyst | CrowdStrike Event Search + nfdump query drafts |
| 6 | Patch recommendations | Ops / sysadmin | Upgrade path + Ansible playbook draft (PatchForge module) |

---

## Platform roadmap

### Phase 1 — Homelab (current scope)
- Single Ubuntu Linux host running Docker
- All outputs are written reports posted to Slack and saved to a local folder
- Analyst triggers output production via `docker exec`
- `setup.sh` handles full installation and configuration

### Phase 2 — Containerised production
- Docker Compose on a dedicated host or cloud VM
- Full Slack bot (socket mode) for interactive menu
- Persistent output store (S3 or NFS volume)
- Structured logging to a SIEM

### Phase 3 — Enterprise
- Governed LLM endpoint behind an API gateway
- RBAC and audit logging
- Auto-deploy signatures to Suricata
- Push IoCs to MISP or a commercial TIP
- Execute patch playbooks via Ansible Automation Platform
- Ticketing system integration (Jira, ServiceNow)
- New telemetry sources (Splunk SPL, Microsoft Sentinel KQL, Elastic EQL)

---

## Design principles

1. **Intelligence first** — the pipeline runs before any AI call. Context quality determines output quality.
2. **Ask before producing** — Claude is called only for outputs the analyst requests. This saves tokens and keeps the analyst in control.
3. **Everything is a draft** — no output is deployed or sent without analyst review and promotion.
4. **Pluggable by design** — new output modules are new Python files and new prompt templates. The core pipeline does not change.
5. **Reproducible** — `setup.sh` builds the full environment from scratch. `docker compose down -v && docker rmi threatforge` destroys it completely.
6. **Auditable** — every output links back to the CVE, the tags, the composite score, and the assembled context that produced it.

---

## Resume bullet

*Designed and building ThreatForge, a CVE intelligence automation platform that ingests vulnerability data from ProjectDiscovery's vulnx API, correlates findings against the CISA Known Exploited Vulnerabilities catalogue, scores and tags each CVE using a composite model (KEV status, RCE detectability, CVSS score, EPSS probability, asset tier), and uses the Claude API to produce on-demand analyst outputs — security advisories, Suricata signature drafts, IoC lists, CrowdStrike and Netflow threat hunting queries, and Ansible patch recommendations — posting a prioritised Slack briefing each morning and waiting for analyst selection before calling the model.*

---

## Enterprise context

The pattern maps directly to enterprise tooling at any scale. vulnx becomes a Tenable, Qualys, or Wiz CVE feed. The CISA KEV and advisory feeds become a commercial TIP such as Recorded Future or MISP. Suricata becomes an enterprise NGFW or managed NIDS. The local model becomes a governed enterprise LLM endpoint. The Slack webhook becomes a ticketing system integration. The output folder becomes a SOAR platform playbook trigger. Every component in Phase 1 has a direct enterprise analogue and the core pipeline pattern does not change at scale.
