> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-54528
> Product:   jupyterlab
> Tags:      [HIGH]
> Score:     20
> Tier:      MONITOR
> Generated: 2026-07-14T21:07:30.392391Z
> Status:    OK

# Technical Findings Report — CVE-2026-54528

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed draft and must be validated by a qualified security analyst before operational use. Specific indicators and detection logic should be tested in a representative environment prior to deployment.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-54528 |
| **Affected Product** | JupyterLab Git extension (`jupyterlab-git`) < 0.54.0 |
| **CVSS Score** | 7.1 (HIGH) [1] |
| **KEV Status** | Not listed in CISA KEV at time of writing |
| **Vulnerability Age** | 5 days old |
| **Fixed Version** | v0.54.0 [3] |
| **PoC Availability** | No public proof-of-concept known |
| **Priority Tier** | MONITOR |

---

## Attack Vector

### Mechanism

The vulnerability is an **information disclosure** caused by improper path exclusion logic in `GitHandler.prepare()`. The handler uses Python's `fnmatch.fnmatchcase()` to enforce `excluded_paths` — a case-*sensitive* matching function [1][4]. On case-insensitive filesystems (e.g., Windows NTFS, macOS HFS+/APFS), an authenticated user can bypass exclusions by requesting paths using alternate capitalisation (e.g., `Secret/` vs `secret/`, or `CREDENTIALS` vs `credentials`).

The root fix, visible in the patch commit [2], enforces case-normalised comparison before the fnmatch evaluation, closing the bypass.

### Required Conditions

| Condition | Detail |
|---|---|
| **Authentication** | Required — the user must have a valid JupyterLab session |
| **Filesystem** | Case-insensitive OS (Windows, macOS) — Linux ext4/xfs are **not** affected unless mounted with `nocase` option |
| **Component** | `jupyterlab-git` extension must be installed and active |
| **Network Access** | Local or network access to the Jupyter server HTTP port (default: `8888/tcp`) |

### CVSS Considerations

The score of 7.1 HIGH [1] reflects:
- **Attack Vector**: Network
- **Authentication / Privileges Required**: Low (authenticated user)
- **Confidentiality Impact**: High (arbitrary directory read within the Jupyter working tree)
- **Integrity / Availability**: None

The authentication requirement constrains the attack surface to **insider threat, compromised credentials, or shared multi-user Jupyter deployments**.

---

## Observable Behaviour

### HTTP Request Pattern

The bypass manifests as HTTP GET or POST requests to the JupyterLab Git API endpoints with path components that differ in case from the configured `excluded_paths`. Analysts should look for:

GET /git/show?ref=HEAD&path=<VARIANT_CASE_OF_EXCLUDED_DIR>/<file>
GET /git/content?path=<VARIANT_CASE_OF_EXCLUDED_DIR>/
POST /git/log  {"history_count": N, "path": "<VARIANT_CASE_PATH>"}

**Specific indicators:**
- URI contains `/git/` API prefix
- Path parameter uses capitalisation inconsistent with the repository's actual directory names (mixed-case attempts indicate enumeration)
- Repeated 200-OK responses to paths that should return 403/404 under correct exclusion enforcement
- Sequential requests cycling through case variants of the same path component (e.g., `secrets/`, `Secrets/`, `SECRETS/`)

### Endpoint Telemetry

On the Jupyter server host:

# Process tree (Jupyter running under Python)
python  → jupyter-lab / jupyter-notebook
         └── jupyterlab_git (extension handler)

# File access events (auditd / Sysmon FileRead)
Paths under the Jupyter root dir with excluded directory names accessed
by the jupyter server process — flagging reads to paths that should be
excluded (e.g., .env files, credential stores, private notebooks)

**Auditd rule for Linux systems (supplementary detection):**
-a always,exit -F arch=b64 -S open,openat -F comm=python3 \
  -F dir=<JUPYTER_ROOT>/secrets -k jupyter_excl_bypass
*(Substitute `<JUPYTER_ROOT>/secrets` with the configured `excluded_paths` directories.)*

### Log Artefacts

| Source | Pattern |
|---|---|
| Jupyter server logs | `200 GET /git/show?path=Secrets/...` where `Secrets` should be excluded |
| Web proxy / WAF | Repeated path enumeration with case-variant segments to `/git/` endpoints |
| File integrity monitoring | Unexpected read events on files within `excluded_paths` directories |

> **Note:** If `excluded_paths` is not explicitly configured on your deployment, the bypass condition does not apply. Confirm your server configuration before triaging alerts.

---

## Detection Coverage

### Suricata Rule (Draft — Analyst Review Required)

# CVE-2026-54528 — JupyterLab Git excluded_paths case-bypass
# DRAFT: Tune pcre pattern and threshold to your environment before deployment.
# This rule fires on requests to the /git/ API with path parameters;
# case-variant abuse is difficult to distinguish without application context.
# Combine with application log analysis for higher-fidelity detection.

alert http $EXTERNAL_NET any -> $HOME_NET 8888:8899 (
    msg:"CVE-2026-54528 JupyterLab Git excluded_paths case-bypass attempt";
    flow:established,to_server;
    http.method; content:"GET"; 
    http.uri; content:"/git/"; 
    http.uri; pcre:"/\/git\/(show|content|log|diff)\?[^\"]*path=[A-Z][a-zA-Z0-9_\-\/]*/i";
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:web-application-attack;
    sid:2026545280;
    rev:1;
    metadata:affected_product JupyterLab-Git, 
              cve CVE-2026-54528, 
              created_at 2026_07_14,
              deployment perimeter;
)

> ⚠️ **Analyst Note:** This rule uses a broad URI pattern. The `pcre` attempts to catch paths beginning with an uppercase character (common in case-variant bypass), but will produce false positives in environments with legitimately mixed-case paths. A threshold of 5 requests/60 seconds is used to surface enumeration behaviour rather than single accesses. Tune `sid`, port range, and threshold before production deployment.

### Jupyter Log Hunting Query (Splunk SPL — Draft)

index=jupyter sourcetype=jupyter_access_log
    uri_path="/git/*"
    status=200
| rex field=uri_path "path=(?P<git_path>[^&\s]+)"
| eval git_path_lower=lower(git_path)
| stats count values(git_path) as path_variants by src_ip, git_path_lower, user
| where count > 3 AND mvcount(path_variants) > 1
| eval note="Multiple case variants of same logical path — possible CVE-2026-54528 bypass"
| table _time, src_ip, user, git_path_lower, path_variants, count, note

> ⚠️ **Analyst Note:** Requires Jupyter access logs to be ingested into Splunk with URI and user fields parsed. Adjust field names (`uri_path`, `user`, `src_ip`) to match your sourcetype schema.

### Sigma Rule (Draft)

title: JupyterLab Git excluded_paths Case-Bypass (CVE-2026-54528)
id: a1b2c3d4-0001-0002-0003-000000005452  # Replace with org-issued UUID
status: experimental
description: >
    Detects repeated access to the JupyterLab Git API (/git/) with path
    parameters that vary only by case, potentially indicating exploitation
    of CVE-2026-54528 excluded_paths bypass on case-insensitive filesystems.
references:
    - https://nvd.nist.gov/
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-54528
[2] github.com — https://github.com/jupyterlab/jupyterlab-git/commit/460035275b5963dc96e364e60ba6a73717fbd033
[3] github.com — https://github.com/jupyterlab/jupyterlab-git/releases/tag/v0.54.0
[4] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-54528
