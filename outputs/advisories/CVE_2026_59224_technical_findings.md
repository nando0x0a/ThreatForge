> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-59224
> Product:   open webui
> Tags:      [HIGH]
> Score:     20
> Tier:      MONITOR
> Generated: 2026-07-14T21:04:15.235901Z
> Status:    OK

# Technical Findings Report — CVE-2026-59224

> **⚠️ DRAFT FOR ANALYST REVIEW — This report is a proposed draft and must be reviewed and validated by a qualified analyst before operational use.**

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-59224 |
| **Affected Product** | Open WebUI < 0.10.0 |
| **CVSS Score** | 8.0 (HIGH) [1] |
| **KEV Status** | Not listed in CISA KEV at time of writing |
| **Age** | 4 days old |
| **PoC Availability** | No public proof-of-concept known |
| **Priority Tier** | MONITOR |

---

## Attack Vector

### Vulnerability Mechanism

CVE-2026-59224 is a **broken access control** vulnerability in the terminal backend of Open WebUI [1][2]. The root cause is twofold:

1. **Unencoded `session_id`** — The session identifier is passed in an unencoded or insufficiently validated form within the terminal backend, allowing it to be guessed, forged, or manipulated by an attacker.
2. **Forwarded `X-User-Id` header** — The backend trusts and forwards the `X-User-Id` HTTP header without adequate server-side validation [2]. An attacker who can craft HTTP requests to the terminal endpoint can supply an arbitrary `X-User-Id` value, causing the backend to process requests in the context of any target user.

### Exploitation Conditions

- **Network Access:** The attacker must be able to send HTTP/HTTPS requests to the Open WebUI terminal backend endpoint. If the instance is internet-exposed, this is achievable without network adjacency.
- **Authentication:** The exact authentication pre-condition is not fully detailed in available sources — it is **unclear whether a valid (but lower-privileged) session is required, or whether the endpoint is accessible unauthenticated**. Analysts should treat this as potentially exploitable by any network-reachable party until clarified by the vendor advisory [2][3].
- **Exploit Complexity:** Exploitation requires crafted HTTP requests [1], but no public PoC exists at this time.

### CVSS Context

The score of 8.0 HIGH [1] is consistent with a network-exploitable access control bypass with significant impact on confidentiality and integrity (impersonation of arbitrary users, including potentially administrators). The precise CVSS vector string is not available from the sources consulted — **analysts should retrieve the full vector from NVD [1] for authoritative component-level detail**.

---

## Observable Behaviour

### HTTP Indicators

The following patterns are characteristic of exploitation attempts. Specific endpoint paths are inferred from the vulnerability description; **analysts should confirm exact routes against the Open WebUI source or commit diff** [3].

**Suspicious Request Pattern:**
POST /api/terminal/* HTTP/1.1
Host: <open-webui-host>
X-User-Id: <victim-user-id>
Cookie: session=<attacker-session>
...

Key observables:

| Indicator | Detail |
|---|---|
| **Header** | `X-User-Id` present and set to a value inconsistent with the authenticated session's own user identity |
| **Endpoint** | Requests targeting terminal backend routes (e.g., `/terminal/`, `/api/terminal/`, `/ws/terminal/` — confirm exact paths from [3]) |
| **Session Mismatch** | `session_id` in cookie or parameter does not correspond to the `X-User-Id` value supplied in the header |
| **Rapid User Enumeration** | Sequential or scripted requests with incrementing/varying `X-User-Id` values from a single source IP |
| **Abnormal Terminal Activity** | Terminal commands executing under user accounts that have no active browser session or are outside business hours |

### Network-Level Observables

- Unexpected WebSocket upgrades or long-lived connections to terminal endpoints from unfamiliar source IPs.
- Repeated HTTP 200 or 101 (WebSocket upgrade) responses to terminal paths where the `X-User-Id` header varies across requests from the same client.

### Application Log Observables

- Log entries where the user identity recorded for a terminal session does not match the authenticated session owner.
- Multiple terminal sessions attributed to the same user from geographically or temporally implausible sources.

### Endpoint / Process Observables

- If terminal execution spawns shell processes: child processes (e.g., `bash`, `sh`, `python`) spawned by the Open WebUI service process under user contexts that do not match the originating session.

---

## Detection Coverage

> **Note:** No CVE-specific Suricata rule or hunting query has been formally published at this time. The following are **analyst-proposed draft detections** based on the vulnerability description. Tuning against your environment is required before deployment.

### Proposed Suricata Rule (Draft)

alert http any any -> $HTTP_SERVERS any (
    msg:"[CVE-2026-59224] Open WebUI - Suspicious X-User-Id Header on Terminal Endpoint";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/terminal"; nocase;
    http.header; content:"X-User-Id:"; nocase;
    classtype:attempted-user;
    sid:2026592240;
    rev:1;
    metadata:affected_product Open_WebUI, cve CVE-2026-59224, created_at 2025-07-14, deployment perimeter;
)

alert http any any -> $HTTP_SERVERS any (
    msg:"[CVE-2026-59224] Open WebUI - X-User-Id Header Enumeration Pattern";
    flow:established,to_server;
    http.uri; content:"/terminal"; nocase;
    http.header; content:"X-User-Id:"; nocase;
    threshold:type threshold, track by_src, count 10, seconds 60;
    classtype:attempted-user;
    sid:2026592241;
    rev:1;
    metadata:affected_product Open_WebUI, cve CVE-2026-59224, created_at 2025-07-14, deployment perimeter;
)

> ⚠️ **Analyst Note:** The exact terminal endpoint URI must be confirmed from the patch commit [3] before deploying these rules. Adjust `content:"/terminal"` accordingly.

### Proposed SIEM / Hunting Query (Draft — Splunk SPL)

index=web_proxy OR index=app_logs
  sourcetype IN ("openwebui:access", "nginx:access", "apache:access")
  uri_path="*terminal*"
  http_header="*X-User-Id*"
| eval session_user=coalesce(cookie_user, auth_user)
| where session_user != x_user_id_header_value
| stats count by src_ip, session_user, x_user_id_header_value, uri_path
| where count > 3
| sort -count

### Proposed KQL (Microsoft Sentinel / Azure Monitor — Draft)

// CVE-2026-59224 - Open WebUI X-User-Id impersonation attempts
W3CIISLog
| where csUriStem contains "terminal"
| where csMethod == "POST"
| extend xUserId = extract(@"X-User-Id:\s*([^\r\n]+)", 1, csBytes)
| where isnotempty(xUserId)
| summarize RequestCount=count(), DistinctUserIds=dcount(xUserId) by cIP, bin(TimeGenerated, 5m)
| where DistinctUserIds > 3 or RequestCount > 10

---

## Affected Assets

> **Action Required:** Run the following queries against your asset inventory to identify exposed instances.

### Identification Criteria

| Criterion | Detail |
|---|---|
| **Product** | Open WebUI |
| **Vulnerable Versions** | All versions < 0.10.0 [1][2] |
| **Fixed Version** | 0.10.0 (inferred from advisory; confirm with [2][3]) |
| **Deployment Contexts** | Self-hosted Docker containers, Kubernetes pods, bare-metal/VM deployments |
| **Exposure Risk Multiplier** | Instances with terminal/shell features enabled; instances internet-exposed without WAF |

###
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-59224
[2] github.com — https://github.com/open-webui/open-webui/security/advisories/GHSA-j657-m4c4-24jq
[3] github.com — https://github.com/open-webui/open-webui/commit/5f3a628a8d291bb5d33e1a0b0c89fb62a2927934
[4] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-59224
