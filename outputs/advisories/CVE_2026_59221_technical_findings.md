> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-59221
> Product:   open webui
> Tags:      [HIGH] [POC]
> Score:     30
> Tier:      MONITOR
> Generated: 2026-07-14T21:00:55.383973Z
> Status:    OK

# Technical Findings Report — CVE-2026-59221

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed analysis requiring validation by a qualified security analyst before operational use. Indicators, patterns, and recommendations should be verified against your environment.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-59221 |
| **Affected Product** | Open WebUI versions 0.9.6 up to (but not including) 0.10.0 [1] |
| **CVSS Score** | 7.7 (HIGH) [1] |
| **KEV Status** | Not currently listed on CISA KEV (no KEV data provided in source context) |
| **Vulnerability Age** | 4 days old (recently disclosed) |
| **PoC Availability** | 1 public proof-of-concept known to exist [5] |
| **Priority Tier** | MONITOR — elevated due to HIGH severity and public PoC availability |

---

## Attack Vector

### Mechanism

The vulnerability resides in the `_sanitize_proxy_path` function within Open WebUI [1][3]. The function performs insufficient decoding of percent-encoded characters in proxy path strings. An attacker can craft a URL path using double or alternate percent-encoding sequences (e.g., `%2F`, `%252F`, or Unicode-normalised variants) that bypass the sanitisation logic, causing the application to resolve and proxy requests to arbitrary filesystem or network paths — a classic path traversal pattern [1][3].

The fix, visible in the patch commit [2], enforces complete iterative or canonical decoding of the proxy path before sanitisation validation is applied.

### Required Conditions

- **Network access** to the Open WebUI instance (likely HTTP/HTTPS, port 80/443 or the default Open WebUI port, commonly **8080**).
- **No authentication** requirement is stated in the vulnerability description [1][4]; the proxy path handler appears to be reachable pre-authentication or with minimal privilege — analysts should confirm this against the patch diff [2].
- The attacker must be able to **craft a proxy path request** — this requires knowledge of the proxy endpoint route structure within Open WebUI.

### CVSS Context

The 7.7 HIGH score indicates a **Network**-accessible attack vector with **Low** complexity and **No** required privilege or user interaction, with **High** impact on Confidentiality (path traversal to read arbitrary paths) and likely **None** on Integrity/Availability — consistent with an unauthenticated read-access traversal [1].

> ⚠️ **Note:** The advisory context provided did not include a full CVSS vector string. The above breakdown is inferred from the score and description. Analysts should retrieve the complete vector from [1] or [4] to confirm each component.

---

## Observable Behaviour

### HTTP Request Patterns

Exploitation will manifest as **crafted HTTP GET requests** to the Open WebUI proxy endpoint containing percent-encoded path traversal sequences. Expected patterns include:

**Single encoding (may be filtered):**
GET /proxy/%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1

**Double encoding (bypass attempt — the attack vector here):**
GET /proxy/%252F..%252F..%252Fetc%252Fpasswd HTTP/1.1
GET /proxy/..%252F..%252F..%252Fetc%252Fshadow HTTP/1.1

**Mixed encoding variants:**
GET /proxy/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
GET /proxy/..%c0%af..%c0%afetc%c0%afpasswd HTTP/1.1

> **Analyst note:** The specific proxy endpoint path (e.g., `/proxy/`, `/api/proxy/`) is not confirmed in available source material [1][3][5]. Review the patch diff [2] and pull request [3] to identify the exact route before finalising detection signatures.

### Key Indicators

| Indicator Type | Value / Pattern |
|---|---|
| HTTP Method | `GET` (expected; confirm against source) |
| URL Pattern | Proxy path containing `%25`, `%2F`, `%2E` sequences in combination |
| Traversal Strings | `../`, `..%2F`, `..%252F`, `%2e%2e/` in decoded path segments |
| Target Resources | Sensitive OS paths: `/etc/passwd`, `/etc/shadow`, application config files, secrets/API key files |
| Response Size Anomaly | Unusually large or structured response from proxy endpoint (file contents returned) |
| Source | Any external IP; internal exploitation also possible if multi-tenant |

### Server-Side Telemetry

- **Application logs:** Requests to the proxy route with decoded paths resolving outside the intended base directory.
- **File access logs (if enabled):** `open()` syscalls from the Open WebUI process against paths outside its working directory (e.g., `/etc/`, `/home/`, `/app/../`).
- **Container runtime (if Dockerised):** Unexpected file reads visible via `auditd` or Falco rules monitoring the container's process.

---

## Detection Coverage

### Suricata / IDS Signature (Draft — Analyst Review Required)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"CVE-2026-59221 Open WebUI Path Traversal via Percent-Encoded Proxy Path";
    flow:established,to_server;
    http.uri;
    content:"%25";
    pcre:"/\/proxy\/[^\s]*(%252[Ff]|%25(?:2[Ee]|c0%25[Aa][Ff])|\.\.%25)/i";
    classtype:web-application-attack;
    sid:20265922101;
    rev:1;
    metadata:CVE CVE-2026-59221, created_at 2026-06-xx, affected_product Open_WebUI;
)

> ⚠️ This rule targets double-encoded sequences (`%25` prefix). It **requires** the analyst to confirm the correct proxy endpoint path prefix from [2][3] and insert it into the `content` match. The PCRE pattern is a draft and should be tested against captured PoC traffic [5] before deployment.

### SIEM / Hunting Query (Splunk SPL — Draft)

index=web_access_logs sourcetype=access_combined
| rex field=uri "(?<proxy_path>/[^?#]+)"
| where match(proxy_path, "%25|%252[Ff]|%2[Ee]%2[Ee]")
| eval decoded_path=urldecode(urldecode(proxy_path))
| where match(decoded_path, "\.\./|/etc/|/proc/|/var/|/root/|/home/")
| table _time, src_ip, uri, decoded_path, status, bytes
| sort -_time

### Endpoint Detection (Falco — if containerised)

- rule: Open WebUI Path Traversal File Access CVE-2026-59221
  desc: Detects Open WebUI process accessing files outside its expected working directory
  condition: >
    open_read and
    proc.name = "python3" and
    not fd.name startswith "/app/" and
    not fd.name startswith "/usr/" and
    not fd.name startswith "/tmp/" and
    fd.name startswith "/"
  output: "Suspicious file read by Open WebUI process (file=%fd.name proc=%proc.cmdline)"
  priority: WARNING
  tags: [CVE-2026-59221, path_traversal]

> **Analyst note:** Tune the Falco rule's process name and allowed path prefixes to match your specific deployment layout.

---

## Affected Assets

Based on the vulnerability scope [1][4]:

| Criteria | Detail |
|---|---|
| **Affected Versions** | Open WebUI **≥ 0.9.6** and **< 0.10.0** |
| **Fixed Version** | Open WebUI **0.10.0** (patch commit [2], PR [3]) |
| **Deployment Contexts** | Self-hosted instances (Docker, bare metal, Kubernetes); cloud-hosted Open WebUI deployments if version-pinned to affected range |

**Recommended Asset Inventory Steps:**
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-59221
[2] github.com — https://github.com/open-webui/open-webui/commit/05098d25a58d03738e01c4e85e8852c3b4ad849c
[3] github.com — https://github.com/open-webui/open-webui/pull/26050
[4] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-59221
[5] PoC (nvd) — https://github.com/open-webui/open-webui/security/advisories/GHSA-frvj-c5qp-xj4w
