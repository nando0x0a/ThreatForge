> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-10699
> Product:   moveit
> Tags:      [RCE] [HIGH] [T1]
> Score:     80
> Tier:      HIGH PRIORITY
> Generated: 2026-07-14T20:38:03.128008Z
> Status:    OK

# Technical Findings Report — CVE-2026-10699

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed draft generated for analyst verification. All indicators, detections, and recommendations should be validated against your environment before operationalisation.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-10699 |
| **Affected Product** | Progress MOVEit Transfer |
| **Affected Versions** | 2025.0.0 – 2025.0.7 · 2025.1.0 – 2025.1.3 · 2026.0.0 [1][3] |
| **Fixed Versions** | 2025.0.8 · 2025.1.4 · 2026.0.1 [2] |
| **CVSS Score** | 7.5 (HIGH) [1] |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (inferred from score and description — specific vector string not confirmed in available sources) |
| **Vulnerability Class** | CWE-401 — Missing Release of Memory After Effective Lifetime |
| **KEV Status** | Not listed in CISA KEV at time of writing (verify current status) |
| **Vulnerability Age** | 6 days |
| **PoC Available** | No public proof-of-concept known |
| **RCE Potential** | Flagged YES (network-exploitable); see Attack Vector section for important qualification |

> ⚠️ **RCE Flag Qualification:** The description [1][3] characterises this as a **memory release vulnerability leading to denial of service**. The RCE flag in the priority metadata should be treated with caution — the primary confirmed impact is availability (A:H). Analysts should monitor vendor advisories [2] for updated impact assessment; remote code execution via memory exhaustion or heap manipulation is theoretically possible in some CWE-401 scenarios but is **not confirmed by available sources**. Do not downgrade urgency, but document this ambiguity for escalation decisions.

---

## Attack Vector

### Exploitation Mechanism

The vulnerability resides in the **Custom Reports module** of Progress MOVEit Transfer [1][3]. Memory allocated during report processing is not released after its effective lifetime, creating a condition exploitable for denial of service through repeated, resource-exhausting requests.

### Network Path and Conditions

| Component | Detail |
|---|---|
| **Attack Vector** | Network (AV:N) — exploitable remotely without local access |
| **Complexity** | Low (AC:L inferred) — no race condition or special configuration required |
| **Privileges Required** | None (PR:N) — exploit requires no special privileges [1] |
| **User Interaction** | None (UI:N) — no victim interaction required |
| **Authentication** | Not required based on PR:N designation; however, analysts should verify whether the Custom Reports API endpoint is exposed pre-authentication or whether anonymous access to MOVEit Transfer is enabled in their deployment |

### Attack Scenario

An unauthenticated remote attacker sends repeated requests targeting the Custom Reports module endpoint. Each request causes the application to allocate memory that is never freed. Over time, this exhausts available memory on the MOVEit Transfer host, causing the service to become unresponsive or crash — resulting in denial of service to legitimate file transfer operations.

The absence of a public PoC [as noted in priority metadata] means specific request structure details are not confirmed at this time.

---

## Observable Behaviour

> **Note:** Because no public PoC exists and vendor advisory technical detail [2] was not fully retrievable, specific payload signatures cannot be confirmed. The following indicators are derived from the vulnerability class (CWE-401), affected module (Custom Reports), and product architecture. Analyst validation is required.

### Network / HTTP Telemetry

| Indicator | Detail |
|---|---|
| **Protocol** | HTTPS (TCP/443 — MOVEit Transfer default) |
| **Likely Target Path** | Requests to Custom Reports API endpoints; exact paths unconfirmed — monitor for high-frequency requests to paths containing `/api/v1/reports`, `/reportingws/`, or similar Custom Reports-related URIs (verify against your MOVEit Transfer deployment's URL structure) |
| **Request Pattern** | Repeated, rapid requests to the same reporting endpoint from a single source IP or small IP range |
| **Response Pattern** | Degrading HTTP response times; eventual HTTP 500 or connection timeout responses from the MOVEit Transfer web service |
| **Volume Signature** | Anomalously high request rate to reporting endpoints relative to baseline; may appear as a low-and-slow pattern if attacker throttles to avoid rate limiting |

### Host / Process Telemetry

| Indicator | Detail |
|---|---|
| **Memory Pressure** | Monotonically increasing memory consumption by the MOVEit Transfer application process (`MOVEitDMZ` service or IIS application pool hosting MOVEit) without corresponding release |
| **Process** | `w3wp.exe` (IIS worker process) or dedicated MOVEit service process exhibiting sustained memory growth |
| **Windows Event Logs** | Application pool recycling events (Event ID 5117, 5059 in IIS logs); Windows Event ID 2004 (Resource exhaustion diagnostics) |
| **Service Disruption** | IIS application pool crash or automatic recycle; MOVEit Transfer service restart events |

### Log Patterns

# IIS Access Log pattern to hunt (illustrative — validate path against your deployment)
# Look for high-frequency 200/500 responses to reporting endpoints from a single source
GET /moveitisapi/moveitisapi.dll?action=... (Custom Reports parameters) - 500
POST /api/v1/reports/... 500 -

# Windows System Event indicating memory pressure
Source: Resource-Exhaustion-Detector
Event ID: 2004

---

## Detection Coverage

> Detection rules below are **proposed drafts for analyst review**. Tune thresholds and paths against your environment before deployment.

### Suricata / NIDS — High-Frequency Reporting Endpoint Alert

# DRAFT — Analyst review required before deployment
# CVE-2026-10699 — MOVEit Transfer Custom Reports Memory Exhaustion
# Trigger on high-frequency HTTPS requests to MOVEit Transfer
# NOTE: Requires TLS inspection (e.g., via decryption proxy) to inspect HTTP content
# Without TLS inspection, alert on connection frequency to MOVEit Transfer host/port

alert tcp $EXTERNAL_NET any -> $MOVEIT_SERVERS 443 (
  msg:"[CVE-2026-10699] MOVEit Transfer - Possible Custom Reports DoS - High Connection Rate";
  flow:to_server,established;
  threshold:type both, track by_src, count 50, seconds 10;
  classtype:attempted-dos;
  sid:20261069901;
  rev:1;
  metadata:cve CVE-2026-10699, created_at 2026_06, affected_product MOVEit_Transfer;
)

> ⚠️ **Limitation:** Without TLS decryption, path-specific matching is not possible at the NIDS layer. The rule above triggers on connection rate only. If your environment decrypts TLS at an inspection proxy, add `content:"/reports"` or the confirmed Custom Reports path as a content match. Specific URI paths must be confirmed against vendor documentation [2].

### SIEM — Splunk Hunting Query (Memory Exhaustion Pattern)

| comment "CVE-2026-10699 — MOVEit Transfer Custom Reports Memory Exhaustion Hunt"
| comment "DRAFT — validate field names against your IIS log ingestion"

index=web_logs sourcetype=iis_access
  (cs_uri_stem="*report*" OR cs_uri_stem="*Report*")
  host IN (<moveit_transfer_hostnames>)
| bucket _time span=1m
| stats count as request_count, 
        dc(c_ip) as unique_sources,
        values(sc_status) as status_codes,
        values(cs_uri_stem) as uri_paths
    by _time, c_ip
| where request_count > 30
| eval severity=case(
    request_count > 100, "HIGH",
    request_count > 50, "MEDIUM",
    true(), "LOW"
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-10699
[2] community.progress.com — https://community.progress.com/s/article/MOVEit-Transfer-Critical-Security-Bulletin-June-2026
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-10699
