> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0284
> Product:   palo alto pan-os
> Tags:      [RCE] [CRIT] [T1]
> Score:     90
> Tier:      CRITICAL — ACT NOW
> SEVERITY DISCREPANCY: NVD/vulnx says 9.9 (CRITICAL) — CVE.org (CNA, v4.0) says 4.7 (MEDIUM). See https://www.cve.org/CVERecord?id=CVE-2026-0284
> Generated: 2026-07-14T11:40:46.576560Z
> Status:    OK

# Technical Findings Report — CVE-2026-0284

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed assessment based on available context at time of writing. All findings, indicators, and recommendations should be validated by a qualified analyst before operational use.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0284 |
| **Affected Product** | Palo Alto Networks PAN-OS — Large Scale VPN (LSVPN) functionality |
| **Vulnerability Type** | XML Injection via improper input handling |
| **CVSS Score** | See severity discrepancy note below |
| **KEV Status** | Not listed in CISA KEV at time of writing (no KEV context provided) |
| **Exploit Maturity** | UNREPORTED [2] |
| **Age** | 3 days old |
| **Priority Tier** | CRITICAL — ACT NOW (internal priority score: 90) |

### ⚠️ Severity Discrepancy — Analyst Action Required

There is a material disagreement between scoring sources that must be adjudicated before prioritisation decisions are finalised:

- **[1] NVD scores this CVSS 9.9 (CRITICAL)** — consistent with the unauthenticated, network-exploitable, RCE-capable characterisation in the NVD record.
- **[3] CVE.org (CNA-published record, CVSS v4.0) scores this 4.7 (MEDIUM)** — the CNA (Palo Alto Networks) assessed this as MODERATE urgency with UNREPORTED exploit maturity and AUTOMATIC recovery characteristics [2].

This is not a minor rounding difference — it is a CRITICAL vs. MEDIUM classification split. The discrepancy likely arises from differing CVSS base metric interpretations (particularly scope, confidentiality/integrity impact, and the use of CVSS v3.x at NVD vs. CVSS v4.0 at the CNA). The vendor advisory also characterises urgency as **MODERATE** [2], which aligns more closely with the CNA score [3]. **Analysts should review both scoring rationales and the vendor advisory before finalising response tier.**

---

## Attack Vector

### Exploitation Path

CVE-2026-0284 is an XML injection vulnerability in the **Large Scale VPN (LSVPN)** component of PAN-OS, caused by improper input handling [1][2]. XML injection in VPN gateway components typically involves an attacker supplying malformed or adversarially constructed XML content through an externally exposed interface — in this case, the LSVPN service endpoint.

### Required Conditions

| Condition | Detail |
|---|---|
| **Network Access** | Required — attacker must have network reachability to the LSVPN interface |
| **Authentication** | None required — unauthenticated attack surface [1] |
| **User Interaction** | None required |
| **Special Privileges** | None required |

### CVSS Vector Components (NVD, v3.x) [1]

- **AV:N** — Attack Vector: Network (no physical proximity required)
- **PR:N** — Privileges Required: None
- **UI:N** — User Interaction: None
- **RCE-capable** — Network-exploitable with no prerequisites [1]

### Attack Surface

The LSVPN (GlobalProtect Large Scale VPN) component typically exposes management and satellite gateway interfaces. The specific HTTP paths or ports through which XML input is processed are **not confirmed in available source material** — specific endpoint paths should be obtained from the vendor advisory or PA-CERT before writing targeted signatures.

---

## Observable Behaviour

> **Note:** No confirmed proof-of-concept code or active exploitation telemetry is available at this time (exploit maturity: UNREPORTED [2]). The following indicators are derived from the vulnerability class (XML injection in VPN gateway) and should be treated as investigative starting points pending vendor or community confirmation of specific IOCs.

### Network / HTTP Indicators

- **Unexpected XML metacharacters** in LSVPN-destined HTTP/HTTPS request bodies or URI parameters, including but not limited to:
  - `<`, `>`, `&`, `"`, `'` in fields not expected to contain markup
  - XML entity references: `&lt;`, `&gt;`, `&#x...;`, `&xxe;`
  - Injected XML tags or attribute injection patterns: `"><injected/>`, `' injected='`
  - External entity declarations: `<!DOCTYPE`, `<!ENTITY`, `SYSTEM "file://`, `SYSTEM "http://`
- **Anomalous payload sizes** on LSVPN gateway ports (typically TCP/4501 UDP or HTTPS/443 for GlobalProtect/LSVPN interfaces — confirm against your deployment)
- **Responses containing unexpected data** — XML injection causing information disclosure may produce verbose or malformed XML responses leaking configuration data

### PAN-OS Log Indicators

- **Threat logs**: Look for policy violations or parser errors originating from external satellite or gateway IP addresses on LSVPN interfaces
- **System logs**: XML parsing errors or unexpected process restarts in `pan_gp_gateway`, `pan_lsvpn`, or related LSVPN daemons
- **Traffic logs**: Connections to LSVPN endpoints from unexpected source IP ranges or geographies

### Endpoint / Process Indicators

- Specific process chains are **not confirmed in available source material**. If data corruption impact is realised, watch for unexpected configuration changes in PAN-OS running config (compare against last known-good baseline)

---

## Detection Coverage

> The following are proposed detection approaches for analyst review. Rule specificity is limited by the absence of confirmed IOC detail in available sources [1][2][3]. Rules should be refined once vendor-confirmed payload patterns are published.

### Suricata / Network IDS — Proposed Rule Concept

# DRAFT — CVE-2026-0284 — PAN-OS LSVPN XML Injection Detection
# Requires analyst validation; payload patterns are inferred from vulnerability class,
# not confirmed by vendor advisory. Refine with confirmed IOCs before deployment.

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"DRAFT ThreatForge - CVE-2026-0284 PAN-OS LSVPN XML Injection Attempt - Entity Injection Pattern";
    flow:established,to_server;
    content:"<!ENTITY"; nocase; http_client_body;
    content:"LSVPN"; nocase; http_uri; # Adjust URI path per confirmed advisory detail
    threshold:type limit, track by_src, count 1, seconds 60;
    classtype:web-application-attack;
    metadata:cve CVE-2026-0284, affected_product PAN-OS_LSVPN, confidence LOW, analyst_review REQUIRED;
    sid:20260284001; rev:1;
)

alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"DRAFT ThreatForge - CVE-2026-0284 PAN-OS LSVPN XML Injection Attempt - DOCTYPE Declaration";
    flow:established,to_server;
    content:"<!DOCTYPE"; nocase; http_client_body;
    pcre:"/<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"'](?:file|http|ftp|https):\/\//i";
    classtype:web-application-attack;
    metadata:cve CVE-2026-0284, affected_product PAN-OS_LSVPN, confidence LOW, analyst_review REQUIRED;
    sid:20260284002; rev:1;
)

### SIEM / Hunting Query Concepts

**Splunk — PAN-OS Threat Log Hunt (DRAFT)**
index=panos sourcetype=pan:threat
| search (description="*xml*" OR description="*injection*" OR description="*lsvpn*")
| where src_ip != "KNOWN_SATELLITE_IP_RANGE"
| table _time, src_ip, dst_ip, app, threat_name, action
| eval cve="CVE-2026-0284"

**Splunk — Anomalous LSVPN Connection Volume (DRAFT)**
index=panos sourcetype=pan:traffic
| search app="globalprotect" OR dest_port=4501
| stats count by src_ip, dest_ip, dest
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0284
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0284
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0284
