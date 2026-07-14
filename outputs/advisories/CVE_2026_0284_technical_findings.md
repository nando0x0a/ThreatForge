> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0284
> Product:   palo alto pan-os
> Tags:      [RCE] [CRIT] [T1]
> Score:     90
> Tier:      CRITICAL — ACT NOW
> SEVERITY DISCREPANCY: NVD/vulnx says 9.9 (CRITICAL) — CVE.org (CNA, v4.0) says 4.7 (MEDIUM). See https://www.cve.org/CVERecord?id=CVE-2026-0284
> Generated: 2026-07-14T20:13:55.239726Z
> Status:    OK

# Technical Findings Report — CVE-2026-0284

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed draft. All indicators, behavioral patterns, and recommendations should be validated by a qualified analyst before operational use.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0284 |
| **Affected Product** | Palo Alto Networks PAN-OS — Large Scale VPN (LSVPN) functionality |
| **CVSS Score** | **⚠️ DISCREPANCY — see note below** |
| **KEV Status** | Not listed in CISA KEV at time of report |
| **Vulnerability Age** | 4 days |
| **PoC Availability** | No public proof-of-concept known |
| **Exploit Maturity** | UNREPORTED [2] |

### ⚠️ Severity Discrepancy — Analyst Action Required

There is a material disagreement in CVSS scoring between sources that must be adjudicated before prioritisation is finalised:

- **[1] NVD scores this CVSS 9.9 (CRITICAL)** — consistent with the RCE, network-exploitable, no-auth characterisation in the vulnerability description.
- **[3] CVE.org (CNA-published record, CVSS v4.0) scores this 4.7 (MEDIUM)** — the originating vendor (Palo Alto Networks as CNA) assigns a substantially lower severity under the newer CVSS v4.0 methodology.

The vendor advisory [2] corroborates the lower urgency characterisation, rating the urgency as **MODERATE** with exploit maturity **UNREPORTED** and recovery **AUTOMATIC**. The NVD score of 9.9 may reflect base metric inflation under CVSS v3.x or an independent scoring assessment. **Analysts should not rely on either score in isolation.** The CNA score under CVSS v4.0 [3] reflects the vendor's own technical assessment and should be weighed against the NVD score [1] before determining response tier. The automated priority score of 90 / CRITICAL tier assigned to this finding was driven by the NVD score [1] and the RCE flag — this should be reviewed once the scoring discrepancy is resolved.

---

## Attack Vector

**Vulnerability class:** XML Injection via improper input handling in the LSVPN component of PAN-OS.

**CVSS attack characteristics (per NVD [1]):**
- **Attack Vector (AV): Network** — exploitable remotely, no physical or adjacent-network requirement
- **Privileges Required (PR): None** — unauthenticated exploitation
- **User Interaction (UI): None** — no victim action required

**Exploitation path:**

An unauthenticated attacker with IP-level network access to a PAN-OS device with LSVPN enabled can send crafted requests containing malicious XML constructs to the LSVPN-facing interface. Due to improper input handling, the injected XML is processed by the LSVPN subsystem without adequate sanitisation, potentially permitting:

1. **Information disclosure** — extraction of configuration data, credentials, or session material parsed by the XML processor
2. **Data corruption** — manipulation of XML structures that feed into configuration or state management logic

> **Note:** The specific HTTP endpoint(s), XML parameter names, and precise injection syntax are not publicly documented at time of writing. No vendor advisory technical deep-dive or public PoC exists [2]. The following observable behaviour section is based on generic XML injection characteristics applicable to LSVPN — specific field values should be validated against vendor guidance as it becomes available.

---

## Observable Behaviour

> ⚠️ Technical indicators below are inferred from the vulnerability class (XML injection, PAN-OS LSVPN). No vendor-confirmed IoCs or PoC payload signatures are available [2]. Treat these as hunting hypotheses, not confirmed signatures.

### Network / HTTP Layer

- **Destination:** PAN-OS management interface or LSVPN satellite/portal-facing interface (typically TCP/443 or TCP/4501 for IPsec IKE, but XML processing likely occurs over HTTPS)
- **Protocol:** HTTPS (TLS-wrapped), likely targeting a REST or web-based LSVPN registration/configuration endpoint
- **Payload anomalies to look for:**
  - XML content containing special characters in unexpected fields: `<`, `>`, `&`, `]]>`, entity references (`&xxe;`, `&#x...;`)
  - Unexpected or malformed XML entity declarations (`<!ENTITY`, `<!DOCTYPE`)
  - Unusually large XML payloads to LSVPN-related endpoints
  - Repeated rapid requests to LSVPN endpoints from a single unauthenticated source (enumeration/fuzzing pattern)

### Endpoint / Log Telemetry (PAN-OS)

- **PAN-OS system logs:** Look for parser errors, XML processing exceptions, or unexpected process restarts in the LSVPN daemon (`ikemgr`, `configd`, or equivalent LSVPN-handling process)
- **PAN-OS traffic logs:** Unauthenticated connections to LSVPN portal/gateway from unexpected external IPs
- **Configuration audit logs:** Unexpected configuration changes or state transitions in LSVPN gateway/satellite records following anomalous inbound traffic

### Splunk / SIEM Hunting Query (PAN-OS Logs — Draft)

index=panos sourcetype=pan:system
(message="*xml*" OR message="*parse error*" OR message="*lsvpn*")
| eval suspicious=if(match(message, "(?i)(entity|doctype|cdata|\]\]>|&#x)"), "YES", "NO")
| where suspicious="YES"
| stats count by host, _time, message
| sort -_time

index=panos sourcetype=pan:traffic
app="ssl" OR app="web-browsing"
dest_port=443
(dest_zone="untrust" OR src_zone="untrust")
url="*/LSVPN*" OR url="*/global-protect*" OR url="*/ssl-vpn*"
| stats count by src_ip, dest_ip, dest_port, url
| where count > 20
| sort -count

> Both queries are proposed drafts requiring tuning to your specific log schema, index names, and LSVPN endpoint paths.

---

## Detection Coverage

| Control Type | Coverage | Notes |
|---|---|---|
| **Network IDS/IPS** | Partial | Generic XML injection patterns detectable; LSVPN-specific payloads unknown without PoC |
| **PAN-OS Threat Prevention** | Unknown | Check whether Palo Alto has released a Threat Prevention content update addressing CVE-2026-0284 [2] |
| **SIEM Log Analysis** | Partial | PAN-OS system and traffic logs provide visibility; queries above are starting points |
| **WAF** | Limited | LSVPN traffic is typically not WAF-fronted; unlikely to provide coverage |
| **Vulnerability Scanning** | Pending | Confirm scanner vendor support for CVE-2026-0284 detection; 4-day-old CVE may lack scanner plugins |

### Suricata Rule (Draft — Analyst Review Required)

alert http $EXTERNAL_NET any -> $HOME_NET 443 (
    msg:"ThreatForge DRAFT — CVE-2026-0284 PAN-OS LSVPN XML Injection Attempt";
    flow:established,to_server;
    content:"POST"; http_method;
    content:"/LSVPN"; http_uri; nocase;
    pcre:"/(<!\s*(ENTITY|DOCTYPE)|(\]\]>)|&#x[0-9a-fA-F]+;)/Pi";
    threshold:type both, track by_src, count 3, seconds 60;
    classtype:web-application-attack;
    reference:cve,2026-0284;
    reference:url,security.paloaltonetworks.com/CVE-2026-0284;
    sid:9002026284;
    rev:1;
    metadata:affected_product PAN-OS, created_at 2026_01_01,
             cvss_score_nvd 9.9, cvss_score_cna_v4 4.7,
             deployment DRAFT_ANALYST_REVIEW_REQUIRED;
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0284
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0284
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0284
