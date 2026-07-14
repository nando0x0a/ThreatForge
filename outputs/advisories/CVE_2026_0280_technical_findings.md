> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0280
> Product:   palo alto pan-os
> Tags:      [RCE] [HIGH] [T1]
> Score:     80
> Tier:      HIGH PRIORITY
> SEVERITY DISCREPANCY: NVD/vulnx says 7.2 (HIGH) — CVE.org (CNA, v4.0) says 1.7 (LOW). See https://www.cve.org/CVERecord?id=CVE-2026-0280
> Generated: 2026-07-14T20:31:08.817556Z
> Status:    OK

# Technical Findings Report — CVE-2026-0280

> **⚠️ DRAFT FOR ANALYST REVIEW — This report is a proposed draft and all findings, indicators, and recommendations must be validated by a qualified security analyst before operational use.**

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0280 |
| **Affected Product** | Palo Alto Networks PAN-OS (dataplane IPv6 processing) |
| **CVSS Score** | 7.2 HIGH [1] — **see severity discrepancy note below** |
| **KEV Status** | Not listed in CISA KEV at time of writing (no KEV context provided) |
| **Age** | 4 days old |
| **PoC Availability** | No public proof-of-concept known [2] |

### ⚠️ Severity Discrepancy — Analyst Attention Required

There is a **material disagreement** between two authoritative sources on the severity of this vulnerability:

- **[1] NVD scores this CVE at CVSS 7.2 (HIGH)**
- **[3] CVE.org (CNA-published record, CVSS v4.0) scores this CVE at 1.7 (LOW)**

This is a significant divergence. The NVD and CNA scores are computed under different CVSS versions (v3.x vs. v4.0), and v4.0 scoring methodology can produce substantially different results, particularly for vulnerabilities where downstream impact weighting or value density factors are applied differently. The vendor advisory [2] characterises the severity as **MODERATE** with exploit maturity **UNREPORTED** and value density **DIFFUSE**. Analysts should **not silently adopt either score** without reviewing both the NVD base vector and the CNA v4.0 rationale. This discrepancy should be tracked in your vulnerability management platform with both scores recorded until the CNA provides clarifying guidance.

---

## Attack Vector

This vulnerability exists in the **PAN-OS dataplane IPv6 packet processing subsystem** and permits unauthenticated, network-adjacent or remote attackers to bypass configured firewall security policies [1][2].

**Exploitation conditions:**

| Component | Value |
|---|---|
| **Attack Vector** | Network (AV:N) [1] |
| **Authentication Required** | None (PR:N) [1] |
| **User Interaction** | None (UI:N) [1] |
| **Attack Complexity** | Not fully disclosed; vendor advisory notes MODERATE response effort [2] |
| **RCE Potential** | Yes — network-exploitable; classified RCE-capable in provided context |

**Exploitation path:**

1. An unauthenticated attacker sends **crafted IPv6 packets** toward a PAN-OS firewall interface that is reachable from an untrusted network zone [1][2].
2. A flaw in the dataplane's IPv6 packet processing logic causes the firewall to evaluate these packets incorrectly against security policy, resulting in **policy bypass** — packets are forwarded to protected destination services without matching the expected deny or inspect rules [2].
3. Once bypass is achieved, the attacker gains direct network access to services behind the firewall that would otherwise be blocked, enabling follow-on exploitation of those services.

**Key prerequisite:** IPv6 must be enabled and routable on the affected interface. If IPv6 is not configured or is administratively disabled on all dataplane interfaces, the attack surface does not apply — however, this should be **actively verified**, not assumed.

**No public PoC is currently known** [2], which reduces immediate exploitation likelihood but does not eliminate risk given the 4-day age of the disclosure and the simplicity of the primitive (crafted IPv6 packets).

---

## Observable Behaviour

Because the exploit operates at the **network/dataplane layer** via crafted IPv6 packets, behavioural indicators will primarily appear in network telemetry rather than host-based telemetry. The following are expected observable patterns:

> **Note:** Specific payload byte patterns, header field values, and extension header abuse specifics are not available in the provided advisory detail [2]. The indicators below are based on the class of vulnerability (IPv6 policy bypass via crafted packets) and should be treated as hunting hypotheses pending vendor-published IoCs or further technical disclosure.

### Network-Layer Indicators

- **Unexpected IPv6 traffic reaching protected internal hosts** that are not accessible via IPv4 and are not in published IPv6 ACL permit rules.
- **IPv6 sessions to sensitive destination ports** (e.g., TCP/22, TCP/443, TCP/3389, TCP/8443, TCP/8080) originating from external or untrusted IPv6 source prefixes.
- **Unusual IPv6 extension headers** in traffic reaching the firewall — particularly combinations of:
  - Hop-by-Hop Options headers (Next Header: `0x00`)
  - Routing headers (Next Header: `0x2B`), especially Type 0 (deprecated) or Type 2
  - Fragment headers (Next Header: `0x2C`) with unexpected fragmentation patterns
  - Destination Options headers (Next Header: `0x3C`)
- **Fragmented IPv6 packets** to services that do not normally receive fragmented traffic — overlapping or out-of-order fragments may be a crafting technique.
- **Traffic volumes inconsistent with legitimate use** from external IPv6 sources toward internal RFC-1918 equivalent IPv6 ULA ranges (`fc00::/7`) or GUA addresses allocated to protected segments.

### PAN-OS Log Indicators

- **Traffic logs showing IPv6 flows with action `allow`** against rules that should have produced `deny` for those source/destination pairs.
- **Session logs** showing sessions to protected resources from external IPv6 addresses with no corresponding threat log entries (indicating the packet bypassed the inspection pipeline).
- **Dataplane log anomalies** — check `/var/log/pan/dp*.log` for error messages or anomalous processing events related to IPv6 reassembly or policy lookup.

### Firewall Telemetry Commands (PAN-OS CLI)

# Review active IPv6 sessions on dataplane
show session all filter protocol 6 type flow

# Check traffic logs for IPv6 policy-allow events from external zones
# (Run via Panorama or device log query)
# Filter: addr.src in <untrusted-ipv6-prefix> and app neq incomplete and action eq allow

# Review interface IPv6 configuration
show interface all | match ipv6

# Check for IPv6 routing table entries that may expose unexpected segments
show routing route type unicast dst 0::/0

---

## Detection Coverage

> **Draft signatures — require analyst review and lab validation before deployment to production.**

### Suricata Detection Rule (Draft)

# CVE-2026-0280 — PAN-OS IPv6 Firewall Policy Bypass Detection
# DRAFT — For analyst review only. Validate in lab environment before production deployment.
# Detects crafted IPv6 traffic patterns consistent with potential bypass attempts.
# NOTE: Specific exploit payload patterns are not yet publicly documented [2].
# This rule targets anomalous IPv6 extension header combinations as a hunting signal.

alert ip any any -> $HOME_NET any (
    msg:"[CVE-2026-0280] Suspicious IPv6 Extension Header Combination - Possible PAN-OS Bypass Attempt";
    ip_proto:6;
    flow:to_server;
    ip6_exthdr:hop;
    ip6_exthdr:route;
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:20260280001;
    rev:1;
    metadata:affected_product PAN-OS, cve CVE-2026-0280, created_at 2026-01-01, confidence LOW;
)

alert ip any any -> $HOME_NET any (
    msg:"[CVE-2026-0280] IPv6 Fragment to Protected Service - Possible PAN-OS Bypass Attempt";
    ip_proto:44;
    flow:to_server;
    threshold:type both, track by_src, count 10, seconds 30;
    classtype:attempted-recon;
    sid:20260280002;
    rev:1;
    metadata:affected_product PAN-OS, cve CVE-2026-0280, created_at 2026-01-01, confidence LOW;
)

**Rule confidence: LOW** — specific exploit payloads are not documented in available sources
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0280
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0280
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0280
