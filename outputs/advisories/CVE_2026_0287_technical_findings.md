> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0287
> Product:   palo alto pan-os
> Tags:      [RCE] [HIGH] [T1]
> Score:     80
> Tier:      HIGH PRIORITY
> SEVERITY DISCREPANCY: NVD/vulnx says 7.5 (HIGH) — CVE.org (CNA, v4.0) says 6.6 (MEDIUM). See https://www.cve.org/CVERecord?id=CVE-2026-0287
> Generated: 2026-07-14T11:47:24.723014Z
> Status:    OK

# Technical Findings Report — CVE-2026-0287

> **⚠️ DRAFT FOR ANALYST REVIEW** — This report is a proposed draft. All findings, indicators, and recommendations should be validated by a qualified analyst before operational use.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0287 |
| **Affected Product** | Palo Alto Networks PAN-OS (dataplane interface processing) |
| **NVD CVSS Score** | 7.5 (HIGH) [1] |
| **CNA CVSS Score** | 6.6 (MEDIUM) — CVSS v4.0, CNA-published [3] |
| **Vendor Severity** | 6.6 MEDIUM (Palo Alto Networks advisory) [2] |
| **KEV Status** | Not currently listed in CISA KEV (not confirmed exploited in the wild at time of writing) |
| **Exploit Maturity** | UNREPORTED [2] |
| **Age** | 3 days old |
| **Priority Tier** | HIGH PRIORITY \[RCE\] \[HIGH\] \[T1\] |

### ⚠️ Severity Discrepancy — Analyst Action Required

A scoring disagreement exists between sources and must be adjudicated before this finding is closed or triaged at a fixed severity level:

- **NVD [1]** scores this **CVSS 7.5 (HIGH)**, consistent with a network-exploitable, no-authentication, no-interaction DoS with `AV:N/AC:L/PR:N/UI:N`.
- **CVE.org CNA record [3]** scores this **6.6 (MEDIUM)** under CVSS v4.0, which applies a revised scoring methodology that may weight availability impact or exploitability conditions differently.
- **Palo Alto Networks' own advisory [2]** aligns with the MEDIUM/6.6 assessment and rates exploit maturity as UNREPORTED and response effort as MODERATE.

**Analyst judgement is required** to determine which score governs internal SLA and escalation decisions. CVSS v4.0 vs v3.x methodological differences, plus the vendor's own lower rating, suggest the NVD 7.5 may reflect a more conservative worst-case assumption. Both scores should be presented to the risk owner.

---

## Attack Vector

### Exploitation Mechanism

CVE-2026-0287 represents **multiple denial of service vulnerabilities** within PAN-OS network traffic processing on dataplane interfaces [1][2]. The plural framing ("multiple vulnerabilities") indicates this may be a family of related defects in packet parsing, protocol state handling, or resource allocation within the PAN-OS dataplane forwarding path.

### CVSS Vector Analysis (NVD, v3.x) [1]

AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H

| Component | Value | Implication |
|---|---|---|
| Attack Vector | Network (AV:N) | Exploitable remotely without physical or local access |
| Attack Complexity | Low (AC:L) | No special conditions or race conditions required |
| Privileges Required | None (PR:N) | Unauthenticated attacker |
| User Interaction | None (UI:N) | No victim action needed |
| Scope | Unchanged (S:U) | Impact confined to the vulnerable component |
| Confidentiality | None (C:N) | No data exposure |
| Integrity | None (I:N) | No data modification |
| Availability | High (A:H) | Full DoS; device or service becomes unavailable |

### Required Conditions

- **Network path**: The attacker must be able to reach a **dataplane interface** on the PAN-OS device. This is the interface handling live traffic (e.g., Ethernet ports carrying production traffic flows), distinct from the management plane interface.
- **Authentication**: None required [1]. The vulnerability is triggerable by any host capable of sending network packets to the dataplane.
- **Interaction**: None required. The device processes the crafted traffic without any operator or user interaction.

### Attack Surface

The attack surface is the **dataplane network interfaces** of PAN-OS devices — PA-series firewalls, Panorama managed devices, or VM-Series instances with exposed dataplane interfaces. Perimeter-facing devices with internet-routable dataplane IPs are at highest risk. Internal firewalls reachable from compromised hosts within the network are also in scope.

> **Note**: The specific protocol(s) or traffic patterns exploited (e.g., TCP, UDP, specific L7 protocols) are not disclosed in available sources [1][2][3]. Palo Alto Networks has rated exploit maturity as UNREPORTED [2], meaning no public proof-of-concept is known at this time. Specific payload patterns cannot be confirmed without additional vendor disclosure.

---

## Observable Behaviour

> **Caveat**: Because the exploit maturity is UNREPORTED [2] and specific technical packet-level detail is not publicly available in the referenced sources, the following indicators are based on the described vulnerability class (dataplane DoS via crafted traffic). Analysts should treat these as *candidate observables* pending vendor-provided IOCs or packet captures.

### Device-Level Symptoms

| Observable | Detail |
|---|---|
| **Dataplane process crash/restart** | PAN-OS dataplane daemons (`pan_task`, `pan_comm`, `dataplane`) cycling or generating core dumps in system logs |
| **Throughput degradation** | Sudden drop in packets-per-second metrics on dataplane interfaces; visible in PAN-OS operational commands |
| **Session table exhaustion** | Spike in session table entries without corresponding legitimate traffic growth |
| **Interface error counters** | Elevated RX errors, drops, or malformed packet counters on dataplane interfaces |
| **High CPU on dataplane** | Sustained 100% dataplane CPU without traffic volume justification |

### PAN-OS Operational Commands (on-device triage)

# Check dataplane health
show system state | match dp
show interface all
show counter global filter severity drop

# Check for dataplane restarts
show system info | match uptime
less mp-log pan_task.log

# Session table inspection
show session all | match discard
show session info

### Network-Level Observables

- **Source pattern**: Repeated high-volume packets from one or few source IPs directed at dataplane interface IPs on non-standard or high-numbered ports, or malformed packets against well-known ports.
- **Traffic anomaly**: Traffic flows that do not establish complete sessions (e.g., SYN floods, malformed headers, or protocol state violations) arriving at firewall dataplane IPs.
- **Timing**: Correlated with device availability events (HA failover, session drops reported by downstream systems).

> Specific HTTP paths, payload byte sequences, or process chains cannot be stated with specificity — the advisory does not disclose packet-level detail [2]. Fabricating specific patterns would be misleading and is not done here.

---

## Detection Coverage

### Recommended Suricata / IDS Approach

Because specific payload signatures are not publicly available [2][3], **signature-based detection of the exploit payload itself is not feasible at this time**. Detection should focus on **behavioural and anomaly-based** rules.

#### Suricata — Anomalous Traffic Volume to Firewall Dataplane IPs (Candidate Rule)

# CVE-2026-0287 — Candidate detection rule — DRAFT FOR ANALYST REVIEW
# Detects high-rate traffic directed at known PAN-OS dataplane interface IPs
# Analyst must populate $PANOS_DATAPLANE_IPS with actual asset IPs
# Threshold values require tuning to environment baseline

alert ip any any -> $PANOS_DATAPLANE_IPS any (
    msg:"CVE-2026-0287 CANDIDATE - High rate traffic to PAN-OS dataplane interface";
    threshold: type both, track by_src, count 1000, seconds 10;
    classtype:attempted-dos;
    sid:20260287001;
    rev:1;
    metadata:cve CVE-2026-0287, created_at 2026_07_14, confidence LOW;
)

> **Analyst Note**: This rule will generate false positives in high-traffic environments. Baseline normal traffic rates to the dataplane IPs before enabling. This rule does NOT match on exploit payload — it matches on volumetric anom
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0287
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0287
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0287
