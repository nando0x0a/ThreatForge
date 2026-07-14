> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0287
> Product:   palo alto pan-os
> Tags:      [RCE] [HIGH] [T1]
> Score:     80
> Tier:      HIGH PRIORITY
> SEVERITY DISCREPANCY: NVD/vulnx says 7.5 (HIGH) — CVE.org (CNA, v4.0) says 6.6 (MEDIUM). See https://www.cve.org/CVERecord?id=CVE-2026-0287
> Generated: 2026-07-14T20:24:06.828930Z
> Status:    OK

# Technical Findings Report — CVE-2026-0287
### PAN-OS: Denial of Service Vulnerabilities in Network Traffic Processing
**Draft for Analyst Review — Not for distribution without verification**

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0287 |
| **Affected Product** | Palo Alto Networks PAN-OS (dataplane interfaces) |
| **CVSS Score (NVD)** | 7.5 HIGH [1] |
| **CVSS Score (CNA/CVE.org)** | 6.6 MEDIUM (CVSS v4.0) [3] |
| **Vendor Severity** | 6.6 MEDIUM [2] |
| **KEV Status** | Not listed in CISA KEV at time of writing |
| **Age** | 4 days old |
| **PoC Availability** | No public proof-of-concept known |
| **Priority Tier** | HIGH PRIORITY (Priority Score: 80) |

> ⚠️ **SEVERITY DISCREPANCY — ANALYST ACTION REQUIRED:**
> NVD scores this vulnerability at **CVSS 7.5 HIGH** [1], while the CNA-published record at CVE.org scores it at **CVSS v4.0 6.6 MEDIUM** [3]. The vendor advisory also aligns with the lower MEDIUM rating [2]. This discrepancy is likely attributable to differences between CVSS v3.x (used by NVD) and CVSS v4.0 (used by the CNA), which changed scoring methodology for network-based DoS vulnerabilities. Analysts should review both scores and apply the rating most consistent with their environment's risk tolerance. The NVD HIGH score is used as the conservative baseline in this report's prioritisation.

---

## Attack Vector

CVE-2026-0287 represents **multiple denial of service vulnerabilities** triggered by specially crafted network traffic directed at **PAN-OS dataplane interfaces** [1][2].

**Exploitation Conditions:**

| Component | Value | Implication |
|---|---|---|
| Attack Vector | Network (AV:N) | Remotely exploitable over IP |
| Privileges Required | None (PR:N) | No account or session needed |
| User Interaction | None (UI:N) | Fully automated exploitation possible |
| Authentication | Unauthenticated | Any network-reachable attacker qualifies |
| Exploit Maturity | Unreported [2] | No confirmed in-the-wild exploitation |

The attack surface is the **dataplane interface** — the high-throughput forwarding plane of PAN-OS appliances responsible for processing live network traffic. This is distinct from the management plane. Importantly, this means:

- **Internet-facing firewalls** are at greatest risk if dataplane interfaces are reachable from untrusted networks.
- The attacker requires **network adjacency to a dataplane interface**, not necessarily to the management interface.
- The vulnerability encompasses **multiple** DoS conditions within traffic processing logic [1][2], suggesting the attack surface may span more than one protocol handler or parsing pathway. Specific protocol details are not available in current public advisories — this should be confirmed against vendor-released IOCs when available [2].

The vendor rates response effort as **MODERATE** [2], suggesting patching is actionable but not trivially fast across large fleets.

---

## Observable Behaviour

> ⚠️ **Note:** No public proof-of-concept exists [as stated in context], and vendor advisories do not currently detail specific packet structures or payload patterns [2]. The observable indicators below are derived from the known vulnerability class (network traffic processing DoS on PAN-OS dataplane) and should be validated against actual traffic captures if exploitation is suspected. Do not treat these as confirmed IOCs.

**Expected Crash/DoS Symptoms:**

- **Dataplane process restarts** visible in PAN-OS system logs:
  - Log type: `system`
  - Severity: `critical`
  - Description pattern: `dataplane restarted` or `dp-monitor` events
  - CLI verification: `show system state | match dp`

- **High CPU or resource exhaustion on dataplane:**
  - CLI: `show running resource-monitor`
  - CLI: `show interface all` — look for interface drops and error counters incrementing on dataplane-facing interfaces

- **Traffic forwarding interruption** — firewall stops passing traffic without rebooting (characteristic of dataplane crash vs. system-wide crash).

**Network-Side Indicators (Hypothesis — Verify Against Captures):**

- **Anomalous traffic patterns** arriving at dataplane interfaces from unexpected sources, particularly:
  - High-rate packet floods from a single source IP targeting the firewall's own dataplane IP (not a behind-firewall host)
  - Malformed or oversized packets to services processed by the dataplane
  - Unusual protocol combinations or fragmented traffic targeting PAN-OS parsing logic

- **Source IPs directly targeting firewall interface IPs** (as opposed to transit traffic destined for internal hosts) should be treated with elevated suspicion.

**Log Sources to Monitor:**

/var/log/pan/dp.log          # Dataplane process log
/var/log/pan/system          # System event log (accessible via GUI/CLI)
show log system direction equal backward              # CLI log review

---

## Detection Coverage

### Suricata Detection Rule (Proposed Draft — Analyst Review Required)

> This rule targets anomalous direct traffic to PAN-OS dataplane interface IPs. It is necessarily broad due to the absence of specific payload signatures. Tune `$PANOS_DP_IPS` to your inventory. Review for false positives before deployment to production.

# CVE-2026-0287 — PAN-OS Dataplane DoS — Anomalous Direct Traffic
# DRAFT: Requires analyst tuning and validation before production use
# Specificity is limited due to absence of public PoC/payload details

alert ip any any -> $PANOS_DP_IPS any (
    msg:"[CVE-2026-0287] Potential PAN-OS Dataplane DoS - High Rate Direct Traffic to Firewall Interface";
    flow:stateless;
    threshold:type both, track by_src, count 500, seconds 10;
    detection_filter:track by_src, count 500, seconds 10;
    classtype:attempted-dos;
    sid:20260287001;
    rev:1;
    metadata:affected_product PAN-OS,
              attack_target Network_Firewall,
              cve CVE-2026-0287,
              created_at 2026_01_01,
              severity high,
              confidence low;
)

alert ip any any -> $PANOS_DP_IPS any (
    msg:"[CVE-2026-0287] Potential PAN-OS Dataplane DoS - Malformed/Fragmented Traffic to Firewall Interface";
    fragbits:M+D;
    classtype:attempted-dos;
    sid:20260287002;
    rev:1;
    metadata:affected_product PAN-OS,
              attack_target Network_Firewall,
              cve CVE-2026-0287,
              created_at 2026_01_01,
              severity high,
              confidence low;
)

**Confidence Note:** Rules carry **low confidence** due to absence of specific payload patterns. These are volume/behaviour-based heuristics only. Update SIDs when vendor releases IOC detail [2].

### SIEM Hunting Query (Splunk SPL — Draft)

index=panos sourcetype="pan:system"
| search description IN ("*dataplane*restart*", "*dp-monitor*", "*dataplane*crash*", "*dp0*down*")
| eval cve="CVE-2026-0287"
| table _time, host, description, severity, cve
| sort -_time

index=panos sourcetype="pan:traffic"
(dest IN ($PANOS_DP_IPS))
| stats count by src_ip, dest_ip, dest_port, proto
| where count > 1000
| eval alert="[CVE-2026-0287] High-volume direct traffic to PAN-OS dataplane interface"
| table src_ip, dest_ip, dest_port, proto, count, alert
| sort -count

---

## Affected Assets

> **Analyst Action Required:** Cross-reference the below with your
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0287
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0287
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0287
