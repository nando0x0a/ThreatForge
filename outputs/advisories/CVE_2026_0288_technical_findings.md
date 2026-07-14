> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0288
> Product:   palo alto pan-os
> Tags:      [RCE] [HIGH] [T1]
> Score:     80
> Tier:      HIGH PRIORITY
> Generated: 2026-07-14T20:34:42.134365Z
> Status:    OK

# Technical Findings Report — CVE-2026-0288

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed assessment produced by ThreatForge automation. All findings, indicators, and recommendations must be validated by a qualified security analyst before operational use.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0288 |
| **Affected Product** | Palo Alto Networks PAN-OS — User-ID Terminal Server (TS) Agent component [2] |
| **CVSS Score** | 7.5 HIGH (NVD) [1] / 7.2 HIGH (Palo Alto Networks advisory) [2] |
| **KEV Status** | Not listed in CISA KEV at time of report generation — analyst should verify current KEV catalogue |
| **Exploit Maturity** | UNREPORTED — no public proof-of-concept known [2] |
| **Vulnerability Age** | 5 days |
| **RCE Capable** | Yes — network-exploitable [1] |

### ⚠️ SEVERITY DISCREPANCY BETWEEN SOURCES

NVD records a CVSS score of **7.5 HIGH** [1], while the Palo Alto Networks vendor advisory records **7.2 HIGH** [2]. The scoring difference may reflect differing assessment of a specific vector component (e.g., attack complexity or scope). Analysts should review both base vectors independently and apply the score most appropriate to their environment. **Do not silently adopt either score without noting this discrepancy in your risk register.**

---

## Attack Vector

CVE-2026-0288 describes **multiple buffer overflow vulnerabilities** residing in the **User-ID Terminal Server (TS) Agent** component of PAN-OS [2]. The following conditions define the attack surface:

- **Network Reachability (AV:N):** The vulnerable component accepts network traffic. An attacker does not require physical or local access — exploitation is possible from any host with network connectivity to the TS Agent listener port.
- **No Privileges Required (PR:N):** The vulnerability can be triggered without authentication [1][2]. The TS Agent does not require the attacker to hold any account or session credential prior to exploitation.
- **No User Interaction (UI:N):** Exploitation is fully automated and does not depend on any victim action.
- **Attack Complexity:** The NVD vector implies low complexity (contributing to the 7.5 score) [1]; the vendor advisory's slightly lower score (7.2) [2] may reflect a modest complexity distinction — analyst review of the full CVSS vector string from each source is recommended.

**Exploitation mechanism:** The attacker sends crafted network traffic — packets or protocol messages specifically constructed to overflow one or more fixed-size buffers in the TS Agent's parsing or processing logic [1][2]. Successful exploitation outcomes include:

1. **Denial of Service** — process crash or hang, disrupting User-ID mapping functionality and potentially degrading policy enforcement relying on user identity.
2. **Remote Code Execution** — if the overflow overwrites control-flow data (e.g., return addresses, function pointers) and the attacker achieves reliable control of the instruction pointer.

**Network path:** The User-ID TS Agent runs as a Windows service on Terminal Server infrastructure that bridges Windows event log data to PAN-OS firewalls. The agent listens on a dedicated TCP port (Palo Alto Networks documentation historically references **TCP/5007** for TS Agent communication, though analysts should confirm the active port in their deployment — specific port confirmation from the advisory is not available in the provided context).

---

## Observable Behaviour

> **Note:** No public proof-of-concept exists at this time [2], and the vendor advisory does not detail specific payload patterns or protocol frame layouts in the context provided. The indicators below are based on the vulnerability class (network buffer overflow in a TCP service) and general behaviour of this attack category. Analysts should treat these as hunting hypotheses, not confirmed IoCs.

### Network-Layer Indicators

| Indicator | Description |
|---|---|
| **Anomalous packet sizing** | Packets to the TS Agent listener port containing payloads significantly exceeding expected message sizes for the TS Agent protocol. Look for individual TCP segments or reassembled application-layer messages in the multi-kilobyte range directed at the agent port. |
| **Malformed framing** | Protocol messages with unexpected length field values, missing delimiters, or truncated/overlong field values relative to the TS Agent message format. |
| **High-rate connection attempts** | Rapid, repeated TCP connections from a single source to the TS Agent port, potentially indicative of fuzzing or reliability-tuning preceding exploitation. |
| **Connections from unexpected sources** | TS Agent should only receive connections from PAN-OS firewall management interfaces. Connections originating from non-firewall IP addresses are anomalous and warrant immediate investigation. |

### Endpoint / Process Telemetry (on the Windows TS Agent host)

| Indicator | Description |
|---|---|
| **TS Agent process crash** | `PanGPAgent.exe` or the relevant TS Agent process (confirm binary name in deployment) terminating unexpectedly, generating Windows Event ID **1000** (Application Error) or **1001** (Windows Error Reporting). |
| **Unexpected child processes** | If RCE is achieved, look for unusual child processes spawned from the TS Agent parent, particularly `cmd.exe`, `powershell.exe`, or other shells. |
| **Memory access violations** | Application crash dumps in `%LOCALAPPDATA%\CrashDumps\` or Watson/WER directories referencing the TS Agent binary — these may contain stack traces useful for confirming exploitation attempt. |
| **New network listeners** | Post-exploitation, an adversary may establish a reverse shell or bind listener. Monitor for new `LISTEN` sockets on the TS Agent host via `netstat -anob` baselines. |
| **Lateral movement from TS Agent host** | The TS Agent host has privileged visibility into user identity mappings. Post-RCE, monitor for LDAP queries, SMB connections, or credential access activity originating from this host. |

### Log Sources

- **Windows Security Event Log** on the TS Agent host
- **Windows Application Event Log** (crash events)
- **PAN-OS System Logs** — loss of User-ID mapping data or TS Agent connectivity errors
- **Network flow data (NetFlow/IPFIX)** to/from the TS Agent listener port
- **EDR telemetry** on the TS Agent Windows host

---

## Detection Coverage

> **Note:** Because no public proof-of-concept exists [2] and specific protocol framing details for the PAN-OS TS Agent wire format are not available in the provided advisory context, the following detection guidance focuses on anomaly-based and behavioural patterns rather than byte-exact signatures. Signature-based rules should be refined once Palo Alto Networks or the research community publish technical details.

### Suricata — Network Anomaly Rule (Draft)

# CVE-2026-0288 — PAN-OS TS Agent Buffer Overflow — Anomalous Traffic Detection
# DRAFT FOR ANALYST REVIEW
# Author: ThreatForge (automated draft)
# Reference: https://security.paloaltonetworks.com/CVE-2026-0288
# NOTE: TCP port 5007 is the historically documented TS Agent port.
#       Validate against your deployment before enabling.
# NOTE: Byte-exact payload signatures are NOT available at this time.
#       This rule fires on anomalous message length as a hunting aid only.
#       Expect false positives — tune dsize threshold to your baseline.

alert tcp any any -> $TS_AGENT_HOSTS 5007 (
    msg:"CVE-2026-0288 PANOS TS Agent Possible Oversized Payload (Hunting Rule)";
    flow:to_server,established;
    dsize:>4096;
    threshold:type limit, track by_src, count 1, seconds 60;
    classtype:attempted-dos;
    sid:2026028801;
    rev:1;
    metadata:
        affected_product "Palo Alto Networks PAN-OS TS Agent",
        cve CVE-2026-0288,
        created_at 2026_01_01,
        confidence LOW,
        analyst_review REQUIRED;
)

alert tcp any any -> $TS_AGENT_HOSTS 5007 (
    msg:"CVE-2026-0288 PANOS TS Agent Connection from Non-Firewall Source (Hunting Rule)";
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0288
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0288
[3] security.paloaltonetworks.com — https://security.paloaltonetworks.com/
[4] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0288
