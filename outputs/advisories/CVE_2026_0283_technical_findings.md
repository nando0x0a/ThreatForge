> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-0283
> Product:   palo alto pan-os
> Tags:      [RCE] [HIGH] [T1]
> Score:     80
> Tier:      HIGH PRIORITY
> SEVERITY DISCREPANCY: NVD/vulnx says 7.2 (HIGH) — CVE.org (CNA, v4.0) says 4.5 (MEDIUM). See https://www.cve.org/CVERecord?id=CVE-2026-0283
> Generated: 2026-07-14T20:27:35.098838Z
> Status:    OK

# Technical Findings Report — CVE-2026-0283

> **⚠️ ANALYST REVIEW REQUIRED — This is a proposed draft for analyst review. All findings, indicators, and recommendations must be validated against your environment before action is taken.**

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-0283 |
| **Affected Product** | Palo Alto Networks PAN-OS — Large Scale VPN (LSVPN) functionality |
| **CVSS Score** | **See Severity Discrepancy below** |
| **KEV Status** | Not listed in CISA KEV at time of reporting |
| **Age** | 4 days old |
| **Exploit Maturity** | Unreported — no public proof-of-concept known [2] |
| **Priority Tier** | HIGH PRIORITY (Score: 80) [RCE] [HIGH] [T1] |

### ⚠️ Severity Discrepancy Between Sources

Analysts must note a material disagreement in CVSS scoring between two authoritative sources:

- **[1] NVD scores this CVE at CVSS 7.2 (HIGH)** — this score is reflected in the priority tags applied to this report.
- **[3] CVE.org (CNA-published record, CVSS v4.0) scores this CVE at 4.5 (MEDIUM)** — this is the score published by Palo Alto Networks as the CNA and is also reflected in the vendor advisory [2], which rates severity as **MEDIUM** with a score of **4.5**.

The discrepancy likely reflects differences between the CVSS v3.x scoring methodology used by NVD [1] and the CVSS v4.0 methodology used in the CNA record [3]. CVSS v4.0 introduced revised scoring mechanics (particularly for attack complexity and privilege requirements) that can produce meaningfully different scores for the same vulnerability. **Analysts should evaluate both scores in the context of their environment.** The presence of network-exploitable authentication bypass affecting VPN infrastructure is operationally significant regardless of which score is accepted.

---

## Attack Vector

CVE-2026-0283 is an **authentication bypass** vulnerability residing in the **Large Scale VPN (LSVPN)** component of Palo Alto Networks PAN-OS [1][2]. LSVPN is a hub-and-spoke VPN architecture used to automate the deployment of satellite VPN devices (GlobalProtect Satellites) connecting to a GlobalProtect Portal/Gateway acting as an LSVPN hub.

**Exploitation conditions:**

- **Network Access Required:** The attacker must have network-level access to the LSVPN service endpoint on an affected PAN-OS device. This corresponds to `AV:N` (Attack Vector: Network) in the CVSS vector, meaning the vulnerability is remotely exploitable without requiring physical or adjacent-layer access [1].
- **No Authentication Required:** The flaw exists in the authentication handling of the LSVPN tunnel establishment process, meaning a pre-authentication exploit path exists. This corresponds to `PR:N` (Privileges Required: None) [1].
- **No User Interaction:** Exploitation does not require action from a legitimate user (`UI:N`) [1].
- **Outcome:** A successful exploit allows an attacker to **establish an unauthorized site-to-site VPN connection** to the target PAN-OS LSVPN hub. This places the attacker inside the VPN tunnel fabric, potentially granting access to resources reachable via the VPN, the ability to intercept or manipulate VPN-routed traffic, and a network foothold within the enterprise routing domain.

**RCE Classification Note:** This CVE is tagged `[RCE]` based on the network-exploitable nature (`AV:N/PR:N/UI:N`) of the vector. However, analysts should note that the primary described impact is **unauthorized VPN connection establishment** (an authentication bypass). Whether arbitrary code execution is achievable as a consequence of the VPN tunnel access or as a secondary step is **not confirmed in available sources at this time**. The RCE tag may reflect the severity of network-reachable, zero-authentication exploitation rather than confirmed remote code execution in the traditional sense. **This distinction should be clarified with Palo Alto Networks PSIRT or via vendor advisory updates** [2].

**Affected Service Exposure:**
- LSVPN hub functionality typically operates on the GlobalProtect Portal/Gateway interfaces, exposed on TCP/443 (HTTPS) or custom configured ports.
- Only PAN-OS devices configured as **LSVPN hubs** (GlobalProtect Portal with satellite authentication enabled) are in scope. PAN-OS devices not configured for LSVPN are not confirmed to be affected — verify configuration scope against your inventory.

---

## Observable Behaviour

> **Note:** No public proof-of-concept is available [2], and specific payload patterns, HTTP paths, or packet-level indicators have not been published in vendor advisory materials at this time [2]. The following represents analyst-inferred observable behaviour based on the vulnerability class (authentication bypass in LSVPN satellite registration) and standard PAN-OS LSVPN protocol behaviour. **All indicators below require validation once additional technical detail is published.**

### Network-Level Indicators

**Unexpected LSVPN Satellite Registration Attempts:**
- LSVPN satellite-to-hub authentication occurs over **HTTPS (TCP/443)** to the GlobalProtect Portal. Observe for:
  - Connections to GlobalProtect Portal IP(s) from **unrecognized source IP addresses** not matching the registered satellite device inventory.
  - High-frequency or repeated authentication attempts against the LSVPN portal endpoint from a single external IP, potentially indicating authentication bypass probing.
  - Successful SSL/TLS session establishment followed by LSVPN-characteristic URI paths from unknown sources.

**Typical LSVPN URI paths (PAN-OS standard — not exploitation-specific):**
POST /ssl-vpn/login.esp
POST /global-protect/getconfig.esp
GET  /global-protect/portal/css/
Observe for these paths originating from IPs not in the authorized satellite address space.

**IPSec/IKE Traffic Following Successful Portal Authentication:**
- After portal authentication, LSVPN establishes an IPSec tunnel. Watch for:
  - Unexpected **IKEv2 (UDP/500, UDP/4500)** negotiations originating from unknown external hosts to the LSVPN hub's outside interface.
  - IPSec SA establishment (`IKE_AUTH` exchange completions) for satellite identities not present in the authorized satellite configuration.

### Log-Based Indicators (PAN-OS)

**GlobalProtect System Logs:**
(subtype eq globalprotect) and (eventid eq satellite-connected)
- Alert on `satellite-connected` events where the satellite serial number or IP does not match the authorised satellite inventory.
- Look for `satellite-prelogin` or authentication events followed immediately by `satellite-connected` without corresponding expected satellite IDs.

**Traffic Logs:**
- New VPN tunnel traffic (`application eq ipsec`) from external addresses not in the LSVPN satellite whitelist.
- Large data volumes transiting newly established satellite tunnels from unknown endpoints.

**System Logs / Authentication Logs:**
- Authentication bypass may produce anomalous log entries — look for successful satellite authentication events lacking corresponding prior credential validation log entries, or authentication log gaps.

### Endpoint/Host Telemetry

- Specific process chains on PAN-OS are not published at this time. If your PAN-OS devices forward logs to a SIEM, focus on `pan-os` source type events with event categories related to `globalprotect` and `vpn`.

---

## Detection Coverage

> **Note:** No vendor-published Snort/Suricata signatures or specific SIEM queries exist for CVE-2026-0283 at the time of this report. The following are **analyst-proposed hunting queries** for SOC review. No Suricata rule has been produced for this CVE due to absence of specific payload-level indicators in published sources.

### Splunk — Hunting Query: Unexpected LSVPN Satellite Connection

index=panos sourcetype=pan:system
  (subtype="globalprotect" OR subtype="vpn")
  (eventid="satellite-connected" OR eventid="satellite-auth-success")
| eval src_ip=coalesce(src_ip, src)
| lookup lsvpn_authorized_satellites.csv satellite_ip AS src_ip OUTPUT authorized
| where isnull(authorized) OR authorized="false
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-0283
[2] security.paloaltonetworks.com — https://security.paloaltonetworks.com/CVE-2026-0283
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-0283
