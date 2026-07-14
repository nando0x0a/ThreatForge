> **ThreatForge Output — TECHNICAL_FINDINGS**
>
> CVE:       CVE-2026-10698
> Product:   moveit
> Tags:      [HIGH] [T1]
> Score:     40
> Tier:      STANDARD
> Generated: 2026-07-14T20:57:47.092156Z
> Status:    OK

# Technical Findings Report — CVE-2026-10698

> **DRAFT FOR ANALYST REVIEW** — This report is a proposed assessment based on available context and should be validated by a qualified security analyst before action is taken.

---

## CVE Summary

| Field | Detail |
|---|---|
| **CVE ID** | CVE-2026-10698 |
| **Affected Product** | Progress MOVEit Transfer |
| **Affected Versions** | 2025.0.0 – 2025.0.7, 2025.1.0 – 2025.1.3, 2026.0.0 [1][2] |
| **Fixed Versions** | 2025.0.8, 2025.1.4, 2026.0.1 [2] |
| **Vulnerability Type** | SQL Injection (CWE-89) — improper neutralization of special elements in data query logic |
| **Affected Module** | Custom Reports |
| **CVSS Score** | 7.2 (HIGH) [1] |
| **KEV Status** | Not listed in CISA KEV at time of report |
| **Vulnerability Age** | 6 days |
| **PoC Availability** | No public proof-of-concept known |
| **Priority Tier** | STANDARD \| Tags: [HIGH] [T1] \| Priority Score: 40 |

---

## Attack Vector

The vulnerability resides in the **Custom Reports module** of MOVEit Transfer, where user-supplied input is insufficiently sanitised before being incorporated into backend SQL query logic [1][2]. This enables an attacker to inject arbitrary SQL syntax and manipulate database queries.

**Exploitation conditions:**

- **Network Path:** Remotely exploitable over the network — MOVEit Transfer is typically exposed via HTTPS (TCP/443) and potentially SFTP/FTP interfaces. The Custom Reports functionality is accessible through the MOVEit Transfer web application.
- **Authentication:** The CVSS score of 7.2 with the HIGH severity designation is consistent with a low-privilege authenticated attack surface, though specific CVSS vector string components (AV, AC, PR, UI, S, C, I, A) are not explicitly enumerated in the available sources. **Analysts should retrieve the full CVSS vector from NVD [1] to confirm authentication requirements.** A score of 7.2 in the context of MOVEit Transfer SQL injection is broadly consistent with authenticated network access with low privileges, but this should be independently verified.
- **Exploit Complexity:** Requires crafted input submitted to the Custom Reports query logic [1][3]. No pre-existing PoC is publicly known, which modestly reduces near-term exploitation likelihood, but MOVEit Transfer has a well-documented history of being a high-value target.
- **Interaction:** No indication of user-interaction requirement beyond the attacker's own crafted request.

**Potential SQL injection impact:**
- Data exfiltration from the MOVEit Transfer database (user credentials, file transfer metadata, stored files references, audit logs)
- Potential for privilege escalation within the application depending on database user permissions
- Possible data manipulation or deletion if `INSERT`/`UPDATE`/`DELETE` injection is achievable

---

## Observable Behaviour

The following indicators are **inferred from the vulnerability class and affected module**. Specific payload signatures confirmed by vendor or researcher analysis are not available in current sources [2]. Analysts should treat these as a starting hypothesis for hunting, not confirmed IOCs.

### HTTP Indicators

**Likely targeted endpoint paths** (based on Custom Reports module in MOVEit Transfer web UI — exact paths not confirmed in sources):

POST /moveitisapi/moveitisapi.dll
POST /api/v1/reports
POST /human.aspx
GET  /CustomReports*

**SQL injection payload patterns in HTTP body or query string parameters:**

# Classic injection delimiters to look for in URL-encoded form data or JSON body:
'  --  ;--  ' OR '1'='1  ' UNION SELECT  ' AND SLEEP(  WAITFOR DELAY  xp_cmdshell

**HTTP field focus:**
- `Content-Type: application/x-www-form-urlencoded` or `application/json`
- Anomalously long parameter values in report filter/query fields
- Parameters containing SQL keywords: `UNION`, `SELECT`, `INSERT`, `DROP`, `EXEC`, `CAST`, `CONVERT`, `CHAR(`, `NCHAR(`
- URL-encoded variants: `%27` (single quote), `%3B` (semicolon), `%2D%2D` (double dash)

### Application / Database Log Indicators

- Database error strings appearing in HTTP responses: `Incorrect syntax near`, `OLE DB`, `ODBC`, `SQL Server`, `unclosed quotation mark`
- Unusual query volumes or durations originating from the Custom Reports module in database slow-query logs
- MOVEit Transfer application logs showing report generation failures or unexpected query structures

### Network Telemetry

- Repeated POST requests to Custom Reports endpoints from a single source IP over short windows
- Responses with unusually large payloads (data exfiltration via UNION-based injection)
- Time-based blind injection may manifest as artificially delayed HTTP responses (e.g., consistent ~5s response times where `WAITFOR DELAY '0:0:5'` is used)

### Endpoint / Process Telemetry

- If SQL injection achieves command execution via `xp_cmdshell` (SQL Server): child processes spawned under the SQL Server process (`sqlservr.exe`) such as `cmd.exe`, `powershell.exe`, `net.exe`
- Unusual outbound network connections from the MOVEit Transfer host process or `sqlservr.exe`

---

## Detection Coverage

### Recommended Suricata / NIDS Rule (Draft — Analyst Review Required)

# CVE-2026-10698 — MOVEit Transfer Custom Reports SQL Injection
# DRAFT — Analyst review required before deployment
# Source: ThreatForge / CVE-2026-10698

alert http $EXTERNAL_NET any -> $HTTP_SERVERS [443,80] (
    msg:"[CVE-2026-10698] MOVEit Transfer Custom Reports SQLi Attempt";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"Report"; nocase;
    http.request_body;
        pcre:"/(\%27|\'|\-\-|\%3B|UNION[\s\+]+SELECT|WAITFOR[\s]+DELAY|xp_cmdshell|CAST\s*\(|CONVERT\s*\()/i";
    threshold:type limit, track by_src, count 3, seconds 60;
    classtype:web-application-attack;
    sid:9102669801;
    rev:1;
    metadata:
        cve CVE-2026-10698,
        affected_product "Progress MOVEit Transfer",
        created_at 2026_06_01,
        deployment draft;
)

> ⚠️ **Note:** Exact URI paths for the Custom Reports module are not confirmed in available sources [2]. The `content:"Report"` match is a generalisation. Analysts should inspect MOVEit Transfer access logs to identify the precise endpoint path and refine the `http.uri` content match accordingly before production deployment.

---

### SIEM / Threat Hunting Query (Splunk SPL — Draft)

# CVE-2026-10698 — MOVEit Transfer Custom Reports SQL Injection Hunting
# DRAFT — Analyst review required
# Adjust sourcetype and field names to match your MOVEit/IIS/WAF log schema

index=web_logs sourcetype=iis OR sourcetype=moveit_access
    (uri_path="*report*" OR uri_path="*Report*")
    (cs_method="POST")
    (
        cs_uri_query="*%27*" OR cs_uri_query="*UNION*" OR cs_uri_query="*SELECT*"
        OR request_body="*UNION*SELECT*" OR request_body="*WAITFOR*DELAY*"
        OR request_body="*xp_cmdshell*" OR request_body="*' OR '*"
        OR request_body="*CAST(*" OR request_body="*--*"
    )
| eval src_ip=coalesce(c_ip, src_ip, client_ip)
| stats
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-10698
[2] community.progress.com — https://community.progress.com/s/article/MOVEit-Transfer-Critical-Security-Bulletin-June-2026
[3] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-10698
