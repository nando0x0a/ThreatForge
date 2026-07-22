> **ThreatForge Output — ADVISORY**
>
> CVE:       CVE-2026-58644
> Product:   sharepoint_server
> Tags:      [KEV] [RCE] [CRIT]
> Score:     120
> Tier:      CRITICAL — ACT NOW
> Generated: 2026-07-22T03:08:38.248954Z
> Status:    OK

# Security Advisory: Critical Microsoft SharePoint Vulnerability
**Classification:** CRITICAL — IMMEDIATE ACTION REQUIRED
**Date Issued:** 2026-07-20
**Advisory Reference:** CVE-2026-58644
**Priority Tier:** CRITICAL — ACT NOW

> ⚠️ *This advisory is a proposed draft for analyst review prior to distribution.*

---

## Executive Summary

A critical security vulnerability has been discovered in Microsoft SharePoint — the widely used collaboration and document management platform — that allows attackers to take complete control of affected systems without requiring any login credentials or user interaction [1]. This vulnerability is being actively exploited by real-world attackers right now, as confirmed by both independent security researchers and the U.S. Cybersecurity and Infrastructure Security Agency (CISA) [2][3]. The attack can be launched remotely over the internet, meaning no physical access to your organization is required. This is one of the most severe vulnerability classifications possible, carrying a near-maximum risk score of 9.8 out of 10 [1]. **Management must immediately authorize emergency patching and direct IT teams to treat this as a top-priority incident. Federal guidance requires remediation on an expedited timeline under BOD 26-04 [3].**

---

## Business Impact

If this vulnerability is not addressed urgently, your organization faces the following concrete business risks:

- **Full System Compromise:** Attackers who exploit this flaw gain the ability to execute any command on the SharePoint server, which can serve as a launchpad to compromise your broader corporate network and Active Directory environment [4]. Security researchers have documented real-world attack chains leading from initial SharePoint exploitation all the way to **full domain compromise** [4].

- **Data Breach:** SharePoint commonly stores sensitive corporate documents, contracts, HR records, financial data, and intellectual property. A successful attack could result in mass data exfiltration, triggering breach notification obligations under GDPR, HIPAA, state privacy laws, or other applicable regulations.

- **Operational Disruption:** Ransomware actors and other threat groups actively target SharePoint environments. Exploitation could result in encryption of files, deletion of backups, or extended downtime affecting collaboration and business continuity.

- **Regulatory and Legal Exposure:** Because U.S. federal authorities (CISA) have formally designated this as a known exploited vulnerability [3], failure to act in a timely manner could complicate cyber insurance claims, regulatory examinations, or post-incident liability assessments.

- **Reputational Damage:** A breach originating from an unpatched, publicly known vulnerability — one the security community is actively tracking — is difficult to defend to customers, partners, or a board of directors.

---

## Affected Systems

The following Microsoft products are affected. Please confirm with your IT team which versions are deployed in your environment:

- **Microsoft SharePoint Server** — on-premises deployments (specific version details should be confirmed against the vendor's official security update guidance)
- Organizations running **internet-facing SharePoint portals** are at the highest immediate risk, as the attack requires no authentication and can be launched from anywhere on the internet [1]
- Organizations running SharePoint in **internal-only configurations** remain at risk from attackers who have already gained a foothold in the network

> *Note: Specific version numbers affected should be confirmed with your IT team against Microsoft's official advisory. Your team should assess cloud-hosted SharePoint Online exposure separately, per CISA guidance on cloud services [3].*

---

## Recommended Action

Management is asked to **approve and communicate the following actions immediately:**

1. **Authorize Emergency Patching — Today:** Direct your IT and security teams to apply Microsoft's available security patches for SharePoint as the single highest-priority action this week. No competing projects should delay this work [3].

2. **Mandate Exposure Assessment — Within 24 Hours:** Require IT to confirm which SharePoint instances are accessible from the internet and to immediately restrict external access to any unpatched system. Internet-facing systems are at the greatest risk of opportunistic attack [1].

3. **Initiate Threat Hunt — Within 48 Hours:** Given that active exploitation has been confirmed in the wild [2][3][4], direct your security team or a third-party provider to review SharePoint logs for signs of suspicious access or compromise that may have already occurred.

4. **Activate Incident Response Readiness:** Ensure your incident response plan is on standby. If exploitation is detected during the investigation, escalate to full incident response immediately.

5. **Comply with Federal Directive:** If your organization is subject to CISA's Binding Operational Directive (BOD) 26-04, ensure your remediation timeline meets the required federal patching deadlines [3].

6. **Communicate to Stakeholders:** If patching will cause temporary SharePoint downtime, communicate proactively to affected business units and schedule maintenance windows as soon as operationally feasible — measured in hours, not days.

---

## Timeline

Based on the **CRITICAL — ACT NOW** priority tier, active exploitation in the wild, and the maximum-severity risk rating, the following timeline is directed:

| Milestone | Deadline |
|---|---|
| Management approval to proceed with emergency patching | **Immediately / Today** |
| Identification and isolation of internet-facing SharePoint systems | **Within 24 hours** |
| Patch applied to all internet-facing SharePoint instances | **Within 24–48 hours** |
| Patch applied to all internal SharePoint instances | **Within 72 hours** |
| Threat hunt / log review completed for signs of prior compromise | **Within 48 hours** |
| Confirmation of remediation reported to CISO | **Within 96 hours** |
| Post-remediation review and lessons learned | **Within 14 days** |

> ⚠️ *These timelines reflect the critical nature of active exploitation. Any deviation should be documented with a formal risk acceptance from senior leadership.*

---

*This advisory was prepared based on threat intelligence current as of 2026-07-20 and is subject to revision as additional vendor guidance or threat intelligence becomes available. It is a proposed draft for analyst review prior to management distribution.*

---

## Sources

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-58644
[2] VulnCheck KEV, added 2026-07-14 — https://www.vulncheck.com/kev
[3] CISA Known Exploited Vulnerabilities Catalog, added 2026-07-16 — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[4] www.resecurity.com — https://www.resecurity.com/es/blog/article/from-web-request-to-domain-compromise-understanding-the-july-2026-sharepoint-attacks
[5] www.rapid7.com — https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild/
[6] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-58644
## Sources (ThreatForge-verified)

[1] NVD — https://nvd.nist.gov/vuln/detail/CVE-2026-58644
[2] VulnCheck KEV, added 2026-07-14 — https://www.vulncheck.com/kev
[3] CISA Known Exploited Vulnerabilities Catalog, added 2026-07-16 — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[4] www.resecurity.com — https://www.resecurity.com/es/blog/article/from-web-request-to-domain-compromise-understanding-the-july-2026-sharepoint-attacks
[5] www.rapid7.com — https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild/
[6] CVE.org (CNA-published record) — https://www.cve.org/CVERecord?id=CVE-2026-58644
