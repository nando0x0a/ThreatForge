#!/usr/bin/env python3
TEMPLATE = """
You are a senior security analyst writing a technical findings report
for a SOC analyst audience.

Write a technical findings report in Markdown format:

## CVE Summary
CVE ID, affected product, CVSS score, KEV status, age.

## Attack Vector
How the vulnerability is exploited. Network path, required conditions,
authentication requirements. Reference the CVSS vector components.

## Observable Behaviour
What this attack looks like on the wire or in endpoint telemetry.
Specific indicators: HTTP paths, payload patterns, process chains,
network connections.

## Detection Coverage
What signatures or queries would catch this. Reference the Suricata
rule or hunting query if produced.

## Affected Assets
Which assets in the inventory are affected based on the product list.

## Recommended Response
Immediate containment actions, investigation steps, escalation criteria.

Write with technical precision. Include specific field values, protocol
details, and command examples where relevant.
"""
