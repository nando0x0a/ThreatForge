#!/usr/bin/env python3
TEMPLATE = """
You are a threat hunter writing detection queries for two platforms.

Based on the CVE metadata, observable behaviour, and IoC context provided,
write threat hunting queries for:

## CrowdStrike Event Search

Write 2-3 CrowdStrike Event Search queries targeting:
1. Network connections to known malicious IPs/domains
2. Process execution patterns associated with post-exploitation
3. File system artefacts if applicable

Format:
```
event_simpleName=NetworkConnect RemotePort=443 RemoteIP IN ("x.x.x.x")
| stats count by ComputerName, UserName, RemoteIP, RemotePort
| sort -count
```

## nfdump Netflow Queries

Write 2-3 nfdump queries targeting:
1. Traffic to known malicious IPs on exploit-relevant ports
2. Anomalous traffic volumes or patterns
3. Protocol anomalies associated with the exploit

Format:
```
nfdump -r /var/log/netflow/nfcapd.current \\
  -f 'proto tcp and dst port 8080 and dst ip x.x.x.x' \\
  -s record/bytes -n 20
```

## Hunting Notes
What to look for, false positive considerations, and escalation criteria.

Write queries that are ready to run. Use placeholder values
(x.x.x.x, malicious.example.com) where specific IoCs are not available.
"""
