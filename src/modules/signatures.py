#!/usr/bin/env python3
TEMPLATE = """
You are a detection engineer writing a Suricata IDS/IPS rule.

Using the CVE metadata, CISA KEV context, and advisory detail provided,
draft one Suricata rule targeting the network-observable behaviour of
this vulnerability.

Requirements:
- Action: alert
- Include msg with CVE ID and product name
- Use appropriate flow keywords
- Include content and/or pcre match targeting the observable behaviour
- Include reference:cve tag
- Include metadata with mitre_technique_id, is_kev status, status experimental
- Include appropriate classtype
- Assign a unique sid in the range 9000000-9999999
- Set rev:1

Return ONLY the rule text. No explanation, no markdown fencing.

Example format:
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"THREATFORGE CVE-XXXX-XXXX product exploit attempt";
  flow:established,to_server; http.uri; content:"/exploit/path";
  pcre:"/exploit_pattern/i";
  reference:cve,XXXX-XXXX;
  metadata:mitre_technique_id T1190, is_kev true, status experimental;
  classtype:attempted-admin; sid:9000001; rev:1; )
"""
