---
title: "Wazuh + Suricata: SQL injection detection"
date: 2026-03-09
draft: false
summary: "Detected a SQL Injection attack, observed 85 alerts across 6 rule IDs, and configured automated IP blocking via active response."
tags:
  - Wazuh
  - SOC
  - SQL injection
---
{{< infobox platform="Wazuh Lab" difficulty="Medium" os="Linux" date="2026-03-09" >}}

### <span style="color:lightblue">Objective</span>
Investigate a SQL Injection attack detected by Wazuh and Suricata targeting
a DVWA instance, triage alerts, identify the attack pattern and tooling,
and configure automated response to block the attacker IP.

### <span style="color:lightblue">Environment</span>
| Role     | OS                  | IP              |
|----------|---------------------|-----------------|
| Attacker | Kali Linux          | 192.168.248.129 |
| Agent    | Ubuntu 22.04 Server | 192.168.248.140 |
| Wazuh    | Ubuntu 24.04 Server | 192.168.248.50  |

### <span style="color:red">What Wazuh Detected</span>
![Dashboard overview filtered by 192.168.248.129](image.png)

Wazuh generated **85 alerts** from source IP `192.168.248.129` over
approximately 2 minutes. The alert spike began at 15:47 UTC and
corresponds to automated SQL Injection tooling activity.
MITRE ATT&CK: T1190 - Exploit Public-Facing Application.

![Alert table with rule IDs](image1.png)

Six rule IDs were triggered during the attack:

| Rule ID | Level | Description                                  | Count |
|---------|-------|----------------------------------------------|-------|
| 31103   | 7     | SQL injection attempt                        | 28    |
| 31106   | 6     | A web attack returned code 200 (success)     | 20    |
| 31171   | 6     | SQL injection attempt (SELECT/INSERT)        | 16    |
| 31122   | 5     | Web server 500 error code (Internal Error)   | 16    |
| 31152   | 10    | Multiple SQL injection attempts from same IP | 4     |
| 31162   | 10    | Multiple web server 500 errors from same IP  | 1     |

Rules 31103, 31106, 31171, and 31122 fire per individual event.
Rules 31152 and 31162 are correlation rules that aggregate multiple
events into a higher severity alert (level 10).

\- **16 HTTP 500 responses** confirm injected payloads reached the database
layer and caused query execution errors — a reliable error-based SQLi indicator.  
\- **20 HTTP 200 responses** on rule 31106 mean a portion of payloads
executed successfully and the server returned data.  
\- **Rule 31152** (level 10) fired 4 times after the frequency threshold
for repeated SQLi attempts from a single IP was reached.

Expanded view of a single Rule 31103 alert:

\- **Source IP:** 192.168.248.129  
\- **Target:** 192.168.248.140  
\- **URL:** `/dvwa/vulnerabilities/sqli/?id=1%27+UNION+SELECT+1%2C2--&Submit=Submit`  
\- **HTTP status:** 500  
\- **Tool:** `sqlmap/1.10.2#stable` — confirmed via User-Agent header  
\- **Technique:** Boolean-based blind SQLi with `CASE WHEN` and `CHR()` functions  
\- **MITRE:** T1190 - Exploit Public-Facing Application  
\- **Fired times:** 28  
```json
{
  "agent": { "ip": "192.168.248.140", "name": "agent1", "id": "001" },
  "data": {
    "srcip": "192.168.248.129",
    "id": "200",
    "url": "/dvwa/vulnerabilities/sqli/?id=1%27%20AND%204076%3D%28SELECT%20%28CASE%20WHEN%20%28%28SELECT%20CHR%28102%29%7C%7CCHR%2881%29%7C%7CCHR%28122%29%7C%7CCHR%2898%29%20FROM%20SYSIBM.SYSDUMMY1%29%3D%27fQzb%27%29%20THEN%204076%20ELSE%20%28SELECT%209431%20UNION%20SELECT%207597%29%20END%29%29--%20QdwI&Submit=Submit"
  },
  "rule": {
    "id": "31103",
    "level": 7,
    "description": "SQL injection attempt.",
    "firedtimes": 28,
    "mitre": {
      "technique": ["Exploit Public-Facing Application"],
      "id": ["T1190"],
      "tactic": ["Initial Access"]
    }
  },
  "full_log": "192.168.248.129 - - [09/Mar/2026:14:17:26 +0000] \"GET /dvwa/vulnerabilities/sqli/?id=1%27%20AND%204076%3D...--QdwI&Submit=Submit HTTP/1.1\" 500 295 \"http://192.168.248.140/dvwa/vulnerabilities/sqli/\" \"sqlmap/1.10.2#stable (https://sqlmap.org)\"",
  "timestamp": "2026-03-09T15:47:08.617+0000"
}
```

The User-Agent string `sqlmap/1.10.2#stable` in the full log confirms
the attack was conducted with sqlmap — no inference required. The decoded
URL payload reveals a boolean-based blind injection technique using
`CASE WHEN` logic and `CHR()` character functions, consistent with
sqlmap's database fingerprinting phase.

Suricata independently fingerprinted the source machine as Kali Linux
via DHCP hostname at 15:44 UTC — before the web attack began —
providing network-layer attribution unavailable from Apache logs alone.

![Suricata alert — ET INFO Possible Kali Linux hostname in DHCP](image2.png)


### <span style="color:lightblue">Response</span>
Active response was configured on the Wazuh Manager to automatically
block the attacker IP via `firewall-drop` upon rule 31152 triggering.
Configuration added to `/var/ossec/etc/ossec.conf`:
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>31152</rules_id>
  <timeout>0</timeout>
</active-response>
```

`timeout` is set to `0` — the block is permanent and requires manual
review before removal. This is appropriate for a confirmed TP where
the source IP shows no legitimate use case.


### <span style="color:lightblue">Conclusion</span>
Wazuh successfully detected the SQL Injection attack out of the box,
generating 85 alerts across 6 rule IDs. The attacker tool was confirmed
directly from the User-Agent header (`sqlmap/1.10.2#stable`) without
any inference. Correlation rules 31152 and 31162 fired automatically
without custom configuration, and active response permanently blocked
the attacker IP upon threshold being reached — without manual intervention.
