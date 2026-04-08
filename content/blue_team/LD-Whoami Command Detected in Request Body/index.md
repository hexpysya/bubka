---
title: "LD-Whoami Command Detected in Request Body"
date: 2026-04-02
draft: false
summary: "An external attacker from a CHINANET-hosted IP (61.177.172.87) exploited a command injection vulnerability on WebServer1004, executing five OS commands via the ?c= parameter against /video/ - including cat /etc/passwd and cat /etc/shadow - all of which returned HTTP 200 with distinct response sizes, confirming successful remote code execution. The case was escalated to Tier 2."
tags:
 - SOC
 - SIEM
 - EDR
 - Log Analysis
 - Web Attack
 - Command Injection
 - RCE
 - Escalation to L2
 - True Positive
 - AbuseIPDB
 - VirusTotal
---

### <span class="hl">Alert</span>
```
EventID :                   118
Event Time :                Feb, 28, 2022, 04:12 AM
Rule :                      SOC168 - Whoami Command Detected in Request Body
Level :                     Security Analyst
Hostname :                  WebServer1004
Destination IP Address :    172.16.17.16
Source IP Address :         61.177.172.87
HTTP Request Method :       POST
Requested URL :             https://172.16.17.16/video/
User-Agent :                Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
Alert Trigger Reason :      Request Body Contains whoami string
Device Action :             Allowed
```

### <span style="color:red">Identification</span>

#### <span class="hl">Is the traffic coming from outside?</span>

The source IP **61.177.172.87** falls outside any RFC 1918 private range and resolves to CHINANET Jiangsu Province Network (AS4134, Nanjing, China). Traffic direction is **Internet to Company Network**. This was confirmed not to be a planned penetration test.

#### <span class="hl">Is the source malicious?</span>

I checked **61.177.172.87** on AbuseIPDB - the IP has been reported **86,782 times** with a Confidence of Abuse of **0%**, indicating high historical noise but no active campaign score.

![AbuseIPDB](abuse.png)

VirusTotal flagged the IP as malicious by **4/94 vendors**. Community score is **-1**.

![VirusTotal](virus.png)

#### <span class="hl">What type of attack was attempted?</span>

The attacker exploited a command injection vulnerability on the `/video/` endpoint by passing OS commands through the `?c=` POST parameter. Command injection occurs when user-supplied input is passed unsanitized to a system shell, allowing arbitrary command execution in the context of the web server process. The attacker ran five commands in sequence - `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`. The use of a spoofed legacy User-Agent (MSIE 6.0 / Windows NT 5.1) indicates deliberate evasion.

#### <span class="hl">Did anyone else get targeted?</span>

Reviewing the firewall logs, all five requests were directed exclusively at **172.16.17.16:443**. No other destination addresses appeared in the log window and no lateral movement was observed.

![Firewall logs](logs.png)

#### <span class="hl">Did the attack succeed?</span>

Yes. All five POST requests returned **HTTP 200** with varying response sizes ranging from **910 to 1501 bytes**, consistent with the server executing each command and returning its output.

![Raw log](one_log_detailed.png)

### <span style="color:red">Triage Decision</span>

#### <span class="hl">What is the impact level?</span>

The attacker achieved confirmed remote code execution on **172.16.17.16** (WebServer1004), successfully reading both `/etc/passwd` and `/etc/shadow`. Combined with the `whoami` and `uname` output, the attacker obtained a full OS fingerprint and the privilege context of the web process. **Escalated to Tier 2.**

### <span style="color:red">Containment</span>

#### <span class="hl">Is the attacker still active?</span>

The last observed request from **61.177.172.87** was at **04:15 AM** on Feb 28, 2022. No further entries appeared in the log window beyond that timestamp. The IP was blocked at the perimeter firewall to prevent any follow-up connection attempts.

#### <span class="hl">Is the vulnerable endpoint still exposed?</span>

The `/video/` endpoint on **172.16.17.16** was passing the `?c=` parameter directly to the system shell with no sanitization or allowlist enforcement. The endpoint was taken offline pending a code-level fix. Input validation restricting the `?c=` parameter to expected values was flagged as mandatory before redeployment.

#### <span class="hl">Actions taken</span>

**61.177.172.87** was blocked at the perimeter firewall. **172.16.17.16** was isolated from external access and escalated to Tier 2 for credential rotation on all accounts present in the dumped `/etc/passwd` and `/etc/shadow` files.

### <span class="hl">IOCs</span>

**IPs**   
\- `61.177.172.87` - attacker IP  

**Hosts**  
\- `172.16.17.16` (WebServer1004) - compromised web server  

**Requests**  
\- `?c=ls` 
\- `?c=whoami` 
\- `?c=uname` 
\- `?c=cat /etc/passwd` 
\- `?c=cat /etc/shadow`  

**User-Agents**  
\- `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)` - spoofed legacy User-Agent used across all requests
