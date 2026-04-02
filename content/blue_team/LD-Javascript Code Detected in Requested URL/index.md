---
title: "LD-Javascript Code Detected in Requested URL"
date: 2026-04-02
draft: false
summary: "An external IP performed XSS reconnaissance against the /search/ endpoint, cycling through multiple injection payloads. All requests except the first returned HTTP 302, indicating server-side sanitization blocked execution. The attack did not succeed."
tags:
  - SOC
  - Log Analysis
  - Web Attack
  - XSS
platform: LetsDefend
---

### <span class="hl">Alert</span>
```
EventID :               116
Event Time :            Feb, 26, 2022, 06:56 PM
Rule :                  SOC166 - Javascript Code Detected in Requested URL
Level :                 Security Analyst
Hostname :              WebServer1002
Destination IP Address : 172.16.17.17
Source IP Address :     112.85.42.13
HTTP Request Method :   GET
Requested URL :         https://172.16.17.17/search/?q=<$script>javascript:$alert(1)<$/script>
User-Agent :            Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
Alert Trigger Reason :  Javascript code detected in URL
Device Action :         Allowed
```

### <span style="color:red">Identification</span>

#### <span class="hl">Is the traffic coming from outside?</span>

The source IP `112.85.42.13` is an external address belonging to **China Unicom Jiangsu province network** (AS4837, Nanjing, China). The destination `172.16.17.17` is an internal address. Traffic direction is **Internet to Company Network**. This was confirmed not to be a planned test.

#### <span class="hl">Is the source malicious?</span>

AbuseIPDB shows the IP has been reported **45,324 times** with a Confidence of Abuse of 0%. The high report volume is notable despite the low confidence score - this is a Fixed Line ISP address rather than a cloud VPS, which is less common for attacker infrastructure but not unusual for compromised residential/business connections used as proxies.

![AbuseIPDB](abuse.png)

VirusTotal returned **0/94** detections - no vendor flagged the IP as malicious. However, 1 file was detected communicating with this IP, and the community score is -15, suggesting prior negative community reports.

![VirusTotal](ip_virus.png)

#### <span class="hl">What type of attack was attempted?</span>

Firewall logs show eight consecutive inbound connections from `112.85.42.13` to `172.16.17.17:443` between **06:34 PM and 06:56 PM**, all permitted.

![Firewall logs](logs.png)

Reviewing the raw log for the triggering request confirmed an XSS payload in the `q` parameter:

![Raw log](one_log_detailed.png)

The full request history on the `/search/` endpoint reveals a systematic XSS probing sequence - the attacker started with a benign `q=test` request (HTTP 200, 885 bytes) to confirm the endpoint was live, then escalated through multiple injection techniques:
```
q=test                                              - HTTP 200 (baseline probe)
q=prompt(8)                                         - HTTP 302
q=<img src=q onerror=prompt(8)>                     - HTTP 302 (img onerror)
q=<svg><script ?>alert(1)                           - HTTP 302 (SVG vector)
q=<script>for((i)in(self))eval(i)(1)</script>       - HTTP 302 (obfuscated eval)
q=<script>javascript:alert(1)                       - HTTP 302 (unclosed tag)
q=<script>javascript:alert(1)</script>              - HTTP 302 (final payload)
```

This pattern is consistent with manual or semi-automated XSS fuzzing - testing multiple bypass techniques to find one that evades server-side filtering.

#### <span class="hl">Did anyone else get targeted?</span>

All connections targeted exclusively `172.16.17.17` on the `/search/` endpoint. No other internal hosts were involved.

#### <span class="hl">Did the attack succeed?</span>

No. Only the initial baseline request (`q=test`) returned **HTTP 200** with a response body of 885 bytes. Every subsequent XSS payload returned **HTTP 302** with a response size of 0 - indicating the server redirected the request without processing the payload, consistent with server-side input sanitization or a WAF blocking the injection. No successful script execution was observed.

### <span style="color:red">Triage Decision</span>

**True Positive.** The attack did not succeed - all XSS payloads were blocked with HTTP 302. No Tier 2 escalation required.

#### <span class="hl">What is the impact level?</span>

Low. The server correctly rejected all injection payloads. However, the attacker successfully fingerprinted the endpoint as live and tested multiple bypass vectors, which may inform follow-up attempts with more advanced payloads.

### <span style="color:red">Containment</span>

#### <span class="hl">Is the attacker still active?</span>

The last observed request was at **06:56 PM** on Feb 26, 2022. No further connections from `112.85.42.13` were observed after the triggering event.

#### <span class="hl">Is the vulnerable endpoint still exposed?</span>

The `/search/` endpoint on `172.16.17.17` remains externally accessible. While the current sanitization blocked these specific payloads, the endpoint should be reviewed for completeness of input validation against advanced bypass techniques.

#### <span class="hl">Actions taken</span>

`112.85.42.13` was blocked at the firewall. The `/search/` endpoint was flagged for the application security team to review input validation coverage.

### <span class="hl">IOCs</span>

**IPs**  
\- 112.85.42.13 - attacker IP 
\- 172.16.17.17 - targeted IP  
**URLs**  
\- `hxxps://172.16.17[.]17/search/?q=` - targeted endpoint  
**User-Agent**  
\- `Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1`  

### <span class="hl">MITRE ATT&CK</span>

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Discovery | Network Service Discovery | T1046 |