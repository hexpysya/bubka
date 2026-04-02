---
title: "LD-Passwd Found in Requested URL - Possible LFI Attack"
date: 2026-04-02
draft: false
summary: "An external Tencent Cloud IP sent a single LFI request targeting /etc/passwd via path traversal. The server returned HTTP 500 with an empty response body, confirming the attack did not succeed."
tags:
  - SOC
  - Log Analysis
  - Web Attack
  - LFI
  - No Escalation
  - True Positive
platform: LetsDefend
---

### <span class="hl">Alert</span>
```
EventID :                       120
Event Time :                    Mar, 01, 2022, 10:10 AM
Rule :                          SOC170 - Passwd Found in Requested URL - Possible LFI Attack
Level :                         Security Analyst
Hostname :                      WebServer1006
Destination IP Address :        172.16.17.13
Source IP Address :             106.55.45.162
HTTP Request Method :           GET
Requested URL :                 https://172.16.17.13/?file=../../../../etc/passwd
User-Agent :                    Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)
Alert Trigger Reason :          URL Contains passwd
Device Action :                 Allowed
```

### <span style="color:red">Identification</span>

#### <span class="hl">Is the traffic coming from outside?</span>

The source IP `106.55.45.162` is an external address belonging to **Tencent Cloud Computing (Beijing) Co., Ltd.** (AS45090, Guangzhou, Guangdong, China). The destination `172.16.17.13` is an internal address. Traffic direction is **Internet to Company Network**. This was confirmed not to be a planned test.

#### <span class="hl">Is the source malicious?</span>

AbuseIPDB shows the IP has been reported **3,454 times** with a Confidence of Abuse of 0%. The Data Center/Web Hosting usage type and Chinese cloud provider context are consistent with attacker-controlled VPS infrastructure.

![AbuseIPDB](abuse.png)

VirusTotal returned **0/94** detections, however the community score is -19 with 57 community comments - a strong negative signal indicating prior malicious activity reported by the community despite no vendor detections.

![VirusTotal](virus.png)

#### <span class="hl">What type of attack was attempted?</span>

The alert triggered on a GET request to `/?file=../../../../etc/passwd` - a **Local File Inclusion (LFI)** attack using path traversal. The `file` parameter is used to specify a file to include server-side. By supplying `../../../../etc/passwd`, the attacker attempts to traverse out of the web root and read the system's account file, which contains usernames and can reveal service accounts and system configuration. The outdated User-Agent (`MSIE 6.0 / Windows NT 5.1`) is a fingerprint commonly seen in automated scanning tools.

Reviewing the raw log confirmed the request details:

![Firewall log](logs.png)
```
Request URL:   https://172.16.17.13/?file=../../../../etc/passwd
Request Method: GET
Device Action: Permitted
HTTP Response Size: 0
HTTP Response Status: 500
```

Only one connection from `106.55.45.162` was observed in the firewall logs - a single probe rather than a multi-payload enumeration campaign.

#### <span class="hl">Did anyone else get targeted?</span>

Log review shows only `172.16.17.13` (WebServer1006) was targeted. No other internal hosts were involved.

#### <span class="hl">Did the attack succeed?</span>

No. The server returned **HTTP 500** with a response size of 0 bytes. An HTTP 500 indicates an internal server error - the application failed to process the request but did not return the file contents. A successful LFI would return HTTP 200 with a non-zero response body containing the file data. The attack did not succeed.

### <span style="color:red">Triage Decision</span>

**True Positive.** A single LFI probe from an external Tencent Cloud IP was correctly allowed through to the application layer and was rejected with HTTP 500. No Tier 2 escalation required.

#### <span class="hl">What is the impact level?</span>

Low. The attack did not succeed and no data was returned. However, the HTTP 500 response indicates the application attempted to process the `file` parameter rather than rejecting it at input validation - the endpoint may be vulnerable to LFI with a different traversal depth or encoding.

### <span style="color:red">Containment</span>

#### <span class="hl">Is the attacker still active?</span>

Only one connection was logged at **10:10 AM** on Mar 01, 2022. No follow-up requests were observed.

#### <span class="hl">Is the vulnerable endpoint still exposed?</span>

The `?file=` parameter on `172.16.17.13` remains exposed. The HTTP 500 response suggests the parameter reaches the filesystem layer, making it a candidate for further LFI testing with alternate traversal sequences or encoding bypasses. The endpoint should be reviewed by the application security team.

#### <span class="hl">Actions taken</span>

`106.55.45.162` was blocked at the firewall. The `?file=` parameter on WebServer1006 was flagged for input validation review.

### <span class="hl">IOCs</span>

**IPs**  
\- `106.55.45.162` - attacker IP (Tencent Cloud AS45090, Guangzhou, CN)    
**URLs**  
\- `hxxps://172.16.17[.]13/?file=../../../../etc/passwd` - LFI payload  
**User-Agent**  
\- `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)`  
