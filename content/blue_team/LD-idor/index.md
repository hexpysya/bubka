---
title: "LD-Possible IDOR Attack Detected"
date: 2026-04-02
draft: false
summary: "External IP enumerated the /get_user_info/ endpoint via sequential IDOR requests, all returning HTTP 200 - confirming successful data exfiltration across five user accounts."
tags:
  - SOC
  - Log Analysis
  - Web Attack
  - IDOR
  - Escalation to L2
  - True Positive
platform: LetsDefend
---

### <span class="hl">Alert</span>
```
EventID :               119
Event Time :            Feb, 28, 2022, 10:48 PM
Rule :                  SOC169 - Possible IDOR Attack Detected
Level :                 Security Analyst
Hostname :              WebServer1005
Destination IP Address: 172.16.17.15
Source IP Address :     134.209.118.137
HTTP Request Method :   POST
Requested URL :         https://172.16.17.15/get_user_info/
User-Agent :            Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)
Alert Trigger Reason :  consecutive requests to the same page
Device Action :         Allowed
```
### <span style="color:red">Identification</span>

#### <span class="hl">Is the traffic coming from outside?</span>

The source IP `134.209.118.137` is an external address belonging to DigitalOcean LLC (AS14061), located in North Bergen, New Jersey. The destination `172.16.17.15` is an internal address. The traffic is inbound from outside the network.

#### <span class="hl">Is the source malicious?</span>

AbuseIPDB reported the IP 1,536 times with a confidence of abuse of 0%, indicating it is a known DigitalOcean hosting address with no confirmed malicious history.

![AbuseIPDB result](ip_abuse.png)

VirusTotal returned 0/94 detections — no security vendor flagged the IP as malicious.

![VirusTotal result](ip_virus.png)

Although both sources return clean results, the IP belongs to a cloud hosting provider, which is commonly used to launch attacks anonymously. The repetitive request pattern is the primary indicator here.

#### <span class="hl">What type of attack was attempted?</span>
Firewall logs show five consecutive inbound connections from 134.209.118.137 to 172.16.17.15:443 between 10:45 PM and 10:48 PM, all on different source ports, where each request contained a unique parameter: **?user_id=1, ?user_id=2, ?user_id=3, ?user_id=4, and ?user_id=5**.
![Firewall logs](logs.png)
```
Request URL: https://172.16.17.15/get_user_info/
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)
Request Method: POST
Device Action: Permitted
HTTP Response Size: 253
HTTP Response Status: 200
POST Parameters: ?user_id=2
```
**I**nsecure **D**irect **O**bject **R**eference (IDOR) is an access control vulnerability where an attacker manipulates object references - such as user IDs in a URL or request body - to access data belonging to other users. The endpoint `/get_user_info/` is a target for this type of enumeration. The consecutive POST requests from a single external IP suggest the attacker was iterating through user identifiers to extract account data without authorization.

#### <span class="hl">Did anyone else get targeted?</span>
All connections targeted the same destination - only `172.16.17.15` was affected.
![Firewall logs](logs.png)

#### <span class="hl">Did the attack succeed?</span>

I examined the HTTP response data for each of the five requests.
All five requests returned HTTP 200 with differing response body sizes. I concluded the attack succeeded and that data for all five queried accounts was exfiltrated.
### <span style="color:red">Triage Decision</span>

**True Positive.** An external cloud IP sent repeated automated POST requests to a user data endpoint. The firewall allowed all traffic and the endpoint was exposed. The attack pattern is consistent with IDOR enumeration.

#### <span class="hl">What is the impact level?</span>

High. If the `/get_user_info/` endpoint does not enforce proper authorization checks, the attacker may have successfully retrieved account data for multiple users. The endpoint handles user information and was accessible without restriction from an external IP.

### <span style="color:red">Containment</span>

#### <span class="hl">Is the attacker still active?</span>

The last logged connection was at 10:48 PM on Feb 28, 2022. No additional logs were observed after this timestamp. The attacker may have completed the enumeration or moved on, but the IP has not been blocked.

#### <span class="hl">Is the vulnerable endpoint still exposed?</span>

Yes. The `/get_user_info/` endpoint remains accessible from external IPs with no firewall restriction in place.

#### <span class="hl">Actions taken</span>

`134.209.118.137` was blocked at the firewall level. The `/get_user_info/` endpoint was flagged for the application security team. 
### <span class="hl">IOCs</span>

| Type | Value | Source |
|------|-------|--------|
| IP | 134.209.118[.]137 | Firewall logs |
| URL | hxxps://172.16.17[.]15/get_user_info/ | Alert |
| User-Agent | Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322) | Alert |