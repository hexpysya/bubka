---
title: "LD-LS Command Detected in Requested URL"
date: 2026-04-02
draft: false
summary: "Alert triggered on the string 'ls' found in a legitimate search query parameter. The traffic originated from an internal IP to letsdefend.io and contains no malicious payload. False positive - rule lacks context awareness for partial string matches."
tags:
 - SOC
 - SIEM
 - EDR
 - Log Analysis
 - False Positive
 - No Escalation
---

### <span class="hl">Alert</span>
```
EventID :                   117
Event Time :                Feb, 27, 2022, 12:36 AM
Rule :                      SOC167 - LS Command Detected in Requested URL
Level :                     Security Analyst
Hostname :                  EliotPRD
Destination IP Address :    188.114.96.15
Source IP Address :         172.16.17.46
HTTP Request Method :       GET
Requested URL :             https://letsdefend.io/blog/?s=skills
User-Agent :                Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0
Alert Trigger Reason :      URL Contains LS
Device Action :             Allowed
```

### <span style="color:red">Identification</span>

#### <span class="hl">Is the traffic coming from outside?</span>

The source IP `172.16.17.46` is an **internal** address. The destination `188.114.96.15` resolves to `letsdefend.io` - a legitimate external platform. Traffic direction is **Company Network to Internet**.

#### <span class="hl">Is the source malicious?</span>

The source is an internal host. The destination is a known legitimate platform.

#### <span class="hl">What type of attack was attempted?</span>

No attack was attempted. The alert triggered because the detection rule matched the string `ls` within the word `ski**ls**` in the search query `?s=skills`. This is a **false positive** caused by a substring match - the rule lacks context to distinguish the `ls` Linux command from the same character sequence appearing inside a legitimate word. The request is a standard blog search on `letsdefend.io`.

### <span style="color:red">Triage Decision</span>

**False Positive.** The URL `https://letsdefend.io/blog/?s=skills` is a legitimate search request from an internal user to an external platform. The string `ls` is a substring of `skills` and does not represent a command injection attempt. No malicious traffic was identified.

### <span class="hl">IOCs</span>

None.