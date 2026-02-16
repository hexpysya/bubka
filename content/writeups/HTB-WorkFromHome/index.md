---
title: "HTB-WorkFromHome"
date: 2026-02-16
draft: false
summary: " "
tags:
  - DFIR
  - Log Analysis
  - Windows

platform: DFIR
---
{{< infobox platform="HackTheBox" difficulty="Medium" os="Windows" date="2026-02-16" >}}


### <span style="color:lightblue">TL;DR</span>

### <span style="color:red">What we've got</span>

### <span style="color:red">Phishing URL</span>
Analysing a victim's Chrome History using ChromeHistoryView i identified that victim at `5/25/2025 1:36:42 PM` clicked on phising url `https://login.wowzalnc.co.th/logon.php`. in phishing url changed letter "i" to "l": "wowzainc" -> "wowzalnc".
```
http://intranet.wowzainc.co.th/landing.php	5/23/2025 2:20:07 PM
https://login.wowzalnc.co.th/logon.php	    5/25/2025 1:36:42 PM
https://mail.wowzainc.co.th/inbox.php	    5/23/2025 2:21:17 PM
```