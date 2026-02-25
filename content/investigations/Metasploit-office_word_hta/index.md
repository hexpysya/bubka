---
title: "Metasploit: office_word_hta"
date: 2025-11-21
draft: false
summary: "A malicious RTF document exploits CVE-2017-0199 via an embedded OLE2Link object to fetch and execute a remote HTA payload from an attacker-controlled server."
tags:
  - Malware Analysis
  - Windows
  - RTF
  - CVE-2017-0199
  - HTA
  - rtfobj
platform: Malware Analysis
---

### <span style="color:lightblue">TL;DR</span>
A malicious RTF document contains an embedded `OLE2Link` object that, upon opening, silently fetches a remote HTA file from `192.168.248.129:8080` and executes it via `mshta.exe` — no user interaction required beyond opening the document.

### <span style="color:red">Initial Analysis</span>
```console
msf.doc: Rich Text Format data, version 1, ANSI, code page 1252, default middle east language ID 1025
```

`rtfobj` identified an embedded OLE object of class `OLE2Link` containing a URL pointing to a remote HTA file:
```console
$ rtfobj msf.doc
===============================================================================
File: 'msf.doc' - size: 5743 bytes
---+----------+---------------------------------------------------------------
id |index     |OLE Object
---+----------+---------------------------------------------------------------
0  |000001B4h |format_id: 2 (Embedded)
   |          |class name: b'OLE2Link'
   |          |data size: 2560
   |          |MD5 = '053ba4dffb352244944dba6f29957f4c'
   |          |CLSID: 00000300-0000-0000-C000-000000000046
   |          |StdOleLink (embedded OLE object - Known Related to
   |          |CVE-2017-0199, CVE-2017-8570, CVE-2017-8759 or CVE-2018-8174)
   |          |Possibly an exploit for the OLE2Link vulnerability (VU#921560,
   |          |CVE-2017-0199)
   |          |URL extracted: http://192.168.248.129:8080/default.hta
---+----------+---------------------------------------------------------------
```

**CVE-2017-0199** is a Microsoft Office vulnerability that allows a malicious RTF document to automatically fetch and execute a remote HTA file via `mshta.exe` when the document is opened — without requiring macros to be enabled or any additional user interaction.

### <span style="color:lightblue">IOCs</span>

**Files**  
\- `msf.doc` — malicious RTF document  
\- MD5: `053ba4dffb352244944dba6f29957f4c`  

**Network**  
\- C2 Server: `192.168.248.129`  
\- C2 Port: `8080/tcp`  
\- Payload URL: `http://192.168.248.129:8080/default.hta`