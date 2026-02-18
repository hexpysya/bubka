---
title: "HTB-WorkFromHome"
date: 2026-02-16
draft: false
summary: " "
tags:
  - DFIR
  - Log Analysis
  - Windows

  - EventViewer
platform: DFIR
---
{{< infobox platform="HackTheBox" difficulty="Medium" os="Windows" date="2026-02-16" >}}


### <span style="color:lightblue">TL;DR</span>

### <span style="color:red">What we've got</span>

### <span style="color:red">Phishing URL</span>
Analysing a victim's Chrome History using ChromeHistoryView i identified that victim at `5/25/2025 1:36:42 PM` clicked on phising url `https://login.wowzalnc.co.th/logon.php` and resulting in credential harvesting. in phishing url changed letter "i" to "l": "wowzainc" -> "wowzalnc".
```
http://intranet.wowzainc.co.th/landing.php	5/23/2025 2:20:07 PM
https://login.wowzalnc.co.th/logon.php	    5/25/2025 1:36:42 PM
https://mail.wowzainc.co.th/inbox.php	    5/23/2025 2:21:17 PM
```

### <span style="color:red">first access via RDP</span>
at `2025-05-27 11:59:57` the attacker gained access to user otello.j via RDP(Logon type: 10).
```
# Security.evtx/4624
Logon Information:
	Logon Type:		10
	Restricted Admin Mode:	No
	Virtual Account:		No
	Elevated Token:		No

New Logon:
	Security ID:		S-1-5-21-888844466-1397619329-4015378808-1001
	Account Name:		otello.j
	Account Domain:		WORKSTATION6
	Logon ID:		0x2A017F
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{00000000-0000-0000-0000-000000000000}
```

### malicious site
then at `5/28/2025 3:36:59 PM` user visited a web-site `freehackingtool.com`. 
```
http://freehackingtool.com/		5/28/2025 3:55:02 PM	
http://freehackingtool.com/tools/		5/28/2025 3:53:36 PM	
http://freehackingtool.com/tools/		5/28/2025 3:37:09 PM	
http://freehackingtool.com/		5/28/2025 3:36:59 PM	
```
from theres was attempt to download some files: `SeManageVolumeEXploit.exe`, `a.vbs`, `PrintConfig.dll`
![alt text](image.png)
`SeManageVolumeEXploit.exe` indicates an attempt to exploit the SeManageVolumePrivilege to escalate privileges and gain full control over the C: drive.
at `5/28/2025 3:43:33` `SeManageVolumeEXploit.exe` was succesefully downloaded.

### SeManageVolumePrivilege
The `SeManageVolumePrivilege` privilege in Windows allows a user to perform volume-related operations, such as defragmenting, mounting, or dismounting a volume. This privilege is normally restricted to highly privileged accounts, like Administrators.

Privilege Escalation via SeManageVolumePrivilege occurs when an attacker with this privilege gains access to the system and can exploit it to escalate their privileges further. Specifically, the attacker might use this privilege to:

- Mount/Dismount Volumes: Attackers can mount volumes containing sensitive data, potentially bypassing access control mechanisms.
- Corrupt or Manipulate File Systems: By interacting with file systems at the volume level, attackers could introduce malicious changes or corrupt files to create backdoors or disrupt system functionality.
- Potential Code Execution: Depending on the volume operations allowed, attackers may trigger scenarios that lead to arbitrary code execution.


at `5/28/2025 3:44:01 PM` was attempted to download a `PrintConfig.dll`, but it was interrupted with code 41, which means `The user shut down the browser`.
![alt text](image1.png)
```
// The user shut down the browser.
// Internal use only:  resume pending downloads if possible.
INTERRUPT_REASON(USER_SHUTDOWN, 41)
```

so the attacker at `2025-05-28 3:45:37` using LOLBIN `certutil.exe` succesefully downloaded a `PrintConfig.dll`. I identified that by analysing `CryptnetUrlCache/Metadata`. the legitimate dll located in `C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll` was removed and replaced by a malicious.

In Powershell console history i found that the attacker initializated an object {854A20FB-2D44-457D-992F-EF13785D2B51} that triggered a winspool service to execute a malicious dll.
```
dir
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
dir
reg add "HKCU\control panel\desktop" /v wallpaper /t REG_SZ /d "C:/Users/Public/Pictures/gg.bmp" /f
```