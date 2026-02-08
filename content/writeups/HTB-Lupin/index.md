---
title: "HTB-Lupin"
date: 2026-02-08
draft: false
tags:
  - Malware Analysis
  - Windows
  - PE
platform: Malware Analysis
---



{{< infobox platform="HackTheBox" difficulty="Medium" os="Windows" date="2026-02-08" >}}
Description:  
After a security incident, unusual activity on Samira’s workstation led to the discovery of a suspicious binary operating stealthily in the background. The executable evades standard detection while maintaining persistence and network communication. Your mission is to reverse the binary and extract the attacker’s TTPs for the endpoint security team.

### <span style="color:lightblue">TL;DR</span>


### <span style="color:red">initial analysis</span>
```console
$ file *             
optimize.exe: PE32 executable for MS Windows 5.00 (GUI), Intel i386, 3 sections
```

#### libraries
![alt text](image.png)
\- `WS2_32.dll` + `WININET.dll` potentially used to communication with the C2 server.   
\- `urlmon.dll` indicates file downloading capabilities, likely via `URLDownloadToFile`, suggesting the sample as a Downloader to retrieve and execute secondary payload.


#### imports
```
socket, bind, listen, accept, connect       WS2_32.dll
send, recv, sendto, recvfrom               WS2_32.dll
WSAStartup, WSASocketA, WSASend, WSARecv   WS2_32.dll
InternetOpenA, InternetConnectA            WININET.dll
HttpOpenRequestA, HttpSendRequestA         WININET.dll
URLDownloadToFileW                         urlmon.dll
```


```
RegOpenKeyExW      ADVAPI32.dll
RegSetValueExW     ADVAPI32.dll
RegQueryValueExW   ADVAPI32.dll
RegCloseKey        ADVAPI32.dll
```
\- interaction with Registry, potentially for persistance or modifies system security settings

```
SetClipboardViewer       USER32.dll
ChangeClipboardChain     USER32.dll
OpenClipboard            USER32.dll
GetClipboardData         USER32.dll
SetClipboardData         USER32.dll
IsClipboardFormatAvailable USER32.dll
```
\- сlipboard hijacking capability

```
RegisterRawInputDevices  USER32.dll
GetMessageA             USER32.dll
```
\- potentially keylogging via `RegisterRawInputDevices`

```
CreateFileW, WriteFile              KERNEL32.dll
DeleteFileW, CopyFileW, MoveFileExW KERNEL32.dll
FindFirstFileW, FindNextFileW       KERNEL32.dll
CreateDirectoryW, RemoveDirectoryW  KERNEL32.dll
SetFileAttributesW                  KERNEL32.dll
MapViewOfFile, CreateFileMappingW   KERNEL32.dll
```
\- file system operation  
\- `SetFileAttributesW` can be used for hiding files

```
CreateProcessW     KERNEL32.dll
CreateThread       KERNEL32.dll
ShellExecuteW      SHELL32.dll
```
\- payload execution via `CreateProcessW` or `ShellExecuteW`  
\- combined with download functions -> **dropper/loader** behavior

```
CryptAcquireContextW   ADVAPI32.dll
CryptGenRandom         ADVAPI32.dll
CryptReleaseContext    ADVAPI32.dll
rand, srand            msvcrt.dll
```
\- `CryptGenRandom` - cryptographically secure random generation, potentially used for encryption of C2 traffic
\- `rand/srand` may indicate custom encryption algorithm


```
CreateMutexA          KERNEL32.dll
NtQueryVirtualMemory  ntdll.dll
Sleep, GetTickCount   KERNEL32.dll
```
\- `CreateMutexA` - ensure single instance  
\- `NtQueryVirtualMemory` - detect debuggers/sandboxes via memory inspection  
\- `Sleep` + `GetTickCount` - potential timing-based sandbox evasion  


#### strings
*Hardcoded C2 Servers:*
```
http://185.156.72.39/
http://45.141.233.6/
www.update.microsoft.com (likely decoy/masquerading)
```

*User-Agent String:*
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 
(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
```
\- Recent Chrome UA (v128) for blending with legitimate traffic  
\- HTTP-based C2 communication confirmed  

*Registry Run Keys:*
```
Software\Microsoft\Windows\CurrentVersion\Run\
Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
```

*Zone.Identifier Bypass:*
```
%s:Zone.Identifier
```

*Dropped Files:*
```
%temp%\syscrondvr.exe
%temp%\tbtnds.dat
%temp%\tbtcmds.dat
DriveSecManager.exe (USB)
```

*Dropper Command:*
```
%s.lnk
/c start %s & start %s\DriveSecManager.exe
```

*Cryptocurrency Wallet Addresses Embedded:*
```
Bitcoin:     bc1q9tgkga69k094n5v0pn7ewmpp2kn66sh9hu65gq
bitcoincash: qph44jx8r9k5xeq5cuf958krv3ewrnp5vc6hhdjd3r
ronin:       a77fa3ea6e09a5f3fbfcb2a42fe21b5cf0ecdd1a
Cosmos:      cosmos125f3mw4xd9htpsq4zj5w5ezm5gags37yj6q8sr
Terra:       terra1mw3dhwak2qe46drv4g7lvgwn79fzm8nr0htdq5
Zilliqa:     zil19delrukejtr306u0s7ludxrwk434jcl6ghpng3
... (40+ additional altcoin addresses)
```
- i think sample monitors clipboard for crypto addresses via `SetClipboardViewer` chain and replaces victim's copied address with attacker's corresponding wallet
