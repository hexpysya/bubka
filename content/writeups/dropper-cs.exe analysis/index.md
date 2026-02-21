---
title: "Dropper-cs.exe"
date: 2025-11-23
draft: false
summary: " "
tags:
  - Malware Analysis
platform: Malware Analysis
---


### <span style="color:lightblue">TL;DR</span>

### <span style="color:red">initial analysis</span>
```cosnole
$ file *             
dropper_cs.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```
#### libraries
Confirmed that is .NET executable by seen a huge amount of `mscoree.dl` (Microsoft .NET Runtime Execution Engine)
![alt text](image.png)

#### imports
```
VirtualProtect                              KERNEL32.dll
GetCurrentThread                            KERNEL32.dll
TerminateThread                             KERNEL32.dll
GetConsoleWindow                            KERNEL32.dll
```
- VirtualProtect + PAGE_EXECUTE_READWRITE field → marks memory regions as executable, classic shellcode injection technique
- TerminateThread → forceful thread termination, anti-analysis or cleanup
- GetConsoleWindow + ShowWindow(SW_HIDE) → hides console window from user

```
GetDelegateForFunctionPointer               mscoree.dll (runtime)
PrepareDelegate                             mscoree.dll (runtime)
```
- combined with VirtualProtect → shellcode execution via managed delegate: allocate → make executable → invoke as function pointer

```
Load                                        mscoree.dll (runtime)
CreateDomain, DoCallBack, Unload            mscoree.dll (runtime)
RunEphemeralAssembly, ActivateLoader        mscoree.dll (runtime)
RunTempAppDomain, RunAssembly               mscoree.dll (runtime)
```
- in-memory .NET assembly loading: loads and executes assemblies directly from bytes, never touching disk
- isolated AppDomain created → code executed → domain unloaded to erase traces
- RunEphemeralAssembly name explicitly implies ephemeral/traceless execution

```
Beacon, BeaconSleepMillis, Jitter           mscoree.dll (C2 logic)
GenerateUri, StageUrl, URIs                 mscoree.dll (C2 logic)
GetCommands, SendTaskOutputString           mscoree.dll (C2 logic)
DownloadString, UploadData                  System.Net (WebClient)
```
- classic beacon loop: sleep with jitter → contact C2 → receive commands → send output
- GenerateUri → randomizes request URLs to evade pattern-based detection

```
ProxyUrl, ProxyUser, ProxyPassword          mscoree.dll (config)
UserAgent, HttpReferrer                     mscoree.dll (config)
set_ServerCertificateValidationCallback     System.Net
AllowUntrustedCertificates                  mscoree.dll
```

- full HTTP traffic masquerading: custom User-Agent, Referrer, proxy support
- SSL certificate validation disabled → allows self-signed C2 certs, MITM-friendly

```
PadWithImageData, ImageDataObfuscator       mscoree.dll (C2 logic)
Images, ExtractImages                       mscoree.dll (config)
```
- steganography: C2 traffic disguised as image data
- exfiltrated data or received commands embedded into image payloads to bypass DPI/proxies

```
RijndaelManaged, AesCryptoServiceProvider   System.Security.Cryptography
Encrypt, Decrypt, CreateEncryptor           mscoree.dll
Key, GenerateIV                             mscoree.dll
```
- AES encryption of all C2 traffic
- key embedded in reversed base64 config (reversedBase64Config param) → basic obfuscation of config

```
ParseConfigString, reversedBase64Config     mscoree.dll (config)
KillDate, ImplantId, PipeName, PipeSecret   mscoree.dll (config)
FCommFilePath, DomainCheck                  mscoree.dll (config)
```
- config decoded at runtime from reversed base64 string → evades static string detection
- KillDate → implant self-disables after set date, reduces exposure window
- PipeName/PipeSecret → named pipe support for lateral movement / peer-to-peer C2
- DomainCheck → may verify domain environment before executing, sandbox evasion

```
GetEnvironmentalInfo, GetCurrentProcess     mscoree.dll / System.Diagnostics
get_UserName, get_UserDomainName            System
IsHighIntegrity, WindowsPrincipal.IsInRole  System.Security.Principal
GetEnvironmentVariable                      System
```
- full system reconnaissance: username, domain, process name, PID
- IsHighIntegrity → checks for admin/SYSTEM privileges, likely gates certain capabilities

```
CommandLineToArgvW                          SHELL32.dll
```
- parses command-line arguments, used to receive initial config or staging parameters at launch

#### strings


#### running in Sandbox