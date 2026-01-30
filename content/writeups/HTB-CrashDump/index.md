---
title: "HTB-CrashDump"
date: 2026-01-30
draft: false
tags:
  - Malware Analysis
  - winDBG
  - mini dump
  - cobalt
platform: Malware Analysis
---

{{< infobox difficulty="Easy" os="Windows" date="2026-01-30" >}}

**Description:**  
A suspicious executable was identified running on one of the compromised endpoints. Initial triage suggests that this process may have been leveraged by the threat actor to establish a foothold on the system. To support further malware analysis and behavioral reconstruction, a user‑mode process dump of the suspected executable has been provided.

## TL;DR
Analyzed two process dumps (notepad.exe and update.exe) revealing a Cobalt Strike Beacon infection. The malware used process injection with reflective DLL loading, communicated with C2 server at `101.10.25.4:8023`, and possessed capabilities for privilege escalation, token manipulation, and lateral movement via named pipes.

## <span style="color:red">Initial Analysis</span>
I received 2 mini dump files:
```
notepad.DMP: Mini DuMP crash report, 15 streams, Wed Nov  5 01:14:37 2025, 0x21826 type
update.DMP:  Mini DuMP crash report, 15 streams, Wed Nov  5 01:11:52 2025, 0x21826 type
```

## <span style="color:red">Injected Process (notepad.dmp)</span>

I ran `!analyze -v` to reveal OS information:
```
OS_VERSION:  10.0.10240.16384
OSPLATFORM_TYPE:  x64
OSNAME:  Windows 10
```

I checked for RWX memory regions using `!address -f:PAGE_EXECUTE_READWRITE`. The first bytes at address `b1221a0000` started with `MZ`, indicating an embedded EXE/DLL:
```
        BaseAddress      EndAddress+1        RegionSize     Type       State                 Protect             Usage
--------------------------------------------------------------------------------------------------------------------------
      b1`20870000       b1`20871000        0`00001000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [.H........AQAPRQ]
      b1`221a0000       b1`221ee000        0`0004e000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [MZARUH..H......H]
      b1`23bd0000       b1`23fd0000        0`00400000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [.H....3..E.H....]
```

I examined the threads. Thread with TID 0x3a8 corresponded to the memory page at BaseAddress `20870000`:
```
0xc28   0x0   notepad!WinMainCRTStartup (00007ff7`8dc23fe0)       
0x3a8   0x1   000000b1`20870000      
0x5fc   0x2   ntdll!TppWorkerThread (00007fff`47309040)       
0x2d0   0x3   ntdll!TppWorkerThread (00007fff`47309040)       
```

### Thread Analysis
The code was a shellcode stager that unpacked and executed the payload at `b1221ee000`:
```nasm
0:001> u b120870000 L50
000000b1`20870000 fc              cld
000000b1`20870001 4883e4f0        and     rsp,0FFFFFFFFFFFFFFF0h
000000b1`20870005 e8c8000000      call    000000b1`208700d2
000000b1`2087000a 4151            push    r9
000000b1`2087000c 4150            push    r8
000000b1`2087000e 52              push    rdx
000000b1`2087000f 51              push    rcx
000000b1`20870010 56              push    rsi
000000b1`20870011 4831d2          xor     rdx,rdx
000000b1`20870014 65488b5260      mov     rdx,qword ptr gs:[rdx+60h]
000000b1`20870019 488b5218        mov     rdx,qword ptr [rdx+18h]
000000b1`2087001d 488b5220        mov     rdx,qword ptr [rdx+20h]
000000b1`20870021 488b7250        mov     rsi,qword ptr [rdx+50h]
000000b1`20870025 480fb74a4a      movzx   rcx,word ptr [rdx+4Ah]
000000b1`2087002a 4d31c9          xor     r9,r9
000000b1`2087002d 4831c0          xor     rax,rax
000000b1`20870030 ac              lods    byte ptr [rsi]
000000b1`20870031 3c61            cmp     al,61h
000000b1`20870033 7c02            jl      000000b1`20870037
```

### Payload Extraction
I extracted the injected binary from memory address `b1221a0000`:
```
.writemem c:\Users\f\Desktop\shellcode.bin b1221a0000 L?4e000
```

## <span style="color:red">Malicious Process (update.dmp)</span>
I found another executable in this process and extracted it as `shellcode1.bin`:
```
0:000> !address -f:PAGE_EXECUTE_READWRITE

        BaseAddress      EndAddress+1        RegionSize     Type       State                 Protect             Usage
--------------------------------------------------------------------------------------------------------------------------
       0`003a0000        0`003ee000        0`0004e000 MEM_PRIVATE MEM_COMMIT  PAGE_EXECUTE_READWRITE             <unknown>  [MZARUH..H......H]
```

### C2 Server IP
I searched for HTTP connections in memory:
```
0:000> s -a 0 L?0x7fffffffffffffff "http://"
00000000`0060b8b0  68 74 74 70 3a 2f 2f 31-30 31 2e 31 30 2e 32 35  http://101.10.25
```

I examined the full URL at address `0060b8b0`:
```
0:000> db 0060b8b0 L100
00000000`0060b8b0  68 74 74 70 3a 2f 2f 31-30 31 2e 31 30 2e 32 35  http://101.10.25
00000000`0060b8c0  2e 34 3a 38 30 32 33 2f-6a 2e 61 64 00 00 00 00  .4:8023/j.ad....
```

**C2 Server:** `http://101.10.25.4:8023/j.ad`

## <span style="color:red">Shellcode Analysis</span>

I identified the payload as **Cobalt Strike Beacon** based on strings analysis.

### Framework Identification
```
ascii,10,0x0002C8F0,-,beacon.dll
ascii,14,0x0003B892,-,beacon.x64.dll
ascii,16,0x0003B8A1,-,ReflectiveLoader
```

### C2 Communication
```
ascii,69,0x0002D3D9,-,IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')
ascii,49,0x0002D491,-,powershell -nop -exec bypass -EncodedCommand "%s"
```

### Capabilities

\- *Process Injection:*  
`CreateRemoteThread`, `WriteProcessMemory`, `ReadProcessMemory`, `VirtualAllocEx`, `VirtualProtectEx`, `SetThreadContext`, `GetThreadContext`

\- *Named Pipe Communication:*
`ConnectNamedPipe`, `CreateNamedPipe`, `DisconnectNamedPipe`, `PeekNamedPipe`, `ImpersonateNamedPipeClient`

\- *Privilege Escalation:*
`SeDebugPrivilege`, `SeTcbPrivilege`, `SeCreateTokenPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`

\- *Token Manipulation:*
`ImpersonateLoggedOnUser`, `CreateProcessAsUser`, `CreateProcessWithToken`, `DuplicateTokenEx`, `AdjustTokenPrivileges`

