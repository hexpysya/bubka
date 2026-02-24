---
title: "HTB-Partial_Encryption"
date: 2026-01-26
draft: false
summary: " "
tags:
  - Reverse Engineering
  - Windows
  - PE
  - packer
  - ida
  - x64dbg
platform: reversing
---

{{< infobox platform="HackTheBox" difficulty="Easy" os="Windows" date="2026-01-26" >}}
Description:  
Static-Analysis on this program didn't reveal much. There must be a better way to approach this...


## Static Analysis
Отриманий файл - PE execiteble для Windows 64-bit
```bash
$ file *                                                        
partialencryption.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 5 sections
```
### Packer
Містить невелику кількість imports, що вказують на пакуваня (`VirtualAlloc VirtualProtect VirtualFree`) та на anti-dynamic analysis:  
\- `IsDebuggerPresent` - перевірка чи програма працює під дебагером
\- `QueryPerformanceCounter` та `GetSystemTimeAsFileTime` - можуть використовутися для вимирювання часу між інструкціями  
```
VirtualAlloc
VirtualProtect
VirtualFree
QueryPerformanceCounter
GetCurrentProcessId
GetCurrentThreadId
GetSystemTimeAsFileTime
InitializeSListHead
RtlCaptureContext
RtlLookupFunctionEntry
RtlVirtualUnwind
IsDebuggerPresent
UnhandledExceptionFilter
SetUnhandledExceptionFilter
IsProcessorFeaturePresent
GetModuleHandleW
KERNEL32.dll
```

### Reversing
by static analysis i found that used `aeskeygenassist` та `aesdeclast` instructions. Це вказує на використання процесорних розширень Intel AES-NI для криптографічних операцій 
\- **aeskeygenassist** used to assist in generating round keys on-the-fly
* **aesdeclast** performs the final round of the decryption state
![alt text](image.png)


## Dynamic Analysis
### just running
i tried run program 
```powerhsell
C:\Users\f\Desktop>partialencryption.exe aaaaaaaa
Nope

C:\Users\f\Desktop>partialencryption.exe aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
No
```

### Running over x64dbg

I placed a breakpoint on the `VirtualAlloc` call to identify where data is being written in memory. I set a hardware breakpoint on that address, resumed execution, but only received a **Nope** message. This indicated that a check was failing before the program jumped to the decrypted data.

![alt text](image-1.png)

I then executed the program with a longer input string (e.g., `aaa...`) to observe its behavior under those conditions.

![alt text](image-2.png)

In this case, the program began checking individual characters of the flag.

```asm
...[snip]...
| mov rax,qword ptr ds:[rdx+rax]          |
| movsx eax,byte ptr ds:[rax+rcx]         |
| cmp eax,48                              | 48:'H'
...[snip]...
| mov rax,qword ptr ds:[rdx+rax]          |
| movsx eax,byte ptr ds:[rax+rcx]         |
| cmp eax,54                              | 54:'T'
...[snip]...
| mov rax,qword ptr ds:[rdx+rax]          |
| movsx eax,byte ptr ds:[rax+rcx]         |
| cmp eax,42                              | 42:'B'
...[snip]...
| mov rax,qword ptr ds:[rdx+rax]          |
| movsx eax,byte ptr ds:[rax+rcx]         |
| cmp eax,7B                              | 7B:'{'
...[snip]...
| imul rcx,rcx,15                         | rcx:putchar
| mov rdx,qword ptr ss:[rsp+48]           | rdx:exit
| mov rax,qword ptr ds:[rdx+rax]          |
| movsx eax,byte ptr ds:[rax+rcx]         |
| cmp eax,7D                              | 7D:'}}'
...[snip]...
```

Continuing debugging, I found three identical blocks of code that handle decryption and execution:

```asm
| mov r8d,8000                            |
| xor edx,edx                             |
| mov rcx,qword ptr ss:[rsp+30]           |
| call qword ptr ds:[<VirtualFree>]       |
| xor eax,eax                             |
| cmp eax,1                               |
| je partialencryption.7FF62E0F149A       |
| mov edx,1E0                             |  ## size 480 bytes
| lea rcx,qword ptr ds:[7FF62E0F42E0]     |  ## encryption data source
| call partialencryption.7FF62E0F1050     |  ## decrypting payload into memory
...[snip]...
| call qword ptr ss:[rsp+58]              |  ## jumps directly to the start of that new decrypted code
```
By placing breakpoints on these dynamic `call qword ptr ss:[rsp+??] ` instructions, we intercepted the decrypted logic for each stage.

**call qword ptr ss:[rsp+58]:**
```asm
...[snip]...
| mov rax,qword ptr ds:[rdx+rax]          |
| movsx eax,byte ptr ds:[rax+rcx]         |
| cmp eax,57                              | 57:'W'
...[snip]...
| cmp eax,33                              | 33:'3'
...[snip]...
| cmp eax,33                              | 33:'3'
...[snip]...
| cmp eax,52                              | 52:'R'
...[snip]...
| cmp eax,52                              | 52:'R'
...[snip]...
| cmp eax,5F                              | 5F:'_'
```

By debugging the remaining two parts, I obtained the final flag: **`HTB{W3iRd_RUnT1m3_DEC}`**.
