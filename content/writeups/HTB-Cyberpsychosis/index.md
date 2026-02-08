---
title: "HTB-Cyberpsychosis"
date: 2026-01-28
draft: false
tags:
  - Reverse Engineering
  - Linux
  - ELF
  - ida
  - rootkit
  - LKM
platform: reversing
---

{{< infobox platform="HackTheBox" difficulty="Easy" os="Linux" date="2026-01-28" >}}

**Description:**  
Static analysis on this program didn't reveal much. There must be a better way to approach this...

## <span style="color:red">initial analysis</span>

We're given a 64-bit ELF binary with a `.ko` extension (Kernel Object - a Linux Kernel Module).

```bash
$ file diamorphine.ko
diamorphine.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), 
BuildID[sha1]=e6a635e5bd8219ae93d2bc26574fff42dc4e1105, with debug_info, not stripped
```

## reversing  with IDA

Since this is a Linux Kernel Module, there's no standard `main` function. Instead, the entry point is the initialization function.

![Initialization Function](image.png)

The module manipulates the `cr0` register to grant the rootkit permission to write to read-only sections of memory where the system call table resides.

In the `sys_call_table`, the following system calls are hooked and replaced with malicious functions:  
\- `kill` → `hacked_kill`  
\- `getdents` → `hacked_getdents`  
\- `getdents64` → `hacked_getdents64`  


## *hacked_kill* func (priv esc and stealth)

When analyzing the `hacked_kill` function, we see it checks for signal code 64:

```c
else if ( (_DWORD)si == 64 )
{
    v9 = prepare_creds(pt_regs, a2, v2, di);
    // ... [snip] ...
```

The function calls `prepare_creds()`, which creates a new credential structure for the current process. The credential structure in Linux looks like this:

```c
struct cred {
    kuid_t uid;
    kgid_t gid;
    kuid_t euid;
    kgid_t egid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t fsuid;
    kgid_t fsgid;
    // ... [snip] ...
};
```

The rootkit then overwrites all credential values to 0 (root UID), granting the process root privileges:

```c
// ... [snip] ...
*(_QWORD *)(v9 + 4) = 0;
*(_QWORD *)(v9 + 12) = 0;
*(_QWORD *)(v9 + 20) = 0;
*(_QWORD *)(v9 + 28) = 0;
commit_creds(v9);
return 0;
```

The rootkit can hide itself from the module list by manipulating the doubly-linked list when receiving signal code 46:

```c
if ( (_DWORD)si == 46 )
{
    if ( !module_hidden )
    {
        prev = _this_module.list.prev;
        next = _this_module.list.next;
        v6 = 0;
        next->prev = prev;
        module_previous = prev;
        prev->next = next;
        // ... [snip] ...
        module_hidden = 1;
        return v6;
    }
```
It can also unhide itself


## *hacked_getdents* func

this function first calls the original `getdents` and creates a buffer containing a copy of the directory listing (`linux_dirent` struct).

It then searches for entries containing the string "psychosis" (represented as hex `0x69736F6863797370` + character `115`):

```c
if ( *(_QWORD *)(v12 + 18) != 0x69736F6863797370LL || 
     *((_BYTE *)buffer + v11 + 26) != 115 )
     // ... [snip] ...
```

If found, the entry is removed from the buffer, hiding any files/directories with "psychosis" in their name from `ls` and similar tools.

## exploitation 

With the rootkit analysis complete, I proceeded to exploit and remove it from the compromised system:

1. escalate to root: `kill -64 $$`
2. unhide the module: `kill -46 $$`
3. remove the rootkit: `rmmod diamorphine` (found in `/sys/module/`)
4. find hidden file:

```bash
# find / -name "psychosis*" 2>/dev/null
/opt/psychosis

# cat /opt/psychosis/flag.txt
HTB{N0w_Y0u_C4n_S33_m3_4nd_th3_r00tk1t_h4s_b33n_sUcc3ssfully_d3f34t3d!!}
```
