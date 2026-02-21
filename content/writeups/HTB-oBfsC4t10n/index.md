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