---
title: "CDEF-SigmaPredator"
date: 2026-05-01
draft: false
summary: "An analysis of techniques used by attackers to clear Windows Event Logs, creating Sigma rules and using them to detect malicious activity"
tags:
  - Sigma
  - DFIR
  - Log Analysis
  - Windows
  - PowerShell
  - LOLBins
  - WMI
---
### <span class="hl">TL;DR</span>
I explored the primary methods used to wipe logs - including wevtutil.exe, wmic, Powershell cmdlets, direct .NET API calls, and physical .evtx file deletion. I also created Sigma rules to detect these evasion attempts and used Chainsaw wihh these rules against historical event logs.

   

### <span style="color:red">t1685.005</span>
#### <span class="hl">Who can clean logs?</span>
Not just any user can clear Windows Event Logs, performing this action requires high-level privileges. Only users with Administrator or SYSTEM privileges can clear event logs. That includes:  
\- **Local Administrators**  
\- **Domain Administrators**    
\- **The Local SYSTEM account** 
#### <span style="color:red">wevtutil</span>
*wevtutil.exe* is a legitimate, built-in Windows command-line utility used to retrieve information about event logs and publishers. However, it can be abused with: `cl` (clear-log) wipes all entries from a named log, `sl` (set-log) modifies log properties including disabling the log entirely with `/e:false`, and `el` (enum-logs) lists all available logs on the system.
```bash
wevtutil cl system
wevtutil cl security
wevtutil clear-log application
```
Detection must rely on process creation telemetry (security event id 4688 or sysmon event id 1) capturing the full command line, combined with parent process context and temporal correlation — log clearing shortly after lateral movement or privilege escalation is a strong indicator of malicious intent.

#### <span style="color:red">Powershell cmdlets</span>
**built-in cmdlets**  
PowerShell provides built-in cmdlets and .NET classes that can be used to manipulate or clear event logs.
* `Clear-EventLog`: Deletes all entries from specified classic log(s) | erases content
* `Remove-EventLog`: Deletes the entire log and unregisters event sources | most destructive 
```powershell
Clear-EventLog -LogName application, system -confirm
```
Both cmdlets are **detectable via** event id 4104, Module Logging, and process creation events. 

**.NET classes**  
Also **two .NET namespaces** expose log-clearing APIs that are callable from PowerShell without any additional tools or downloads. The first is `EventLogSession.ClearLog` from the System.Diagnostics.Eventing.Reader namespace. This method clears all events from a named log and can also target remote machines.
```powershell
# a local machine
[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog('Security')

# a remote machine
$session = New-Object System.Diagnostics.Eventing.Reader.EventLogSession("RemoteHost")
$session.ClearLog('Security')
```

The second is `EventLog.Clear` from the System.Diagnostics namespace. This method purges all entries from a classic EventLog instance and is accessible through several equivalent syntax forms:
```powershell
(New-Object System.Diagnostics.EventLog("System")).Clear()
# or 
[System.Diagnostics.EventLog]::new("Security").Clear()
```
Both methods leave characteristic string patterns in **event id 4104 ScriptBlockText**. In environments with PowerShell *Constrained Language Mode (CLM)* enforced, direct .NET type access is blocked, so these API calls would fail.

#### <span style="color:red">Log files</span>
Windows stores event log data as `.evtx` files on disk in the C:\Windows\System32\winevt\logs\ directory. Attackers with admin privileges may bypass command-line utilities and use file deletion commands Item

#### <span style="color:red">Wmic</span>
wmic, which is a LOLBin that wraps WMI functionality through a CLI interface, can also be abused to wipe logs using the *nteventlog* alias. By querying specific log files and invoking the clear method, attackers can wipe logs remotely or locally. 
```powershell
wmic nteventlog where "LogfileName='System'" call cleareventlog
```
Detection logic should look for process creation events where the image or new process name ends in `\wmic.exe` and the command line contains **nteventlog combined with cleareventlog** or the abbreviated cl.

#### <span style="color:red">Event ids</span>
When an attacker successfully clears an event log, Windows generates a final audit event to record the clearing action itself.
* Event id **104**: Generated in the System log whenever any other event log is cleared (System, Application, Windows PowerShell, etc.)
* Event id **1102**: Generated in the Security log specifically when the Security log is cleared.


### <span style="color:red">Analysis</span>
I wrote Sigma rules based on the theoretical data above, and I analyzed the historical event logs with **Chainsaw** using these Sigma rules.
![alt text](image-2.png)
![alt text](image-1.png)
![alt text](image-3.png)

The following commands were executed by the attacker:
```powershell
Clear-EventLog -LogName application, system -confirm
wevtutil  cl WitnessClientAdmin
wevtutil  cl Windows.Globalization/Analytic
wevtutil  cl Windows PowerShell
wevtutil  cl WINDOWS_WMPHOTO_CHANNEL
wevtutil  cl WINDOWS_KS_CHANNEL
wevtutil  cl UIManager_Channel
wevtutil  cl TabletPC_InputPanel_Channel/IHM
wevtutil  cl TabletPC_InputPanel_Channel
wevtutil  cl SystemEventsBroker
wevtutil  cl System
wevtutil  cl SmbWmiAnalytic
wevtutil  cl Setup
wevtutil  cl Security
wevtutil  cl RTWorkQueueTheading
wmic  nteventlog where "LogfileName='System'" cl
wmic  nteventlog where filename="security" cl
```

### <span style="color:red">Detection Rules</span>
#### Powershell ScriptBlock
```yaml
title: Detect Event Log Clearing via PowerShell ScriptBlock
id: 879f3bcc-acfb-467b-b002-8c4f18599d44
status: test
description: Detects attempts to clear Windows Event Logs using PowerShell cmdlets
    captured via ScriptBlock Logging (Event ID 4104).
references:
    - https://attack.mitre.org/techniques/T1070/001/
author: bubka
date: 2026-05-01
tags:
    - attack.t1685.005
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'Clear-EventLog'
            - 'Remove-EventLog'
            - 'wevtutil'
            - '[System.Diagnostics.EventLog]'
            - '[System.Diagnostics.Eventing]'
    condition: selection
falsepositives:
    - Legitimate administrative or maintenance scripts
    - Automated monitoring or housekeeping tasks
level: high
```
 
#### Process creation
```yaml
title: Detect Event Log Clearing via wevtutil (Process Creation)
id: bec2570d-f182-4b48-ab17-6c35f1b4bda4
status: test
description: Detects wevtutil usage to clear Windows Event Logs via process creation
    events (Sysmon EventID 1 or Security EventID 4688).
references:
    - https://attack.mitre.org/techniques/T1070/001/
author: bubka
date: 2026-05-01
tags:
    - attack.t1685.005
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|contains: 'wevtutil.exe'
        OriginalFileName: 'wevtutil.exe'
        CommandLine|contains:
            - 'clear-log'
            - 'cl'
    selection2:
        Image|contains: 'wmic.exe'
        OriginalFileName: 'wmic.exe'
        CommandLine|contains:
            - 'nteventlog'
    condition: selection1 or selection2
falsepositives:
    - Legitimate administrative or maintenance scripts
    - Automated monitoring or housekeeping tasks
level: high
```
 
#### Native event ids
```yaml
title: Detect Event Log Clearing
id: 54c48b69-e2a4-43b7-a3e0-f636bc814c28
status: test
description: Detects attempts to clear Windows Event Logs via Event Log Clearing events
    (Event ID 1102 or 104).
references:
    - https://attack.mitre.org/techniques/T1070/001/
author: bubka
date: 2026-05-01
tags:
    - attack.t1685.005
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID:
            - 1102
            - 104
    condition: selection
falsepositives:
    - Legitimate administrative or maintenance scripts
    - Automated monitoring or housekeeping tasks
level: high
```
