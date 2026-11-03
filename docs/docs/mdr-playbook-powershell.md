# Incident Response Playbook: Suspicious PowerShell Execution with Policy Bypass

**Playbook ID:** `IR-PB-1059`  
**Severity:** Medium / High  
**Target Platform:** Windows Endpoints  
**Primary MITRE ATT&CK Mapping:**  
* **T1059.001:** Command and Scripting Interpreter: PowerShell  
* **T1562.001:** Impair Defenses: Disable or Modify Tools  

---

## 1. Trigger & Detection Logic

This playbook is triggered when Splunk detects a process creation event (Sysmon Event ID 1) where `powershell.exe` is invoked with execution policy suppression or bypass flags.

### SPL Detection Query
```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" (CommandLine="*Bypass*" OR CommandLine="*NoProfile*")
| table _time host User ParentImage CommandLine ProcessId
| sort - _time
2. Initial Triage Checklist (Tier 1 Analyst)
When this alert fires, perform the following triage steps within 15 minutes:

Step 2.1: Analyze Event Artifacts
[ ] Verify Host Context: Identify the endpoint hostname (host).

[ ] Identify Account Context: Determine if the execution was run under a system, administrator, or standard user account (User).

[ ] Inspect Parent Process: Identify ParentImage (e.g., cmd.exe, explorer.exe, or service process).

Red Flag: PowerShell spawned by a browser, MS Office application, or web service (w3wp.exe).

[ ] Evaluate Command Line Arguments: Review the exact payload string in CommandLine:

Look for encoded strings (-EncodedCommand, -e, base64 strings).

Look for remote downloads (Invoke-WebRequest, DownloadString, curl, wget).

Look for unquoted expression execution (IEX, Invoke-Expression).

3. Scoping & Investigation (Tier 2 / Threat Hunt)
Execute secondary Splunk searches to evaluate downstream activity within a +/- 30-minute window:

3.1 Check Network Telemetry (Sysmon Event ID 3)
Determine if the spawned PowerShell process initiated external network connections:
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 Image="*\\powershell.exe"
| table _time host User Image DestinationIp DestinationPort

3.2 Check File Creation Telemetry (Sysmon Event ID 11)
Determine if PowerShell dropped any secondary scripts or executable files:
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 Image="*\\powershell.exe"
| table _time host User TargetFilename

4. Response & Containment Workflow
If the investigation confirms unauthorized, unexpected, or malicious PowerShell activity:

Network Containment: Isolate the affected host (Lab-Windows-Vic) via EDR/MDR agent.

Process Termination: Kill the active process ID (ProcessId) associated with the execution.

Identity Protection: Force password reset and revoke active sessions for LAB-WINDOWS-VIC\SOCAnalyst if credential theft is suspected.

Remediation: Remove dropped payloads, persistence mechanisms, and perform full endpoint AV scan.

5. Closure & Post-Incident Documentation
Closure Status: True Positive / False Positive / Benign Positive

Root Cause Analysis (RCA): Document how the command was initiated.

Tuning Recommendations: If authorized administrative scripts regularly trigger this alert, consider tuning the detection query by whitelisting specific parent paths or service accounts.

