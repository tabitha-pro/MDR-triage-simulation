
# Incident Response Playbook: Suspicious PowerShell Execution with Policy Bypass

**Playbook ID:** `IR-PB-1059`  
**Severity:** Medium / High  
**Target Platform:** Windows Endpoints  
**Detection Source:** Splunk SIEM / Sysmon  
**Incident Category:** Suspicious Script Execution / Defense Evasion

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell execution potentially used to run unauthorized commands or scripts |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Potential defense impairment requiring additional evidence; execution policy bypass alone does not establish this technique |

---

## 1. Trigger & Detection Logic

### Overview

This playbook outlines the investigation and response procedures for suspicious PowerShell execution detected through Splunk.

The detection monitors **Sysmon Event ID 1 (Process Creation)** for PowerShell processes launched with command-line arguments commonly associated with execution policy bypass or modified execution environments.

Although these arguments can be used for legitimate administrative tasks, they may also appear in malicious scripts, unauthorized automation, or attacker-controlled execution chains.

### Detection Criteria

- **Event Source:** Sysmon Operational Logs
- **Event ID:** 1 — Process Creation
- **Process:** `powershell.exe`
- **Suspicious Arguments:**
  - `-ExecutionPolicy Bypass`
  - `-NoProfile`
  - `-EncodedCommand`

### SPL Detection Query

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe"
(CommandLine="*Bypass*" OR CommandLine="*NoProfile*")
| table _time host User ParentImage CommandLine ProcessId ProcessGuid
| sort - _time
```

**Detection Notes:**

- `-ExecutionPolicy Bypass` suppresses execution policy restrictions for the PowerShell session.
- `-NoProfile` prevents PowerShell profile scripts from loading and is frequently used in legitimate automation.
- These flags are not inherently malicious and require contextual investigation.
- The query above is the baseline detection; additional suspicious arguments should be evaluated during triage.

---

## 2. Initial Triage Checklist (Tier 1 Analyst)

**Target Response Time:** Within 15 minutes of alert generation.

The Tier 1 analyst is responsible for validating the alert, reviewing process execution artifacts, and determining whether escalation is necessary.

### 2.1 Analyze Event Artifacts

- [ ] **Verify Host Context:** Identify the affected endpoint using the `host` field.
- [ ] **Identify Account Context:** Determine whether execution occurred under a system, administrator, service, or standard user account.
- [ ] **Inspect Parent Process:** Review `ParentImage` to identify the process responsible for launching PowerShell.
- [ ] **Review Command-Line Arguments:** Examine the full `CommandLine` field for suspicious execution patterns.
- [ ] **Validate Execution Context:** Determine whether the activity aligns with expected administrative tasks or authorized automation.

### 2.2 Identify Suspicious Parent Processes

Pay particular attention to PowerShell executions initiated by:

| Parent Process | Potential Concern |
|---|---|
| `winword.exe` / `excel.exe` | Possible malicious Office document or macro execution |
| `chrome.exe` / `msedge.exe` | Unexpected browser-initiated script execution |
| `w3wp.exe` | Potential web application exploitation |
| `cmd.exe` | Requires review of the originating command and process chain |
| `explorer.exe` | Possible user-initiated execution; validate user activity |

**Red Flag:** Unexpected PowerShell execution originating from Office applications, browser processes, or web services should receive additional scrutiny.

### 2.3 Review Suspicious Command Patterns

Inspect the command line for:

**Encoded Execution**
- `-EncodedCommand`
- `-enc`
- Base64-encoded payloads

**Remote Content Retrieval**
- `Invoke-WebRequest`
- `DownloadString`
- `curl`
- `wget`

**Dynamic Command Execution**
- `IEX`
- `Invoke-Expression`

**Execution Policy Modification**
- `-ExecutionPolicy Bypass`
- `-ep bypass`

### 2.4 Initial Triage Decision

Escalate the alert to Tier 2 when one or more of the following conditions are identified:

- PowerShell execution cannot be attributed to an authorized activity.
- Suspicious encoded commands or remote script retrieval are observed.
- The parent process is inconsistent with normal endpoint activity.
- Network connections to suspicious or unrecognized destinations are detected.
- Additional evidence suggests persistence, credential access, or lateral movement.

---

## 3. Scoping & Investigation (Tier 2 / Threat Hunt)

The Tier 2 analyst performs additional investigation to determine the scope, impact, and potential intent of the PowerShell execution.

**Investigation Window:** 30 minutes before and after the initial detection.

### 3.1 Review Network Telemetry (Sysmon Event ID 3)

Determine whether the suspicious PowerShell process initiated network connections.

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 Image="*\\powershell.exe"
| table _time host User Image ProcessGuid DestinationIp DestinationPort
| sort - _time
```

**Investigation Objectives:**

- Identify outbound connections initiated by PowerShell.
- Review destination IP addresses and ports.
- Determine whether destinations are internal or external.
- Correlate network activity with the suspicious process using `ProcessGuid`.
- Investigate suspicious destinations using available threat intelligence.

**Note:** Sysmon Event ID 3 must be enabled in the endpoint's Sysmon configuration for this telemetry to be available.

### 3.2 Correlate Process Activity

Use `ProcessGuid` to correlate related Sysmon events and identify additional activity associated with the suspicious process.

Investigate:

- Parent-child process relationships
- Additional command execution
- File creation or modification
- Potential persistence mechanisms
- Related activity on other endpoints

### 3.3 Determine Incident Scope

- [ ] Confirm whether the suspicious process executed successfully.
- [ ] Identify any downloaded or dropped payloads.
- [ ] Determine whether additional endpoints exhibit similar behavior.
- [ ] Review related authentication or account activity.
- [ ] Document relevant indicators of compromise (IOCs).
- [ ] Determine whether the activity represents a confirmed security incident.

---

## 4. Response & Containment Workflow

Initiate containment when investigation confirms malicious or unauthorized activity, or when the assessed risk requires immediate intervention.

### 4.1 Endpoint Containment

**Affected Host:** `Lab-Windows-Vic`

- Isolate the affected endpoint using the available EDR/MDR platform.
- Preserve relevant logs and forensic evidence.
- Record the isolation timestamp and incident reference.

### 4.2 Process Termination

- Identify the malicious process using `ProcessId` and `ProcessGuid`.
- Confirm the process identity before termination.
- Terminate malicious processes using approved endpoint response tools.
- Review associated child processes for additional suspicious activity.

### 4.3 Identity Protection

**Account Under Investigation:** `LAB-WINDOWS-VIC\SOCAnalyst`

If credential theft or account compromise is suspected:

- Initiate the approved credential reset procedure.
- Revoke active sessions where supported.
- Review authentication activity for suspicious sign-ins.
- Investigate potential unauthorized account usage.

### 4.4 Remediation

- Remove confirmed malicious payloads and artifacts.
- Identify and eliminate unauthorized persistence mechanisms.
- Perform a full endpoint antivirus or EDR scan.
- Apply necessary security updates or configuration changes.
- Validate endpoint health before restoring normal network access.

---

## 5. Closure & Post-Incident Documentation

Once containment and remediation activities are complete, document the investigation findings and final disposition.

### 5.1 Incident Classification

Select the appropriate closure status:

- [ ] **True Positive:** Confirmed malicious or unauthorized activity.
- [ ] **False Positive:** Detection incorrectly matched the intended behavior or event.
- [ ] **Benign Positive:** Detection correctly identified the behavior, but the activity was authorized and non-malicious.

### 5.2 Root Cause Analysis (RCA)

Document:

- How the PowerShell command was initiated.
- The account and endpoint involved.
- The originating parent process.
- Any identified malicious commands or payloads.
- The observed impact and affected systems.
- Containment and remediation actions performed.

### 5.3 Detection Tuning Recommendations

If authorized administrative scripts regularly trigger this alert, consider:

- Reviewing known administrative automation and service accounts.
- Creating narrowly scoped exceptions for validated legitimate activity.
- Incorporating parent-process and command-line context into detection logic.
- Monitoring recurring suspicious execution patterns.
- Testing detection changes to ensure malicious activity remains visible.

**Important:** Avoid broad exclusions that could suppress legitimate security alerts.

---

## 6. Investigation Summary Template

| Field | Investigation Details |
|---|---|
| Incident ID | IR-PB-1059 |
| Detection Source | Splunk / Sysmon |
| Affected Host | Lab-Windows-Vic |
| Account | LAB-WINDOWS-VIC\SOCAnalyst |
| Event ID | Sysmon Event ID 1 |
| Suspicious Process | powershell.exe |
| Parent Process | Pending Investigation |
| Command Line | Pending Investigation |
| Network Activity | Pending Investigation |
| MITRE ATT&CK | T1059.001 / Potential T1562.001 |
| Incident Classification | Pending Investigation |
| Containment Status | Pending Investigation |
| Final Disposition | Pending Investigation |

---

## 7. References

- [MITRE ATT&CK — T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — T1562.001: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)

---

**Disclaimer:** This playbook is intended for security monitoring, incident response training, and authorized lab environments. Response actions should follow organizational incident handling procedures.
