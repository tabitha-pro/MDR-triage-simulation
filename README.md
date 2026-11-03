
# MDR Triage Simulation & Threat Detection Lab

## 📌 Project Overview

This project simulates an end-to-end **Managed Detection and Response (MDR) / Security Operations Center (SOC)** threat detection and triage workflow within a Windows lab environment.

The lab demonstrates endpoint telemetry collection using Sysmon, centralized log ingestion into Splunk Enterprise, custom SPL detection engineering, and incident response playbook development aligned with the **MITRE ATT&CK** framework.

**Project Objectives:**
- Simulate suspicious PowerShell execution on a Windows endpoint.
- Capture and analyze process creation telemetry using Sysmon.
- Develop SPL queries to detect suspicious command-line arguments.
- Investigate endpoint activity through a structured SOC triage workflow.
- Document detection, escalation, containment, and remediation procedures.

---

## 🛠️ Environment & Architecture

| Component | Technology / Configuration |
|---|---|
| Endpoint | Windows 11 Virtual Machine (`Lab-Windows-Vic`) |
| Endpoint Telemetry | Microsoft Sysmon v14+ |
| SIEM Platform | Splunk Enterprise (Free License — 500 MB/day) |
| Log Source | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Primary Event | Sysmon Event ID 1 — Process Creation |
| Detection Language | Splunk Search Processing Language (SPL) |
| Threat Framework | MITRE ATT&CK |

### Detection Workflow

```text
Windows 11 Endpoint
        |
        v
Suspicious PowerShell Execution
        |
        v
Sysmon Event ID 1 (Process Creation)
        |
        v
Splunk Enterprise (Log Ingestion)
        |
        v
Custom SPL Detection Query
        |
        v
SOC Analyst Triage & Investigation
        |
        v
Incident Response Playbook
```

---

## 🚀 Threat Simulation

A controlled PowerShell execution was performed to simulate suspicious command-line behavior involving execution policy bypass and profile suppression.

The simulation uses native Windows PowerShell with the `-NoProfile` and `-ExecutionPolicy Bypass` arguments, which can appear in both legitimate administrative activity and malicious execution chains.

### PowerShell Simulation Command

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'MDR Simulation Test - Executing payload check'; Start-Sleep -Seconds 2"
```

**Simulation Behavior:**
- `-NoProfile` — Starts PowerShell without loading user profile scripts.
- `-ExecutionPolicy Bypass` — Bypasses PowerShell execution policy restrictions for the session.
- `-Command` — Executes the supplied PowerShell commands.
- `Start-Sleep` — Introduces a short execution delay.

**Note:** This is a benign simulation designed to generate observable endpoint telemetry. It does not execute a malicious payload, disable security tools, or establish persistence.

### MITRE ATT&CK Mapping

| Technique ID | Technique | Relevance |
|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Demonstrated through PowerShell execution |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Investigation consideration only; not demonstrated by this simulation |

---

## 🔍 Detection Engineering & Splunk Triage

### SPL Detection Query

The following SPL query identifies PowerShell process creation events containing execution policy bypass or profile suppression arguments.

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" (CommandLine="*Bypass*" OR CommandLine="*NoProfile*")
| table _time host User ParentImage CommandLine ProcessId
| sort - _time
```

### Detection Logic

The query performs the following operations:

1. Searches ingested Sysmon process creation events (`EventCode=1`).
2. Filters for PowerShell executable activity.
3. Identifies command lines containing `Bypass` or `NoProfile`.
4. Extracts relevant forensic fields for analyst investigation.
5. Sorts results chronologically, displaying the most recent events first.

### Telemetry Evidence & Triage Output

The detection query is designed to surface process creation telemetry, including:

- **Timestamp (`_time`):** Time of process execution.
- **Hostname (`host`):** Endpoint generating the event.
- **User (`User`):** Account responsible for execution.
- **Parent Process (`ParentImage`):** Process that initiated PowerShell.
- **Command Line (`CommandLine`):** Arguments and commands executed.
- **Process ID (`ProcessId`):** Identifier associated with the process.

These artifacts support initial alert validation, process context analysis, and escalation decisions.

---

## 📄 Documentation & Project Artifacts

| Artifact | Description |
|---|---|
| [Incident Response Playbook](Incident%20Response%20Playbook.md) | Tier 1 / Tier 2 investigation, escalation, containment, and remediation procedures |
| [Splunk Detection Queries](Splunk%20Queries.spl) | SPL detection and threat hunting queries |
| [PowerShell Simulation Evidence](attack-simulation-powershell.png) | Screenshot documenting the controlled PowerShell execution |

**Note:** Artifact links assume the referenced files are located in the repository root directory.

---

## 🎯 Skills Demonstrated

- MDR / SOC alert triage and investigation
- Windows endpoint security monitoring
- Sysmon telemetry collection and analysis
- Splunk SIEM log investigation
- SPL detection query development
- Suspicious PowerShell execution analysis
- MITRE ATT&CK technique mapping
- Incident response playbook development

---

## 📚 References

- [MITRE ATT&CK — PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)

---

**Disclaimer:** All threat simulations are conducted in an isolated, authorized lab environment for defensive security research, detection engineering, and incident response training.
