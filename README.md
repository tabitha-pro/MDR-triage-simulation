# MDR Triage Simulation & Threat Detection Lab

## 📌 Project Overview
This project simulates an end-to-end **MDR / SOC Threat Analyst** triage workflow on a Windows endpoint. It demonstrates endpoint telemetry logging via Sysmon, SIEM log ingestion into Splunk Enterprise, custom SPL detection query engineering, and incident response playbook formulation aligned with the **MITRE ATT&CK** framework.

---

## 🛠️ Environment & Architecture
* **Endpoint Machine:** Windows 11 Virtual Machine (`Lab-Windows-Vic`)
* **Telemetry Agent:** System Monitor (Sysmon v14+)
* **Log Ingestion:** Splunk Enterprise (Free License - 500 MB/day)
* **Log Source:** `WinEventLog:Microsoft-Windows-Sysmon/Operational` (Event ID 1 - Process Creation)

---

## 🚀 Threat Simulation
An adversary attempt to execute arbitrary commands while suppressing profile loading and bypassing default system execution policies was simulated using native Windows PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'MDR Simulation Test - Executing payload check'; Start-Sleep -Seconds 2"
MITRE ATT&CK Mapping:
T1059.001: Command and Scripting Interpreter: PowerShell

T1562.001: Impair Defenses: Disable or Modify Tools

🔍 Detection Engineering & Splunk Triage
SPL Detection Query
Splunk SPL
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" (CommandLine="*Bypass*" OR CommandLine="*NoProfile*")
| table _time host User ParentImage CommandLine ProcessId
| sort - _time
Telemetry Evidence & Triage Output
The query isolates process creation events, extracting critical forensic fields including parent-child execution hierarchy and explicit command-line flags:

📄 Documentation & Project Artifacts
📋 Incident Response Playbook: View the complete Tier 1 / Tier 2 triage workflow in Incident Response Playbook.md.

🔍 Splunk Queries: Find the full detection and threat hunting query collection in Splunk Queries.spl.

🖼️ Attack Execution Proof: View the endpoint terminal execution in attack-simulation-powershell.png.
