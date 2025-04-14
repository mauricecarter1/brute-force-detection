# 🛡️ Brute Force Detection & Incident Response Project

## 📝 Description

This project simulates a brute force attack scenario and walks through the detection, alerting, and response process using Microsoft Defender for Endpoint (MDE), Microsoft Sentinel, PowerShell, and a single Windows 10 VM.

When a user attempts to log into the VM, the event is logged locally and sent to MDE via the `DeviceLogonEvents` table. These logs are then forwarded to Microsoft Sentinel via the Log Analytics Workspace.

---

## ⚙️ Part 1: Brute Force Detection (Alert Creation)

KQL query designed to detect failed logon attempts from the same IP address to the same host at least 75 times within 5 hours.

### 📄 KQL Query
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, ActionType, DeviceName
| where EventCount >= 75
| order by EventCount
```
---

### 📋 Analytics Rule Settings
✅ Enable rule

🧠 Set MITRE ATT&CK tactics

⏱️ Run every 4 hours

🕒 Query last 5 hours

🚨 Auto-create incident when triggered

🧩 Entity Mappings set for the Remote IP and DeviceNam

📦 Group alerts into a single incident per 24 hours

🔁 Stop query after alert is triggered (24h)

