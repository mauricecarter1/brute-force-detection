# 🛡️ Brute Force Detection & Incident Response Project

## 📝 Description

This project simulates a brute force attack scenario and walks through the detection, alerting, and response process using Microsoft Defender for Endpoint (MDE), Microsoft Sentinel, PowerShell, and a single Windows 10 VM.

When a user attempts to log into the VM, the event is logged locally and sent to MDE via the `DeviceLogonEvents` table. These logs are then forwarded to Microsoft Sentinel via the Log Analytics Workspace.

---

## ⚙️ Part 1: Brute Force Detection (Alert Creation)

The KQL query designed to detect failed logon attempts from the same IP address to the same host at least 75 times within 5 hours.

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

---

## 🚨Part 2: Trigger Alert with PowerShell
Simulate brute force attempts using a script that triggers failed logon events. 

🧪 PowerShell Brute Force Simulation Script
```powershell
# Brute-Force-Simulation.ps1
# Simulates failed login attempts using ValidateCredentials() to trigger Windows Security Event ID 4625
# Intended for brute-force detection labs in Windows environments (e.g., Defender for Endpoint, Microsoft Sentinel)

<#
.NOTES
    Author: Maurice Carter
    LinkedIn: https://linkedin.com/in/cmcarter38
    GitHub: https://github.com/mauricecarter1
    Date Created: 2025-04-13
    Last Modified: 2025-04-13
  
#>

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Replace "2Phishing-Lab-MC" with the name of a valid local user account on your lab machine 
$TargetUsername = "2Phishing-Lab-MC"

$PasswordList = @("Password1", "123456", "admin", "letmein", "qwerty")

foreach ($password in $PasswordList) {
    Write-Host "Trying password: $password"

    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $env:COMPUTERNAME)
    $result = $context.ValidateCredentials($TargetUsername, $password)

    if ($result) {
        Write-Host "✅ Successful login with password: $password"
    } else {
        Write-Host "❌ Failed login recorded."
    }

    Start-Sleep -Seconds 2
}


```
---
## 🧯Part 3: Incident Response
Action taken in accordance with NIST 800-161: Incident Response Lifecycle: 

### 📌 Preparation
Incident response plan ready and VM onboarded to Microsoft Defender for Endpoint with Sentinel alert rule deployed.

### 🕵️ Detection & Analysis
Identified incident and used Action to assign investigation to myself and set status to active.

Investigated multiple IPs with brute force behavior:

218.92.0.187

194.180.48.85

196.251.84.225

1.194.210.131

185.7.214.81

14.103.132.101

### 🔍 Success Check Query
```kql
DeviceLogonEvents
| where RemoteIP in ("218.92.0.187", "194.180.48.85", "196.251.84.225", "1.194.210.131", "185.7.214.81", "14.103.132.101")
| where ActionType != "LogonFailed"
```
### ✅ No successful logons found — brute force attempts unsuccessful.
---
### 🔐 Containment, Eradication, and Recovery
- I isolated all affected devices in MDE to prevent any damage from spreading. 
- Conducted an antivirus search. 
- Updated Network Security Group (NSG) to prevent RDP attempts from public IPs by using Azure policy. 
- After isolation, and updating NSG, I took the machines out of isolation with no threats related to the incident. 
---

### 📊 Post-Incident Summary

There were 6 different IP addresses found with the brute force. The incident was marked as True Positive — brute force activity detected, but no system compromise occurred. All findings were documented and lessons learned recorded.

---

### 🧠 Lessons Learned
Early detection and automation helped mitigate risk

Sentinel rules can be tuned to different thresholds depending on the use case

PowerShell simulations are effective for testing alert logic

