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

---

## 🚨Part 2: Trigger Alert with PowerShell
I simulate brute force attempts using a script that triggers failed logon events on the local machine.

🧪 PowerShell Simulation Script
```powershell
# Simulate failed logon attempts to a local user account
# Replace "2Phishing-Lab-MC" with a real local account on your VM

$TargetUsername = "2Phishing-Lab-MC"
$PasswordList = @("Password1", "123456", "admin", "letmein", "qwerty")

foreach ($password in $PasswordList) {
    Write-Host "Attempting login with password: $password"
    
    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($TargetUsername, $securePassword)

        # Attempt to trigger a failed login
        Invoke-Command -ComputerName localhost -ScriptBlock { Get-Service } -Credential $cred -ErrorAction Stop
    } catch {
        Write-Host "Failed login attempt recorded."
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

🔍 Success Check Query

