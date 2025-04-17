<p align="center">
  <img src="https://github.com/user-attachments/assets/1fdeab0f-54d0-40dd-a6e1-9a3fac3b5e5d" width="500">
</p>


# Exfiltration of Company Data
- [Scenario Creation](https://github.com/JordanDanielWest/Exfiltration-of-Company-Data/blob/main/Exfiltration%20of%20Company%20Data%20Event%20Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Powershell

##  Scenario: Unusual Outbound HTTP Traffic Detected from Non-Admin Workstation

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.


- **Check `DeviceProcessEvents`**
- **Check `DeviceFileEvents`**
- **Check `DeviceNetworkEvents`**

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I conducted search within MDE DeviceFileEvents for anyFileNames that end with ”.zip” file on the “edr-machine”

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "edr-machine"
| where Timestamp >= datetime(2025-04-15T14:11:46.5195615Z)
| where FileName endswith ".zip"
| sort by Timestamp desc

```
![image](https://github.com/user-attachments/assets/34229330-5f89-491b-8a44-597fe048d905)


---

### 2. Searched the `DeviceProcessEvents` Table

I took an instance of a zip file being created, copied the Timestamp and created a new query under DeviceProcessEvents and then observed two minutes after and two minutes before the archive was created. I discovered around the same time that a powershell script was used to install 7zip silently in the background which then collected and zipped employee data into an archive:
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1


**Query used to locate event:**

```kql

let VMName = "edr-machine";
let specificTime = datetime(2025-04-15T14:11:46.5195615Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/a52845f8-3dca-40eb-9ee7-3d088b7837c1)



---

### 3. Searched the `DeviceNetworkEvents` Table

I then conducted a query within Device Network events and discovered no indication of exfiltration of data from the network.
**Query used to locate events:**

```kql
let VMName = "edr-machine";
let specificTime = datetime(2025-04-10T17:13:21.3552555Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType


```



### Response:

Immediately isolated the system once archiving of files was discovered.
I relayed all of the information to the employee’s manager, including the information regarding the staging of zipped data into an archive created at regular intervals via powershell script. There was no clear evidence of exfiltration however I felt the situation was still suspicious enough to report as it seems to indicate staging of data T1074 – Data Staged of the MITRE ATT&CK framework.

### MITRE ATT&CK TTPs Identified
- **T1059 – Command and Scripting Interpreter**
  - *T1059.001 – PowerShell*  
	Use of PowerShell script (`exfiltratedata.ps1`) to automate tasks and bypass execution policies.
- **T1560 – Archive Collected Data**
  - *T1560.001 – Archive via Utility*  
	Zipping sensitive files using 7-Zip installed silently via script.
- **T1074 – Data Staged**  
Local staging of proprietary data into a ZIP file prior to potential exfiltration.
- **T1204 – User Execution** 
Script manually executed under suspicious conditions
- **T1105 – Ingress Tool Transfer** *(potential)*  
7-Zip installer was downloaded as part of the process



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-14T21:01:37.1940431Z`
- **Event:** The user "ds9-cisco" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\DS9-CISCO\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-14T21:04:58.6035812Z`
- **Event:** The user "ds9-cisco" executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`
- **File Path:** `C:\Users\DS9-CISCO\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-14T21:05:30.6659937Z`
- **Event:** User "ds9-cisco" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\DS9-CISCO\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-14T21:05:38.1904337Z`
- **Event:** A network connection to IP `194.147.140.107` on port `443` by user "ds9-cisco" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ds9-cisco\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-14T21:05:40.7830533Z` - Connected to `116.12.180.234` on port `443`.
  - `2025-04-14T21:06:46.2718388Z` - Local connection to `194.147.140.107` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ds9-cisco" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-14T21:18:38.2736577Z`
- **Event:** The user "ds9-cisco" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\DS9-CISCO\Desktop\tor-shopping-list.txt`

---

## Summary

The user "ds9-cisco" on the "edr-machine" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `edr-machine` by the user `ds9-cisco`. The device was isolated, and the user's direct manager was notified.

---# threat-hunting-scenario-tor# Exfiltration-of-Company-Data
