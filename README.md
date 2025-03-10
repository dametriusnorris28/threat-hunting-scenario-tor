<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/dametriusnorris28/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor shopping list.txt` on the desktop at `22025-03-10T14:56:47.4941883Z`. These events began at `2025-03-10T14:07:20.2553831Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "dn-windows-10p"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-03-10T14:07:20.2553831Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1222" alt="Screenshot 2025-03-10 at 1 15 10 PM" src="https://github.com/user-attachments/assets/88da3ee2-d3cf-4e44-a6d9-b5d485cb7eaa" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.7.exe". Based on the logs returned, at `22025-03-10T14:17:45.625556Z`, an employee on the "dn-windows-10p" device ran the file `tor-browser-windows-x86_64-portable-14.0.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "dn-windows-10p"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1217" alt="Screenshot 2025-03-10 at 1 20 16 PM" src="https://github.com/user-attachments/assets/8aec926a-c6e8-4a7e-9b08-c7a67b19cc05" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-03-10T14:18:38.7930928Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "dn-windows-10p"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1223" alt="Screenshot 2025-03-10 at 1 22 22 PM" src="https://github.com/user-attachments/assets/cd8578ca-aca5-428b-9fb6-d31f8628cbe8" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-10T14:19:43.3867278Z`, an employee on the "dn-windows-10p" device successfully established a connection to the remote IP address `37.221.195.23` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "dn-windows-10p"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1221" alt="Screenshot 2025-03-10 at 1 25 06 PM" src="https://github.com/user-attachments/assets/244a1f36-81ff-4cbd-8296-45643ccf7e79" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-10T14:07:20.2553831Z`
- **Event:** The user "labuser" downloaded a file named "tor-browser-windows-x86_64-portable-14.0.7.exe" to the Downloads folder.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-10T14:17:45.0000000Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-10T14:18:09.0000000Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-10T14:19:43.3867278Z`
- **Event:** A network connection to IP `37.221.195.23` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-10T14:19:43.776876Z` - Connected to `95.216.33.30` on port `443`.
  - `2025-03-10T14:19:55.8710839Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-10T14:56:47.4941883Z`
- **Event:** The user "labuser" created a file named `tor shopping list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor shopping list.txt`

---

## Summary

The user "labuser" on the "dn-windows-10p" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor shopping list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `dn-windows-10p` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
