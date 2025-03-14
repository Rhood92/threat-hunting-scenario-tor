<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Rhood92/threat-hunting-scenario-tor-threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like user “labuserich” downloaded a tor installer. This resulted in many Tor-related things showing in the timestamps, and the user ultimately created a file name “tor-shopping-list.txt” on the desktop. These events began at 2025-03-14T15:06:01.9301058Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "rich-mde-test"
| where FileName contains "tor" or FileName contains "firefox"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc 
| where Timestamp >= datetime(2025-03-14T15:06:01.9301058Z)
```
![image](https://github.com/user-attachments/assets/001b1012-32db-4969-bc61-b132218f828a)

![image](https://github.com/user-attachments/assets/9563c024-0306-46b1-b26b-86f91441e1f3)



---

### 2. Searched the `DeviceProcessEvents` Table

After searching, DeviceProcessEvents discovered that at 11:08 AM on March 14, 2025, a process was created on the device "rich-mde-test". The user "labuserich" executed a file named "tor-browser-windows-x86_64-portable-14.0.7.exe" from the Downloads folder. This execution was initiated by Command Prompt (cmd.exe) from the Windows System32 directory, suggesting it was either manually run via command line or executed as part of a script or automated process. The Tor Browser installer was launched with the "/S" (silent install) flag, indicating an attempt to install it without user prompts.

**Query used to locate event:**

```kql
Query Used: 
DeviceProcessEvents
| where DeviceName == "rich-mde-test"
| where FileName contains "tor" or FileName contains "firefox"
| project Timestamp, DeviceName, ActionType, FileName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

With the same query above, I also noticed that at 11:09 AM on March 14, 2025, on the device "rich-mde-test", the user "labuserich" launched Firefox.exe from within the Tor Browser directory located on their Desktop. This indicates that the Tor Browser was started.


The process was initiated by Windows Explorer (explorer.exe), suggesting that the user likely manually opened the Tor Browser by double-clicking its icon rather than running it via the command line or script.

![image](https://github.com/user-attachments/assets/a7491a6b-dc20-4a80-b226-58aee9a95d1d)

![image](https://github.com/user-attachments/assets/85c0ab5e-fe7a-48ef-b65c-d0a2c666b031)

---

### 3. Searched the `DeviceNetworkEvents` Table for TOR Browser Execution and Connections

After searching DeviceNetworkEvents, I discovered that at 11:10:43 AM on March 14, 2025, on the device "rich-mde-test", the user "labuserich" launched the Tor Browser, and it began listening for incoming connections. Over the next several seconds, multiple successful network connections were established by the Tor process (tor.exe) and its embedded Firefox browser.


9150 & 9100 – These are SOCKS proxy ports used by Tor for anonymized network traffic.


143 & 11154 – These ports could be used for additional connections within the Tor circuit.


Here is a list of all the standard TOR ports: 9001, 9003, 9030, 9050, 9051, 9100, 9101, 9150, 9151, 9200


**Query used to locate events:**

```kql
Query Used: 
DeviceNetworkEvents
| where DeviceName == "rich-mde-test"
| where InitiatingProcessFolderPath contains "tor"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, RemotePort, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/f318c05b-6d55-40e4-a90d-d1484126ad92)

![image](https://github.com/user-attachments/assets/922d23ea-4217-412e-8446-c7bab65c926d)

---

## Chronological Event Timeline 

## 📌 Detailed Summary

### 1⃣ Initial Download and File Creation
- **11:06 AM**: The user **downloaded** the Tor Browser installer and later **renamed** it in the **Downloads folder**.
- **11:07 AM**: The user **created** a file named **"tor-shopping-list.txt"** on the **Desktop**, suggesting some form of **planning or note-taking**.

---

### 2⃣ Installation and Execution
- **11:08 AM**: The **Tor Browser installer was executed silently** via **Command Prompt (cmd.exe)** using the `/S` flag.  
  ⚠️ *This means the user intentionally installed Tor Browser without user prompts—possibly to avoid detection.*

- **11:09 AM**: The **Tor Browser (`firefox.exe`) was launched manually** using **Windows Explorer**, confirming **active user interaction**.

---

### 3⃣ Network Activity and Anonymization
- **11:10:43 AM**: The **Tor process (`tor.exe`) started listening** for **incoming connections**.

- Over the next several seconds, the **Tor network successfully connected to multiple ports**:
  - **Port 9150 & 9100** → SOCKS Proxy for **anonymized traffic**.
  - **Port 443 (HTTPS)** → Likely connecting to **Tor relays**.
  - **Port 143 & 11154** → Additional connections **possibly forming a Tor circuit**.

- **11:10:57 AM**: `firefox.exe` (Tor Browser) **connected via the SOCKS proxy on port 9150**, confirming the user was **actively browsing the web through the Tor network**.

---

### 4⃣ User Modification of "tor-shopping-list.txt"
- **11:23 AM**: The user **modified** `tor-shopping-list.txt`, which changed its **SHA-256 hash**.
  ⚠️ *This suggests that the user updated the contents, possibly documenting steps, websites, or other notes related to Tor usage.*


---

## Summary

## 🚨 Final Assessment

- ✅ **Confirmed Intentional Tor Browser Usage** – The user **actively downloaded, installed, and launched** Tor Browser.
- ✅ **Successful Anonymized Network Activity** – The **Tor process established connections** and **routed traffic through SOCKS proxy (9150)**.
- ✅ **Possible Planning Activity** – The presence of **"tor-shopping-list.txt"** suggests **some form of preparation related to Tor usage**.

---

## 📢 Conclusion
The user **"labuserich"** performed a **structured sequence of actions** to **install, configure, and use Tor Browser** with **anonymized browsing enabled**. 

🚨 *Given the silent installation and file modifications, this may warrant further investigation into the intent and potential misuse of Tor services.*

---

## 🔍 Potential Next Steps
- **Check for additional file modifications** after `tor-shopping-list.txt` was updated.
- **Analyze outbound connections** to confirm whether the user accessed any **known Onion services**.
- **Monitor further activity** on `rich-mde-test` to determine if **Tor is used persistently**.
  
---

## Response Taken

TOR usage was confirmed on the endpoint rich-mde-test by the user labuserich. The device was isolated, and the user's direct manager was notified.

---
