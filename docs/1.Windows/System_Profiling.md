# System Profiling (DFIR)

## Overview

**System Profiling** is a foundational DFIR task used to understand the **baseline characteristics of a Windows system**.  
This information provides critical context for timeline analysis, anomaly detection, and incident scoping.

Through analysis of the **SYSTEM** and **SOFTWARE** registry hives, investigators can determine:

- System identity and configuration
- Operating system version and update history
- Timezone configuration
- Shutdown and reboot activity
- Network history (wired, wireless, VPN)
- Installed applications (including suspicious software)

---

## Registry Artifacts

### SYSTEM Hive
**Path:**  
`C:\Windows\System32\config\SYSTEM`

### SOFTWARE Hive
**Path:**  
`C:\Windows\System32\config\SOFTWARE`

---

## Tools Used

- **Registry Explorer** (Eric Zimmerman)
- **RECmd.exe** (Eric Zimmerman)

---

# Investigative Steps – SYSTEM Hive

## Step 1 — Prep SYSTEM Hive in Registry Explorer

### Procedure
1. Launch **Registry Explorer**
2. Select **File → Load Hive**
3. Browse to the offline SYSTEM hive  
   Example: `E:\C\Windows\System32\config\SYSTEM`
4. If a **dirty hive** is detected, select **Yes**
5. Click **OK** to select transaction logs (skip if not prompted)
6. Highlight `SYSTEM.LOG1` and `SYSTEM.LOG2` (CTRL + click) and select **Open**
7. Click **OK** to replay transaction logs
8. Save the cleaned hive (example: `SYSTEM_clean`)
9. Select **Yes** to load the updated hive
10. Select **No** when prompted to load the dirty hive

📸 **Example Screenshot**

```markdown
![Registry Explorer - Load SYSTEM hive](img/system_profiling/01_load_system_hive.png)
```

---

## Step 2 — Identify the CurrentControlSet

### Registry Path
```
SYSTEM\Select
```

### Task
Identify the value of **Current**, which determines the active control set.

📸 **Example Screenshot**

```markdown
![Registry Explorer - SYSTEM Select key](img/system_profiling/02_currentcontrolset.png)
```

**Example Interpretation**
- `Current = 1` → `CurrentControlSet = ControlSet001`

---

## Step 3 — Identify the Computer Name

### Registry Path
```
SYSTEM\<CurrentControlSet>\Control\ComputerName\ComputerName
```

### Task
Document the **ComputerName** of the system.

📸 **Example Screenshot**

```markdown
![Registry Explorer - ComputerName](img/system_profiling/03_computername.png)
```

---

## Step 4 — Determine the System Timezone

### Registry Path
```
SYSTEM\<CurrentControlSet>\Control\TimeZoneInformation
```

### Task
Document the timezone the system was last set to.

📸 **Example Screenshot**

```markdown
![Registry Explorer - TimeZoneInformation](img/system_profiling/04_timezone.png)
```

**DFIR Significance**
- Timezone is critical for **timeline normalization**
- Prevents misinterpretation of event log and registry timestamps

---

## Step 5 — Last Shutdown / Reboot Time

### Registry Path
```
SYSTEM\<CurrentControlSet>\Control\Windows
```

### Task
- Identify timestamp values stored as **Windows FILETIME**
- Right-click the value → **Data Interpreter**
- Convert to human-readable time
- Document the **last shutdown or reboot**

📸 **Example Screenshot**

```markdown
![Registry Explorer - Last shutdown time](img/system_profiling/05_last_shutdown.png)
```

---

## Step 6 — Network Interface Profiling

### Registry Path
```
SYSTEM\<CurrentControlSet>\Services\Tcpip\Parameters\Interfaces
```

### Task
Review network interface subkeys and document:
- `DhcpDomain`
- Interfaces associated with unusual or suspicious networks

📸 **Example Screenshot**

```markdown
![Registry Explorer - Network interfaces](img/system_profiling/06_network_interfaces.png)
```

**DFIR Notes**
- Interfaces may persist long after a network is no longer used
- Useful for identifying corporate vs. home vs. attacker infrastructure

---

# Investigative Steps – SOFTWARE Hive

## Step 1 — Prep SOFTWARE Hive in Registry Explorer

### Procedure
1. Launch **Registry Explorer**
2. Select **File → Load Hive**
3. Browse to: `E:\C\Windows\System32\config\SOFTWARE`
4. If dirty hive detected, select **Yes**
5. Select `SOFTWARE.LOG1` and `SOFTWARE.LOG2`
6. Replay transaction logs
7. Save cleaned hive as `SOFTWARE_clean`
8. Load the updated hive
9. Do **not** load the dirty hive

📸 **Example Screenshot**

```markdown
![Registry Explorer - Load SOFTWARE hive](img/system_profiling/07_load_software_hive.png)
```

---

## Step 2 — OS Version & Install Information

### Registry Path
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion
```

### Task
Document:
   - Windows Version
   - RegisteredOwner
   - ReleaseID
   - CurrentBuild
   - InstallTime (convert using Data Interpreter)

📸 **Example Screenshot**

```markdown
![Registry Explorer - OS version info](img/system_profiling/08_os_version.png)
```

> ⚠️ **Important Interpretation Note**  
>  Be careful with your interpretation of "InstallTime". This value could be the time the OS was first installed, but more commonly represents the last major update of the system. Starting with Windows 10, Microsoft began releasing frequent major version updates and hence this time typically represents the last update.  This information will be very helpful as you will notice many timestamps set to around this time, indicating the update, not user activity was responsible.

---

## Step 3 — Previous Windows Versions

### Registry Path
```
SYSTEM\Setup\Source OS
```

### Task
Document:
   - Number of previous OS versions
   - ReleaseID and CurrentBuild of previous OS
   - InstallTime (human-readable)

📸 **Example Screenshot**

```markdown
![Registry Explorer - Source OS](img/system_profiling/09_source_os.png)
```

---

## Step 4 — Network History (Known Networks)

### Registry Path
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
```

### Procedure
- Open the **Known Networks** tab in Registry Explorer

### Task
Document:
   - Wireless networks
      - First Connect time
      - Last Connected time
   - Likely **non-managed networks** (home/public)
      - First Connect time
      - Last Connected time
   - WWAN (VPN) networks
      - First Connect time
      - Last Connected time
        
📸 **Example Screenshot**

```markdown
![Registry Explorer - Known Networks](img/system_profiling/10_known_networks.png)
```

---

## Step 5 — Managed Network Identification

### Registry Path
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures
```

### Task
Document which networks are marked as **Managed** (typically domain/corporate).

📸 **Example Screenshot**

```markdown
![Registry Explorer - Network signatures](img/system_profiling/11_network_signatures.png)
```

---

## Step 6 — Installed 64-bit Applications

### Registry Path
```
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

### Task
Document:
   - Web browsers
   - Security tools
   - Suspicious software
   - Install paths from `TEMP` or `Downloads`

📸 **Example Screenshot**

```markdown
![Registry Explorer - 64-bit applications](img/system_profiling/12_installed_apps_64.png)
```

---

## Step 7 — Installed 32-bit Applications

### Registry Path
```
SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
```

### Task
Document:
   - Security tools
   - Suspicious software
   - Install paths from `TEMP` or `Downloads`

📸 **Example Screenshot**

```markdown
![Registry Explorer - 32-bit applications](img/system_profiling/13_installed_apps_32.png)
```

---

# RECmd.exe Automation (System Profiling at Scale)

## Example RECmd Execution

```powershell
RECmd.exe -f "C:\Cases\Hives\SYSTEM" --csv "C:\Cases\Output\RECmd" --csvf SYSTEM_Profile.csv
RECmd.exe -f "C:\Cases\Hives\SOFTWARE" --csv "C:\Cases\Output\RECmd" --csvf SOFTWARE_Profile.csv
```

---

## Example RECmd .reb (Snippet)

```xml
<RegistryExplorerBatch>
  <RegistryKey>
    <HivePath>%%hivepath%%</HivePath>
    <KeyPath>SYSTEM\Select</KeyPath>
    <Comment>Determine CurrentControlSet</Comment>
  </RegistryKey>

  <RegistryKey>
    <HivePath>%%hivepath%%</HivePath>
    <KeyPath>SYSTEM\ControlSet001\Control\ComputerName\ComputerName</KeyPath>
    <Comment>System Computer Name</Comment>
  </RegistryKey>

  <RegistryKey>
    <HivePath>%%hivepath%%</HivePath>
    <KeyPath>SOFTWARE\Microsoft\Windows NT\CurrentVersion</KeyPath>
    <Comment>OS Version and Install Info</Comment>
  </RegistryKey>
</RegistryExplorerBatch>
```

---

# Evidence to Document

## System Profile Summary

- **System Name**
- **Operating System**
- **Install / Last Major Update Time**
- **Timezone**
- **Last Shutdown / Reboot Time**
- **Interesting Networks**
- **VPN / WWAN Activity**
- **Suspicious Installed Applications**

---

## Analyst Notes

- Many timestamps align with **feature updates**, not user activity
- Network artifacts persist long after disconnection
- Always correlate with:
     - Event Logs
     - Prefetch
     - SRUM
     - Firewall logs
     - VPN client logs
