# Application Execution Analysis (DFIR)

## Overview

**Application Execution Analysis** focuses on identifying **what programs ran**, **when they ran**, **which user executed them**, and **what artifacts those programs touched** during execution.

This is essential for:
- Identifying attacker tooling (LOLBins, remote tools, dumpers, exfil tools)
- Correlating execution to the incident timeline
- Proving or disproving user involvement
- Pivoting to file, registry, and log artifacts tied to execution

This workflow uses:
- **Registry Explorer** (interactive analysis)
- **RECmd.exe** (automation)
- **Win Prefetch View** (GUI Prefetch review)
- **PECmd.exe** (bulk Prefetch parsing + timeline output)

---

## Primary Artifacts

### Registry Hives
- `C:\Users\{user}\NTUSER.DAT`
- `C:\Windows\System32\config\SYSTEM`

### Prefetch Files
- `C:\Windows\Prefetch\*.pf`

---

## Tools Used

- **Registry Explorer** (Eric Zimmerman)
- **RECmd.exe** (Eric Zimmerman)
- **Win Prefetch View** (NirSoft)
- **PECmd.exe** (Eric Zimmerman)
- **Timeline Explorer** (Eric Zimmerman)

---

# Workflow – Registry Explorer (NTUSER.DAT + SYSTEM)

## Step 1 — Load NTUSER.DAT_clean and SYSTEM_clean in Registry Explorer

### Goal
Load both hives at once so you can pivot between **user execution artifacts** and **system execution artifacts**.

### Procedure
1. Launch **Registry Explorer**
2. Select **File → Load Hive**
3. Use **CTRL + left click** to select both:
   - `SYSTEM_clean`
   - `NTUSER.DAT_clean`
4. Click **Open**
5. Verify two hives appear in the left navigation tree

📸 **Example Screenshot**

```markdown
![Registry Explorer - Two hives loaded](img/app_execution/01_two_hives_loaded.png)
```

---

## Step 2 — Investigate BAM (Background Activity Moderator)

### What is BAM?
BAM tracks executed applications and their **last execution time**. Entries are stored per-user using subkeys named by SID/RID.

### Registry Path (Example)
```
SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID-RID>
```

Example for RID 1002:
```
SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-528816539-567677750-276746561-1002
```

### Procedure
1. Navigate to the BAM key for the user account of interest
2. Sort entries by **Execution Time**
3. Review executions around timeframe of interest
4. Document suspicious programs

📸 **Example Screenshot**

```markdown
![Registry Explorer - BAM execution times](img/app_execution/02_bam_execution.png)
```

### DFIR Tips
Flag executions such as:
- `powershell.exe`, `cmd.exe`
- `rundll32.exe`, `regsvr32.exe`, `mshta.exe`
- `wmic.exe`, `certutil.exe`, `bitsadmin.exe`
- `procdump.exe`, `mimikatz.exe`, `rclone.exe`
- utilities from `Temp`/`Downloads`/`AppData`

---

## Step 3 — Investigate UserAssist (Deep GUI Execution Insight)

### What is UserAssist?
UserAssist is a per-user execution artifact tied to GUI interactions, including:
- Start Menu launches
- Shortcut executions
- Pinned taskbar items

UserAssist data is stored using ROT-13 encoding; Registry Explorer decodes this through a plugin.

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

### Key GUIDs of Interest
- **Executable file execution**
  - `CEBFF5CD-ACE2-4F4F-9178-9926F41749EA`
- **Shortcut file execution**
  - `F4E57C4B-2036-45F0-A9AB-443BCFE33D9F`

### Procedure
1. Navigate to:
   - `...\UserAssist\{F4E57...}\Count`
2. Sort output by **Program Name**
3. Identify pinned or commonly used applications
4. Next navigate to:
   - `...\UserAssist\{CEBFF...}\Count`
5. Sort by:
   - **Last Executed** (document suspicious tools)
   - **Focus Count** (high focus = heavily used apps)

📸 **Example Screenshot**

```markdown
![Registry Explorer - UserAssist plugin output](img/app_execution/03_userassist.png)
```

### Pivoting Technique (Registry Explorer Find)
If you find suspicious execution at a known time (example: regedit.exe at `2025-10-10 50:25 UTC`):
1. Press **Ctrl+F** (or Tools → Find)
2. Select **Last write timestamp**
3. Choose **Between**
4. Use a +-5 minute window:
   - Start: `2025-10-10 50:25`
   - End: `2025-10-10 55:25`
5. Review hits for keys likely modified around execution time

📸 **Example Screenshot**

```markdown
![Registry Explorer - Find by timestamp window](img/app_execution/04_find_timestamp.png)
```

---

# Workflow – Prefetch (Execution Evidence)

## Step 4 — Investigate Prefetch with Win Prefetch View (GUI)

### What Prefetch provides
Prefetch is one of the strongest sources for application execution, often capturing both:
- GUI executions
- Command-line executions

### Procedure
1. Open **Win Prefetch View**
2. Select:
   - **Options → Advanced Options**
3. Browse to mounted Prefetch directory (example):
   - `E:\C\Windows\Prefetch`
4. Click **OK** and review entries

📸 **Example Screenshot**

```markdown
![Win Prefetch View - Prefetch list](img/app_execution/05_winprefetchview.png)
```

### Key Prefetch Indicators
- `TSTHEME.EXE-*.pf`
  - often associated with **incoming RDP sessions**
- `MSTSC.EXE-*.pf`
  - indicates **outbound RDP** usage
- `WMIADAP.EXE`, `POWERSHELL.EXE`, `CMD.EXE`
- attacker tools staged in unusual paths

Document:
- suspicious executable names
- frequency of execution
- execution window around incident timeframe

---

## Step 5 — Prefetch Parsing with PECmd.exe (Command Line + Timelines)

### 5A — Single Prefetch File Analysis

Example target:
- `E:\C\Windows\Prefetch\SDELETE.EXE-0E837E93.pf`

Command:
```powershell
PECmd.exe -f "E:\C\Windows\Prefetch\SDELETE.EXE-0E837E93.pf"
```

Document:
- execution times
- run count
- **File References** (files touched within ~10 seconds of execution)

📸 **Example Screenshot**

```markdown
![PECmd - single file parse output](img/app_execution/06_pecmd_single.png)
```

### 5B — Bulk Prefetch Parsing (All Prefetch)

Command:
```powershell
PECmd.exe -d "E:\C\Windows\Prefetch" -q --csv "G:\Evidence\Prefetch"
```

Output file:
- `<Timestamp>_PECmd_Output_Timeline.csv`

Procedure:
1. Open output CSV in **Timeline Explorer**
2. Sort by **Run Time**
3. Review chronological execution list
4. Filter by **Executable Name** or keywords

📸 **Example Screenshot**

```markdown
![Timeline Explorer - PECmd timeline output](img/app_execution/07_timeline_explorer_pecmd.png)
```

### DFIR Tips
- Prefetch is ideal for spotting execution chains:
  - `WINWORD.EXE` → `POWERSHELL.EXE` → `RUNDLL32.EXE`
- File References enable rapid pivoting to:
  - payloads
  - dropped artifacts
  - accessed sensitive documents

---

# Workflow – Taskbar FeatureUsage (User Interaction Detail)

## Step 6 — Investigate FeatureUsage (Taskbar + Jump List Interaction)

### What FeatureUsage provides
FeatureUsage tracks taskbar and GUI interaction including:
- pinning applications
- app launch shortcuts
- focus switching
- Jump List right-click usage
- tray activity

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
```

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage key](img/app_execution/08_featureusage_root.png)
```

---

### 6A — AppBadgeUpdated
**Tracks:** applications generating taskbar badge notifications

Task:
- identify which app produced the most alerts
- note browser profiles like `Chrome.UserData.Profile1`

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage AppBadgeUpdated](img/app_execution/09_featureusage_appbadgeupdated.png)
```

---

### 6B — AppLaunch
**Tracks:** taskbar-pinned application launches

Task:
- document interesting pinned apps
- identify suspicious tools pinned to taskbar

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage AppLaunch](img/app_execution/10_featureusage_applaunch.png)
```

---

### 6C — AppSwitched
**Tracks:** application focus switching (in-focus activity)

Task:
- identify most frequently focused apps
- document suspicious items and top focus-switched entries

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage AppSwitched](img/app_execution/11_featureusage_appswitched.png)
```

---

### 6D — ShowJumpView
**Tracks:** number of Jump List right-clicks

Task:
- which Jump List was opened the most?

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage ShowJumpView](img/app_execution/12_featureusage_showjumpview.png)
```

---

### 6E — TrayButtonClicked
**Tracks:** tray item clicks (clock/search/network/etc.)

Task:
- document interesting tray interaction patterns

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage TrayButtonClicked](img/app_execution/13_featureusage_tray.png)
```

---

# Scaling Evidence Collection – RECmd.exe

## Recommended Approach
Use RECmd to scale extraction across many systems and profiles.

### Example RECmd Run (User Hives)
```powershell
RECmd.exe -f "E:\C\Users\user1\NTUSER.DAT" --bn .\Batch\UserActivity.reb --csv "G:\Evidence\Registry"
```

### Example RECmd Run (SYSTEM Hive)
```powershell
RECmd.exe -f "E:\C\Windows\System32\config\SYSTEM" --csv "G:\Evidence\Registry" --csvf SYSTEM_Execution.csv
```

### What to Focus On (Timeline Explorer)
- **Description**
- **Key Path**
- **Value Data**
- **LastWrite timestamps**

---

# Evidence to Document

## Execution Profile Summary

- **BAM executions** around incident timeframe
- **UserAssist** executions + Focus Count insights
- **Prefetch** executions (Win Prefetch View + PECmd)
- **File References** linked to suspicious programs
- **FeatureUsage**: pinned apps, focus switching, Jump List interaction
- Any **suspicious paths**:
  - `Temp`, `Downloads`, `AppData`
  - UNC paths
  - external drives

---

## Analyst Notes / Pitfalls

- UserAssist is GUI-focused; Prefetch captures both GUI + command-line (when enabled)
- Prefetch can be disabled in some environments or limited on servers
- BAM often provides clean “last execution” evidence but not full execution history
- Always correlate execution artifacts with:
  - Security log **4688** (process creation, if enabled)
  - Sysmon Event ID 1 (if deployed)
  - Amcache/SRUM
  - Shimcache
  - Jump Lists
