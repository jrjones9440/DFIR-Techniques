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
1. Open both NTUSER.DAT_clean and SYSTEM_clean Hive in Registry Explorer (refer to 2. System Profiling and 3. NTUSER.DAT Analysis on how to create those hives if not present)
      - Launch **Registry Explorer**
      - Select **File → Load Hive**
      - Use CTRL-left-click to select both SYSTEM_clean and NTUSER.DAT_clean and click Open.
      - There should now be two registry hives open within Registry Explorer

📸 **Example Screenshot**

```markdown
![Registry Explorer - Two hives loaded](img/app_execution/01_two_hives_loaded.png)
```

---

## Step 2 — Investigate BAM (Background Activity Moderator)

### Registry Path (Example)
```
SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID-RID>
```

### What is BAM?
BAM is an acronym for the Background Activity Moderator, and the corresponding registry key maintains a simple list of applications executed and their **last execution time**.  Data is stored per user via sub-keys named for each account **security identifier / relative identifier (SID/RID)**

Example for RID 1002:
```
SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-528816539-567677750-276746561-1002
```

### Procedure
1. Navigate to the BAM key for the user account of interest. Example:
      - `SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-528816539-567677750-276746561-1002`
3. Sort entries by **Execution Time**
4. Sort the contents by Execution Time and review applications executed around the time of interest.
5. Document suspicious programs or applications.

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

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

### What is UserAssist?
UserAssist has long been a valuable Windows artifact for providing deep insight into application use. Because it is present in the NTUSER.DAT hive, all activity is directly tied to the account who owns that NTUSER.DAT. While UserAssist **typically only tracks GUI-based applications**, it provides a wealth of usage information difficult to get elsewhere such as:
   - Start Menu launches
   - Shortcut executions
   - Pinned taskbar items

UserAssist data is stored using ROT-13 encoding; Registry Explorer decodes this through a plugin.

### Key GUIDs of Interest
- **Executable file execution**
  - `CEBFF5CD-ACE2-4F4F-9178-9926F41749EA`
- **Shortcut file execution**
  - `F4E57C4B-2036-45F0-A9AB-443BCFE33D9F`

### Procedure
1. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\` key in Registry Explorer.
2. Notice a series of sub-keys in Globally Unique Identifier (GUID) format. Each GUID represents a different way application execution can be tracked by the operating system (whether something was opened via a shortcut, via the start-menu, via the Windows Universal Application "tiled" interface, etc.)
3. The two most commonly used GUIDs under UserAssist are:
      - `CEBFF5CD-ACE2-4F4F-9178-9926F41749EA` -> **Executable File Execution**
      - `F4E57C4B-2036-45F0-A9AB-443BCFE33D9F` -> **Shortcut File Execution**
4. Start with the GUID beginning with F4E57, and click its sub-key named Count to trigger the Registry Explorer plugin.
      - `...\UserAssist\{F4E57...}\Count`
5. Sort the output by Program Name.
6. Review the contents for items of interest such as what items were pinned to the user's taskbar?
7. Next move to the UserAssist GUID beginning with CEBFF, and click its sub-key named Count to trigger the Registry Explorer plugin.
      - `...\UserAssist\{CEBFF...}\Count`
8. Sort the output by **Last Executed** and document any suspicious entries.
9. Sort the output by **Focus Count**. This value represents the number of times that application was the primary window for the user. Items with a higher focus count often represent more commonly used applications for that user. Document what user applications have high focus count.
10. You can use these execution times to pivot to other artifacts, for example, if regedit.exe was executed at 2025-10-10:50:25 UTC search for registry keys with last write timestamps near that timestamp.
11. Use Ctrl-F (or Tools -> Find) to open the Registry Explorer search dialog.
12. Under Last write timestamp select Between and use the time frame of interest such as 2025-10-10:50:25 and 2025-10-10:55:25. Any results could indicate those registry keys may have been manipulated.

📸 **Example Screenshot**

```markdown
![Registry Explorer - UserAssist plugin output](img/app_execution/03_userassist.png)
```


📸 **Example Screenshot**

```markdown
![Registry Explorer - Find by timestamp window](img/app_execution/04_find_timestamp.png)
```

---

# Workflow – Prefetch (Execution Evidence)

## Step 4 — Investigate Prefetch with Win Prefetch View (GUI)

### What is Prefetch
Prefetch tracks **executed applications** from both the **GUI** and **command-line**, often making it even more comprehensive than other app execution artifacts (and providing an edge against attackers who utilize the command-line in an attempt to leave fewer artifacts)


### Procedure
1. Open **Win Prefetch View**
2. Win Prefetch View defaults to opening up the live system Prefetch, switch to the mounted triage image:
      - Select `Options` -> `Advanced Options`.
      - Browse to the mounted triage image Prefetch folder (such as E:\C\Windows\Prefetch).
      - Click OK
3. Review the entries and document any suspicious or noteworthy executions. The executable name will be the first part of the entry, the alphanumeric after the dash is based on where the executable ran from. Noteworthy execution examples are:
      - `TSTHEME.EXE-01D23267.pf` (executes on the system during incoming remote desktop protocol (RDP) sessions, it is a good indicator of incoming RDP to a computer)
      - `MSTSC.EXE-2B5707A7.pf` (used to engage outbound RDP connections from a system (basically the exact opposite of TSTHEME.exe)

📸 **Example Screenshot**

```markdown
![Win Prefetch View - Prefetch list](img/app_execution/05_winprefetchview.png)
```

---

## Step 5 — Prefetch Parsing with PECmd.exe (Command Line + Timelines)

This is a command-line based tool allowing fast and comprehensive parsing of large numbers of Prefetch files.

### 5A — Single Prefetch File Analysis

### Procedure
1.  Open an Administrator Command Prompt.
2.  Navigate to your evidence directory that contains the Prefetch file (this example will use `E:\C\Windows\prefetch and SDELETE.EXE-0E837E93.pf`)
3.  Execute
Command:
```powershell
PECmd.exe -f "E:\C\Windows\Prefetch\SDELETE.EXE-0E837E93.pf"
```
4. Review execution times and most importantly any interesting File References. The File References are any files that this executable touched within 10 seconds of running which can provide invaluable artifacts to expand your investigation. Document:
      - execution times
      - run count
      - **File References** (files touched within ~10 seconds of execution)

📸 **Example Screenshot**

```markdown
![PECmd - single file parse output](img/app_execution/06_pecmd_single.png)
```

### 5B — Bulk Prefetch Parsing (All Prefetch)

Run PECmd against every Prefetch file acquired from the system.

### Procedure
1.  Open an Administrator Command Prompt.
2.  To do this you will use the -d option to point at the Prefetch directory, the -q option for quiet-mode (less output), and --csv for the output location.
3.  Execute
Command:
```powershell
PECmd.exe -d "E:\C\Windows\Prefetch" -q --csv "G:\Evidence\Prefetch"
```
4. Open Timeline Explorer and open the resulting output file named `<Timestamp>_PECmd_Output_Timeline.csv`.
5. Sort the output by the **Run Time** column and review the PECmd timeline output.
6. This file has every execution recorded by Prefetch in chronological order. It can be very useful for seeing relationships between different tools and in profiling user actions on a system.
7. Filter the Executable Name column for any executions of interest to determine which locations they ran from.

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

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
```

### What is FeatureUsage
FeatureUsage tracks both application execution and an interesting set of data found nowhere else. The set of sub-keys under FeatureUsage track different activities occurring on the Windows task bar. It ties to the user activities like pinning an application and use of the application Jump Lists (application knowledge), number of times the shortcuts were used (execution count), number of times an application was put into focus, and clicks on other parts of the task bar like the system clock and search dialogs. While these artifacts are not necessarily comprehensive (they appear to be only tied to actions involving GUI applications and/or the task bar), they do give great insight into user interactions down to the click level.


📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage key](img/app_execution/08_featureusage_root.png)
```

---

### 6A — AppBadgeUpdated
**Tracks:** applications generating taskbar badge notifications

### Procedure
1. Navigate to the `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated` subkey in Registry Explorer.
2. Document:
      - Which application displayed the most number of new content alerts on the task bar.
      - Note browser profiles like `Chrome.UserData.Profile1` , this will be useful during Browser forensics.

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage AppBadgeUpdated](img/app_execution/09_featureusage_appbadgeupdated.png)
```

---

### 6B — AppLaunch
**Tracks:** taskbar-pinned application launches

### Procedure
1. Navigate to the `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch` subkey in Registry Explorer.
2. Applications listed in this key were pinned to the taskbar. Document:
      - interesting pinned apps
      - identify suspicious tools pinned to taskbar

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage AppLaunch](img/app_execution/10_featureusage_applaunch.png)
```

---

### 6C — AppSwitched
**Tracks:** application focus switching (in-focus activity)

### Procedure
1. Navigate to the `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched` subkey in Registry Explorer.
2. This subkey indicates application execution and how often applications were switched to the active window ("in focus").
3. There are typically many more entries in this key than AppLaunch since applications do not need to be pinned to the task bar to be tracked.
4. Document:
      - The top applications switched in focus
      - Suspicious items
   
📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage AppSwitched](img/app_execution/11_featureusage_appswitched.png)
```

---

### 6D — ShowJumpView
**Tracks:** number of right-clicks on running application icons to show Jump Lists

### Procedure
1. Navigate to the `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView` subkey in Registry Explorer.
2. Document:
      - Which Jump List was requested by the user the most number of times.

📸 **Example Screenshot**

```markdown
![Registry Explorer - FeatureUsage ShowJumpView](img/app_execution/12_featureusage_showjumpview.png)
```

---

### 6E — TrayButtonClicked
**Tracks:** the number clicks to many of the built-in tray applications (clock/search/network/etc.)

### Procedure
1. Navigate to the `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked` subkey in Registry Explorer.
2. Document:
      - Interesting tray interaction patterns.

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
