# NTUSER.DAT Analysis (DFIR)

## Overview

The **NTUSER.DAT** registry hive contains **per-user configuration and activity artifacts** for a Windows profile. From a DFIR standpoint, NTUSER.DAT is one of the most valuable artifacts to:

- Identify **user intent** (searches, typed paths, recent documents)
- Recover evidence of **file access** and **data staging/exfil**
- Attribute actions to a specific user profile
- Detect **persistence mechanisms** (Run keys)
- Correlate activity with a timeframe of interest

This document provides a structured workflow for analyzing NTUSER.DAT using:

- **Registry Explorer** (interactive analysis)
- **RECmd.exe** (automation at scale)

---

## Artifact Location

**Registry Hive:** `NTUSER.DAT`  
**Typical Path:**  
`C:\Users\{user}\NTUSER.DAT`

Associated transaction logs (if present):
- `ntuser.dat.LOG1`
- `ntuser.dat.LOG2`

---

## Tools Used

- **Registry Explorer** (Eric Zimmerman)
- **RECmd.exe** + **Timeline Explorer** (Eric Zimmerman)

---

# Investigative Workflow – Registry Explorer

## Step 1 — Prep NTUSER.DAT Hive in Registry Explorer

### Procedure
1. Launch **Registry Explorer**
2. Select **File → Load Hive**
3. Browse to the offline hive file  
   Example: `E:\C\Users\user1\NTUSER.DAT`
4. If a **dirty hive** is detected, select **Yes**
5. Click **OK** to select the transaction logs to replay (skip if not prompted)
6. In the file selection dialog, navigate to:  
   `E:\C\Users\user1\`
7. Highlight `ntuser.dat.LOG1` and `ntuser.dat.LOG2` (CTRL + click) → **Open**
8. Click **OK** to replay transaction logs
9. Save cleaned hive as: `NTUSER.DAT_clean`
10. Select **Yes** to load the updated hive
11. Select **No** when asked to load the dirty hive

📸 **Example Screenshot**

```markdown
![Registry Explorer - Load NTUSER.DAT hive](img/ntuser_analysis/01_load_ntuser_hive.png)
```

---

## Step 2 — WordWheelQuery (Search Terms)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
```

### What it shows
Search terms typed into **Windows Search / Explorer search**.

### DFIR Notes
- MRU list is **descending**
- MRU position `0` is the most recent search
- Values **do not store timestamps**
- The key’s **LastWrite timestamp** indicates when the most recent search (MRU 0) occurred

### Task
- Identify suspicious search terms
- Document MRU order
- Document key LastWrite timestamp as the latest search time

📸 **Example Screenshot**

```markdown
![Registry Explorer - WordWheelQuery searches](img/ntuser_analysis/02_wordwheelquery.png)
```

---

## Step 3 — TypedPaths (Explorer Path Bar)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

### What it shows
Locations typed manually into the **Explorer address bar**.

### DFIR Notes
- No MRU list
- Entries are ordered by **value name**
- Key **LastWrite** time reflects the most recent update (most recent entry)

### Task
- Document suspicious paths such as:
  - `\\server\share`
  - removable drives (E:, F:)
  - staging folders (Temp, Downloads)
  - unusual admin shares (C$)

📸 **Example Screenshot**

```markdown
![Registry Explorer - TypedPaths](img/ntuser_analysis/03_typedpaths.png)
```

---

## Step 4 — RecentDocs (Recent File Activity)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

### What it shows
Recently opened documents by extension type.

### DFIR Notes
- Uses MRU lists and key LastWrite timestamps
- Subkeys store “extra timestamps”:
  - Each file-type subkey’s LastWrite = time the last file of that type was opened
- Registry Explorer plugin includes **Extension Last Opened** column
- MRU ordering helps **time bounding / bookending**
  - If item is MRU position 41 opened at time T, the 40 above it were opened **after T**

### Tasks
- Review **Extension Last Opened**
- Identify filenames around the timeframe of interest
- Record drive letters from **Target Name**
- Search Target Name for sensitive keywords

📸 **Example Screenshot**

```markdown
![Registry Explorer - RecentDocs plugin view](img/ntuser_analysis/04_recentdocs.png)
```

---

## Step 5 — Office File MRU (Full Paths + Timestamps)

### Registry Path (Example for Word 2016+)
```
NTUSER.DAT\Software\Microsoft\Office\16.0\Word\User MRU\ADAL_*\File MRU
```

> Note: The `ADAL_*` portion varies per user/environment. You may need to expand the tree to locate it.

### Why it matters
Office MRU provides:
- Full path
- Timestamps for every entry
- Duration of access (Last Closed - Last Opened)

### Tasks
- Document drive letters used (C:, D:, E:, etc.)
- Identify cloud storage indicators (examples):
  - `G:` mapped Google Drive / OneDrive sync folder
  - paths containing `Google Drive`, `OneDrive`, `SharePoint`
- Identify sensitive files and how long they were open

📸 **Example Screenshot**

```markdown
![Registry Explorer - Office Word File MRU](img/ntuser_analysis/05_office_file_mru.png)
```

---

## Step 6 — OpenSavePidlMRU (Open/Save Dialog Artifacts)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```

### What it shows
Files and folders interacted with via Open/Save dialogs.

### DFIR Notes
- Often overlaps with RecentDocs
- Provides **full path info** in Registry Explorer plugin (Absolute Path column)

### Task
- Identify suspicious sensitive files
- Identify staging activity (opening archives, scripts, etc.)

📸 **Example Screenshot**

```markdown
![Registry Explorer - OpenSavePidlMRU absolute paths](img/ntuser_analysis/06_opensavepidlmru.png)
```

---

## Step 7 — LastVisitedPidlMRU (Executable Correlation)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```

### What it shows
Associates the Open/Save dialog usage with the application executable responsible.

### DFIR Notes
- Some entries have timestamps in **Opened On**
- Only timestamped entries can be validated directly
- Use MRU order + correlation with OpenSavePidlMRU for weak attribution

### Task
- Identify executables linked to sensitive file interaction
- Correlate with OpenSavePidlMRU and timeframe

📸 **Example Screenshot**

```markdown
![Registry Explorer - LastVisitedPidlMRU executable correlation](img/ntuser_analysis/07_lastvisitedpidlmru.png)
```

---

## Step 8 — Run Key (User Persistence / Startup Items)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
```

### Why it matters
This key runs programs on every user logon and is a common **persistence mechanism**.

### Task
- Identify suspicious values such as:
  - executables in `AppData\Roaming`
  - scripts (`.vbs`, `.ps1`, `.js`, `.bat`)
  - references to Temp/Downloads
  - suspicious LOLBins (rundll32, regsvr32, mshta)

📸 **Example Screenshot**

```markdown
![Registry Explorer - Run key persistence](img/ntuser_analysis/08_run_key.png)
```

---

# Scaling Analysis – RECmd + Timeline Explorer

## Why scale?
Registry Explorer is excellent for investigative pivoting, but RECmd enables:
- bulk processing across many NTUSER.DAT hives
- consistent evidence extraction
- CSV outputs suited for timeline correlation

---

## Use the UserActivity.reb Batch File

This workflow assumes `UserActivity.reb` exists under the `Batch` directory in your RECmd install path.

### Steps

1. Open an **Administrator Command Prompt**
2. Navigate to RECmd install directory
3. Run RECmd with batch:

```powershell
RECmd.exe -f "E:\C\Users\user1\NTUSER.DAT" --bn .\Batch\UserActivity.reb --csv "G:\Evidence\Registry"
```

4. Open output file in **Timeline Explorer**:  
   `<timestamp>_RECmd_Batch_UserActivity_Output.csv`
5. In Timeline Explorer, reset columns:
   - `Tools → Reset column widths` (Ctrl+R)
6. Focus analysis on:
   - **Description**
   - **Key Path**
   - **Value Data**
7. Document interesting findings
8. Review other CSV outputs for individual keys

---

## Evidence Review Guidance (RECmd Output)

### Look for:
- unusual paths in `Value Data`
- references to:
  - `Temp`
  - `Downloads`
  - `AppData`
  - `\UNC\Paths`
  - external drive letters (E:, F:)
- suspicious keywords:
  - `password`
  - `vpn`
  - `putty`
  - `winscp`
  - `rclone`
  - `7zip`
  - `keylogger`
  - `powershell`

---

# Evidence to Document

## User Activity Summary

- Suspicious searches (WordWheelQuery)
- Suspicious typed locations (TypedPaths)
- Recent documents & extension timestamps (RecentDocs)
- Office file access (File MRU)
- Full path file access via dialog (OpenSavePidlMRU)
- Executable attribution (LastVisitedPidlMRU)
- Persistence artifacts (Run key)

---

## Recommended Deliverables

| Artifact | Key Path | Evidence |
|---|---|---|
| Search terms | WordWheelQuery | User intent + timeframe via LastWrite |
| Typed paths | TypedPaths | UNC paths, external drives, staging |
| Recent opened files | RecentDocs | Filenames, drive letters, time bounding |
| Office documents | Office File MRU | Full path + timestamps + open duration |
| Open/Save evidence | OpenSavePidlMRU | Full paths to sensitive/suspicious files |
| Executable correlation | LastVisitedPidlMRU | App attribution and MRU ordering |
| Persistence | Run | Logon execution artifacts |

---

## Analyst Notes / Pitfalls

- Many NTUSER artifacts are **MRU-based**, not timestamp-based
- Always document **key LastWrite time**
- Validate major conclusions using:
  - Event logs (Security 4624/4688)
  - Prefetch
  - SRUM
  - Jump Lists
  - File system timestamps
