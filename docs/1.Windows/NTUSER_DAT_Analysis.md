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
      - Example: `E:\C\Users\user1\NTUSER.DAT`
4. If a **dirty hive** is detected, select **Yes**
5. Click **OK** to select the transaction logs to replay (skip if not prompted)
6. In the “Open” dialog box navigate to offline hive file (such as E:\C\Users\user1) and highlight ntuser.dat.LOG1 and ntuser.dat.LOG2 by holding the CTRL key and clicking the filenames with your mouse. Select Open. (skip if no dirty hive detected).
7. Click **OK** to replay transaction logs
8. Select the save location to the directory you are working in, naming it something like: `NTUSER.DAT_clean`
9. Select **Yes** when asked if you want to load the updated hive.
10. Select **No** when asked to load the dirty hive

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


### Procedure
1. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` in Registry Explorer.
2. Review the searches typed by the account in question and identify any suspicious search terms.
      - MRU, or Most Recently Used, position is in descending order, position 0 is the most recent search.
3. Document any searches with timestamps:
      - WordWheelQuery does not maintain timestamps for its values, it does have one timestamp, the last write time of the key itself.
      - Since the key contains a Most Recently Used (MRU) list, we know that the most recent search conducted is present in MRU position 0.
      - Hence that search was conducted at the time WordWheelQuery was last written.

📸 **Example Screenshot**

```markdown
![Registry Explorer - WordWheelQuery searches](img/ntuser_analysis/02_wordwheelquery.png)
```

### DFIR Notes
- MRU list is **descending**
- MRU position `0` is the most recent search
- Values **do not store timestamps**
- The key’s **LastWrite timestamp** indicates when the most recent search (MRU 0) occurred
  
---

## Step 3 — TypedPaths (Explorer Path Bar)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

### What it shows
Locations typed manually into the **Explorer address bar**.

### Procedure
1. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` key in Registry Explorer.
2. Document any suspicious entries:
      - Examples are:
         - `\\server\share`
         - removable drives (E:, F:)
         - staging folders (Temp, Downloads)
         - unusual admin shares (C$)
3. TypedPaths does not keep a MRU list, but does keep its entries in order by value name, thus the only timestamp that is available is for the most recent entry which is when the key was updated.

📸 **Example Screenshot**

```markdown
![Registry Explorer - TypedPaths](img/ntuser_analysis/03_typedpaths.png)
```

### DFIR Notes
- No MRU list
- Entries are ordered by **value name**
- Key **LastWrite** time reflects the most recent update (most recent entry)
  
---

## Step 4 — RecentDocs (Recent File Activity)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

### What it shows
Recently opened documents by extension type.

### Procedure
1. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` key in Registry Explorer.
2. Timestamps in the RecentDocs key are identified via MRU lists and the last write times of registry keys. Each key has a timestamp and thus each of the sub-keys of RecentDocs keeps the time of the last file of that type to be opened.
3. These "extra" timestamps are collected in the Registry Explorer Recent documents plugin in the Extension Last Opened column. By reviewing this column you can bookend the time periods within which multiple files were opened.
4. The RecentDocs key keeps the order of items opened via its MRU key.
5. For example, if **test.doc** was opened on **2025-10-10:50:25 UTC** and is MRU position 41, that means that the 40 items above it in the list were all opened **AFTER 2025-10-10:50:25 UTC**.
6. Review the Extension Last Opened column in Registry Explorer and identify the filenames opened around the timeframe of interest and document timestamps.
7. Document drive letters referenced within RecentDocs by looking at the Target Name:
      - You can search for interesting or sensitive files by searching within the Target Name field


📸 **Example Screenshot**

```markdown
![Registry Explorer - RecentDocs plugin view](img/ntuser_analysis/04_recentdocs.png)
```

### DFIR Notes
- Uses MRU lists and key LastWrite timestamps
- Subkeys store “extra timestamps”:
  - Each file-type subkey’s LastWrite = time the last file of that type was opened
- Registry Explorer plugin includes **Extension Last Opened** column
- MRU ordering helps **time bounding / bookending**
  - If item is MRU position 41 opened at time T, the 40 above it were opened **after T**
    
---

## Step 5 — Office File MRU (Full Paths + Timestamps)

### Registry Path (Example for Word 2016+)
```
NTUSER.DAT\Software\Microsoft\Office\16.0\Word\User MRU\ADAL_*\File MRU
```

> Note: The `ADAL_*` portion varies per user/environment. You may need to expand the tree to locate it. An example is `NTUSER.DAT\Software\Microsoft\Office\16.0\Word\User MRU\ ADAL_71509F4C9F29E24E25306165B32FE79B68FD54A88446B7C792A3A9D5AB6BB5AE\File MRU`

### What it shows
Office MRU provides:
   - Full path
   - Timestamps for every entry
   - Duration of access (Last Closed - Last Opened)

### Procedure
1. Navigate to the NTUSER.DAT\Software\Microsoft\Office\16.0\Word\User MRU\ ADAL_*\File MRU key in Registry Explorer.
2. Document what drive letters were used to open Office files of interest (like Word documents) during the timeframe of interest (C:, D:, E:, etc.).
4. What drive letters may be Cloud storage like Google Drive? Look for paths like:
      - `Google Drive`
      - `OneDrive`
      - `SharePoint`
5. Identify any sensitive files opened (work with the network owner) and how long they were opened for (subtract Last Closed from Last Opened timestamp).

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
Files and folders interacted with via Open/Save dialogs. Most of the files referenced in OpenSavePidlMRU are also present in RecentDocs. However, this is a good data source to review largely because it provides full path information not available in RecentDocs.

### Procedure
1. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` key in Registry Explorer.
2. Use the full path information available here in the Absolute Path column to look for suspicious or sensitive files opened.
3. Document any suspicious or sensitive files along with the full path.

📸 **Example Screenshot**

```markdown
![Registry Explorer - OpenSavePidlMRU absolute paths](img/ntuser_analysis/06_opensavepidlmru.png)
```

### DFIR Notes
- Often overlaps with RecentDocs
- Provides **full path info** in Registry Explorer plugin (Absolute Path column)
  
---

## Step 7 — LastVisitedPidlMRU (Executable Correlation)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
```

### What it shows
Associates the Open/Save dialog usage with the application executable responsible. 

### Procedure
1. Correlate OpenSavePidlMRU information with application information present in the LastVisitedPidlMRU key.
2. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` key in Registry Explorer.
3. Reference timestamps and the MRU position to attempt to identify the Executable responsible for interacting with the file in question.
4. Only entries with timestamp values in the Opened On column can be validated, others will need more correlating information.

📸 **Example Screenshot**

```markdown
![Registry Explorer - LastVisitedPidlMRU executable correlation](img/ntuser_analysis/07_lastvisitedpidlmru.png)
```

### DFIR Notes
- Some entries have timestamps in **Opened On**
- Only timestamped entries can be validated directly
- Use MRU order + correlation with OpenSavePidlMRU for weak attribution
  
---

## Step 8 — Run Key (User Persistence / Startup Items)

### Registry Path
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
```

### Why it matters
This key runs programs on every user logon and is the most common place for malware to add a reference to itself in an attempt to survive a reboot (commonly called a **persistence mechanism**).

### Procedure
1. In addition to helping discover potential malware, this key also gives an indication of applications installed by the user.
2. Navigate to the `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` key in Registry Explorer.
3. Document any suspicious entries such as:
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
      -`<timestamp>_RECmd_Batch_UserActivity_Output.csv`
5. In Timeline Explorer, reset columns:
      - `Tools → Reset column widths` (Ctrl+R is the keyboard shortcut)
6. Focus analysis on:
      - **Description**
      - **Key Path**
      - **Value Data**
7. Document interesting findings
8. Review other CSV outputs for individual keys discussed above.

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
