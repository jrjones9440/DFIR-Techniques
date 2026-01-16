# Cloud Storage Forensics – OneDrive (DFIR)

## Overview

OneDrive (Personal and Business) is a common avenue for:
- **data staging and exfiltration**
- **unauthorized access via shared links**
- **cloud-only file persistence**
- **sync-based data compromise** (SharePoint / Teams libraries)

This MKDoc outlines a structured DFIR workflow for investigating OneDrive on Windows endpoints using:

- **Registry Explorer** (account configuration + sync metadata)
- **OneDrive Explorer** (OneDrive sync databases)
- **ShadowExplorer** (Volume Shadow Copy historical folder states)
- **Timeline Explorer** (CSV & UAL investigation at scale)

---

## Primary Evidence Locations

### Registry Hive
- `C:\Users\{user}\NTUSER.DAT`

### OneDrive Sync Databases (Endpoint)
- Personal:
  - `C:\Users\{user}\AppData\Local\Microsoft\OneDrive\settings\Personal\<UserCid>.dat`
- Business:
  - `C:\Users\{user}\AppData\Local\Microsoft\OneDrive\settings\Business1\<TenantGuid>.dat`

### OneDrive Sync Folder
- Personal:
  - `C:\Users\{user}\OneDrive\`
- Business:
  - `C:\Users\{user}\OneDrive - <OrgName>\`

### Recycle Bin Evidence
- `C:\$Recycle.Bin\<SID-RID>\`

### Cloud Logs (Org Provided)
- Microsoft **Unified Audit Logs (UAL)** exported to CSV

---

## Tools Used

- **Registry Explorer** (Eric Zimmerman)
- **OneDrive Explorer** (Eric Zimmerman)
- **ShadowExplorer**
- **Timeline Explorer** (Eric Zimmerman)

---

# Workflow – Registry Explorer (NTUSER.DAT)

## Step 1 — Load NTUSER.DAT_clean in Registry Explorer

### Procedure
1. Launch **Registry Explorer**
2. Select **File → Load Hive**
3. Select `NTUSER.DAT_clean`
4. Click **Open**
5. Confirm hive appears in left navigation

📸 **Example Screenshot**

```markdown
![Registry Explorer - Load NTUSER.DAT_clean](img/onedrive_forensics/01_load_ntuser.png)
```

---

## Step 2 — Investigate OneDrive Accounts Key

### Registry Path
```
NTUSER.DAT\Software\Microsoft\OneDrive\Accounts
```

### Task
Document OneDrive account(s) present. For each account, record:
- `UserEmail`
- `UserFolder`
- `cid`
- `SPOResourceID` (if present)

📸 **Example Screenshot**

```markdown
![Registry Explorer - OneDrive Accounts key](img/onedrive_forensics/02_onedrive_accounts.png)
```

### Business Tenant Folders (SharePoint/Teams)
If OneDrive for Business is present:
```
NTUSER.DAT\Software\Microsoft\OneDrive\Accounts\Business1\Tenants
```

Document:
- tenant folders
- SharePoint/Teams synchronized libraries (“Tenants”)
- shared folder names potentially tied to sensitive data exposure

📸 **Example Screenshot**

```markdown
![Registry Explorer - OneDrive Business Tenants](img/onedrive_forensics/03_business_tenants.png)
```

---

# Workflow – OneDrive Explorer (Personal)

## Step 3 — Prepare OneDrive Personal in OneDrive Explorer

### Analyst Prep: Interview the Network Owner
Before searching, obtain:
- names of sensitive projects
- critical file names / keywords
- suspected exfil targets
- timeframe of concern

### Procedure
1. Open **OneDrive Explorer**
2. Select: **Options → Preferences**
3. Enable automatic CSV export for high efficiency:
     - **Select Auto Save to CSV**
     - Auto Save Path: `F:\Evidence\CloudStorage` ((or whatever working evidence directory you are using)
     - Click **Save**
4. Load OneDrive Personal database:
     - **File → OneDrive settings → Load <UserCid>.dat**
     - Example file:
     - `E:\C\Users\user1\AppData\Local\Microsoft\OneDrive\settings\Personal\a322388cbcb18cb.dat`
5. When asked for registry hive → **Yes**
     - Browse to: `E:\C\Users\user1\NTUSER.DAT`
6. When asked for $Recycle.Bin → **Yes**
     - Browse to:
       - `E:\C\$Recycle.Bin\S-1-5-21-...-1002`
       - Use the RID you identified to load the correct one. Triage images are particularly useful for this step as access to these folders in mounted disk images often have difficulties due to Windows auto-redirection of Recycle Bin folders.
8. After load completes, the root of the OneDrive folder hierarchy should appear in the Path pane. Click into the Path pane and begin expanding the folder hierarchy. Spend a few minutes looking through the folders and files to become familiar with the information available.

📸 **Example Screenshot**

```markdown
![OneDrive Explorer - Load Personal database](img/onedrive_forensics/04_onedriveexplorer_personal_load.png)
```

---

## Step 4 — Investigate Deleted Files (OneDrive Recycle Bin)

### Goal
Identify deleted OneDrive items relevant to incident scope.

### Procedure
1. Locate the **Deleted Files** folder in OneDrive Explorer
2. Identify files of interest (keyword search first)
3. Document:
   - filename
   - prior OneDrive path
   - deleted time (if present)
4. Use the **Find** bar for sensitive keywords

📸 **Example Screenshot**

```markdown
![OneDrive Explorer - Deleted Files](img/onedrive_forensics/05_deleted_files.png)
```

**DFIR Tip:** Deleted items often signal **covering tracks** or **cleanup after staging**.

---

# Workflow – ShadowExplorer (Volume Shadow Copies)

## Step 5 — Review Prior OneDrive States via Volume Shadow Copies

### Goal
Identify differences between:
- current OneDrive folder state
- prior shadow-copy snapshots

This can reveal:
- files that used to exist but were deleted
- folder structures that changed over time
- earlier versions of sensitive data

### Procedure
1. Open **ShadowExplorer**
2. Select mounted evidence drive from dropdown (example: `F:`)
3. If drive letter isn’t visible:
   - evidence likely mounted incorrectly (must be “Write temporary”)
   - close/reopen ShadowExplorer after remount
4. Navigate to:
   - `Users\user1\OneDrive`
5. Review shadow copies from newest → oldest
6. Compare results to OneDrive Explorer findings and document differences

📸 **Example Screenshot**

```markdown
![ShadowExplorer - OneDrive folder in VSS](img/onedrive_forensics/06_shadowexplorer_onedrive.png)
```

---

# Workflow – OneDrive Explorer (Business1)

## Step 6 — Prepare OneDrive for Business (If Applicable)

### Notes
OneDrive Explorer supports multiple databases loaded simultaneously.

**Important:** Ensure Find/search bar is empty before loading additional DBs.

### Procedure
1. Load Business database:
   - **File → OneDrive settings → Load <UserCid>.dat**
   - Example file:
     - `E:\C\Users\user1\AppData\Local\Microsoft\OneDrive\settings\Business1\c2b6b128-5267-5cca-abca-c9cd34be2569.dat`
2. Provide registry hive:
   - `E:\C\Users\user1\NTUSER.DAT`
3. Provide $Recycle.Bin:
   - `E:\C\$Recycle.Bin\S-1-5-21-...-1002`
4. Expand new folder hierarchy

📸 **Example Screenshot**

```markdown
![OneDrive Explorer - Load Business1 database](img/onedrive_forensics/07_onedriveexplorer_business_load.png)
```

---

## Step 7 — Investigate OneDrive for Business Content

### Tasks
1. Keyword search for sensitive files (from owner interview)
2. Identify interesting files and their locations
3. Visit files in mounted image using Windows File Explorer
4. Interpret cloud-only files:
   - cloud symbol / missing content = placeholder
   - actual file data not stored locally
5. For interesting files:
   - open **Properties**
   - document Created / Modified

### Timestamp Interpretation
If **Modified** is before **Created**:
- file likely **copied** into OneDrive folder
- Created time represents the copy operation

📸 **Example Screenshot**

```markdown
![OneDrive Explorer - Cloud-only file indicators](img/onedrive_forensics/08_cloud_only_files.png)
```

---

# Workflow – Timeline Explorer (CSV Review)

## Step 8 — Analyze OneDrive Explorer CSV Output in Timeline Explorer

### Goal
Move from GUI browsing → high speed bulk analysis.

### Procedure
1. Locate exported CSVs (Auto Save Path)
2. Open CSV in **Timeline Explorer**
3. Reset wide columns:
   - Tools → Reset column widths
4. Apply global searches and filters for:
   - sensitive keywords
   - file names
   - specific directories
   - delete activity
   - downloads/sync conflicts

📸 **Example Screenshot**

```markdown
![Timeline Explorer - OneDrive CSV analysis](img/onedrive_forensics/09_timeline_explorer_csv.png)
```

### Exportable Evidence
Timeline Explorer provides:
- filtering
- sorting
- bookmarks
- CSV export for reporting

---

# Workflow – Unified Audit Logs (UAL)

## Step 9 — Investigate OneDrive Usage via Unified Audit Logs

### Why UAL?
Endpoint artifacts only show what synced locally.
UAL answers:
- who accessed files in cloud
- downloads/uploads
- anonymous link access
- external IP usage
- sharing behavior

### Procedure
1. Obtain UAL CSV export from network owner/admin
2. Open in **Timeline Explorer**
3. Reset wide columns:
   - Tools → Reset column widths

📸 **Example Screenshot**

```markdown
![Timeline Explorer - Unified Audit Log CSV](img/onedrive_forensics/10_ual_overview.png)
```

---

### 9A — Investigate Files of Interest (Keyword Search)

Tasks:
- Search all columns for sensitive terms
- Document for each file:
  - did this account access it?
  - is it referenced in endpoint OneDrive data?
  - earliest access time
  - activity type:
    - Created files/folders
    - Uploads
    - Downloads
    - File preview
    - Sync events
  - IP addresses involved

---

### 9B — Audit Sharing Links

Procedure:
1. Clear global filter
2. Filter **User** column to email of interest
3. Filter **Activity** column to `Links`

Document:
- files/folders shared
- anonymous link access
- IP addresses predominating

---

### 9C — Audit Downloads

Procedure:
1. Keep **User** filter
2. Filter Activity for:
   - `Downloaded files to computer`

Document:
- unusual download dates
- IP address clusters

---

### 9D — Audit Deletions

Procedure:
1. Filter Activity for:
   - `Deleted File`

Document:
- deleted sensitive files
- deletion timeframe relevance
- IP addresses involved

---

# Evidence to Document

## OneDrive Profile Summary
- OneDrive accounts present
  - Personal vs Business
- `UserEmail`, `UserFolder`, `cid`, `SPOResourceID`
- business Tenants / SharePoint libraries synced
- deleted OneDrive files + original paths
- sensitive files located (and cloud-only status)

## Activity Summary
- suspicious file access patterns
- abnormal deletions
- link sharing behavior (anonymous access)
- unusual download activity
- IP addresses tied to high-risk activity

## Key Questions for Reporting
- What sensitive data was accessed?
- Was data downloaded to a computer?
- Were anonymous links used?
- Were files deleted after access?
- What is earliest known exposure time?

---

## Analyst Notes / Pitfalls

- Endpoint artifacts are limited by sync state (cloud-only placeholders exist)
- OneDrive for Business may sync multiple SharePoint libraries
- Always corroborate endpoint findings with **UAL**
- Recycle Bin redirection often breaks in mounted images; triage images help
- Be careful interpreting Created vs Modified times in synced folders
