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

### Procedure
1. In **Registry Explorer** navigate to the Accounts Key:
     - `NTUSER.DAT\Software\Microsoft\OneDrive\Accounts`
2. Document what accounts have data present.
3. For each account present, document
     - `UserEmail`
     - `UserFolder`
     - `cid`
     - `SPOResourceID` (if present)
4. If there is a OneDrive for Business account present on the system, it may be synchronizing multiple shared folders from Sharepoint / Teams (Microsoft calls these "Tenants").
5. In **Registry Explorer** navigate to the subkey of the Accounts Key:
     - `NTUSER.DAT\Software\Microsoft\OneDrive\Accounts\Business1\Tenants`
6. Document any interesting Share Folders present, this is could be useful information in assessing potential data compromise locations for the damage assessment.

📸 **Example Screenshot**

```markdown
![Registry Explorer - OneDrive Accounts key](img/onedrive_forensics/02_onedrive_accounts.png)
```

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
1. Use the OneDrive Explorer menu item File -> OneDrive settings -> Load <UserCid>.dat to browse and open the One Drive for Business database file from your mounted triage image:
     - Example file:
       - `E:\C\Users\user1\AppData\Local\Microsoft\OneDrive\settings\Business1\c2b6b128-5267-5cca-abca-c9cd34be2569.dat`
2. When asked to provide a registry hive, select Yes and browse to the user's hive:
     - `E:\C\Users\user1\NTUSER.DAT`
3. When asked to provide the path to the user's $Recycle.Bin, select Yes and browse to:
     - `E:\C\$Recycle.Bin\S-1-5-21-...-1002`
     - Use the RID you identified to load the correct one
4. After a brief load time, the new OneDrive folder hierarchy should appear

📸 **Example Screenshot**

```markdown
![OneDrive Explorer - Load Business1 database](img/onedrive_forensics/07_onedriveexplorer_business_load.png)
```

---

## Step 7 — Investigate OneDrive for Business Content

### Procedure
1. Document any interesting files and their locations (remember to do key word searches for sensitive documents from your Network Owner interview)
2. If you find any interesting files, use Windows File Explorer to visit them in your mounted drive image.
3. If you see a cloud symbol next to them in OneDriveExplorer or an X on the file in Windows File Explorer, that means they are "cloud-only", meaning they are only placeholders to them in this folder with no real data stored.
4. For any interesting files, click on properties and note the Created and Modified times for any sensitive files.

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
Move from OneDrive Explorer GUI browsing → high speed bulk analysis using Timeline Explorer.

### Procedure
1. While the OneDriveExplorer GUI is useful for navigating early investigations, if you correctly set the Auto Save Preferences earlier in this workflow, you should also have .csv output available for each OneDrive .dat file parsed.
2. Open CSV in **Timeline Explorer**
3. Reset wide columns:
   - Tools → Reset column widths
4. Perform the same analysis as above concerning:
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
OneDrive for Business (and most business-oriented cloud storage applications) has a log that administrators can use to track user activity. Called the Unified Audit Log, it is available via the Microsoft administrator portal and is an excellent source of evidence.  Endpoint artifacts only show what synced locally. UAL answers:
    - who accessed files in cloud
    - downloads/uploads
    - anonymous link access
    - external IP usage
    - sharing behavior

### Procedure
1. Obtain UAL CSV export from network owner/admin
2. Open in **Timeline Explorer**
3. Your columns in Timeline Explorer may be very wide. To shrink everything down to fit on smaller screens:
     - Tools → Reset column widths
4. Continue your investigation of suspicious or sensitive files by using the filter/search bar to identify any entries across all of the columns that contain that term.
5. Document the following for any files of interest:
     - Did this account have access to the file?
     - Are the files referenced in these logs the same as the ones identified in their OneDrive account?
     - What is the earliest known access to these files?
     - What type of activity did this account have with those files:
       - Created Folders
       - Created Files
       - Uploads
       - Downloads
       - File Previews
     - What IP Addresses are involved?
7. Clear your global filter and create a filter on the User column for the email in question. Now create a second filter in the Activity column for all activity related to "Links". Auditing links can help identify how content is being shared and how shared content is being accessed.
8. Review the data and document any interesting artifacts related to:
     - What files and folders did the account of interest share?
     - What files and folders did the account of interest access via anonymous (non-authenticated) links?
     - What IP address(s) predominates for this activity?
10. Audit downloads conducted by the account of interest. To do this, clear your filter on the Activity column. Then create a new filter on the Activity column for all activity related to "Downloaded files to computer". Keep your User filter for the account of interest.
     - Document dates of unusual download activity and the IP addresses involved.
12. Audit files deleted by the account of interest. To do this, clear your filter on the Activity column. Then create a new filter on the Activity column for all activity related to "Deleted File".
     - Document any files that were deleted that are tied to the timeframe we are focused on or sensitive file deletion.

📸 **Example Screenshot**

```markdown
![Timeline Explorer - Unified Audit Log CSV](img/onedrive_forensics/10_ual_overview.png)
```

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
