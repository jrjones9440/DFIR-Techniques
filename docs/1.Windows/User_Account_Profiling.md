# User Account Profiling (SAM Hive)

## Overview

**User Account Profiling** is a DFIR activity focused on identifying **local accounts**, **built-in system accounts**, and **Microsoft/cloud-linked accounts**, then extracting evidence such as:

- Account Name
- RID
- Whether it’s a Cloud/Microsoft account
- Email tied to the account
- Last Logon timestamp

This work is commonly performed by analyzing the **SAM Registry hive**.

---

## Artifact Location

### Registry Hive / Key
**SAM**  
`SAM\Domains\Account\Users`

### Forensic Relevance

The `Users` key contains the system’s **local account database**, including:

- **Account name and RID (Relative Identifier)**
- **Last Logon time**
- **Password metadata (last change time)**
- **Login counters**
- **Group membership indicators**
- Markers indicating **Microsoft/cloud accounts**, such as values with `Internet` in their name

This hive is extremely useful for:

- Identifying **suspicious accounts** (unknown admins, rogue local accounts)
- Finding **recently active** accounts (Last Login)
- Determining whether **built-in accounts were used**
- Mapping accounts into the timeline of compromise

> ⚠️ Note: SAM hive data is **not the full source of truth** for all auth activity. Always validate logon activity with Security log events (4624/4625) and other sources.

---

## Tools

### Primary tools used
- **Registry Explorer** (Eric Zimmerman)
- **RECmd.exe** (Eric Zimmerman)

---

## Data Acquisition (Recommended)

Collect the following:
- `C:\Windows\System32\config\SAM`
- `C:\Windows\System32\config\SYSTEM` (needed to decrypt SAM in some workflows)

> If you're using KAPE, include modules/targets for SAM + SYSTEM hives.

---

# Investigative Workflow

## Step 1 — Parse SAM Users with Registry Explorer

### Goal
Use Registry Explorer’s built-in parsing for `Users` to quickly enumerate accounts and metadata.

### Procedure
1. Open **Registry Explorer**
2. Load the **SAM hive**
3. Navigate to:

   `SAM\Domains\Account\Users`

4. Select the **Users** key
5. In the lower pane, select the **User accounts** tab

You should now see parsed accounts from the SAM.

📸 **Screenshot Example** (add yours here):

```markdown
![Registry Explorer - SAM Users User accounts tab](img/user_account_profiling/01_registry_explorer_users_tab.png)
```

---

## Step 2 — Count User Accounts (RID ≥ 1000)

### Background
The first column in the User Accounts view is **User Id** which is the **Relative Identifier (RID)**.

- **RID < 1000**: built-in/system accounts
- **RID ≥ 1000**: user-created accounts (local and cloud-linked)

### Task
**How many user accounts are present in this SAM hive?**

### How to Answer
In the User Accounts tab:
- Filter/sort by **User Id**
- Count all rows where RID ≥ 1000

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Sorted RIDs](img/user_account_profiling/02_sorted_by_rid.png)
```

---

## Step 3 — Identify Accounts of Interest

### Task
What are the **User Names** of accounts of interest and what are their **User Id (RID)** values?

### How to Answer
From the User Accounts plugin output:
- Record `User Name`
- Record `User Id`

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Accounts of interest highlighted](img/user_account_profiling/03_accounts_of_interest.png)
```

**Example documentation format:**

| User Name | RID | Notes |
|---|---:|---|
| Administrator | 500 | Built-in |
| Guest | 501 | Built-in |
| jsnow | 1002 | Account of interest |
| svc-backup | 1004 | Suspicious service account |

---

## Step 4 — Group Memberships and Admin Rights

### Task
What **Groups** are the accounts of interest a member of? Identify groups with **Administrative rights**.

### Where to check
- Registry Explorer parsing (if populated)
- SAM group membership artifacts under:
  - `SAM\Domains\Builtin\Aliases`
  - `SAM\Domains\Account\Aliases`

> In many incidents, the key question is whether the user is in **Administrators** (RID 544 group).

### Approach
In Registry Explorer:
- Identify account RID
- Check group membership in parsed views OR pivot into alias membership

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Group memberships view](img/user_account_profiling/04_group_memberships.png)
```

**Annotate administrative groups:**
- Administrators
- Remote Desktop Users (situational)
- Backup Operators (situational)
- Hyper-V Administrators (situational)

---

## Step 5 — Determine Last Login Time

### Task
What is the **Last Login Time** for the account(s) of interest?

### How to Answer
In Registry Explorer User Accounts tab:
- Locate `Last login time` (or similar parsed field)

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Last login time](img/user_account_profiling/05_last_login_time.png)
```

**DFIR note:**  
If the account is suspicious, correlate Last Login with:
- Security log 4624 logons
- RDP logons (RemoteInteractive)
- Logon type anomalies

---

## Step 6 — Used Built-In Accounts (RID < 1000)

### Task
How many built-in system accounts (**RID < 1000**) have been used on the system?

### How to Answer
In the User Accounts tab:
- Filter RID < 1000
- Evaluate Last Login timestamps
- A “used” account typically shows Last Login > null/zero

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Built-in accounts usage](img/user_account_profiling/06_builtin_accounts_used.png)
```

**Common built-in accounts**
- 500 Administrator
- 501 Guest
- 502 KRBTGT (domain controllers)
- Other service/system accounts depending on context

---

## Step 7 — Why Total Login Count Might Be 0

### Task
Why might **Total Login Count = 0** even though a **Last Login Time exists**?

### Explanation
For **newer Microsoft Accounts (cloud-linked logons)**, Windows may **not reliably update** the legacy SAM values like:

- Total Login Count
- Some password metadata

Even if logons are occurring, the SAM counters may remain `0`.

**How to validate**
- Use Security event logs:
  - 4624 successful logon
  - 4625 failed logon

---

## Step 8 — Invalid Login Count for Administrator Accounts

### Task
What is the **Invalid Login Count** for any Administrator accounts?

### How to Answer
In Registry Explorer:
- Locate `Invalid login count` for:
  - RID 500 Administrator
  - Any local accounts in Administrators group

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Invalid login counts](img/user_account_profiling/07_invalid_login_count.png)
```

**Interpretation notes**
- Elevated invalid counts may indicate:
  - brute force attempts
  - password spraying
  - credential stuffing
  - misconfigured service using stale password

---

## Step 9 — Password Change Timestamp Before Created Timestamp

### Task
Why might **Last Password Change** time be *before* **Created On** time?

### Explanation
Major Windows updates are known to modify/normalize registry timestamps. This can lead to timestamp behavior that **does not align with true historical creation**.

### Validation workflow
- Identify the **last major system update time**
- Validate via:
  - `SYSTEM` hive
  - Windows Update logs
  - CBS logs
  - Event logs (Setup / WindowsUpdateClient)

Document update time and justify timestamp inconsistency.

---

## Step 10 — Review Raw SAM User Subkeys (Hex RID)

### Task
Each user is stored as a **subkey under Users**, named as the **hex RID**.

Example:
- RID `1002` in hex = `3EA`

### How to Answer
1. Find RID for account of interest (ex: 1002)
2. Convert RID → hex
3. Navigate to:

`SAM\Domains\Account\Users\000003EA`

📸 **Screenshot Example**:

```markdown
![Registry Explorer - User subkey 000003EA](img/user_account_profiling/08_hex_rid_subkey.png)
```

### What to review
Inspect values such as:
- `V`
- `F`
- `InternetUserName` (if present)

---

## Step 11 — Identify Microsoft (Cloud) Accounts (Internet* values)

### Task
Determine if an account is a Microsoft/cloud account using values containing `Internet`.

### Procedure (Registry Explorer)
1. Select the account subkey (hex RID)
2. Locate values with `Internet` in their name (example: `InternetUserName`)
3. Click the value
4. In the **Type Viewer pane**, inspect raw contents
5. Document the email address tied to that account

📸 **Screenshot Example**:

```markdown
![Registry Explorer - InternetUserName raw view](img/user_account_profiling/09_internetusername_raw.png)
```

**DFIR significance**
- Confirms Microsoft account linkage
- Adds **identity attribution** (email address)
- Supports scoping and correlating across devices/cloud logs

---

# RECmd.exe Workflow (Evidence at Scale)

Registry Explorer is great for interactive analysis; **RECmd** is how you scale and automate.

## Example RECmd Execution

### Run RECmd against SAM using a .reb
```powershell
RECmd.exe -f "C:\Cases\Hives\SAM" --csv "C:\Cases\Output\RECmd" --csvf SAM_UserAccounts.csv
```

### Recommended approach
Create a `.reb` that targets:
- `SAM\Domains\Account\Users`
- account subkeys
- values containing `Internet`

---

## Example RECmd .reb (Snippet)

Save as: `REB/SAM_UserAccount_Profiling.reb`

```xml
<RegistryExplorerBatch>
  <RegistryKey>
    <HivePath>%%hivepath%%</HivePath>
    <KeyPath>SAM\Domains\Account\Users</KeyPath>
    <Recursive>false</Recursive>
    <Comment>Enumerate local users from SAM</Comment>
  </RegistryKey>

  <RegistryKey>
    <HivePath>%%hivepath%%</HivePath>
    <KeyPath>SAM\Domains\Account\Users\Names</KeyPath>
    <Recursive>true</Recursive>
    <Comment>Account name mapping</Comment>
  </RegistryKey>

  <RegistryKey>
    <HivePath>%%hivepath%%</HivePath>
    <KeyPath>SAM\Domains\Account\Users</KeyPath>
    <Recursive>true</Recursive>
    <Comment>Look for InternetUserName values indicating Microsoft accounts</Comment>
  </RegistryKey>
</RegistryExplorerBatch>
```

> You can tune recursion and filter output further once you test against real hives.

---

# Evidence Output Requirements

At the end of this workflow, you should be able to report:

| Account Name | RID | Cloud Account | Email | Last Logged On |
|---|---:|---|---|---|
| jsnow | 1002 | Yes | jsnow@outlook.com | 2025-12-10 14:22:01Z |
| svc-backup | 1004 | No | N/A | 2025-12-05 09:13:12Z |

---

# Analyst Notes / Pitfalls

- SAM timestamps can be affected by system updates and registry operations
- Total Login Count may be unreliable for Microsoft accounts
- Always correlate with:
  - Event logs (4624/4625/4672)
  - RDP logs
  - LSA secrets (if applicable)
  - Browser artifacts for email account reuse
