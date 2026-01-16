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
      -`SAM\Domains\Account\Users`
4. Select the **Users** key
5. After selecting the Users key, in the data viewing pane, select the **User accounts** Tab at the top of the pane and view the data parsed by the Registry Explorer plugin

📸 **Screenshot Example** (add yours here):

```markdown
![Registry Explorer - SAM Users User accounts tab](img/user_account_profiling/01_registry_explorer_users_tab.png)
```
6. The first column in the Registry Explorer User Accounts plugin-in is named User Id and represents a value Microsoft calls the "Relative Identifier (RID)". RID values of 1000 or higher are reserved for user accounts and those below that value are used for system accounts. Document:
      - How many user accounts are present in this SAM hive?

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Sorted RIDs](img/user_account_profiling/02_sorted_by_rid.png)
```

7. What are the User Names of the accounts of interest and document their User Id values.

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
| svc-backup | 1004 | Suspicious service account 

8. What Groups are the accounts of interest a member of? Annotate any Group memberships that have Administrative rights.

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Group memberships view](img/user_account_profiling/04_group_memberships.png)
```

9. Document the Last Login Time for the account(s) of interest.
      - Why might the Total Login Count = 0 for the account of interest?  New Microsoft Accounts no longer update this value within the SAM. Since there is a Last Login Time we would expect Total Login Count to be greater than zero.
        
📸 **Screenshot Example**:

```markdown
![Registry Explorer - Last login time](img/user_account_profiling/05_last_login_time.png)
```

10. How many of the built-in system accounts (RID < 1000) have been used on the system?

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Built-in accounts usage](img/user_account_profiling/06_builtin_accounts_used.png)
```
**Analysis Tip: Common built-in accounts**
- 500 Administrator
- 501 Guest
- 502 KRBTGT (domain controllers)
- Other service/system accounts depending on context

12. What is the Invalid Login Count for the any Administrator accounts?

📸 **Screenshot Example**:

```markdown
![Registry Explorer - Invalid login counts](img/user_account_profiling/07_invalid_login_count.png)
```

**Analysis Tip: Interpretation notes**
- Elevated invalid counts may indicate:
  - brute force attempts
  - password spraying
  - credential stuffing
  - misconfigured service using stale password


14. Why might the Last Password Change time be before the account Created On time of the account of interest?  Major system updates are known to change a lot of timestamps in the Windows Registry. This is a known phenomenon for major Windows updates,  document the last system update time to validate.
15. he raw data for user accounts in the SAM hive are stored as sub-keys under the Users key. Each account has a sub-key named according to the hex representation of its Relative Identifier (RID). For example the hex value for RID 1002 is 3EA. Examine the accounts of interest.

📸 **Screenshot Example**:

```markdown
![Registry Explorer - User subkey 000003EA](img/user_account_profiling/08_hex_rid_subkey.png)
```

17. How we can tell a particular account is a Microsoft (Cloud) Account are the values with "Internet" in their names. Click on the InternetUserName value and look at the raw data in the Type Viewer pane. Document the email account associated with the accounts of interest.

📸 **Screenshot Example**:

```markdown
![Registry Explorer - InternetUserName raw view](img/user_account_profiling/09_internetusername_raw.png)
```

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
