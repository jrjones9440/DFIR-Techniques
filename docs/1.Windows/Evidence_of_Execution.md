# Windows Execution Artifacts for DFIR

This section provides a **Digital Forensics & Incident Response (DFIR)**–focused overview of three core Windows execution artifacts:

- **Prefetch**
- **Amcache**
- **ShimCache (AppCompatCache)**

It explains **what they are**, **why they matter**, **what they look like**, and **how to parse them using common forensic tools**.

---

## Table of Contents

1. [Prefetch](#prefetch)
2. [Amcache](#amcache)
3. [ShimCache (AppCompatCache)](#shimcache-appcompatcache)
4. [Correlation & Analyst Tips](#correlation--analyst-tips)
5. [Tooling Summary](#tooling-summary)

---

## Prefetch

### What is Prefetch?

**Prefetch** files are created by Windows to improve application startup performance. When an executable runs, Windows records metadata about its execution and the files it loads.

From a DFIR perspective, Prefetch is one of the **strongest indicators of program execution** on a system.

- Enabled by default on most desktop versions of Windows
- Stored as `.pf` files
- Limited in count (typically 128–1024 files depending on OS)

### Location

```
C:\Windows\Prefetch\
```

Example filename:
```
POWERSHELL.EXE-3F0D7E6A.pf
```

---

### Forensic Value

Prefetch can help answer:

- **Was this program executed?**
- **How many times was it executed?**
- **When was it last executed?**
- **Which files and DLLs were accessed?**

This makes Prefetch extremely useful for:

- Malware execution confirmation
- Living-off-the-land (LOLbin) abuse
- Timeline reconstruction

---

### Key Data Points

- Executable name
- Full path of executable
- Run count
- Last execution timestamp
- Referenced files and DLLs

---

### Example Output (PECmd.exe)

```
ExecutableName: POWERSHELL.EXE
RunCount: 14
LastRunTime: 2024-11-18 13:42:51 UTC
FullPath: \DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE

Referenced Files:
- KERNEL32.DLL
- NTDLL.DLL
- AMSI.DLL
```

---

### Tools for Prefetch

#### PECmd.exe (Eric Zimmerman)

Parse Prefetch files:

```
PECmd.exe -d C:\Windows\Prefetch --csv prefetch.csv
```

Common flags:
- `-d` : Directory of Prefetch files
- `--csv` : Export to CSV
- `--json` : Export to JSON

---

## Amcache

### What is Amcache?

**Amcache** tracks application installation and execution metadata. It is especially valuable because it may record **executables that never generated Prefetch**.

Amcache was significantly expanded starting in Windows 8+.

### Location

Primary hive:
```
C:\Windows\AppCompat\Programs\Amcache.hve
```

---

### Forensic Value

Amcache can provide:

- Executable file paths
- File hashes (SHA1)
- Compilation timestamps
- First-seen timestamps
- Program metadata (company name, product name)

This is critical for:

- Identifying dropped malware
- Detecting renamed binaries
- Validating attacker toolkits

---

### Key Data Points

- File path
- SHA1 hash
- File size
- Compile time
- First execution time
- Program name and vendor

---

### Example Output (AmcacheParser)

```
Path: C:\Users\Public\svchost.exe
SHA1: 9f2c3e9f1a9d7b9a7a5c5d8f3b2a1e4c6d9e8f7a
CompileTime: 2023-09-12 08:15:22 UTC
FirstRunTime: 2024-11-17 02:31:44 UTC
Company: Microsoft Corporation
```

---

### Tools for Amcache

#### AmcacheParser.exe (Eric Zimmerman)

```
AmcacheParser.exe -f Amcache.hve --csv amcache.csv
```

Useful flags:
- `-f` : Path to Amcache hive
- `--csv` : CSV output
- `--json` : JSON output

---

## ShimCache (AppCompatCache)

### What is ShimCache?

**ShimCache**, also known as **AppCompatCache**, is part of the Windows Application Compatibility framework.

It records executables to determine whether compatibility shims are required.

> ⚠️ Important: ShimCache **does NOT reliably indicate execution** — it only indicates that Windows was aware of the file.

---

### Location

Stored in the SYSTEM registry hive:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Offline hive:
```
SYSTEM
```

---

### Forensic Value

ShimCache can help:

- Identify presence of executables
- Discover files that were deleted
- Detect attacker staging activity

Best used in **correlation with other artifacts**.

---

### Key Data Points

- File path
- Last modified timestamp
- File size (varies by OS)

---

### Example Output (AppCompatCacheParser)

```
Path: C:\Temp\mimikatz.exe
LastModified: 2024-11-16 22:10:03 UTC
FileSize: 856064

ExecutionFlag: Unknown
```

---

### Tools for ShimCache

#### AppCompatCacheParser.exe (Eric Zimmerman)

```
AppCompatCacheParser.exe -f SYSTEM --csv shimcache.csv
```

Common flags:
- `-f` : SYSTEM hive
- `--csv` : CSV output
- `--json` : JSON output

---

## Correlation & Analyst Tips

### Execution Confidence Ranking

| Artifact   | Execution Confidence |
|-----------|----------------------|
| Prefetch  | High                 |
| Amcache   | Medium–High           |
| ShimCache | Low                  |

### Analyst Tips

- **Correlate timestamps** across artifacts
- Look for **renamed LOLbins** (e.g., `svchost.exe` in user directories)
- Use **Amcache hashes** to pivot into malware databases
- Prefetch absence does **not** mean no execution

---

## Timeline Correlation Example

### Scenario

An analyst is investigating suspected malware execution involving a renamed credential-dumping tool (`svchost.exe`) dropped into a user-writable directory.

The goal is to **correlate Prefetch, Amcache, and ShimCache** to assess execution confidence and build a timeline.

### Correlated Timeline

| Timestamp (UTC) | Artifact | Evidence |
|---------------|----------|----------|
| 2024-11-16 22:09:58 | ShimCache | File present in Temp directory |
| 2024-11-17 02:31:44 | Amcache | SHA1 recorded, FirstRunTime |
| 2024-11-18 13:42:51 | Prefetch | RunCount = 3 |

### Analyst Interpretation

- **ShimCache** shows early presence (possible staging)
- **Amcache** confirms file metadata and first execution
- **Prefetch** strongly confirms repeated execution

Combined, these artifacts provide **high confidence execution evidence**.

---

## KAPE Targets

KAPE (Kroll Artifact Parser and Extractor) can be used to collect and parse these artifacts at scale.

### Prefetch Targets

```
Targets\Windows\Prefetch.tkape
```

Collects:
- Prefetch files (`*.pf`)

Parser Module:
```
Modules\Windows\PECmd.mkape
```

---

### Amcache Targets

```
Targets\Windows\Amcache.tkape
```

Collects:
- Amcache.hve

Parser Module:
```
Modules\Windows\AmcacheParser.mkape
```

---

### ShimCache Targets

```
Targets\Windows\Registry\SYSTEM.tkape
```

Collects:
- SYSTEM registry hive

Parser Module:
```
Modules\Windows\AppCompatCacheParser.mkape
```

---

### Example KAPE Command

```
kape.exe --tsource C: --tdest E:\KAPE --target Prefetch,Amcache,SYSTEM --module PECmd,AmcacheParser,AppCompatCacheParser
```

---

## Malware Case Study: Renamed Credential Dumper

### Incident Overview

A SOC receives an alert for suspicious PowerShell activity. Investigation reveals a suspicious binary named `svchost.exe` located in a user-writable directory.

---

### Findings by Artifact

#### ShimCache

- Indicates the file existed on disk prior to execution

#### Amcache

- Records SHA1 hash and first execution time
- Hash does not match legitimate Windows binary

#### Prefetch

- Confirms execution and multiple runs

---

### Final Assessment

| Question | Answer |
|--------|--------|
| Was the file present? | Yes |
| Was it executed? | Yes |
| Was it persistent? | Likely |
| Is it legitimate? | No |

### Analyst Conclusion

The binary masquerading as `svchost.exe` was executed multiple times and is highly likely malicious.

---

## Common Attacker Evasion Techniques

Attackers are aware of Windows execution artifacts and may attempt to evade or limit forensic visibility. Understanding these techniques helps analysts avoid false negatives.

---

### Prefetch Evasion

**Techniques:**

- Disabling Prefetch via registry:
  - `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`
  - `EnablePrefetcher = 0`
- Using portable executables executed only once
- Executing binaries from removable media or network shares
- Deleting Prefetch files post-execution

**DFIR Notes:**

- Absence of Prefetch does **not** equal absence of execution
- Check OS version and Prefetch configuration
- Correlate with Amcache, ShimCache, and event logs

---

### Amcache Evasion

**Techniques:**

- Running malware purely in memory (reflective loading)
- Using scripts (PowerShell, JavaScript, WMI) instead of binaries
- Cleaning or replacing `Amcache.hve`

**DFIR Notes:**

- Amcache is resilient and often survives basic cleanup
- Look for suspicious compile times or mismatched metadata
- Hashes are valuable for threat intelligence pivoting

---

### ShimCache (AppCompatCache) Evasion

**Techniques:**

- Relying on the artifact’s ambiguity (presence ≠ execution)
- Clearing or rolling SYSTEM registry hives
- Executing binaries briefly and deleting them

**DFIR Notes:**

- ShimCache is best used as a **supporting artifact**
- Deleted malware often still appears here
- Timestamp interpretation varies by Windows version

---

### Living-off-the-Land (LOLbin) Abuse

**Techniques:**

- Abuse of signed Windows binaries:
  - `powershell.exe`
  - `wmic.exe`
  - `mshta.exe`
  - `rundll32.exe`

**DFIR Notes:**

- Prefetch still records LOLbin execution
- Focus on **command-line artifacts** and child processes
- Correlate with PowerShell logs, SRUM, and UserAssist

---

### Analyst Takeaways

- Never rely on a **single execution artifact**
- Artifact gaps are often intentional
- Correlation beats individual indicators
- Document evasion possibilities in reports

---

## MITRE ATT&CK Mapping

The following MITRE ATT&CK techniques are commonly associated with activity uncovered through Prefetch, Amcache, and ShimCache analysis.

---

### Execution

- **T1059 – Command and Scripting Interpreter**
  - PowerShell, CMD, WMIC, MSHTA execution often visible via Prefetch

- **T1204 – User Execution**
  - Malicious binaries executed via phishing or user interaction

- **T1047 – Windows Management Instrumentation**
  - WMI-launched executables may appear in Amcache and ShimCache

---

### Defense Evasion

- **T1036 – Masquerading**
  - Renamed binaries (e.g., `svchost.exe` in user directories)

- **T1070 – Indicator Removal on Host**
  - Deletion of Prefetch files or registry hives

- **T1112 – Modify Registry**
  - Disabling Prefetch or tampering with AppCompat settings

---

### Persistence (Related)

- **T1547 – Boot or Logon Autostart Execution**
  - Execution artifacts may reveal binaries later used for persistence

---

## Execution Investigation Workflow (Checklist)

The following checklist provides a **repeatable DFIR workflow** for investigating suspected program execution on Windows systems.

---

### 1. Initial Triage

- Identify suspicious filename or hash
- Note file location (system vs user-writable path)
- Check alerting source (EDR, SIEM, user report)

---

### 2. Prefetch Analysis

- Parse Prefetch directory with `PECmd.exe`
- Look for matching executable names
- Record:
  - Run count
  - Last execution time
  - Full execution path
- Validate Prefetch configuration status

---

### 3. Amcache Analysis

- Parse `Amcache.hve`
- Locate matching file paths or hashes
- Record:
  - SHA1 hash
  - Compile timestamp
  - First-seen / execution time
- Compare metadata against known-good binaries

---

### 4. ShimCache Analysis

- Parse SYSTEM hive AppCompatCache
- Identify presence of suspicious executables
- Note last modified timestamps
- Treat as **supporting evidence only**

---

### 5. Correlation & Validation

- Align timestamps across all artifacts
- Identify execution order and repetition
- Validate against:
  - Event logs
  - PowerShell logs
  - SRUM / UserAssist

---

### 6. Adversary Behavior Assessment

- Check for masquerading indicators
- Identify LOLbin usage
- Determine possible execution method (scripted vs binary)

---

### 7. Reporting & Response

- Document execution confidence level
- Note possible attacker evasion techniques
- Preserve parsed artifacts and raw evidence
- Escalate for containment and remediation

---

### Execution Confidence Summary

| Evidence | Confidence |
|--------|------------|
| Prefetch present | High |
| Amcache only | Medium |
| ShimCache only | Low |
| Correlated artifacts | Very High |

---

## Additional Windows Execution Artifacts

In addition to Prefetch, Amcache, and ShimCache, modern Windows systems contain several other **high-value execution and user-activity artifacts** in the registry.

These artifacts are especially useful when:

- Prefetch is disabled or absent
- Malware executes via GUI shortcuts, Run dialog, or pinned apps
- Attackers rely heavily on interactive execution rather than services

---

### BAM (Background Activity Moderator)

**Purpose:** Records background app activity, including executable path and last executed time.

Registry Path:

```
SYSTEM\<CurrentControlSet>\Services\bam\State\UserSettings\{SID}
```

**Example Entry:**

```
Value Name: \Device\HarddiskVolume3\Users\Public\svchost.exe
Data: 2024-11-18 13:42:51 UTC
```

**DFIR Value:**

- Strong evidence of program execution
- Tracks full path
- Useful on Windows 10/11 where Prefetch may be limited

**How to Audit (Registry Explorer):**

- Load SYSTEM hive
- Navigate to BAM path
- Review per-SID keys and value timestamps

**Command Line Tools:**

- `RECmd.exe` (Eric Zimmerman) can parse BAM keys when using appropriate batch files.

Example:

```
RECmd.exe -f SYSTEM --bn RegistryExplorerBatch.reb --csv bam.csv
```

---

### DAM (Desktop Activity Moderator)

**Purpose:** Tracks desktop activity for Modern Standby / battery life management.

Registry Path:

```
SYSTEM\<CurrentControlSet>\Services\dam\State\UserSettings\{SID}
```

**Example Entry:**

```
Value Name: \Device\HarddiskVolume3\Windows\System32\cmd.exe
Data: 2024-11-17 02:35:11 UTC
```

**DFIR Value:**

- Evidence of interactive desktop execution
- Similar structure to BAM

Audit steps mirror BAM.

---

### RunMRU (Windows+R Command History)

**Purpose:** Records commands entered into the **Run dialog**.

Registry Path:

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

**Example:**

```
a = cmd
b = powershell -enc SQBFAFgA...
MRUList = "ba"
```

**DFIR Value:**

- Identifies user-initiated command execution
- Useful for detecting LOLbin usage
- Often reveals encoded PowerShell

**Audit (Registry Explorer):**

- Load NTUSER.DAT
- Navigate to RunMRU key
- Review values and MRUList ordering

**Command Line:**

```
RECmd.exe -f NTUSER.DAT --bn RegistryExplorerBatch.reb --csv runmru.csv
```

---

### UserAssist

**Purpose:** Tracks GUI program execution via Explorer (not background/terminal). Includes **Focus Count** and **Focus Time**.

Registry Path:

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

Useful GUIDs:

- `CEBFF5CD-ACE2-4F4F-9178-9926F41749EA` (Executable File Execution)
- `F4E57C4B-2036-45F0-A9AB-443BCFE33D9F` (Shortcut File Execution)

**Example:**

```
Value Name (ROT13): HRZR_EHACNGU:P:\Users\Public\svchost.exe
Run Count: 7
Focus Count: 3
Focus Time: 00:05:22
Last Run: 2024-11-18 13:41:02 UTC
```

**DFIR Value:**

- Excellent for user-driven execution
- Tracks frequency and interaction

**Audit:**

- Registry Explorer shows decoded values
- Look for unusual paths and high run counts

---

### FeatureUsage (Explorer Activity)

Windows records additional Explorer app usage under FeatureUsage.

#### AppLaunch

**Purpose:** Apps pinned to taskbar and executed from pinned shortcut.

Path:

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch
```

Example:

```
\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe : 12
```

#### AppSwitched

**Purpose:** Records apps switched into focus.

Path:

```
...\FeatureUsage\AppSwitched
```

Example:

```
\Device\HarddiskVolume3\Users\Public\svchost.exe : 5
```

#### AppBadgeUpdated

**Purpose:** Badge updates / notifications count.

Path:

```
...\FeatureUsage\AppBadgeUpdated
```

#### ShowJumpView

**Purpose:** Counts right-clicks showing Jump Lists.

Path:

```
...\FeatureUsage\ShowJumpView
```

#### TrayButtonClicked

**Purpose:** Tracks clicks on built-in tray applications.

Path:

```
...\FeatureUsage\TrayButtonClicked
```

**DFIR Value for FeatureUsage:**

- Identifies which apps were launched interactively
- Helps confirm user engagement
- Supports timeline reconstruction

---

## Searching & Auditing with Registry Explorer

### Workflow

1. Acquire hives:
   - `SYSTEM`
   - `NTUSER.DAT`
2. Open in **Registry Explorer**
3. Use the search function for:
   - suspicious filename (`svchost.exe`, `rundll32.exe`, etc.)
   - known LOLbins
   - attacker tool names

### CLI Workflow with RECmd

`RECmd.exe` supports batch parsing using `.reb` batch files.

Example collection:

```
RECmd.exe -f SYSTEM --bn RegistryExplorerBatch.reb --csv system_artifacts.csv
RECmd.exe -f NTUSER.DAT --bn RegistryExplorerBatch.reb --csv user_artifacts.csv
```

---

## Evasion Techniques for Additional Artifacts

Attackers may attempt to reduce registry artifact visibility.

### BAM/DAM Evasion

- Execute tools via service context or scheduled task that avoids user context
- Clear BAM/DAM keys (requires admin)
- Roll back or replace SYSTEM hive

### RunMRU Evasion

- Avoid Run dialog usage
- Clear RunMRU key
- Use alternate execution methods (shortcut, task scheduler)

### UserAssist Evasion

- Use command-line only execution
- Run from non-Explorer contexts
- Clear UserAssist keys (user-level)

### FeatureUsage Evasion

- Avoid pinned apps
- Launch via CLI, scripts, WMI, or services
- Clear FeatureUsage keys

**Analyst Note:** Artifact deletion attempts often create additional evidence such as:

- Registry hive timestamp changes
- USN journal entries
- Unexpected gaps in user activity

---

## KAPE Collection Targets for These Registry Artifacts

KAPE **collects files**, not individual registry keys. For the artifacts below, you typically collect the **registry hives that contain them**, then parse with RECmd/Registry Explorer.

### Required Hives to Collect

| Artifact Group | Hive File(s) to Collect | Typical On-Disk Path |
|---|---|---|
| BAM / DAM | `SYSTEM` | `C:\Windows\System32\config\SYSTEM` |
| RunMRU / UserAssist / FeatureUsage | `NTUSER.DAT` (per user) | `C:\Users\<User>\NTUSER.DAT` |
| (Optional but recommended) Shell/UI context | `UsrClass.dat` (per user) | `C:\Users\<User>\AppData\Local\Microsoft\Windows\UsrClass.dat` |

### Common KAPE Targets to Use

Depending on how your KAPETargets are organized, these are the most common target patterns that cover what you need:

- **SYSTEM hive target** (collects `SYSTEM`): often named something like `SYSTEM` or `RegistryHives` (varies by KapeFiles version)
- **NTUSER targets** (collect per-user): often named something like `NTUSER` or `UserHives`
- **UsrClass.dat targets** (optional): often named something like `UsrClass` or included in broader user-hive targets

### Practical KAPE Command Examples

Collect only the required hives:

```
kape.exe --tsource C: --tdest E:\KAPE --target SYSTEM,NTUSER
```

Collect hives and immediately parse with RECmd (if you have a module set up for it):

```
kape.exe --tsource C: --tdest E:\KAPE --target SYSTEM,NTUSER --module RECmd
```

> Tip: Use `--sim` first to validate volume/paths before collecting.

---

## Correlation Matrix

Use this matrix to quickly decide **which artifact answers which question**, and what its common blind spots are.

| Artifact | What it Answers | What It Typically Stores | Execution Confidence | Common Gaps / Pitfalls |
|---|---|---|---|---|
| Prefetch | Was an EXE run? When? How often? | Run count, last run time(s), path, loaded files | High | Disabled/limited; not guaranteed for all executions |
| Amcache | What EXE existed/was seen? Hash/metadata? | Path, SHA1, compile time, “first seen/run” style metadata | Med–High | In-memory/script-only may not appear; hive tampering |
| ShimCache | Was Windows aware of an EXE path? | Path + timestamp (version dependent) | Low | Presence ≠ execution; timestamp semantics vary |
| BAM | When did this EXE run in user context? | Full path + last execution timestamp per SID | Med–High | Can be cleared; depends on OS/user context |
| DAM | Similar to BAM, desktop activity | Full path + last execution timestamp per SID | Med–High | Similar limitations to BAM |
| RunMRU | What was typed into Win+R? | Commands/strings + MRU ordering | Medium | No timestamp; only Win+R; easily cleared |
| UserAssist | What GUI apps were launched via Explorer? | Run count, focus count/time, last run time | Medium | No CLI/background; ROT13; can be cleared |
| FeatureUsage\AppLaunch | What was launched from pinned/taskbar? | Counts keyed by app path | Low–Medium | Counts only; UI-driven; limited context |
| FeatureUsage\AppSwitched | What apps were switched into focus? | Focus/switch counts | Low | Not proof of launch; only UI focus events |

---

## RECmd Batch File Snippets (.reb)

RECmd batch files are YAML-formatted and let you script extraction of specific keys across many hives. Below are **minimal snippets** for the artifacts you listed.

> These are intended to be dropped into a custom `.reb` file (e.g., `ExecutionArtifacts_Custom.reb`). You can also compare against the maintained “DFIR Batch File” examples shipped with RECmd.

### SYSTEM Hive: BAM + DAM

```yaml
Description: Execution artifacts (BAM/DAM)
Author: YourTeam
Version: 1
Id: 11111111-1111-1111-1111-111111111111
Keys:
  - Description: BAM UserSettings
    HiveType: SYSTEM
    Category: Program Execution
    KeyPath: ControlSet*\Services\bam\State\UserSettings\* 
    Recursive: true

  - Description: DAM UserSettings
    HiveType: SYSTEM
    Category: Program Execution
    KeyPath: ControlSet*\Services\dam\State\UserSettings\* 
    Recursive: true
```

### NTUSER.DAT: RunMRU

```yaml
  - Description: RunMRU (Win+R)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    Recursive: false
```

### NTUSER.DAT: UserAssist

```yaml
  - Description: UserAssist (EXE execution)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count
    Recursive: true

  - Description: UserAssist (LNK execution)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count
    Recursive: true
```

### NTUSER.DAT: FeatureUsage

```yaml
  - Description: FeatureUsage AppLaunch
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch
    Recursive: true

  - Description: FeatureUsage AppSwitched
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
    Recursive: true

  - Description: FeatureUsage AppBadgeUpdated
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated
    Recursive: true

  - Description: FeatureUsage ShowJumpView
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
    Recursive: true

  - Description: FeatureUsage TrayButtonClicked
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
    Recursive: true
```

### Running RECmd with Your Custom Batch

Parse a single hive:

```
RECmd.exe -f SYSTEM --bn ExecutionArtifacts_Custom.reb --csv E:\out
RECmd.exe -f NTUSER.DAT --bn ExecutionArtifacts_Custom.reb --csv E:\out
```

Parse a directory of hives recursively:

```
RECmd.exe -d E:\KAPE\Files --bn ExecutionArtifacts_Custom.reb --csv E:\out
```

---

## Mini RECmd Batch File Template (Single Cohesive .reb)

Below is a complete **starter RECmd batch file** you can save as `ExecutionArtifacts_Custom.reb`.

> Note: RECmd batch files support multiple key definitions in a single YAML document. This template includes **SYSTEM + NTUSER** keys together; RECmd will only apply entries that match the hive type being parsed.

```yaml
Description: Windows Execution Artifacts (Prefetch Adjacent + Registry Execution Evidence)
Author: DFIR Team
Version: 1
Id: 8b0c0e7e-3c8e-4d62-a1cf-000000000001
Keys:
  # -----------------------------
  # SYSTEM Hive
  # -----------------------------

  - Description: BAM UserSettings (Background Activity Moderator)
    HiveType: SYSTEM
    Category: Program Execution
    KeyPath: ControlSet*\Services\bam\State\UserSettings\*
    Recursive: true

  - Description: DAM UserSettings (Desktop Activity Moderator)
    HiveType: SYSTEM
    Category: Program Execution
    KeyPath: ControlSet*\Services\dam\State\UserSettings\*
    Recursive: true

  # -----------------------------
  # NTUSER.DAT Hive
  # -----------------------------

  - Description: RunMRU (Windows+R)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    Recursive: false

  - Description: UserAssist (Executable File Execution)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count
    Recursive: true

  - Description: UserAssist (Shortcut File Execution)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count
    Recursive: true

  - Description: FeatureUsage AppLaunch (Pinned apps execution count)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch
    Recursive: true

  - Description: FeatureUsage AppSwitched (App focus switches)
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
    Recursive: true

  - Description: FeatureUsage AppBadgeUpdated (Notification badges)
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated
    Recursive: true

  - Description: FeatureUsage ShowJumpView (Jump List right-click count)
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
    Recursive: true

  - Description: FeatureUsage TrayButtonClicked (Tray UI clicks)
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked
    Recursive: true
```

### Example Usage

```
RECmd.exe -f SYSTEM --bn ExecutionArtifacts_Custom.reb --csv E:\out
RECmd.exe -f C:\Users\Alice\NTUSER.DAT --bn ExecutionArtifacts_Custom.reb --csv E:\out
```

---

## Artifact Pivot Batch (.reb)

Sometimes you don’t know *which* artifact will contain your indicator. In those cases, it’s useful to run an **artifact pivot** batch that extracts the most common execution-related keys from SYSTEM and NTUSER, then **pivot (search)** in the output for an indicator such as:

- suspicious filename (`mimikatz.exe`, `svchost.exe` in user paths)
- known LOLbin (`rundll32.exe`, `mshta.exe`)
- a directory (`C:\Users\Public`, `C:\Temp`)

### How the Pivot Works:**

1. Run RECmd with the pivot batch (exports CSV/JSON)
2. Search the output with `findstr`, `Select-String`, or your SIEM/forensic notebook

### Pivot Batch Template: `ExecutionArtifacts_Pivot.reb`

```yaml
Description: Artifact Pivot (Execution + User Activity)
Author: DFIR Team
Version: 1
Id: 8b0c0e7e-3c8e-4d62-a1cf-000000000002
Keys:
  # -----------------------------
  # SYSTEM Hive
  # -----------------------------

  - Description: BAM UserSettings (Background Activity Moderator)
    HiveType: SYSTEM
    Category: Program Execution
    KeyPath: ControlSet*\Services\bam\State\UserSettings\*
    Recursive: true

  - Description: DAM UserSettings (Desktop Activity Moderator)
    HiveType: SYSTEM
    Category: Program Execution
    KeyPath: ControlSet*\Services\dam\State\UserSettings\*
    Recursive: true

  # -----------------------------
  # NTUSER.DAT Hive
  # -----------------------------

  - Description: RunMRU (Windows+R)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    Recursive: false

  - Description: UserAssist (All GUIDs)
    HiveType: NTUSER
    Category: Program Execution
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
    Recursive: true

  - Description: FeatureUsage (All)
    HiveType: NTUSER
    Category: User Activity
    KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
    Recursive: true
```

### Run RECmd (Pivot Collection)

```
RECmd.exe -f SYSTEM --bn ExecutionArtifacts_Pivot.reb --csv E:\pivot_out
RECmd.exe -f C:\Users\Alice\NTUSER.DAT --bn ExecutionArtifacts_Pivot.reb --csv E:\pivot_out
```

### Pivot (Search) Examples

#### Windows `findstr`

Search all pivot CSV output for a suspicious string:

```
findstr /S /I "svchost.exe C:\Users\Public mimikatz" E:\pivot_out\*.csv
```

#### PowerShell `Select-String`

```
Get-ChildItem E:\pivot_out\*.csv | Select-String -Pattern "svchost.exe","mimikatz","C:\Temp" -CaseSensitive:$false
```

#### Linux/WSL `grep` (if your output is staged on a Linux host)

```
grep -RinE "svchost\.exe|mimikatz|C:\Temp" ./pivot_out/
```

### Notes

- This pivot batch intentionally targets **broader parent keys** for UserAssist and FeatureUsage to maximize recall.
- If you want higher precision, use the earlier **Custom** batch file with specific GUIDs/subkeys.

---

## Tooling Summary

| Artifact   | Tools |
|----------|-------|
| Prefetch | PECmd.exe |
| Amcache  | AmcacheParser.exe |
| ShimCache| AppCompatCacheParser.exe |

Additional Helpful Tools:

- Timeline Explorer
- KAPE
- Plaso / log2timeline

---

## References

- Eric Zimmerman Tools
- Microsoft Windows Internals
- SANS DFIR Posters

---

*Author: DFIR Reference*
