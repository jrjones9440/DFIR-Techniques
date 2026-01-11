# Windows Execution Artifacts for DFIR

This README provides a **Digital Forensics & Incident Response (DFIR)**–focused overview of three core Windows execution artifacts:

* **Prefetch**
* **Amcache**
* **ShimCache (AppCompatCache)**

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

* Enabled by default on most desktop versions of Windows
* Stored as `.pf` files
* Limited in count (typically 128–1024 files depending on OS)

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

* **Was this program executed?**
* **How many times was it executed?**
* **When was it last executed?**
* **Which files and DLLs were accessed?**

This makes Prefetch extremely useful for:

* Malware execution confirmation
* Living-off-the-land (LOLbin) abuse
* Timeline reconstruction

---

### Key Data Points

* Executable name
* Full path of executable
* Run count
* Last execution timestamp
* Referenced files and DLLs

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

* `-d` : Directory of Prefetch files
* `--csv` : Export to CSV
* `--json` : Export to JSON

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

* Executable file paths
* File hashes (SHA1)
* Compilation timestamps
* First-seen timestamps
* Program metadata (company name, product name)

This is critical for:

* Identifying dropped malware
* Detecting renamed binaries
* Validating attacker toolkits

---

### Key Data Points

* File path
* SHA1 hash
* File size
* Compile time
* First execution time
* Program name and vendor

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

* `-f` : Path to Amcache hive
* `--csv` : CSV output
* `--json` : JSON output

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

* Identify presence of executables
* Discover files that were deleted
* Detect attacker staging activity

Best used in **correlation with other artifacts**.

---

### Key Data Points

* File path
* Last modified timestamp
* File size (varies by OS)

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

* `-f` : SYSTEM hive
* `--csv` : CSV output
* `--json` : JSON output

---

## Correlation & Analyst Tips

### Execution Confidence Ranking

| Artifact  | Execution Confidence |
| --------- | -------------------- |
| Prefetch  | High                 |
| Amcache   | Medium–High          |
| ShimCache | Low                  |

### Analyst Tips

* **Correlate timestamps** across artifacts
* Look for **renamed LOLbins** (e.g., `svchost.exe` in user directories)
* Use **Amcache hashes** to pivot into malware databases
* Prefetch absence does **not** mean no execution

---

## Timeline Correlation Example

### Scenario

An analyst is investigating suspected malware execution involving a renamed credential-dumping tool (`svchost.exe`) dropped into a user-writable directory.

The goal is to **correlate Prefetch, Amcache, and ShimCache** to assess execution confidence and build a timeline.

### Correlated Timeline

| Timestamp (UTC)     | Artifact  | Evidence                       |
| ------------------- | --------- | ------------------------------ |
| 2024-11-16 22:09:58 | ShimCache | File present in Temp directory |
| 2024-11-17 02:31:44 | Amcache   | SHA1 recorded, FirstRunTime    |
| 2024-11-18 13:42:51 | Prefetch  | RunCount = 3                   |

### Analyst Interpretation

* **ShimCache** shows early presence (possible staging)
* **Amcache** confirms file metadata and first execution
* **Prefetch** strongly confirms repeated execution

Combined, these artifacts provide **high confidence execution evidence**.

---

## KAPE Targets

KAPE (Kroll Artifact Parser and Extractor) can be used to collect and parse these artifacts at scale.

### Prefetch Targets

```
Targets\Windows\Prefetch.tkape
```

Collects:

* Prefetch files (`*.pf`)

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

* Amcache.hve

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

* SYSTEM registry hive

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

* Indicates the file existed on disk prior to execution

#### Amcache

* Records SHA1 hash and first execution time
* Hash does not match legitimate Windows binary

#### Prefetch

* Confirms execution and multiple runs

---

### Final Assessment

| Question              | Answer |
| --------------------- | ------ |
| Was the file present? | Yes    |
| Was it executed?      | Yes    |
| Was it persistent?    | Likely |
| Is it legitimate?     | No     |

### Analyst Conclusion

The binary masquerading as `svchost.exe` was executed multiple times and is highly likely malicious.

---

## Common Attacker Evasion Techniques

Attackers are aware of Windows execution artifacts and may attempt to evade or limit forensic visibility. Understanding these techniques helps analysts avoid false negatives.

---

### Prefetch Evasion

**Techniques:**

* Disabling Prefetch via registry:

  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`
  * `EnablePrefetcher = 0`
* Using portable executables executed only once
* Executing binaries from removable media or network shares
* Deleting Prefetch files post-execution

**DFIR Notes:**

* Absence of Prefetch does **not** equal absence of execution
* Check OS version and Prefetch configuration
* Correlate with Amcache, ShimCache, and event logs

---

### Amcache Evasion

**Techniques:**

* Running malware purely in memory (reflective loading)
* Using scripts (PowerShell, JavaScript, WMI) instead of binaries
* Cleaning or replacing `Amcache.hve`

**DFIR Notes:**

* Amcache is resilient and often survives basic cleanup
* Look for suspicious compile times or mismatched metadata
* Hashes are valuable for threat intelligence pivoting

---

### ShimCache (AppCompatCache) Evasion

**Techniques:**

* Relying on the artifact’s ambiguity (presence ≠ execution)
* Clearing or rolling SYSTEM registry hives
* Executing binaries briefly and deleting them

**DFIR Notes:**

* ShimCache is best used as a **supporting artifact**
* Deleted malware often still appears here
* Timestamp interpretation varies by Windows version

---

### Living-off-the-Land (LOLbin) Abuse

**Techniques:**

* Abuse of signed Windows binaries:

  * `powershell.exe`
  * `wmic.exe`
  * `mshta.exe`
  * `rundll32.exe`

**DFIR Notes:**

* Prefetch still records LOLbin execution
* Focus on **command-line artifacts** and child processes
* Correlate with PowerShell logs, SRUM, and UserAssist

---

### Analyst Takeaways

* Never rely on a **single execution artifact**
* Artifact gaps are often intentional
* Correlation beats individual indicators
* Document evasion possibilities in reports

---

## MITRE ATT&CK Mapping

The following MITRE ATT&CK techniques are commonly associated with activity uncovered through Prefetch, Amcache, and ShimCache analysis.

---

### Execution

* **T1059 – Command and Scripting Interpreter**

  * PowerShell, CMD, WMIC, MSHTA execution often visible via Prefetch

* **T1204 – User Execution**

  * Malicious binaries executed via phishing or user interaction

* **T1047 – Windows Management Instrumentation**

  * WMI-launched executables may appear in Amcache and ShimCache

---

### Defense Evasion

* **T1036 – Masquerading**

  * Renamed binaries (e.g., `svchost.exe` in user directories)

* **T1070 – Indicator Removal on Host**

  * Deletion of Prefetch files or registry hives

* **T1112 – Modify Registry**

  * Disabling Prefetch or tampering with AppCompat settings

---

### Persistence (Related)

* **T1547 – Boot or Logon Autostart Execution**

  * Execution artifacts may reveal binaries later used for persistence

---

## Execution Investigation Workflow (Checklist)

The following checklist provides a **repeatable DFIR workflow** for investigating suspected program execution on Windows systems.

---

### 1. Initial Triage

* Identify suspicious filename or hash
* Note file location (system vs user-writable path)
* Check alerting source (EDR, SIEM, user report)

---

### 2. Prefetch Analysis

* Parse Prefetch directory with `PECmd.exe`
* Look for matching executable names
* Record:

  * Run count
  * Last execution time
  * Full execution path
* Validate Prefetch configuration status

---

### 3. Amcache Analysis

* Parse `Amcache.hve`
* Locate matching file paths or hashes
* Record:

  * SHA1 hash
  * Compile timestamp
  * First-seen / execution time
* Compare metadata against known-good binaries

---

### 4. ShimCache Analysis

* Parse SYSTEM hive AppCompatCache
* Identify presence of suspicious executables
* Note last modified timestamps
* Treat as **supporting evidence only**

---

### 5. Correlation & Validation

* Align timestamps across all artifacts
* Identify execution order and repetition
* Validate against:

  * Event logs
  * PowerShell logs
  * SRUM / UserAssist

---

### 6. Adversary Behavior Assessment

* Check for masquerading indicators
* Identify LOLbin usage
* Determine possible execution method (scripted vs binary)

---

### 7. Reporting & Response

* Document execution confidence level
* Note possible attacker evasion techniques
* Preserve parsed artifacts and raw evidence
* Escalate for containment and remediation

---

### Execution Confidence Summary

| Evidence             | Confidence |
| -------------------- | ---------- |
| Prefetch present     | High       |
| Amcache only         | Medium     |
| ShimCache only       | Low        |
| Correlated artifacts | Very High  |

---

## Tooling Summary

| Artifact  | Tools                    |
| --------- | ------------------------ |
| Prefetch  | PECmd.exe                |
| Amcache   | AmcacheParser.exe        |
| ShimCache | AppCompatCacheParser.exe |

Additional Helpful Tools:

* Timeline Explorer
* KAPE
* Plaso / log2timeline

---

## References

* Eric Zimmerman Tools
* Microsoft Windows Internals
* SANS DFIR Posters

---

*Author: DFIR Reference*
