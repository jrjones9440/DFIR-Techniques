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

