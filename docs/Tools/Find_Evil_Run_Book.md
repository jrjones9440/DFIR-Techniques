# Find Evil DFIR Run Book (SANS Hunt Evil Poster Driven)

> **Purpose:** This run book operationalizes the **SANS DFIR “Hunt Evil / Find Evil” poster** into an Incident Response + Forensic Analysis workflow. It provides step-by-step **collection**, **analysis**, and **hunting** checklists, including a **RECmd `.reb` bundle** for poster registry artifacts.  
> Source poster: **SANS DFIR Hunt Evil Poster** 

---

## Table of Contents
1. [Operating Rules](#operating-rules)
2. [Response Modes](#response-modes)
3. [Collection Plan](#collection-plan)
4. [Know Normal (Process Baseline)](#know-normal-process-baseline)
5. [Evidence of Program Execution](#evidence-of-program-execution)
6. [Lateral Movement](#lateral-movement)
7. [KAPE Collection Mapping](#kape-collection-mapping)
8. [Deliverables](#deliverables)
9. [Appendix A — RECmd `.reb` Bundle](#appendix-a--recmd-reb-bundle)

---

## Operating Rules

### Evidence handling
- Maintain **chain of custody** for all media/images/exports.
- Record:
  - Hostname / asset ID
  - Date/time acquired (UTC)
  - Tool used + version
  - Hashes (MD5/SHA256)

### Time normalization
- Record:
  - System time + timezone
  - NTP settings
- Normalize all timestamps to **UTC** for correlation.

---

## Response Modes

### Rapid Triage (30–90 minutes/host)
Use when immediate scoping is needed.
Collect:
- Volatile triage (processes + net connections)
- Event logs (Security/System + poster-relevant operational logs)
- Registry hives (SYSTEM/SOFTWARE/SAM/SECURITY + user hives)
- Execution artifacts (Prefetch, Amcache, ShimCache, BAM/DAM, SRUM, Jump Lists)

### Full Forensic Acquisition (2–6+ hours/host)
Use when:
- Privilege escalation is suspected
- Malware present/unknown
- Lateral movement is confirmed
- Legal/regulatory requirements exist  
Collect triage set +:
- Full disk image
- Full memory image
- pagefile/hiberfile
- VSS snapshots (if feasible)

---

## Collection Plan

### Minimum Artifact Checklist (per host)
**Memory**
- RAM capture (preferred)
- Running processes + command lines
- Network connections + listening ports
- Loaded modules / suspicious injections

**Disk**
- MFT / USN Journal (if possible)
- Prefetch (`C:\Windows\Prefetch`) 
- Amcache (`C:\Windows\AppCompat\Programs\Amcache.hve`) 
- SRUM (`C:\Windows\System32\SRU\SRUDB.dat`) 
- Jump Lists (AutomaticDestinations) 

**Registry**
- SYSTEM / SOFTWARE / SECURITY / SAM
- NTUSER.DAT and USRCLASS.DAT (primary users)
- Poster keys:
  - BAM/DAM
  - ShimCache/AppCompatCache
  - Services
  - Scheduled TaskCache
  - RDP Client servers list
  - MountPoints2
  - PowerShell ExecutionPolicy 

**Event logs**
- `Security.evtx`
- `System.evtx`
- Operational logs:
  - TaskScheduler Operational
  - PowerShell Operational + Windows PowerShell
  - WinRM Operational
  - WMI Activity Operational
  - RDPClient Operational
  - RdpCoreTS / RemoteConnectionManager / LocalSessionManager
  - SMBClient Security 

---

## Know Normal (Process Baseline)

The poster emphasizes **“Know Normal”** to identify malicious outliers quickly. 

### Baseline validation checklist
- [ ] Validate **image path** is expected (system binaries in correct directories)
- [ ] Validate **signature** (Microsoft signed expected for Windows binaries)
- [ ] Validate **parent process** is expected
- [ ] Validate **user context** (SYSTEM vs user context)
- [ ] Look for spelling tricks (`svch0st.exe`, `1sass.exe`, etc.)
- [ ] Identify anomalies:
  - weird command-line args
  - unsigned binaries in Windows dirs
  - unexpected children of `lsass.exe`, `services.exe`, `wininit.exe`

---

## Evidence of Program Execution

The poster execution artifacts to prioritize: **SRUM, BAM/DAM, UserAssist, Jump Lists, ShimCache, Prefetch, Amcache**. 

### SRUM
- Location: `C:\Windows\System32\SRU\SRUDB.dat`
- Hunt:
  - [ ] Identify apps with unusual network usage
  - [ ] Identify rare executables and spikes
  - [ ] Correlate with logon timestamps

### BAM/DAM
- Location:  
  - `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`  
  - `SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`  
  - `...bam\State\UserSettings\{SID}` (Win10 1809+) 
- Hunt:
  - [ ] Flag executions from user-writable dirs
  - [ ] Identify LOLBins used unusually

### UserAssist
- Location:  
  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` 
- Hunt:
  - [ ] Decode ROT13 values
  - [ ] Identify first-seen admin tools or remote tools

### Jump Lists
- Location:  
  `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` 
- Hunt:
  - [ ] Identify remote paths / staging locations
  - [ ] Map access to sensitive files

### ShimCache (AppCompatCache)
- Location:  
  - XP: `SYSTEM\...\Session Manager\AppCompatibility`  
  - Win7+: `SYSTEM\...\Session Manager\AppCompatCache` 
- Hunt:
  - [ ] Identify suspicious executables that existed on disk
  - [ ] Correlate with MFT/Amcache hashes

### Prefetch
- Location: `C:\Windows\Prefetch` 
- Hunt:
  - [ ] Identify suspicious EXE executions
  - [ ] Review embedded referenced files/paths

### Amcache.hve
- Location: `C:\Windows\AppCompat\Programs\Amcache.hve` 
- Hunt:
  - [ ] Extract SHA1 for suspicious binaries/drivers
  - [ ] Identify odd compilation time/publisher anomalies

---

## Lateral Movement

Poster provides a practical map for **Remote Access** and **Remote Execution** artifact hunting. 

### Remote Access: SMB / Admin shares
**Source host**
- Security log: **4648**
- SMBClient Security: **31001**
- Registry: MountPoints2, Shellbags
- Execution: ShimCache/BAM-DAM/Amcache/Prefetch for `net.exe` / `net1.exe` 

**Destination host**
- Security: **4624 Type 3**, **4672**, **4776**, **5140**, **5145**
- DC: **4768**, **4769**
- Files: attacker tool drops (creation time = copy time) 

### Remote Access: RDP
**Source**
- Registry: `NTUSER\...\Terminal Server Client\Servers`
- RDPClient Operational: **1024**, **1102**
- Files: Jump lists for MSTSC, bitmap cache, `Default.rdp`

**Destination**
- Security: **4624 Type 10**, **4778/4779**
- RDS logs: 1149, 21/22/25/41, 98/131 

### Remote Execution: Scheduled Tasks
- Security: **4698**, **4702**, **4699**, **4700/4701**
- TaskScheduler Operational: **106**, **140**, **141**, **200/201**
- Registry: TaskCache `Tasks` + `Tree`
- Files: `C:\Windows\Tasks`, `C:\Windows\System32\Tasks`, `C:\Windows\SysWOW64\Tasks` 

### Remote Execution: Services
- Security: **4697** (if enabled)
- System: **7034**, **7035**, **7036**, **7040**, **7045**
- Registry: `SYSTEM\CurrentControlSet\Services\` 

### Remote Execution: PowerShell Remoting / WinRM
- WinRM Operational: **6**, **91**, **142**, **161**, **169**
- PowerShell Operational: **40961**, **40962**, **8193/8194**, **8197**
- Script Block Logging: **4103/4104** (if enabled)
- Registry: ExecutionPolicy key 

### Remote Execution: WMI/WMIC
- WMI Activity Operational: **5857**, **5860**, **5861**
- Files: `.mof`, repository changes under `C:\Windows\System32\wbem\Repository` 

### Remote Execution: PsExec
- Registry:
  - `NTUSER.DAT\Software\Sysinternals\PsExec\EulaAccepted`
  - `SYSTEM\CCS\Services\PSEXESVC`
- System: **7045**
- Files: `psexesvc.exe` in `ADMIN$ (\Windows)` 
---

## KAPE Collection Mapping

**Triage KAPE target set**
- Registry: SYSTEM/SOFTWARE/SAM/SECURITY + NTUSER/USRCLASS
- Event logs: Security/System + poster operational logs
- Prefetch, Amcache, SRUM, Jump Lists, PSReadline history

**Full KAPE target set**
- Add: `$MFT`, `$UsnJrnl`, LNK files, browser artifacts, recycle bin, scheduled task folders, services keys

---

## Deliverables

**Per host**
- Collection log + hashes
- Execution evidence timeline (Prefetch/Amcache/ShimCache/BAM-DAM/SRUM/UserAssist/Jumplists)
- Auth + movement chain (source user/host → destination/method)
- IOC list (hashes, filenames/paths, service/task names, IPs/domains)

**Enterprise**
- Lateral movement map
- Affected host list
- Containment recommendations

---

## Appendix A — RECmd `.reb` Bundle

> Save as: `SANS_HuntEvil_PosterArtifacts.reb`  
> This RECmd bundle aligns to poster artifacts: **BAM/DAM, ShimCache, Amcache (hive), Services, Scheduled TaskCache**, plus key lateral-movement support keys (RDP servers, MountPoints2, PsExec, ExecutionPolicy). 

```xml
<?xml version="1.0" encoding="utf-8"?>
<RegistryExplorerBookmarkFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                              xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                              Comment="SANS Hunt Evil / Find Evil Poster - Registry Artifacts Bundle"
                              Author="DFIR Run Book"
                              Version="1">

  <!-- ========================= -->
  <!-- Evidence of Program Execution -->
  <!-- ========================= -->

  <!-- BAM/DAM (Win10+) -->
  <Bookmark Name="BAM - UserSettings (Win10+)"
            Category="Execution Evidence\BAM-DAM"
            Description="BAM tracks executed file full path and last execution time (typically ~1 week)."
            KeyPath="SYSTEM\CurrentControlSet\Services\bam\UserSettings" />

  <Bookmark Name="BAM - State (Win10 1809+)"
            Category="Execution Evidence\BAM-DAM"
            Description="Some Win10+ builds store execution data under State."
            KeyPath="SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" />

  <Bookmark Name="DAM - UserSettings (Win10+)"
            Category="Execution Evidence\BAM-DAM"
            Description="DAM tracks executed file full path and last execution time (typically ~1 week)."
            KeyPath="SYSTEM\CurrentControlSet\Services\dam\UserSettings" />

  <Bookmark Name="DAM - State (Win10 1809+)"
            Category="Execution Evidence\BAM-DAM"
            Description="Some Win10+ builds store execution data under State."
            KeyPath="SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" />

  <!-- ShimCache / AppCompatCache -->
  <Bookmark Name="ShimCache (XP) - AppCompatibility"
            Category="Execution Evidence\ShimCache"
            Description="XP-era AppCompatibility database location."
            KeyPath="SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility" />

  <Bookmark Name="ShimCache (Win7+) - AppCompatCache"
            Category="Execution Evidence\ShimCache"
            Description="Win7+ AppCompatCache (ShimCache). Presence != proof of execution."
            KeyPath="SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" />

  <!-- Prefetch control (EnablePrefetcher) -->
  <Bookmark Name="Prefetch Settings - PrefetchParameters"
            Category="Execution Evidence\Prefetch"
            Description="EnablePrefetcher value (0 disabled; 3 app launch + boot)."
            KeyPath="SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" />

  <!-- Amcache.hve (separate hive; include as an input hive) -->
  <Bookmark Name="Amcache - Root"
            Category="Execution Evidence\Amcache"
            Description="Amcache tracks program/driver presence; includes SHA1 for executables/drivers."
            KeyPath="Amcache" />

  <Bookmark Name="Amcache - File Entries (Common)"
            Category="Execution Evidence\Amcache"
            Description="Common Amcache file inventory areas vary by OS build; review subkeys for file path, publisher, SHA1."
            KeyPath="Amcache\Root" />

  <!-- ========================= -->
  <!-- Persistence & Remote Execution -->
  <!-- ========================= -->

  <!-- Services -->
  <Bookmark Name="Services - All"
            Category="Persistence\Services"
            Description="All services and drivers. Review ImagePath/ServiceDll/Start/Type/ObjectName/FailureActions."
            KeyPath="SYSTEM\CurrentControlSet\Services" />

  <Bookmark Name="Services - ControlSet001 (alt view)"
            Category="Persistence\Services"
            Description="Alternate control set view (helpful when CurrentControlSet is ambiguous)."
            KeyPath="SYSTEM\ControlSet001\Services" />

  <Bookmark Name="Services - ControlSet002 (alt view)"
            Category="Persistence\Services"
            Description="Alternate control set view (if present)."
            KeyPath="SYSTEM\ControlSet002\Services" />

  <!-- Scheduled Tasks TaskCache -->
  <Bookmark Name="Scheduled Tasks - TaskCache Tasks"
            Category="Persistence\Scheduled Tasks"
            Description="Task GUID nodes and metadata. Correlate to filesystem Tasks folder and event logs."
            KeyPath="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" />

  <Bookmark Name="Scheduled Tasks - TaskCache Tree"
            Category="Persistence\Scheduled Tasks"
            Description="Task names/folders mapping to task GUIDs. Good pivot for human-readable names."
            KeyPath="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" />

  <!-- ========================= -->
  <!-- Lateral Movement - Remote Access/Execution -->
  <!-- ========================= -->

  <!-- RDP destinations -->
  <Bookmark Name="RDP Client - Servers"
            Category="Lateral Movement\RDP (Source)"
            Description="Per-user RDP destination history (mstsc)."
            KeyPath="NTUSER\Software\Microsoft\Terminal Server Client\Servers" />

  <!-- MountPoints2 -->
  <Bookmark Name="MountPoints2 - Mapped Shares / Removable"
            Category="Lateral Movement\SMB (Source)"
            Description="Tracks remotely mapped shares and removable usage. Useful for net use / Explorer mappings."
            KeyPath="NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" />

  <!-- PsExec EULA -->
  <Bookmark Name="PsExec - EulaAccepted"
            Category="Lateral Movement\PsExec (Source)"
            Description="Sysinternals PsExec EULA acceptance indicator per-user."
            KeyPath="NTUSER\Software\Sysinternals\PsExec" />

  <!-- PowerShell Execution Policy -->
  <Bookmark Name="PowerShell - ExecutionPolicy"
            Category="Lateral Movement\PowerShell/WinRM"
            Description="ExecutionPolicy changes may indicate attacker loosening restrictions (e.g., Bypass)."
            KeyPath="SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" />

  <!-- WMI (limited; primary artifacts are logs + repository) -->
  <Bookmark Name="WMI - CIMOM"
            Category="Lateral Movement\WMI"
            Description="WMI service configuration helper key."
            KeyPath="SOFTWARE\Microsoft\WBEM\CIMOM" />

  <!-- ========================= -->
  <!-- Authentication / Context -->
  <!-- ========================= -->

  <Bookmark Name="LSA - Authentication Packages"
            Category="Context\Authentication"
            Description="Review Security Support Providers and auth packages for suspicious additions."
            KeyPath="SYSTEM\CurrentControlSet\Control\Lsa" />

  <Bookmark Name="Winlogon - Shell"
            Category="Context\Logon"
            Description="Default shell. Unexpected shells (cmd.exe/powershell.exe) can indicate persistence."
            KeyPath="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" />

</RegistryExplorerBookmarkFile>
```

---

### RECmd execution example (optional)
Example execution idea:
- Run the `.reb` against:
  - `SYSTEM`
  - `SOFTWARE`
  - `NTUSER.DAT`
  - `Amcache.hve`

Then merge outputs into your case timeline.

---

*End of run book.*
