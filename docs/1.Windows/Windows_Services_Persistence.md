# Windows Services Persistence (DFIR)

This document provides a **Digital Forensics & Incident Response (DFIR)**–focused overview of **Windows Services** as a persistence mechanism.

Windows services are one of the most common and resilient ways attackers maintain access because they:

* execute with elevated privileges
* can start automatically at boot or logon
* may run without user interaction
* blend in with legitimate system services

---

## Table of Contents

1. [Windows Services Overview](#windows-services-overview)
2. [Service Registry Location](#service-registry-location)
3. [How Services Work](#how-services-work)
4. [Service Accounts](#service-accounts)
5. [Persistence-Relevant Settings](#persistence-relevant-settings)
6. [Start Values and Persistence](#start-values-and-persistence)
7. [Forensic Value](#forensic-value)
8. [Key Data Points](#key-data-points)
9. [Examples of Malicious Service Tradecraft](#examples-of-malicious-service-tradecraft)
10. [How to Investigate Services](#how-to-investigate-services)
11. [Tools and Commands](#tools-and-commands)
12. [Evasion Techniques](#evasion-techniques)

---

## Windows Services Overview

A **Windows Service** is a long-running executable (or driver) managed by the **Service Control Manager (SCM)**. Services can:

* start during system boot
* start automatically at logon
* start on demand
* restart on failure

Services are frequently used by:

* operating system components
* device drivers
* enterprise security tooling
* endpoint management platforms

Attackers abuse services because they provide:

* **privileged persistence**
* **reliable execution**
* a mechanism that can survive reboots

---

## Service Registry Location

### Persistence Location

```
HKLM\SYSTEM\CurrentControlSet\Services
```

This key contains:

* service configurations
* device driver configurations
* parameters for each service/driver
* executable path and launch settings

Offline path:

* Hive: `SYSTEM`
* File location: `C:\Windows\System32\config\SYSTEM`

---

## How Services Work

Services are controlled by the **Service Control Manager (SCM)**.

Key concepts:

* SCM loads service configuration from registry
* SCM starts services based on the `Start` value
* Services can be configured to restart on failure
* Many services run without interactive desktops

Services can be:

* user-mode services (`.exe`)
* kernel-mode drivers (`.sys`)

---

## Service Accounts

Services typically run under one of these built-in accounts:

### LocalSystem

* Highest default privilege on the local machine
* Has extensive local rights
* Can access network as the computer account (`DOMAIN\\HOSTNAME$`)

### LocalService

* Limited local privileges
* Uses anonymous credentials on the network

### NetworkService

* Limited local privileges
* Uses the computer account on the network

### Custom Service Accounts

* Domain user accounts
* Managed Service Accounts (MSA/gMSA)

**DFIR Tip:** Persistence is more suspicious when:

* a service runs as LocalSystem but does not need to
* a service uses an unexpected domain account

---

## Persistence-Relevant Settings

Each service has a registry subkey:

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

Common values include:

* `ImagePath` – binary path or driver path
* `Start` – startup type
* `Type` – service vs driver
* `ObjectName` – the account used to run the service
* `Description`
* `DisplayName`

---

## Start Values and Persistence

The `Start` value determines when the service/driver loads.

| Start Value (Hex) | Meaning       | Persistence Impact                          |
| ----------------- | ------------- | ------------------------------------------- |
| `0x00`            | Boot (driver) | **Very high** – loads during boot (drivers) |
| `0x01`            | System        | High – loads early                          |
| `0x02`            | Automatic     | High – starts automatically                 |
| `0x03`            | Manual        | Medium – requires trigger                   |
| `0x04`            | Disabled      | None (unless modified)                      |

### Why `0x02` and `0x00` Matter

* `0x02` services ensure malware runs after reboot
* `0x00` boot-start drivers can run before many security controls initialize

---

## Forensic Value

Services help answer:

* How did persistence occur?
* Was a new service created or an existing service modified?
* What binary executed and where is it located?
* What account/privilege context is used?
* Was failure recovery configured to execute malware?

---

## Key Data Points

When analyzing a suspicious service, extract:

* `ServiceName` (registry key name)
* `DisplayName` and `Description`
* `ImagePath` (target binary)
* `Start` type
* `Type` (service vs driver)
* `ObjectName` (account)
* service DLL / parameters if present
* timestamps (registry key last write)

---

## Examples of Malicious Service Tradecraft

### 1) New Service Creation (APT1 Example)

**Technique:** Create a new service pointing to a malicious binary.

Example:

* Service name: `IPRIP`
* Display name: `RIP Listener Service`

Registry Example (Registry Explorer):

```
Key: ...\Services\IPRIP
ImagePath: "C:\Windows\Temp\iprip.exe"
Start: 0x02
ObjectName: LocalSystem
DisplayName: RIP Listener Service
```

Forensic indicators:

* Service name not aligned with vendor
* Binary in `Temp` / user-writable path

---

### 2) Service Replacement (GlassRAT Example)

**Technique:** Replace a legitimate but disabled service with a malicious payload.

Known example:

* Service: `RasAuto` (Remote Access Auto Connection Manager)
* Attacker replaces `ImagePath` to point to malicious executable

Registry Example:

```
Key: ...\Services\RasAuto
ImagePath: "C:\ProgramData\rasauto.exe"
Start: 0x02
```

Forensic indicators:

* Service name is legitimate
* Binary path is not

---

### 3) Service Failure Recovery Abuse

**Technique:** Configure failure actions to launch malware.

Attacker approach:

* Force service to crash
* Configure failure recovery to execute malicious binary

Evidence may include:

* unusual `FailureActions`
* unexpected `sc failure` configuration

Example Behavior:

```
sc failure "Spooler" reset= 0 actions= restart/5000/run/5000
sc failureflag "Spooler" 1
```

Forensic indicators:

* critical service failure actions running unknown executables

---

## How to Investigate Services

### Services Persistence Triage Checklist

Use this checklist during incident response to quickly assess whether a service is likely malicious.

#### 1) Identify High-Risk Services First

* [ ] Newly created service names (not present in baseline)
* [ ] Recently modified service keys (LastWrite time on `...\Services\<Name>`)
* [ ] Services with **Start = 0x02 (Automatic)** unexpectedly
* [ ] Drivers with **Start = 0x00 (Boot)** or `0x01 (System)` that are unknown

#### 2) Validate Service Identity

* [ ] Does `DisplayName` / `Description` match expected vendor/software?
* [ ] Does the service name masquerade as Windows (e.g., `Windows Audio Driver`, `Update Service`)?
* [ ] Is the service name similar to legitimate service names (typosquatting)?

#### 3) Inspect ImagePath & Parameters

* [ ] Does `ImagePath` point to **user-writable locations**?

  * `C:\Users\Public`
  * `%AppData%` / `%LocalAppData%`
  * `%Temp%`
  * `C:\ProgramData`
  * `C:\Windows\Temp`
* [ ] Is the binary signed and from an expected publisher?
* [ ] Are there suspicious command line patterns?

  * `powershell.exe -enc`
  * `cmd.exe /c`
  * `rundll32.exe`
  * `mshta.exe`
  * `.vbs`, `.js`, `.ps1`
* [ ] Is there unusual quoting or spacing in the path (common evasion)?

#### 4) Account/Privilege Context (ObjectName)

* [ ] Runs as **LocalSystem** when not expected
* [ ] Runs as **NetworkService/LocalService** but points to suspicious binary
* [ ] Runs as a domain user or custom account unexpectedly

#### 5) Startup Behavior

* [ ] `Start` type appears inconsistent with service function
* [ ] Service set to auto-start but should be manual
* [ ] Disabled service (`0x04`) was changed to auto-start

#### 6) Failure Recovery / FailureActions Abuse

* [ ] Failure actions configured unusually (restart loops)
* [ ] Failure actions set to execute programs (launch malware)
* [ ] Service appears intentionally crashing to trigger failure recovery

Use:

```
sc qfailure <ServiceName>
```

#### 7) Correlate With Logs

* [ ] System log: **7045** (service installed)
* [ ] System log: **7036** (service state changed)
* [ ] Security log: **4697** (service installed — if enabled)

#### 8) Correlate With Execution Artifacts

* [ ] Prefetch shows service executable execution
* [ ] Amcache records dropped service binary hash
* [ ] ShimCache indicates presence of service payload
* [ ] BAM/DAM corroborates user-context execution (if applicable)

#### 9) Containment & Evidence

* [ ] Preserve SYSTEM hive + EVTX logs
* [ ] Collect the service binary and compute hashes
* [ ] Capture service configuration output:

```
sc qc <ServiceName>
sc qfailure <ServiceName>
```

---

### Quick Triage Questions

* Is this service **new** or recently modified?
* Does `ImagePath` point to a legitimate signed binary?
* Is the binary located in a **user-writable directory**?
* Is `Start` set to `0x02` (Automatic) unexpectedly?
* Is the service running as **LocalSystem**?
* Are failure actions configured unusually?

---

## Recommended Indicator List (Services Persistence Hunting)

Use this list to pivot quickly when reviewing services via **Autoruns**, `sc`, Registry Explorer/RECmd output, or EVTX parsing.

### High-Signal LOLBins / Service Abuse Targets

Search for these executables appearing in `ImagePath` or parameters:

* `powershell.exe` / `pwsh.exe`
* `cmd.exe`
* `rundll32.exe`
* `regsvr32.exe`
* `mshta.exe`
* `wscript.exe` / `cscript.exe`
* `bitsadmin.exe`
* `certutil.exe`
* `schtasks.exe` (often used alongside services)

### Suspicious Command-Line Patterns

* `-enc` / `-encodedcommand`
* `IEX` / `Invoke-Expression`
* `FromBase64String`
* `DownloadString`
* `WebClient`
* `Start-Process`
* `Hidden` / `WindowStyle Hidden`
* DLL execution patterns:

  * `rundll32.exe <dll>,<export>`

### High-Risk Paths for Service Binaries

These paths are suspicious as service targets (especially for auto-start services):

* `C:\ProgramData`
* `C:\Users\Public`
* `%AppData%` / `\AppData\Roaming`
* `%LocalAppData%` / `\AppData\Local`
* `%Temp%` / `\AppData\Local\Temp`
* `C:\Windows\Temp`

### Common Masquerading Filenames

Look for these names when they appear outside `C:\Windows\System32`:

* `svchost.exe`
* `lsass.exe`
* `services.exe`
* `spoolsv.exe`
* `taskhostw.exe`
* `winlogon.exe`
* `explorer.exe`

### Naming Patterns That Deserve Scrutiny

* Services with vague names:

  * `Update Service`, `Windows Update Helper`, `Security Service`
* Random-looking names:

  * `svc123`, `a1b2c3`, `WinSysHost`
* Typosquatting:

  * `WindiwsUpdate`, `Micros0ft`

### Quick Pivot Strings

Use these directly in `findstr` / PowerShell searches:

* `powershell.exe -enc`
* `rundll32.exe`
* `mshta.exe`
* `\programdata\`
* `\users\public\`
* `\appdata\`
* `\temp\`

---

## Tools and Commands

### Sysinternals Autoruns

Autoruns highlights:

* Services tab shows auto-start services
* detects unsigned binaries
* provides quick triage of persistence locations

---

### Built-in Commands (`sc`)

List all services:

```
sc query state= all
```

Query a specific service:

```
sc qc <ServiceName>
```

Query failure actions:

```
sc qfailure <ServiceName>
```

---

### Registry Explorer + RECmd

**Registry Explorer**:

* Load `SYSTEM` hive
* Navigate to:

  * `ControlSet001\\Services`
  * `CurrentControlSet\\Services`

RECmd batch parsing example:

```
RECmd.exe -f SYSTEM --kn "ControlSet*\\Services" --csv services.csv
```

---

### Kansa Framework — Get-SvcFail.ps1

Kansa includes scripts for service misconfiguration and failure actions.

Example:

```
.\\Get-SvcFail.ps1
```

DFIR Use:

* quickly enumerates suspicious failure recovery
* highlights services launching binaries on failure

---

## RECmd Batch Template (.reb) — Services (Including FailureActions)

Below is a cohesive RECmd batch file you can save as:

* `Services_Persistence.reb`

It targets common service persistence indicators under `CurrentControlSet\Services` and also extracts the `Control` keys commonly used to store service **FailureActions**.

> Note: Service configuration can exist under `ControlSet00x` and `CurrentControlSet`. Using `ControlSet*` maximizes recall for offline hives.

```yaml
Description: Windows Services Persistence (Services + FailureActions)
Author: DFIR Team
Version: 1
Id: 8b0c0e7e-3c8e-4d62-a1cf-000000000020
Keys:
  - Description: Services (All) — Current/ControlSets
    HiveType: SYSTEM
    Category: Persistence
    KeyPath: ControlSet*\Services
    Recursive: true

  - Description: Service Control (FailureActions / FailureActionsOnNonCrashFailures)
    HiveType: SYSTEM
    Category: Persistence
    KeyPath: ControlSet*\Control
    Recursive: true
```

### RECmd Usage Examples

Single hive:

```
RECmd.exe -f SYSTEM --bn Services_Persistence.reb --csv E:\out
```

Directory of hives (post-KAPE):

```
RECmd.exe -d E:\KAPE\Files --bn Services_Persistence.reb --csv E:\out
```

**Pivot Tip:** After export, search for:

* suspicious paths (`C:\ProgramData`, `C:\Users\Public`, `\Temp`)
* LOLbins (`rundll32.exe`, `powershell.exe`, `mshta.exe`)
* unexpected drivers (`.sys` under non-standard directories)

---

## KAPE Targets & Modules (Services + Event Logs)

To investigate service persistence, collect:

* `SYSTEM` hive (service configuration)
* Windows Event Logs containing service creation/start/stop evidence

### What to Collect

| Evidence               | Where         | Notes                                   |
| ---------------------- | ------------- | --------------------------------------- |
| Service configs        | `SYSTEM` hive | `C:\Windows\System32\config\SYSTEM`     |
| Service install events | Security log  | Event ID **4697** (if auditing enabled) |
| Service creation (SCM) | System log    | Event ID **7045**                       |
| Service state changes  | System log    | Event ID **7036**                       |

### KAPE Targets

Target names vary by your KAPETargets pack, but commonly include:

* `SYSTEM` or `RegistryHives`
* `EventLogs` or `EVTX`

Example collection:

```
kape.exe --tsource C: --tdest E:\KAPE --target SYSTEM,EventLogs
```

### KAPE Modules (Optional Parsing)

* `RECmd` (parse SYSTEM hive)
* `EvtxECmd` (parse EVTX)

Example collect + parse:

```
kape.exe --tsource C: --tdest E:\KAPE --target SYSTEM,EventLogs --module RECmd,EvtxECmd
```

> Tip: If you have a custom RECmd module/batch, point the module to `Services_Persistence.reb`.

---

## MITRE ATT&CK Mapping (Services)

### Persistence

* **T1543.003 – Create or Modify System Process: Windows Service**

  * Creating a new service (e.g., `sc create`)
  * Modifying an existing service (`ImagePath`, `Start`, `ObjectName`)
  * Service replacement (legitimate service name, malicious binary)

### Privilege Escalation (Related)

* **T1543.003** often results in execution under high privilege (LocalSystem)

### Defense Evasion (Related)

* **T1036 – Masquerading**

  * Legitimate-sounding service names/descriptions
  * Reusing real service names

* **T1070 – Indicator Removal on Host**

  * Removing service keys
  * Clearing System/Security logs

* **T1562 – Impair Defenses**

  * Disabling logging/auditing needed for 4697

### Execution (Related)

* **T1059 – Command and Scripting Interpreter**

  * Services that execute `cmd.exe`, `powershell.exe`, scripts

---

## Evasion Techniques

Attackers may:

* masquerade service names/descriptions
* use legitimate service names (service replacement)
* point `ImagePath` to:

  * `C:\ProgramData`
  * `C:\Users\Public`
  * `%AppData%`
* use signed LOLbins as service targets
* disable logging or clear event logs
* revert registry hives / timestomp binaries

---

## References

* Microsoft Service Control Manager documentation
* Sysinternals Autoruns
* MITRE ATT&CK T1543.003 (Windows Service)
* Kansa Framework
