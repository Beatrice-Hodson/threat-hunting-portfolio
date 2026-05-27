# Splunk Field Reference — Sysmon & Windows Event IDs

> A quick-reference cheat sheet for table queries during active threat hunts. Use these field sets to surface the right data fast without having to look up field names mid-investigation.

---

## Sysmon Events

### EID 1 — Process Creation

    index=sysmon EventCode=1
    | table _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel

**Key fields:**
- `Image` — full path of the process that was created
- `CommandLine` — full command line including arguments
- `ParentImage` — the process that spawned this one
- `ParentCommandLine` — command line of the parent process
- `IntegrityLevel` — privilege level (System, High, Medium, Low)

**Additional fields for process verification:**

    | table _time, host, Image, CommandLine, Company, MD5, SHA256

- `Company` — vendor name from binary metadata — blank or unexpected value = suspicious
- `MD5` / `SHA256` — submit to VirusTotal on any unknown binary

**Reference:** https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

### EID 3 — Network Connection

    index=sysmon EventCode=3
    | table _time, Computer, User, Image, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol

**Key fields:**
- `Image` — process making the network connection
- `DestinationIp` / `DestinationPort` — where the connection is going
- `SourceIp` — useful for identifying internal pivot hosts

**Hunting value:** Unexpected outbound connections from trusted processes (svchost, explorer), connections on unusual ports (8080, 4444), workstations connecting to external IPs.

---

### EID 11 — File Creation

    index=sysmon EventCode=11
    | table _time, Computer, User, TargetFilename, Image, ProcessId

**Key fields:**
- `TargetFilename` — full path of the file created
- `Image` — process that created the file

**Hunting value:** Executables dropped to unusual paths (Temp, AppData, Public), files created by Office or browser processes, payloads written to C:\Windows by non-installer processes.

---

### EID 13 — Registry Value Set

    index=sysmon EventCode=13
    | table _time, Computer, User, TargetObject, Details, Image, ProcessGuid, ProcessId

**Key fields:**
- `TargetObject` — full registry path being modified
- `Details` — the value being written
- `Image` — process making the registry modification

**Hunting value:** Modifications to Run keys, services registry entries, or any persistence-related registry paths. Note: when a service is created on Windows, a corresponding registry entry is created under `HKLM\SYSTEM\CurrentControlSet\Services\` — cross-reference with EID 7045 and Sysmon EID 13 together for full service installation picture.

---

### EID 17 & 18 — Pipe Created / Pipe Connected

    index=sysmon EventCode=17 OR EventCode=18
    | table _time, Computer, User, EventID, EventType, PipeName, Image, ProcessId

**Key fields:**
- `PipeName` — name of the named pipe
- `EventID` — 17 = pipe created, 18 = pipe connected
- `Image` — process creating or connecting to the pipe

**Hunting value:** PsExec and RemCom use named pipes for communication. EID 17 (pipe created) followed by EID 18 (pipe connected) from System (PID 4) is a strong lateral movement indicator. Look for pipes with random or tool-specific naming patterns.

---

## Windows Event Log Events

### Winevent 4688 — Process Creation

    index=wineventlog EventCode=4688
    | table _time, Computer, SubjectUserName, NewProcessName, NewProcessId, CommandLine, ParentProcessName, ProcessId

**Key fields:**
- `NewProcessName` — process being created
- `CommandLine` — requires audit policy to be enabled for command line logging
- `ParentProcessName` — spawning process
- `ProcessId` — this returns the Creator Process ID (parent process ID)
- `SubjectUserName` — account context the process ran under

**Note:** Requires "Include command line in process creation events" audit policy to be enabled. Without it, CommandLine will be blank.

---

### Winevent 1102 — Audit Log Cleared (Security Log)

    index=wineventlog EventCode=1102
    | table _time, Computer, Channel, EventID, ClientProcessId, SubjectUsername, name

**Key fields:**
- `SubjectUsername` — who cleared the log
- `Channel` — which log was cleared
- `ClientProcessId` — process that performed the action

**Hunting value:** Log clearing is a defense evasion technique (MITRE T1070.001). Any instance of 1102 during an investigation should be treated as a high-priority finding — the attacker is covering tracks.

---

### Winevent 104 — System Log Cleared

    index=wineventlog EventCode=104
    | table _time, Computer, Channel, EventID, object, action

**Key fields:**
- `Channel` — confirms System log was cleared
- `object` / `action` — what was cleared and how

**Hunting value:** Companion to 1102. EID 1102 covers Security log clearing, EID 104 covers System log clearing. Hunt both together — an attacker clearing logs will often clear multiple channels.

---

### Winevent 7045 — New Service Installed

    index=wineventlog EventCode=7045
    | table _time, Computer, AccountName, ServiceName, ImagePath, ServiceType, StartType

**Key fields:**
- `ServiceName` — name of the new service
- `ImagePath` — executable the service runs
- `AccountName` — account used to install the service
- `StartType` — auto, manual, disabled — auto on a new unknown service is suspicious

**Hunting value:** Service creation events are an anomaly in and of themselves and should always be investigated. Random short service names (4-8 characters), services pointing to executables in non-standard paths, and services installed outside of change windows are high-confidence indicators.

**Cross-reference:** When a service is created, Windows automatically creates a corresponding registry entry under `HKLM\SYSTEM\CurrentControlSet\Services\`. Cross-reference EID 7045 with Sysmon EID 13 (Registry Value Set) to get the full picture of service installation.

---

## Quick Reference Summary

| Event ID | Source | What It Shows |
|---|---|---|
| 1 | Sysmon | Process creation — command lines, parent-child chains |
| 3 | Sysmon | Network connections — C2, lateral movement |
| 11 | Sysmon | File creation — dropped payloads, staged tools |
| 13 | Sysmon | Registry modifications — persistence, service creation |
| 17 | Sysmon | Named pipe created — PsExec/RemCom lateral movement |
| 18 | Sysmon | Named pipe connected — confirms pipe-based lateral movement |
| 4688 | Windows Security | Process creation — requires audit policy for CommandLine |
| 1102 | Windows Security | Security log cleared — defense evasion |
| 104 | Windows System | System log cleared — defense evasion |
| 7045 | Windows System | New service installed — always investigate |

---

*Part of the Threat Hunting Portfolio — github.com/Beatrice-Hodson/threat-hunting-portfolio*
