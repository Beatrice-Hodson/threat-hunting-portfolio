# Attack Chain Analysis — Avongate Industries

> Full kill chain reconstruction from Kansa forensic artifacts with MITRE ATT&CK mapping.

---

## Kill Chain Overview

    [STAGE 1] Initial Access
        └── WKS-94ZA — DNS queries to raw.githubusercontent.com
        └── Payload delivered and executed

    [STAGE 2] Execution
        └── ggWmgFMT.exe (RemCom) written to C:\Windows
        └── L9XJe2iA.exe (Rozena backdoor) written to C:\Windows
        └── APPRUNTIME.EXE deployed — masquerading as legitimate Windows binary

    [STAGE 3] Privilege Escalation
        └── Binaries written to %systemroot% — requires SYSTEM privileges
        └── Attacker operating with or obtained SYSTEM-level access

    [STAGE 4] Persistence
        └── 6 independent mechanisms installed (see persistence-analysis.md)
        └── Mechanisms designed to recreate each other — attacker-side resilience

    [STAGE 5] Defense Evasion
        └── APPRUNTIME.EXE — name suggests legitimacy, no real Windows binary exists
        └── svchost.exe masquerading in Temp folder as "Diagostic System Host"
        └── Fileless execution — Base64 PS reverse shell runs in memory, no file on disk

    [STAGE 6] Command & Control
        └── TCP reverse shell → dormaire.euwf.cn:443 (fileless, in-memory)
        └── WMI payload delivery → fini-27q.pages.dev:8080/a
        └── Internal pivot host → 10.0.2.6

    [STAGE 7] Lateral Movement
        └── agadmin compromised account used for SMB sessions
        └── WKS-94ZA (x4 sessions) + WKS-A29B (x1 session)

    [STAGE 8] Collection
        └── Hidden staging share: share$ → C:\Users\Public\Music
        └── Data staged for exfiltration

---

## Stage-by-Stage Breakdown

### Stage 1 — Initial Access
**MITRE:** T1105 — Ingress Tool Transfer

- **Patient Zero:** WKS-94ZA
- DNS queries observed to raw.githubusercontent.com — used to pull down initial payload
- GitHub raw content hosting used to evade reputation-based URL filtering (trusted domain)

**Kansa Module:** Get-DNSCache

**Hunting Signal:** DNS queries to raw.githubusercontent.com or gist.githubusercontent.com from workstations — legitimate but frequently abused for payload delivery.

---

### Stage 2 — Execution
**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell

**ggWmgFMT.exe (RemCom)**
A remote command execution tool functionally similar to PsExec. Provides interactive remote command-line access without requiring a dedicated RAT. Frequently abused by threat actors as a living-off-the-land adjacent tool.

- MD5: 6983F7001DE10F4D19FC2D794C3EB534
- Written to C:\Windows — requires elevated privileges

**L9XJe2iA.exe (Rozena Backdoor)**
A known backdoor providing persistent reverse shell capability. Establishes outbound C2 connection to evade inbound firewall rules.

- MD5: 8D1F07419790D26A9F95CE353C9F88D3
- Written to C:\Windows — requires elevated privileges

**APPRUNTIME.EXE**
Masquerading binary — name designed to appear legitimate. No known Windows binary exists with this name. Validated using Strontic xcyclopedia.

**Kansa Module:** Get-ProcsWMI, Get-PrefetchListing

**Hunting Signal:** Executables written to C:\Windows from non-installer processes. Hash submission to VirusTotal on any unknown binary.

---

### Stage 3 — Privilege Escalation
**MITRE:** T1068 — Exploitation for Privilege Escalation

- All three malicious binaries written to %systemroot% (C:\Windows)
- Writing to this path requires SYSTEM-level privileges
- Attacker either arrived with SYSTEM access or escalated shortly after initial execution

**Hunting Signal:** Process writing executable files to C:\Windows where the parent process is not a trusted installer (msiexec, Windows Update, etc.)

---

### Stage 4 — Persistence
**MITRE:** T1547.001, T1053.005, T1543.003, T1546.003, T1136.001

Six persistence mechanisms deployed — see [persistence-analysis.md](./persistence-analysis.md) for full detail.

**Key tradecraft observation:** The Spooler service failure action (mechanism 4) was configured to reinstall the WMI Event Consumer (mechanism 5) if it was removed. Removing the WMI consumer without first fixing the Spooler failure action results in automatic re-infection on the next service failure. This is deliberate, sophisticated redundancy.

---

### Stage 5 — Defense Evasion
**MITRE:** T1036 — Masquerading

**APPRUNTIME.EXE** — Named to suggest it is a legitimate runtime component. No entry exists in Strontic xcyclopedia or any known Windows binary database.

**svchost.exe in Temp folder**

- Process name: svchost.exe
- Path: C:\Windows\Temp\
- Display name: Diagostic System Host (note: misspelling of "Diagnostic")

Legitimate svchost.exe only runs from C:\Windows\System32\. Any instance outside that path is malicious. The misspelled service display name is an additional indicator.

**Fileless Execution — Base64 PS Reverse Shell**

- Registry Run Key persistence executes a Base64-encoded PowerShell command
- Payload runs entirely in memory — no file written to disk
- Evades traditional AV/EDR file scanning
- C2: dormaire.euwf.cn:443

**Kansa Module:** Get-Autorunsc, Get-SvcAll

**Hunting Signal:** svchost.exe running from any path other than C:\Windows\System32\. Service display names with misspellings.

---

### Stage 6 — Command & Control
**MITRE:** T1071 — Application Layer Protocol
**MITRE:** T1090 — Proxy: Internal Proxy

Three simultaneous C2 channels:

| Channel | Destination | Method | VT Detections |
|---|---|---|---|
| Primary | dormaire.euwf.cn:443 | TCP reverse shell — fileless, in-memory | 13 vendors |
| Secondary | fini-27q.pages.dev:8080/a | WMI payload delivery | 7 vendors |
| Internal pivot | 10.0.2.6 | Internal host used as C2 relay | N/A |

Redundant C2 is a hallmark of sophisticated operators — losing one channel does not disrupt the operation.

**Kansa Module:** Get-Netstat, Get-DNSCache

**Hunting Signal:** Outbound connections from workstations to non-business IPs, especially on port 8080. Internal hosts receiving inbound connections from multiple workstations.

---

### Stage 7 — Lateral Movement
**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares

- Compromised agadmin domain account used for authentication
- SMB sessions observed into WKS-94ZA (x4) and WKS-A29B (x1)
- Source of SMB sessions: internal pivot host 10.0.2.6

**Kansa Module:** Get-SmbSession

**Hunting Signal:** SMB sessions using agadmin from unexpected source IPs. Multiple SMB sessions from a single source in a short timeframe.

---

### Stage 8 — Collection
**MITRE:** T1074 — Data Staged: Local Data Staging

- Hidden share share$ created on WKS-94ZA
- Mapped to C:\Users\Public\Music — an inconspicuous, world-readable path
- Data staged here prior to exfiltration

**Kansa Module:** Get-SmbShare

**Hunting Signal:** Admin shares ($ suffix) not present in environment baseline. Shares pointing to user-writable paths like C:\Users\Public\.

---

## MITRE ATT&CK Summary

| Stage | Tactic | Technique | ID |
|---|---|---|---|
| 1 | Initial Access | Ingress Tool Transfer | T1105 |
| 2 | Execution | PowerShell | T1059.001 |
| 3 | Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| 4 | Persistence | Registry Run Keys | T1547.001 |
| 4 | Persistence | Scheduled Task | T1053.005 |
| 4 | Persistence | Windows Service | T1543.003 |
| 4 | Persistence | WMI Event Subscription | T1546.003 |
| 4 | Persistence | Create Local Account | T1136.001 |
| 5 | Defense Evasion | Masquerading | T1036 |
| 6 | Command & Control | Application Layer Protocol | T1071 |
| 6 | Command & Control | Internal Proxy | T1090 |
| 7 | Lateral Movement | SMB | T1021.002 |
| 8 | Collection | Local Data Staging | T1074 |

---

*See [persistence-analysis.md](./persistence-analysis.md) for detailed breakdown of all 6 persistence mechanisms.*
*See [ioc-list.md](./ioc-list.md) for containment-ready indicators.*
