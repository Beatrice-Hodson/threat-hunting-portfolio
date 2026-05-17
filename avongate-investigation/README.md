# Avongate Industries — Incident Response Investigation

> **Post-compromise forensic analysis of an enterprise intrusion using Kansa-collected artifacts.**  
> Conducted as part of structured threat hunting methodology practice.

---

## Executive Summary

Avongate Industries experienced a multi-stage intrusion in which an attacker gained initial access, established persistence through six independent mechanisms, moved laterally across the environment, and maintained command-and-control (C2) communication via three external channels.

This investigation was conducted using host-based forensic artifacts collected via **Kansa**, a PowerShell-based incident response framework. Analysis covered DNS cache, prefetch, running processes, active network connections, SMB sessions, scheduled tasks, services, and WMI event consumers across multiple workstations.

**The attacker demonstrated advanced tradecraft** — deliberately deploying redundant persistence mechanisms designed to survive partial remediation. A naive approach of removing persistence in the wrong order would have allowed the attacker to re-establish a foothold.

---

## Key Findings

| Finding | Detail |
|---|---|
| **Patient Zero** | WKS-94ZA |
| **Initial Access Vector** | DNS queries to raw.githubusercontent.com — payload delivery |
| **Malware Identified** | ggWmgFMT.exe (RemCom/C2) + L9XJe2iA.exe (Rozena backdoor) |
| **Masquerading Binary** | APPRUNTIME.EXE — no legitimate Windows binary exists with this name |
| **Persistence Mechanisms** | 6 independent mechanisms — mutually reinforcing by design |
| **Lateral Movement** | Compromised agadmin account — SMB sessions into WKS-94ZA (x4) + WKS-A29B (x1) |
| **C2 Channels** | dormaire.euwf.cn:443 (reverse shell) + fini-27q.pages.dev:8080 (WMI Consumer payload) + 10.0.2.6 (internal pivot) |
| **Staging Share** | share$ → C:\Users\Public\Music (hidden staging directory) |
| **Backdoor Account** | helpdesk — local admin created by attacker on WKS-94ZA |

---

## Attack Overview

```
Initial Access (WKS-94ZA)
DNS queries → raw.githubusercontent.com
        │
        ▼
Execution
ggWmgFMT.exe (RemCom) + L9XJe2iA.exe (Rozena) written to C:\Windows
APPRUNTIME.EXE masquerading as legitimate binary
        │
        ▼
Privilege Escalation
Binaries written to %systemroot% — requires SYSTEM privileges
        │
        ▼
Persistence (6 mechanisms — redundant by design)
Registry Run Key → Scheduled Task → Service
Spooler Failure Action → WMI Consumer → Backdoor Account
        │
        ▼
C2 Communication
TCP reverse shell → dormaire.euwf.cn:443 (fileless, in-memory)
WMI payload delivery → fini-27q.pages.dev:8080
Internal pivot → 10.0.2.6
        │
        ▼
Lateral Movement
agadmin account — SMB into WKS-94ZA + WKS-A29B
        │
        ▼
Collection
share$ → C:\Users\Public\Music (hidden staging share)
```

## Investigation Files

| File | Contents |
|---|---|
| [attack-chain.md](./attack-chain.md) | Full kill chain with MITRE ATT&CK mapping |
| [persistence-analysis.md](./persistence-analysis.md) | All 6 persistence mechanisms with artifact locations |
| [ioc-list.md](./ioc-list.md) | Containment-ready IOC list |
| [remediation-playbook.md](./remediation-playbook.md) | Correct remediation order with rationale |

---

## Tools & Frameworks Used

| Tool | Purpose |
|---|---|
| Kansa | PowerShell IR framework — enterprise artifact collection |
| MITRE ATT&CK Navigator | TTP mapping |
| VirusTotal | Hash and domain reputation |
| Pulsedive | IOC enrichment |
| Strontic xcyclopedia | Known Windows binary database — masquerading detection |
| Eric Zimmerman Timeline Explorer | CSV artifact correlation |

---

## MITRE ATT&CK Techniques Identified

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Ingress Tool Transfer | T1105 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Windows Service | T1543.003 |
| Persistence | WMI Event Subscription | T1546.003 |
| Persistence | Create Account: Local Account | T1136.001 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Lateral Movement | Remote Services: SMB | T1021.002 |
| Command & Control | Application Layer Protocol | T1071 |
| Command & Control | Proxy: Internal Proxy | T1090 |
| Collection | Local Data Staging | T1074 |

---

*Investigation conducted using Kansa-collected forensic artifacts in a controlled lab environment.*
