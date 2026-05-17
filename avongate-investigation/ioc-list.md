# IOC List — Avongate Industries

> Containment-ready indicators of compromise identified during Kansa-based forensic investigation.

---

## Executables

| Filename | MD5 Hash | Classification | Location |
|---|---|---|---|
| ggWmgFMT.exe | 6983F7001DE10F4D19FC2D794C3EB534 | RemCom — remote execution tool | C:\Windows\ |
| L9XJe2iA.exe | 8D1F07419790D26A9F95CE353C9F88D3 | Rozena backdoor | C:\Windows\ |
| APPRUNTIME.EXE | Unknown | Masquerading binary — no legitimate Windows binary exists with this name | C:\Windows\ |

**Hunting Signal:** Any of these filenames present anywhere in the environment. Submit hashes to VirusTotal immediately on discovery.

---

## Domains

| Domain (Defanged) | Port | Purpose | VirusTotal Detections |
|---|---|---|---|
| dormaire.euwf[.]cn | 443 | Primary C2 — TCP reverse shell, fileless in-memory | 13 vendors |
| fini-27q.pages[.]dev | 8080 | Secondary C2 — WMI payload delivery | 7 vendors |
| raw.githubusercontent[.]com | 443 | Initial payload delivery — used during initial access | Trusted domain, abused |
| gist.githubusercontent[.]com | 443 | WMI reinstaller download cradle | Trusted domain, abused |

**Hunting Signal:** Any connection to dormaire.euwf.cn or fini-27q.pages.dev from any host. Connections to raw.githubusercontent.com or gist.githubusercontent.com from servers or outside business hours.

---

## IP Addresses

| IP | Role | Context |
|---|---|---|
| 10.0.2.6 | Internal C2 pivot host | Source of SMB sessions into WKS-94ZA (x4) and WKS-A29B (x1) |

**Hunting Signal:** Any host making multiple SMB connections originating from 10.0.2.6. Treat 10.0.2.6 as compromised pending investigation.

---

## Accounts

| Account | Type | Detail |
|---|---|---|
| helpdesk | Local administrator | Backdoor account created by attacker on WKS-94ZA |
| agadmin | Domain account | Compromised — used for lateral movement via SMB |

**Immediate Actions:**
- Disable helpdesk account on WKS-94ZA
- Disable agadmin in Active Directory and reset password
- Audit all systems agadmin authenticated to in the past 30 days

---

## Services

| Service Name | Payload | Detail |
|---|---|---|
| vmhK | ggWmgFMT.exe (RemCom) | Malicious service — configured with endless restart on failure |
| Diagostic System Host | svchost.exe (masquerading) | Legitimate name misspelled — running from C:\Windows\Temp\ |

**Hunting Signal:** Services with random short names (3-5 characters). svchost.exe running from any path other than C:\Windows\System32\.

---

## Scheduled Tasks

| Task Name | Payload | Detail |
|---|---|---|
| \HealthCheck | L9XJe2iA.exe (Rozena) | Scheduled task ensuring Rozena stays active |

**Hunting Signal:** Scheduled tasks referencing executables with random-looking names or tasks created outside of known software deployment windows.

---

## WMI Artifacts

| Component | Name | Detail |
|---|---|---|
| WMI EventConsumer | WMI Background Svc | CommandLineEventConsumer — downloads payload from fini-27q.pages.dev:8080/a on reboot |
| WMI EventFilter | (reboot trigger) | Fires on system reboot |
| WMI FilterToConsumerBinding | (links filter to consumer) | All three components must be removed |

**Hunting Signal:** Sysmon EID 19 + EID 20 + EID 21 firing together = WMI persistence implant confirmed. Use Get-WMIEvtConsumer (Kansa) to enumerate outside standard GUI tools.

---

## Shares

| Share Name | Path | Detail |
|---|---|---|
| share$ | C:\Users\Public\Music | Hidden staging share on WKS-94ZA — used for data collection |

**Hunting Signal:** Non-standard admin shares ($ suffix) not present in environment baseline. Shares pointing to user-writable public paths.

---

## Behavioral Indicators

| Behavior | MITRE | Detection Anchor |
|---|---|---|
| svchost.exe running outside C:\Windows\System32\ | T1036 | Process path validation |
| PowerShell with -enc flag in Run key | T1547.001 | Registry value content |
| Service failure action pointing to external URL | T1543.003 | Get-SvcFail output |
| SMB sessions from 10.0.2.6 using agadmin | T1021.002 | SMB session logs |
| DNS queries to githubusercontent.com from servers | T1105 | DNS logs |
| Outbound connections on port 8080 from workstations | T1071 | Firewall/proxy logs |
| Executables written to C:\Windows by non-installer process | T1068 | File creation events |

---

## Affected Hosts

| Host | Role | Confirmed Artifacts |
|---|---|---|
| WKS-94ZA | Patient Zero | All 6 persistence mechanisms, all malware, backdoor account, staging share |
| WKS-A29B | Lateral movement target | SMB session from agadmin — scope of compromise to be confirmed |
| 10.0.2.6 | Internal pivot host | Source of SMB lateral movement — treat as compromised |
| FS-01 | File server | Referenced in investigation — requires further scoping |

---

*See [attack-chain.md](./attack-chain.md) for kill chain context.*
*See [remediation-playbook.md](./remediation-playbook.md) for containment sequencing.*
