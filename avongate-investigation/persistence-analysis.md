# Persistence Analysis — Avongate Industries

> Six independent persistence mechanisms identified. Deployed with intentional redundancy — designed to survive partial remediation.

---

## Critical Finding: Interdependent Persistence Architecture

The attacker did not install six separate, independent persistence mechanisms. They installed six mechanisms that were designed to recreate each other.

This means:
- Removing any single mechanism without removing all others risks re-infection
- The Spooler failure action (mechanism 4) will automatically reinstall the WMI Consumer (mechanism 5) if removed out of order
- The correct remediation approach requires removing all mechanisms in the correct sequence

This is a hallmark of sophisticated threat actor tradecraft. See [remediation-playbook.md](./remediation-playbook.md) for correct removal order.

---

## Mechanism 1 — Registry Run Key (Base64 PS Reverse Shell)
**MITRE:** T1547.001 — Boot or Logon Autostart: Registry Run Keys

| Attribute | Detail |
|---|---|
| Location | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| Payload | Base64-encoded PowerShell reverse shell |
| C2 | dormaire.euwf.cn:443 |
| Effect | Executes fileless reverse shell on every system boot |
| Kansa Module | Get-Autorunsc |
| Detection Event ID | Sysmon EID 13 — Registry Value Set |

The Base64-encoded command decodes to a PowerShell download cradle that connects back to dormaire.euwf.cn on port 443. The payload runs entirely in memory — no additional file is written to disk — making it invisible to traditional file-based AV scanning.

**Hunting Signal:** New Run key values pointing to PowerShell with encoded commands (-enc flag). Any Run key value containing Base64 strings.

---

## Mechanism 2 — Scheduled Task (Rozena Re-execution)
**MITRE:** T1053.005 — Scheduled Task/Job: Scheduled Task

| Attribute | Detail |
|---|---|
| Task Name | \HealthCheck |
| Payload | L9XJe2iA.exe (Rozena backdoor) |
| Effect | Re-executes Rozena on schedule — ensures backdoor stays active |
| Kansa Module | Get-SchedTasks |
| Detection Event ID | Windows Security EID 4698 — Scheduled Task Created |

The task name \HealthCheck is chosen to blend in with legitimate monitoring tasks that might exist in an enterprise environment.

**Hunting Signal:** Scheduled tasks referencing executables with random-looking names. Tasks created outside of software deployment windows.

---

## Mechanism 3 — Malicious Service (RemCom Persistence)
**MITRE:** T1543.003 — Create or Modify System Process: Windows Service

| Attribute | Detail |
|---|---|
| Service Name | vmhK |
| Payload | ggWmgFMT.exe (RemCom) |
| Start Type | Configured with endless restart on failure |
| Effect | Keeps RemCom running as a service — survives reboots |
| Kansa Module | Get-SvcAll |
| Detection Event ID | System EID 7045 — New Service Installed |

The service name vmhK is a random 4-character string — a common pattern when attackers use tools like PsExec or RemCom to install services programmatically. The endless restart configuration means even if the process is killed, the service manager will restart it automatically.

**Hunting Signal:** Services with random short names (3-5 characters). Services with executables in non-standard paths. Services configured to restart indefinitely on failure.

---

## Mechanism 4 — Spooler Failure Action (WMI Reinstaller)
**MITRE:** T1543.003 — Create or Modify System Process: Windows Service

| Attribute | Detail |
|---|---|
| Target Service | Windows Print Spooler (spooler) |
| Failure Action | Configured to download and execute WMI installer from gist.githubusercontent.com |
| Effect | If WMI Consumer (mechanism 5) is removed, Spooler failure triggers reinstall |
| Kansa Module | Get-SvcFail |
| Detection Event ID | System EID 7045 / registry modification |

This is the most sophisticated mechanism in the chain. The attacker modified the Spooler service failure action — a legitimate Windows feature that allows administrators to define what happens when a service fails — to instead download a fresh WMI installer from gist.githubusercontent.com.

**Why this matters:** If an analyst removes the WMI Consumer (mechanism 5) without first fixing the Spooler failure action, the next time the Spooler service has any issue, it will automatically reinstall the WMI Consumer. The attacker survives remediation.

**Hunting Signal:** Spooler (or any core Windows service) failure action pointing to a download cradle or external URL. Get-SvcFail output showing unexpected failure action commands.

---

## Mechanism 5 — WMI Event Consumer
**MITRE:** T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription

| Attribute | Detail |
|---|---|
| Consumer Name | WMI Background Svc |
| Consumer Type | CommandLineEventConsumer |
| Trigger | System reboot (WMI EventFilter) |
| Payload | fini-27q.pages.dev:8080/a |
| Effect | Downloads and executes payload from C2 on every reboot |
| Kansa Module | Get-WMIEvtConsumer |
| Detection Event ID | Sysmon EID 19 (EventFilter), EID 20 (EventConsumer), EID 21 (FilterToConsumerBinding) |

WMI Event Subscriptions are one of the most hidden persistence mechanisms available to attackers. They live in the WMI repository — not in the registry, not in the filesystem, not in the task scheduler — making them invisible to most standard GUI-based persistence checks.

The full WMI persistence implant consists of three components:
- EventFilter — defines the trigger condition (system reboot)
- EventConsumer — defines the action (run the payload)
- FilterToConsumerBinding — links filter to consumer

All three must be removed. Removing only the consumer leaves the filter and binding in place.

**Hunting Signal:** Sysmon EIDs 19+20+21 firing together = WMI persistence implant confirmed. Get-WMIEvtConsumer output showing CommandLineEventConsumer with external URLs.

---

## Mechanism 6 — Backdoor Local Admin Account
**MITRE:** T1136.001 — Create Account: Local Account

| Attribute | Detail |
|---|---|
| Account Name | helpdesk |
| Account Type | Local administrator |
| Scope | WKS-94ZA only |
| Effect | Attacker retains local admin access even if all malware is removed |
| Kansa Module | Get-LocalAdmins |
| Detection Event ID | Windows Security EID 4720 — User Account Created |

The account name helpdesk is chosen to blend in — in many enterprises a helpdesk or support account is expected and may not draw immediate scrutiny. This mechanism operates entirely outside the malware layer — even a complete OS reinstall of the affected host would not remove this account unless AD/local account cleanup is part of remediation.

**Hunting Signal:** Local admin accounts not in approved baseline. Accounts named helpdesk, support, admin, or similar generic names created outside of HR/IT provisioning processes.

---

## Persistence Mechanism Summary

| # | Mechanism | MITRE ID | Kansa Module | Removal Step |
|---|---|---|---|---|
| 1 | Registry Run Key — Base64 PS reverse shell | T1547.001 | Get-Autorunsc | Step 5 |
| 2 | Scheduled Task — \HealthCheck — Rozena | T1053.005 | Get-SchedTasks | Step 6 |
| 3 | Service — vmhK — RemCom | T1543.003 | Get-SvcAll | Step 7 |
| 4 | Spooler failure action — WMI reinstaller | T1543.003 | Get-SvcFail | Step 3 (first!) |
| 5 | WMI Event Consumer — reboots trigger payload | T1546.003 | Get-WMIEvtConsumer | Step 4 |
| 6 | Backdoor local admin — helpdesk | T1136.001 | Get-LocalAdmins | Step 9 |

---

## Key Lesson: Removal Order Is Not Optional

Mechanism 4 (Spooler failure action) reinstalls Mechanism 5 (WMI Consumer) if Mechanism 5 is removed first.

Wrong order: Remove WMI Consumer → Spooler fails → WMI Consumer reinstalled → attacker survives.

Correct order: Fix Spooler failure action first → then remove WMI Consumer → no reinstaller remains.

See [remediation-playbook.md](./remediation-playbook.md) for the complete removal sequence.

---

*See [attack-chain.md](./attack-chain.md) for full kill chain context.*
*See [remediation-playbook.md](./remediation-playbook.md) for correct remediation sequence.*
