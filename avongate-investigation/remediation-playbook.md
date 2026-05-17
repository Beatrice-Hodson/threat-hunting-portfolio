# Remediation Playbook — Avongate Industries

> Correct remediation sequence for a multi-persistence, active-C2 intrusion.
> Order is not arbitrary — incorrect sequencing allows the attacker to survive remediation and re-establish a foothold.

---

## Why Order Matters

This attacker deployed six interdependent persistence mechanisms designed to recreate each other.

The critical relationship:
- Mechanism 4 (Spooler failure action) is configured to reinstall Mechanism 5 (WMI Consumer) if it is removed
- If WMI Consumer is removed before the Spooler failure action is fixed, the next Spooler failure will automatically reinstall the WMI Consumer
- The attacker survives remediation

Wrong order: Remove WMI Consumer → Spooler fails → WMI Consumer reinstalled → attacker persists.

Correct order: Fix Spooler failure action first → remove WMI Consumer → no reinstaller remains.

---

## Pre-Remediation Requirements

Before touching any affected host:

- [ ] Forensic preservation complete — disk images and memory captures taken
- [ ] Full scope confirmed — all affected hosts identified (WKS-94ZA, WKS-A29B, 10.0.2.6, FS-01)
- [ ] All 6 persistence mechanisms confirmed and documented per host
- [ ] Out-of-band communication established — assume attacker has access to email
- [ ] Change freeze in effect — no new deployments during remediation window
- [ ] Remediation team roles assigned — lead, comms, documentation

Never remediate as you find. Scope everything first.

---

## Remediation Steps

### Step 1 — Block External URLs at Perimeter Firewall
**Why first:** Cut off payload delivery before touching any host. If the attacker sees remediation starting, they cannot pull down fresh payloads.

- Block dormaire.euwf.cn
- Block fini-27q.pages.dev
- Block outbound port 8080 from all workstations
- Log all attempted connections to these destinations for timeline reconstruction

---

### Step 2 — Isolate Affected Hosts
**Why second:** Stop lateral movement and C2 communication simultaneously across all hosts.

Isolate all hosts at the same time — isolating one while leaving others connected tips off the attacker.

- Network isolate WKS-94ZA
- Network isolate 10.0.2.6 (internal pivot host)
- Begin scoping WKS-A29B and FS-01 — isolate if compromise confirmed

---

### Step 3 — Fix Spooler Failure Action
**Why third:** This must happen before removing the WMI Consumer. The Spooler failure action is the reinstaller — disable it first or the WMI Consumer will be recreated.

- Reset Spooler service failure actions to default (no action on failure)
- Confirm gist.githubusercontent.com download cradle is no longer referenced in any service failure action
- Verify with Get-SvcFail output

---

### Step 4 — Remove WMI Event Consumer
**Why fourth:** Now that the reinstaller (Spooler failure action) is disabled, the WMI Consumer can be safely removed without risk of recreation.

Remove all three WMI components — all must be removed:
- WMI EventFilter (reboot trigger)
- WMI EventConsumer — WMI Background Svc (CommandLineEventConsumer)
- WMI FilterToConsumerBinding (links filter to consumer)

Verify with Get-WMIEvtConsumer — confirm no CommandLineEventConsumers remain.

Sysmon confirmation: no further EID 19/20/21 events after removal.

---

### Step 5 — Remove Registry Run Key
**Why fifth:** Kill the Base64 PowerShell reverse shell persistence.

- Remove malicious value from HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- Confirm no Base64-encoded PowerShell commands remain in any Run key (HKLM and HKCU)
- Verify with Get-Autorunsc output

---

### Step 6 — Remove \HealthCheck Scheduled Task
**Why sixth:** Kill the Rozena re-execution mechanism.

- Delete scheduled task \HealthCheck
- Verify with Get-SchedTasks — confirm task is gone
- Confirm L9XJe2iA.exe is no longer referenced in any scheduled task

---

### Step 7 — Remove vmhK Service
**Why seventh:** Kill the RemCom persistence mechanism.

- Stop service: vmhK
- Delete service: vmhK
- Verify with Get-SvcAll — confirm service no longer exists

---

### Step 8 — Remove Malicious Binaries from C:\Windows
**Why eighth:** All persistence mechanisms referencing these binaries are now removed — safe to delete the files.

Remove all three binaries:
- ggWmgFMT.exe (RemCom) — MD5: 6983F7001DE10F4D19FC2D794C3EB534
- L9XJe2iA.exe (Rozena) — MD5: 8D1F07419790D26A9F95CE353C9F88D3
- APPRUNTIME.EXE (masquerading binary)

Verify no instances of these filenames remain anywhere on affected hosts.

---

### Step 9 — Disable and Remove helpdesk Account
**Why ninth:** Remove the attacker's backdoor local admin access on WKS-94ZA.

- Disable helpdesk local account on WKS-94ZA
- Remove from local administrators group
- Audit all logon events for helpdesk account in the past 30 days

---

### Step 10 — Reset agadmin Credentials
**Why tenth:** Invalidate the compromised domain account used for lateral movement.

- Disable agadmin in Active Directory
- Reset agadmin password
- Remove agadmin from any privileged groups it should not be in
- Audit all systems agadmin authenticated to in the past 30 days — treat each as potentially compromised

---

### Step 11 — Remove share$ from WKS-94ZA
**Why eleventh:** Remove the hidden staging share.

- Delete share$ (mapped to C:\Users\Public\Music)
- Review contents of C:\Users\Public\Music for staged data
- Preserve contents for evidence before deletion

---

### Step 12 — Investigate and Remediate FS-01
**Why twelfth:** File server referenced in investigation — scope of compromise must be confirmed before returning to service.

- Run Kansa collection against FS-01
- Apply same artifact analysis methodology
- Remediate per findings

---

### Step 13 — Verify Clean — Reboot and Recheck
**Why last:** Confirm no persistence survived — particularly WMI, which only triggers on reboot.

Verification checklist:
- [ ] Reboot WKS-94ZA — confirm WMI Consumer does not re-fire (no EID 19/20/21 post-reboot)
- [ ] Confirm no malicious processes running (Get-ProcsWMI)
- [ ] Confirm no malicious services (Get-SvcAll)
- [ ] Confirm no malicious scheduled tasks (Get-SchedTasks)
- [ ] Confirm no malicious Run key values (Get-Autorunsc)
- [ ] Confirm no WMI Event Consumers (Get-WMIEvtConsumer)
- [ ] Confirm helpdesk account disabled (Get-LocalAdmins)
- [ ] Confirm agadmin disabled in AD
- [ ] Confirm share$ removed (Get-SmbShare)
- [ ] Confirm no outbound connections to known C2 destinations (Get-Netstat)

---

## Remediation Timeline Summary

    Hour 0      Scope confirmed — all hosts and mechanisms documented
    Hour 0-1    Step 1-2: Firewall blocks + host isolation (simultaneous)
    Hour 1      Step 3: Spooler failure action fixed
    Hour 1-2    Step 4-8: WMI, Run key, task, service, binaries removed
    Hour 2-3    Step 9-11: Accounts reset, share removed
    Hour 3+     Step 12: FS-01 investigation begins
    Hour 4+     Step 13: Verification — reboot and recheck all hosts
    Day 5       Full incident documentation complete
    Day 14      Lessons learned, detection gaps identified
    Day 30      New detections deployed based on IOCs

---

## Key Lessons

| Attacker Behavior | Defender Implication |
|---|---|
| Spooler failure action reinstalls WMI Consumer | Must fix the reinstaller before removing what it installs |
| 6 persistence mechanisms across multiple artifact types | Standard GUI tools miss WMI — always use Kansa or equivalent |
| Redundant C2 channels | Blocking one C2 does not end the intrusion |
| Masqueraded process names | Path validation required — name alone is not sufficient |
| Compromised domain account | Credential reset is part of malware remediation, not a follow-up task |
| Internal pivot host | Lateral movement source must be isolated, not just the patient zero |

---

*See [persistence-analysis.md](./persistence-analysis.md) for full persistence mechanism detail.*
*See [ioc-list.md](./ioc-list.md) for IOC reference during verification steps.*
