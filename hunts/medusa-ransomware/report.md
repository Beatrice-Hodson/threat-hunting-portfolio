# Threat Hunt Technical Report: [Threat Actor / Campaign Name]

**Author:** Bea Hodson
**Date:**
**Lab Environment:** Proxmox home lab — Wazuh SIEM (Docker, Ubuntu VM) + Windows 11 victim host (Sysmon, Olaf Hartong config) + Atomic Red Team
**Primary Source(s):** [CISA Advisory link] | [MITRE ATT&CK Group page link, if applicable]

---

## Methodology & Preface

*(This section is boilerplate — reuse as-is across every report, tweak only the framing if the source material changes.)*

This hunt uses a hypothesis-driven methodology: for each stage of the documented attack chain, a hypothesis is formed *before* consulting incident-specific reporting in detail, based on the threat actor's known tradecraft profile (from MITRE ATT&CK group data and/or prior CTI reporting). The hypothesis is then compared against the specific incident/advisory data, and where lab conditions allow, emulated using Atomic Red Team and hunted for in Wazuh.

Because I control both the emulation (red side) and the detection stack (blue side) in this lab, every hypothesis in this exercise is expected to resolve true. The value isn't in genuine uncertainty of outcome — it's in practicing the analytical discipline of predicting adversary behavior from a threat actor's documented profile before consulting incident-specific reporting. This mirrors the actual cognitive process of professional threat hunting, where hypotheses are generated from CTI and actor knowledge rather than from advance knowledge of the specific intrusion under investigation.

A hypothesis being "true" in this exercise reflects that it was formed with sound reasoning grounded in a credible actor profile — not that a genuine unknown was resolved.

---

## Table 1: Full ATT&CK Matrix — Complete Analytical Record

*(Every stage of the documented attack chain gets a row, whether or not it was ultimately emulated. This table is the record that you reasoned through the entire chain.)*

| Stage | Technique | ID | Hypothesis | Grounded In | Atomic Test Available | Emulation Status |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |

**Column guide:**
- **Stage** — ATT&CK tactic (Initial Access, Discovery, Credential Access, Lateral Movement, Defense Evasion, Persistence, Privilege Escalation, Exfiltration, Impact, etc.)
- **Technique** — plain-language name
- **ID** — MITRE technique ID (T-number)
- **Hypothesis** — written *before* re-checking the specific incident report's command-level detail; grounded in the actor's general tradecraft profile
- **Grounded In** — `CISA Advisory` / `MITRE Group Page` / `Both`
- **Atomic Test Available** — Y / N (check via `Invoke-AtomicTest <ID> -ShowDetails`)
- **Emulation Status** — `Emulated` or `Not Emulated — [reason]` (e.g., requires domain controller, requires public-facing vulnerable app, requires second host, requires Linux victim)

---

## Table 2: Confirmed Reproducible Findings

*(Filtered from Table 1 — only rows marked `Emulated`. This is the evidence trail, tied directly to the appendix.)*

| Stage | Technique | ID | Figure Ref | Key Observation |
|---|---|---|---|---|
| | | | | |

---

## Appendix: Evidence

*(One entry per Figure referenced in Table 2. Screenshot + caption + brief narrative.)*

### Figure 1: [Technique name / ID]
*[Screenshot]*

**Caption:** [What this shows]

**Narrative:** [What was run, what was observed in Sysmon/Wazuh, any detection gap or tuning note]

---

## Hunt Summary / Findings Summary

[Plain-language recap: what was tested, what was found, what stood out. This is the "so what" section — written for someone who won't read the full tables.]

---

## Incident Response Summary (PICERL)

*(Applied retroactively to this self-generated scenario, as if responding to it as a live incident — framed explicitly as such, not presented as a real IR engagement.)*

**Preparation:**
[Lab readiness, tooling, baseline state prior to emulation]

**Identification:**
[How the activity was first identified — which alert, which query, which log source]

**Containment:**
[What containment would look like in a real environment given these IOCs/TTPs]

**Eradication:**
[Steps to remove the threat actor's access/tools given the observed artifacts]

**Recovery:**
[Steps to restore normal operations]

**Lessons Learned:**
[What this hunt revealed about detection coverage, gaps, and what changed as a result — e.g., custom Wazuh rules written in response]

---

## Mitigation & Remediation Strategy

[Concrete, actionable recommendations tied to the specific TTPs observed — patch management, detection rule additions, config hardening, etc.]

---

## References

- [CISA Advisory — full citation and link]
- [MITRE ATT&CK Group page — full citation and link]
- [Any other sources cited, e.g., LOLBAS project, Atomic Red Team technique pages]