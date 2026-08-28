# Threat Hunt Technical Report: [Threat Actor / Campaign Name]

**Author:** Bea Hodson
**Date:**
**Lab Environment:** Proxmox home lab — Wazuh SIEM (Docker, Ubuntu VM) + Windows 11 victim host (Sysmon, Olaf Hartong config) + Atomic Red Team
**Primary Source(s):** [CISA Advisory link] | [MITRE ATT&CK Group page link, if applicable] | [Any third-party research, e.g. Unit 42]

---

## Methodology & Preface

*(This section is boilerplate — reuse as-is across every report, tweak only the framing if the source material changes.)*

This hunt uses a hypothesis-driven methodology: for each stage of the documented attack chain, a hypothesis is formed *before* consulting incident-specific reporting in detail, based on the threat actor's known tradecraft profile (from MITRE ATT&CK group data and/or prior CTI reporting). The hypothesis is then compared against the specific incident/advisory data, and where lab conditions allow, emulated using Atomic Red Team and hunted for in Wazuh.

Because I control both the emulation (red side) and the detection stack (blue side) in this lab, every hypothesis in this exercise is expected to resolve true. The value isn't in genuine uncertainty of outcome — it's in practicing the analytical discipline of predicting adversary behavior from a threat actor's documented profile before consulting incident-specific reporting. This mirrors the actual cognitive process of professional threat hunting, where hypotheses are generated from CTI and actor knowledge rather than from advance knowledge of the specific intrusion under investigation.

A hypothesis being "true" in this exercise reflects that it was formed with sound reasoning grounded in a credible actor profile — not that a genuine unknown was resolved.

Reconnaissance and Resource Development, while critical to the attack chain, are harder to detect. Therefore, I made the decision to exclude them from the tables. These tactics occur entirely on attacker-controlled infrastructure before the victim compromise, and so they produce no observable events. That said, there are ways to reduce the likelihood of falling victim to Initial Access Brokers' (IABs') exploits, and this will be addressed in the Mitigation and Remediation section to outline preventative controls (credential hygiene, phishing-resistant MFA) rather than detective.

Where a technique could not be reproduced in this lab (due to missing infrastructure — a domain controller, a second host, a vulnerable public-facing application, etc.), third-party incident research (e.g., Unit 42, DFIR Report) is used as a stand-in for direct observation. These findings are clearly marked as externally sourced, both in the table's "Grounded In" column and in a dedicated reference-artifacts appendix, to preserve the distinction between evidence I personally reproduced and evidence I am citing from someone else's published research.

---

## Table 1: Full ATT&CK Matrix — Complete Analytical Record

*(Every stage of the documented attack chain gets a row, whether or not it was ultimately emulated. This table is the record that you reasoned through the entire chain. Reconnaissance and Resource Development are intentionally excluded — see Methodology above.)*

| Stage | Technique | ID | Hypothesis (Pre-Analysis) | Finding (Post-Analysis) | Grounded In | Atomic Test Available | Emulation Status |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

**Column guide:**
- **Stage** — ATT&CK tactic (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact)
- **Technique** — plain-language name
- **ID** — MITRE technique ID (T-number), use the most specific sub-technique ID available
- **Hypothesis (Pre-Analysis)** — written *before* re-checking the specific incident report's command-level detail; grounded in the actor's general tradecraft profile. This column stays intentionally general/predictive.
- **Finding (Post-Analysis)** — the specific detail confirmed once the incident-specific source (CISA, Unit 42, etc.) is consulted or the technique is emulated. Leave blank for rows with no available source detail.
- **Grounded In** — list every source that informed this row: `CISA Advisory`, `MITRE Group Page`, `Unit 42`, etc. (comma-separate if multiple)
- **Atomic Test Available** — Y / N (check via `Invoke-AtomicTest <ID> -ShowDetails`)
- **Emulation Status** — `Emulated` or `Not Emulated — [reason]` (e.g., requires domain controller, requires public-facing vulnerable app, requires second host, requires Linux victim)

---

## Table 2: Confirmed Reproducible Findings

*(Filtered from Table 1 — only rows marked `Emulated`, meaning YOU personally reproduced this in your own lab. This is your own evidence trail, tied to Appendix A. Do not include Not Emulated rows here, even if third-party evidence exists for them — see Appendix B instead.)*

| Stage | Technique | ID | Figure Ref | Key Observation |
|---|---|---|---|---|
| | | | | |

---

## Appendix A: Reproduced Evidence

*(Screenshots of YOUR OWN lab work — Atomic Red Team execution, Sysmon events, Wazuh queries/alerts. One entry per Figure referenced in Table 2. Labeled "Figure #".)*

### Figure 1: [Technique name / ID]
*[Screenshot]*

**Caption:** [What this shows]

**Narrative:** [What was run, what was observed in Sysmon/Wazuh, any detection gap or tuning note]

---

## Appendix B: Reference Artifacts (External Sources)

*(Screenshots or figures cited from third-party research, used to support a Finding where the technique could not be reproduced in this lab. Labeled "Figure R#" to distinguish from self-generated evidence in Appendix A. Never presented as your own lab output.)*

### Figure R1: [Technique name / ID] — Source: [Publication name]
*[Screenshot]*

**Caption:** [What this shows]

**Source citation:** [Full citation/link to the original article]

**Relevance:** [Why this supports the Finding for this row]

---

## Hunt Summary / Findings Summary

[Plain-language recap: what was tested, what was found, what stood out. This is the "so what" section — written for someone who won't read the full tables. Good place to call out any independent findings not explicitly named in the primary source (e.g., a technique you identified via MITRE cross-referencing that CISA didn't name directly).]

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

[Concrete, actionable recommendations tied to the specific TTPs observed — patch management, detection rule additions, config hardening. Include preventative controls for excluded Reconnaissance/Resource Development stages here (credential hygiene, phishing-resistant MFA, dark web/breach monitoring).]

---

## References

- [CISA Advisory — full citation and link]
- [MITRE ATT&CK Group page — full citation and link]
- [Unit 42 / other third-party research — full citation and link]
- [Any other sources cited, e.g., LOLBAS project, Atomic Red Team technique pages]
