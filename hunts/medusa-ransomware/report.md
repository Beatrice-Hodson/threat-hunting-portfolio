# Threat Hunt Technical Report: Medusa Ransomware (RaaS)

**Author:** Bea Hodson
**Date:** [fill in]
**Lab Environment:** Proxmox home lab — Wazuh SIEM (Docker, Ubuntu VM) + Windows 11 victim host (Sysmon, Olaf Hartong config) + Atomic Red Team
**Primary Source(s):**
- CISA Advisory AA25-071A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
- MITRE ATT&CK Group G1051 (Medusa Group): https://attack.mitre.org/groups/G1051/
- Unit 42 (Palo Alto Networks) — Medusa initial access reporting [add full citation/link]

---

## Methodology & Preface

This hunt uses a hypothesis-driven methodology: for each stage of the documented attack chain, a hypothesis is formed *before* consulting incident-specific reporting in detail, based on the threat actor's known tradecraft profile (from MITRE ATT&CK group data and/or prior CTI reporting). The hypothesis is then compared against the specific incident/advisory data, and where lab conditions allow, emulated using Atomic Red Team and hunted for in Wazuh.

Because I control both the emulation (red side) and the detection stack (blue side) in this lab, every hypothesis in this exercise is expected to resolve true. The value isn't in genuine uncertainty of outcome — it's in practicing the analytical discipline of predicting adversary behavior from a threat actor's documented profile before consulting incident-specific reporting. This mirrors the actual cognitive process of professional threat hunting, where hypotheses are generated from CTI and actor knowledge rather than from advance knowledge of the specific intrusion under investigation.

A hypothesis being "true" in this exercise reflects that it was formed with sound reasoning grounded in a credible actor profile — not that a genuine unknown was resolved.

Reconnaissance and Resource Development, while critical to the attack chain, are harder to detect. Therefore, I made the decision to exclude them from the tables. These tactics occur entirely on attacker-controlled infrastructure before the victim compromise, and so they produce no observable events. That said, there are ways to reduce the likelihood of falling victim to Initial Access Brokers' (IABs') exploits, and this will be addressed in the Mitigation and Remediation section to outline preventative controls (credential hygiene, phishing-resistant MFA) rather than detective.

Where a technique could not be reproduced in this lab (due to missing infrastructure — a domain controller, a second host, a vulnerable public-facing application, etc.), third-party incident research (e.g., Unit 42, DFIR Report) is used as a stand-in for direct observation. These findings are clearly marked as externally sourced, both in the table's "Grounded In" column and in a dedicated reference-artifacts appendix, to preserve the distinction between evidence I personally reproduced and evidence I am citing from someone else's published research.

---

## Table 1: Full ATT&CK Matrix — Complete Analytical Record

| Stage | Technique | ID | Hypothesis (Pre-Analysis) | Finding (Post-Analysis) | Grounded In | Atomic Test Available | Emulation Status |
|---|---|---|---|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Medusa targeted public facing web application weaknesses. | Medusa gained access through a Microsoft Exchange Server vulnerability by modifying the ASPX file and uploading a webshell (cmd.aspx). | CISA Advisory, MITRE Group Page, Unit 42 | TBD | Not Emulated — lab lacks a vulnerable public-facing Exchange server |
| Persistence | Web Shell | T1505.003 | | | | | |
| Execution | BITS Jobs | T1197 | | | | | |
| Command and Control | Remote Desktop Software | T1219.002 | | | | | |

---

## Table 2: Confirmed Reproducible Findings

*(Only rows marked `Emulated` in Table 1 go here — self-reproduced evidence only.)*

| Stage | Technique | ID | Figure Ref | Key Observation |
|---|---|---|---|---|
| | | | | |

---

## Appendix A: Reproduced Evidence

*(Your own lab work — Atomic Red Team execution, Sysmon events, Wazuh queries/alerts.)*

### Figure 1: [Technique name / ID]
*[Screenshot]*

**Caption:**

**Narrative:**

---

## Appendix B: Reference Artifacts (External Sources)

*(Third-party research screenshots, used to support a Finding where the technique could not be reproduced in this lab.)*

### Figure R1: Web Shell (cmd.aspx) — Source: Unit 42
*[Screenshot]*

**Caption:** Example of the cmd.aspx webshell used by Medusa operators following exploitation of a Microsoft Exchange Server.

**Source citation:** [Full Unit 42 citation/link]

**Relevance:** Supports the Finding for the T1190 (Exploit Public-Facing Application) and T1505.003 (Web Shell) rows in Table 1 — this lab lacks a vulnerable Exchange server, so this technique could not be reproduced directly.

---

## Hunt Summary / Findings Summary

[Fill in once the full table is complete.]

---

## Incident Response Summary (PICERL)

**Preparation:**

**Identification:**

**Containment:**

**Eradication:**

**Recovery:**

**Lessons Learned:**

---

## Mitigation & Remediation Strategy

[Include preventative controls for excluded Reconnaissance/Resource Development stages here — credential hygiene, phishing-resistant MFA, dark web/breach monitoring — plus TTP-specific recommendations as the table fills in.]

---

## References

- CISA. (2025, March 12, updated Aug. 18, 2026). #StopRansomware: Medusa Ransomware. AA25-071A. https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
- MITRE ATT&CK. Medusa Group, G1051. https://attack.mitre.org/groups/G1051/
- Unit 42, Palo Alto Networks. [Full citation for the Medusa initial access article]
