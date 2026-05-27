# Threat Hunting Framework — Universal Detection Methodology

*Developed by Bea Hodson through hands-on SOC analysis, incident response, and enterprise-level intrusion investigations.*

---

> "It is not enough to have a framework or a checklist. Alone, these produce mediocre hypotheses at best. It is the ability to think like the attacker at each stage of the intrusion that allows the defender to retrace the attack with higher certainty. The essential question, 'What would I do next if I were them?', backed by specific threat intelligence, is what generates the strong hypotheses needed to trace the entirety of the attack chain."
> — Bea Hodson

---

## Overview

This document captures a repeatable, tool-agnostic threat hunting methodology. It applies whether you are hunting for a known adversary tool, investigating a new TTP from a threat report, or responding to an active intrusion. The process is the same every time — only the artifact changes.

This methodology was developed and validated across multiple enterprise-level intrusion investigations including a full Kansa-based IR lab and a live PSAP certification exam investigation spanning 4 compromised hosts.

---

## The 5-Phase Investigation Framework

| Phase | Name | Key Actions |
|---|---|---|
| 1 | Pre-Hunt Intelligence | Read threat actor profile. Map to real APT groups. Build weighted MITRE Navigator layer. Identify highest overlap TTPs. |
| 2 | Initial Triage | Run pstree for big picture. Identify patient zero. Form first hypothesis based on attacker mindset. |
| 3 | Phased Investigation | Follow attack chain chronologically. One phase per tactic. Each phase = hypothesis + query + analysis. Prove or disprove. |
| 4 | Validation | Kansa for scope confirmation. Cross-reference log sources. Verify every assumption with evidence. |
| 5 | Documentation | Incident summary writes itself. Timeline built from phases. Report follows naturally from the evidence. |

---

## The 7-Step Investigation Process

    Step 1 — Build Threat Intelligence Profile
        Who is this attacker?
        What do they want?
        How do they operate?
        Which sectors do they target?
        Build a weighted MITRE Navigator layer before touching any data.

    Step 2 — Map to MITRE ATT&CK
        What TTPs should I hunt based on this actor?
        Where is the evidence likely to live?
        Which log sources are most relevant?

    Step 3 — Get the Big Picture
        Run pstree to see the full attack chain visually.
        Understand the story before drilling into individual artifacts.
        Identify patient zero and anchor the timeline.

    Step 4 — Think Like the Attacker
        At each stage ask: "What would I do next if I were them?"
        That question becomes your next hypothesis automatically.
        Backed by specific threat intelligence, this generates
        strong, directed hypotheses — not guesses.

    Step 5 — Prove It With Evidence
        Query the right log source.
        Find the artifact.
        Document with EID, timestamp, host, and command line.
        If you cannot reference specific evidence, you do not
        have a proven finding.

    Step 6 — Pivot to Next Hypothesis
        What did finding this tell me about what the attacker did next?
        Each finding generates the next question.
        Return to Step 4.

    Step 7 — Build the Complete Story
        The report writes itself because you followed the chain.
        Every phase has hypothesis, evidence, and analysis.
        Documentation is not a separate task — it is the output
        of doing the investigation correctly.

---

## Phase 3 Deep Dive — Hypothesis Quality Check

For every finding in the phased investigation, validate it against these three questions before including it in your report:

**WHAT — Exactly did you see?**
Specific EIDs, timestamps, IPs, command lines. If you cannot reference specific evidence you do not have a proven finding.

**HOW — Does it connect to other phases?**
Each finding should reference prior phase evidence. Findings that stand alone without connection to the broader attack chain belong in an appendix, not the main report.

**WHY — Does it matter?**
Control failure, attack progression, or business impact. If you cannot answer why it matters, it does not belong in the report.

---

## The Universal Detection Workflow

Beyond active investigations, this methodology applies to building durable detections from any tool or TTP.

**Understand the artifact → Find the telemetry → Transform the data → Encode the pattern → Deploy universally**

For any attacker tool or technique, answer these four questions:

    What does it create?
        Files, services, scheduled tasks, registry keys,
        named pipes, network connections, WMI subscriptions

    Where is the telemetry?
        Sysmon EID 1  -- Process Creation
        Sysmon EID 3  -- Network Connection
        Sysmon EID 11 -- File Creation
        Sysmon EID 13 -- Registry Value Set
        Sysmon EID 17 -- Pipe Created
        Sysmon EID 18 -- Pipe Connected
        Sysmon EID 19 -- WMI EventFilter
        Sysmon EID 20 -- WMI EventConsumer
        Sysmon EID 21 -- WMI FilterToConsumerBinding
        Windows Security EID 4624 -- Logon
        Windows Security EID 4697 -- Service Installed
        Windows Security EID 5145 -- Network Share Access
        Windows System EID 7045  -- New Service Installed

    What is the naming pattern?
        Masquerading -- validate path and signature against known-good baseline
        High entropy -- regex on name length and character set
        Hardcoded    -- read source code for fixed strings

    What regex encodes the pattern?
        Build. Test against known good. Deploy.

---

## Attacker Naming Strategies

Attackers use one of two naming approaches when deploying tools. Identifying which one shapes your detection strategy.

### Masquerading
The attacker names their artifact to blend in with legitimate system components.

**Detection approach:** Path validation and binary baseline comparison. The name looks legitimate — the path or signature gives it away. Cross-reference against Strontic xcyclopedia and the SANS Hunt Evil poster.

**Key rule:** svchost.exe is only legitimate from C:\Windows\System32\. Anywhere else is malicious. Full stop.

### High Entropy (Random Naming)
The attacker uses programmatically generated random names — typically because the tool creates artifacts automatically.

**Detection approach:** Entropy analysis and character pattern matching. Legitimate software has human-readable names. A 4-8 character random alphanumeric string with no vendor association is a high-confidence anomaly.

Regex pattern for random short service names:

    ^[A-Za-z0-9]{4,8}$

---

## Pyramid of Pain — Why Pattern Detections Win

| Indicator Type | Cost to Attacker to Evade | Example |
|---|---|---|
| Hash | Trivial — recompile or change one byte | Binary MD5 |
| IP Address | Easy — rotate infrastructure | C2 IP |
| Domain | Moderate — register new domain | C2 domain |
| Network artifact | Harder — change tool behavior | User-Agent string |
| Host artifact | Hard — requires tool redesign | Named pipe format |
| TTP | Very hard — change how the attack works | Service name pattern |

IOCs belong in your blocklist and threat intel platform. Patterns belong in your SIEM as persistent detection rules. Build both — but invest detection engineering effort at the top of the pyramid.

---

## Key Lessons

**Use the ATT&CK Navigator as a compass, not a checklist.**
The Navigator layer provides direction. Think like the attacker first and use the Navigator to confirm your instincts.

**Attackers move iteratively — your hunt should too.**
Land, establish persistence, enumerate, identify next target, move laterally. Recognizing this pattern lets you anticipate the next phase before you find it.

**Offensive training translates directly to defensive hunting.**
PJPT methodology and attacker mindset are force multipliers for hypothesis generation. The question "What would I do next?" is not a thought experiment — it is an investigative technique.

**Splunk and Kansa together provide the complete picture.**
Splunk proves what happened. Kansa proves what remains. Volatile artifacts like DNS cache and Netstat must be collected during the incident — not after.

**The phased approach writes the report.**
Breaking the investigation into chronological phases with hypothesis, query, findings, and analysis for each phase means the report writes itself. Understanding each phase deeply makes documentation natural, not forced.

---

## The One-Sentence Test

Before building any detection or forming any hypothesis, answer this:

**"What artifact does this tool leave, where does that artifact appear in my telemetry, and what pattern distinguishes it from legitimate activity?"**

If you can answer all three parts, you can build the detection. If you cannot, go back to the source — threat intelligence, tool documentation, source code, or sandbox analysis — until you can.

---

*Part of the Threat Hunting Portfolio — github.com/Beatrice-Hodson/threat-hunting-portfolio*
