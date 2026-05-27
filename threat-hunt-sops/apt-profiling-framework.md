# APT Profiling Framework — Pre-Hunt Intelligence Methodology

*Developed by Bea Hodson as part of a hypothesis-driven threat hunting methodology.*

---

## Overview

Before touching a single log, the hunter must understand who they are hunting. This framework provides a repeatable process for building a threat actor profile from available intelligence, mapping that profile to known APT groups, and constructing a weighted MITRE ATT&CK Navigator layer to guide the hunt.

The output of this process is not a checklist. It is a compass — a directional tool that sharpens your attacker mindset and generates stronger hypotheses before the investigation begins.

---

## Why This Matters

A hunter who begins an investigation without a threat actor profile is hunting blind. They are reacting to artifacts rather than anticipating them. The profiling process transforms the hunt from reactive to proactive — you arrive at the data already thinking like the attacker.

The profile does not tell you what you will find. It tells you where to look first and what to expect at each stage of the attack chain. That is the difference between a focused, purposeful investigation and an aimless triage.

---

## Step 1 — Draft the Threat Actor Description

Begin with whatever intelligence is available about the actor you are hunting. This may come from:

- An internal incident report
- A threat intelligence feed or vendor report
- An industry ISAC alert
- A government advisory (CISA, FBI, NSA)
- Open source reporting (blogs, conference talks, academic research)

From that intelligence, draft a short description of the actor covering:

- **Sector targeting** — what industries does this actor pursue?
- **Motivation** — financial, espionage, disruption, data theft?
- **Access pattern** — opportunistic or targeted? Fast or slow?
- **Behavioral profile** — how do they move once inside? What is their general approach?

Keep this description concise — two to four sentences. You are extracting signal, not writing a report.

---

## Step 2 — Extract Key TTPs as Keywords

Read your description and extract the behavioral keywords that describe how this actor operates. These are not IOCs — they are behavioral descriptors that will map to MITRE ATT&CK tactics and techniques.

**Examples of behavioral keywords:**
- Sector focus (manufacturing, logistics, healthcare, finance)
- Tactical behaviors (enumeration, discovery, credential harvesting)
- Evasion approaches (LOLBins, masquerading, blending with legitimate tools)
- Movement patterns (rapid exploitation, slow and deliberate, island hopping)

These keywords are your search terms for the next step. They translate the actor description into huntable concepts.

---

## Step 3 — Map to Known APT Groups

Open the MITRE ATT&CK Groups page and use your extracted keywords to identify known APT groups that share similar behavioral profiles with the actor you are hunting.

**Process:**
- Use Ctrl+F to search for your keywords across group descriptions
- Look for sector overlap — groups that target the same industries
- Look for behavioral overlap — groups that use similar techniques
- Identify two to four groups that most closely resemble your target actor

You are not looking for an exact match. You are looking for the closest known analogs — groups whose documented TTPs give you the best starting model for anticipating your actor's behavior.

**Key question at this step:** Which known groups have operated in the same sectors and used broadly similar approaches to the actor I am hunting?

---

## Step 4 — Build a Weighted MITRE ATT&CK Navigator Layer

With your analog groups identified, open MITRE ATT&CK Navigator and build a layered visualization.

**Weighting methodology:**

Assign scores to each group based on how closely they map to your target actor. The group with the strongest overlap in both sector targeting and behavioral profile receives the highest weight. Groups with partial overlap receive lower weights.

    Example weighting approach:
    Closest analog (strongest sector + TTP overlap): score 2
    Secondary analogs (partial overlap):             score 1

Add all groups to a single Navigator layer. Use a color gradient from transparent to a strong color (red works well) so that techniques shared across multiple groups appear darker — these are your highest-confidence hunting priorities.

**What the layer tells you:**
- Darker techniques = more likely based on analog group overlap
- These are where you focus first
- Lighter or absent techniques = possible but lower confidence

---

## Step 5 — Use the Layer as a Compass, Not a Map

This is the most important step — and the most commonly misunderstood.

The Navigator layer is a starting point, not a script. It tells you where to look first. It does not tell you what you will find, and it should never create tunnel vision.

**How to use it correctly:**

Use the layer to identify your patient zero and anchor the initial investigation. Once you have your first confirmed finding, shift your primary guidance to your attacker mindset — not the layer.

At each phase of the investigation ask: *"What would I do next if I were them?"*

That question, backed by the specific threat intelligence you gathered in Steps 1 and 2, will generate your next hypothesis more reliably than the Navigator layer alone. Use the layer to check your findings and confirm alignment — not to dictate your next move.

**A well-constructed profile and layer will align with a significant portion of your findings.** But the techniques you find that fall outside the layer are equally important — they tell you something new about how this actor operates that was not captured in the known APT analogs.

---

## The Profiling Process — Summary

    Step 1 — Draft the threat actor description
            Sector, motivation, access pattern, behavioral profile
            Source: threat intel feeds, advisories, open source reporting

    Step 2 — Extract behavioral keywords
            Sector targets, tactical behaviors, evasion approaches
            These become your MITRE search terms

    Step 3 — Map to known APT groups
            Search MITRE ATT&CK Groups by keyword
            Identify 2-4 closest behavioral analogs

    Step 4 — Build weighted Navigator layer
            Highest weight: strongest sector + TTP overlap
            Lower weight: partial overlap
            Color gradient: transparent to red
            Darker = higher confidence hunting priority

    Step 5 — Use as compass, not map
            Anchor patient zero identification
            Then shift to attacker mindset
            Ask: "What would I do next if I were them?"
            Use layer to confirm — not to direct

---

## Key Principles

**The profile sharpens your mindset, not your checklist.**
The value of the profiling process is not the Navigator layer itself — it is the attacker mindset you develop by deeply understanding how this type of actor operates before you begin hunting.

**Sector overlap matters as much as TTP overlap.**
An APT group that targets the same sector as your actor is a stronger analog than one that shares individual techniques but operates in a different domain. Sector targeting reflects motivation — and motivation drives behavior.

**The layer is a starting model, not a final answer.**
Emerging threat actors will not map perfectly to any known group. Treat the layer as your best current model, knowing it will be refined by what you find.

**Findings outside the layer are intelligence.**
When you find techniques not covered by your Navigator layer, document them. You may be observing the evolution of a known group, a new actor borrowing TTPs, or a capability that has not yet been publicly documented. Either way it is valuable.

---

*Part of the Threat Hunting Portfolio — github.com/Beatrice-Hodson/threat-hunting-portfolio*
