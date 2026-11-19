# Real tools: DFD drawing, ATT&CK Navigator, attack-tree tools and card games

> **Hedged guide.** Tools, versions and URLs change. Everything here is "verify at source": read the project's own page first. Nothing in this chapter's tests needs these tools. Use fictional systems in experiments and never upload a real architecture to a service you have not approved. Only test systems you own or have written permission to test.

## DFD drawing (lesson 01, labs dfd-stride and password-reset-threat-model)

| Tool | Notes |
|---|---|
| **OWASP Threat Dragon** (v2, desktop and web) | Draw DFDs with trust boundaries, add STRIDE (and other) threats per element, store the model as JSON in git. Good for workshops. |
| **Microsoft Threat Modeling Tool** | Free, Windows only. Draw a DFD from a stencil set; it generates STRIDE threats per element automatically. Updates are infrequent; check current support. |
| **draw.io / diagrams.net** | Free general drawing; no threat generation. Many teams use a DFD shape library. |
| **OWASP pytm** | Describe the system in Python; generate the DFD (Graphviz) and threats. Taught in chapter 05 and in [devsecops real-tools](../../../devsecops-course/03-security-requirements-and-threat-modeling/real-tools/threat-modeling-tools.md). |
| **Threagile** | YAML model, risk rules, diagrams; container or binary. |

To reproduce the lab in Threat Dragon: create a new model, draw the six elements and eight flows from `password_reset_dfd.json`, add four trust boundary boxes, then for each element add threats with the STRIDE type and mitigation. Compare your list with `demo.py`'s candidates.

## MITRE ATT&CK Navigator (lesson 03, lab threat-actor-personas)

The ATT&CK Navigator is a free web app from MITRE for colouring the matrix. Create a layer per persona, mark its techniques, and export the layer JSON next to your threat model. Overlay layers to see which techniques several personas share (detection priorities). Check the matrix version you load (Enterprise v18 at the time of writing; verify).

## Attack trees (lesson 03, lab attack-trees)

- **ADTool** (attack-defense trees, academic), **Graphviz** or **Mermaid** for drawing trees from text, and spreadsheet trees for small teams.
- Some commercial threat modeling platforms include attack-tree views. Keep your trees as text in the repo so they diff in reviews.

## Card games (lesson 04, lab threat-card-game)

- **Elevation of Privilege** (Microsoft / OWASP), **OWASP Cornucopia** (web; v2 adds mobile), **OWASP Cumulus** (cloud/DevOps), **LINDDUN GO** (privacy), **Backdoors & Breaches** (IR tabletop): most have free printable decks and online play options. Check licences before printing for a company event.
- Run a 60-minute session: DFD on the table, 3 to 6 players, one scribe recording threats straight into the tracker.

## Rating (lesson 05, lab threat-rating)

- **OWASP Risk Rating calculator** (community web calculators exist; check you trust the site, or use the lab function).
- **FIRST CVSS v4.0 calculator** for vulnerability severity.
- **Mozilla RRA** guide and templates (verify they are still published).
