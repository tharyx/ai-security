# Real tool: CAIRIS (hedged walkthrough)

> **Hedge.** CAIRIS is open source (cairis.org, GitHub). Check how active the project is and the current install method before relying on it. Menu names are approximate. Use the shipped example models or fictional data. Only test systems you own or have written permission to test.

## Run it

The documentation has described a Docker-based install (a CAIRIS container plus a database) and a hosted demo instance; verify both. Log in, then import an **example model** that ships with CAIRIS (examples such as NeuroGrid and ACME Water have been used in its documentation; verify).

## Exploring a completed model (the course exercise)

Work through these questions, which the [offline lab](../labs/threat-dragon-and-cairis-models/README.md) also asks of a simplified model:

1. **Environments:** which environments exist and how do they differ (for example day versus night shift, production versus DR)?
2. **Risk analysis:** open the risk analysis model; sort risks by score. Which risk is highest, in which environment?
3. **Attacker → threat → asset:** for the top risks, which attacker (capability, motive) uses which threat on which asset, exploiting which vulnerability?
4. **Coverage:** which assets are at risk but have no requirement or countermeasure?
5. **Usability:** which personas and tasks touch high-risk assets? Would a countermeasure break their task?
6. **Documentation:** generate the requirements specification or model documentation and see how CAIRIS links requirements to risks.

## Tips

- CAIRIS models are XML. Parse exported files safely (no external entities; use `defusedxml`).
- CAIRIS is strongest when usability matters (clinical, industrial control rooms) and when the same system runs in different environments.
