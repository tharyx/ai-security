# Lab: Threat Dragon models and completed CAIRIS models, offline

**Course exercises:** [CTMP 4] "Threat Modeling with OWASP Threat Dragon", "Exploring Completed CAIRIS Models". Lesson: [02 Tools and templates](../../02-threat-modeling-tools-and-templates.md). Real-tool guides: [Threat Dragon](../../real-tools/owasp-threat-dragon.md), [CAIRIS](../../real-tools/cairis.md).

**Time:** 50 minutes. **Tests:** 8, all offline. **Safety:** fictional models. Only test systems you own or have written permission to test.

> **Hedge.** [threat_dragon_shop.json](fixtures/threat_dragon_shop.json) follows the general **shape** of OWASP Threat Dragon 2.x files as we understand it (summary, detail, diagrams, cells with `data.type` such as `tm.Process`). Field names change between versions: save a model from **your** Threat Dragon version and compare. [cairis_clinic.xml](fixtures/cairis_clinic.xml) is a **simplified, CAIRIS-inspired** XML, not the real CAIRIS export format.

## Goal

1. Treat a Threat Dragon model as a file in git and **validate** it in CI: every in-scope element analysed, out-of-scope decisions explained, STRIDE types valid, `hasOpenThreats` consistent, flows connected, no unencrypted public flows, and a list of open High threats.
2. **Explore a completed CAIRIS-style model** the way a reviewer does: which environments, which risks are highest, which attacker reaches which asset, which assets at risk have no requirement, and which persona tasks touch high-risk assets.

## Concept

- [tdmodel.py](tdmodel.py): `elements`, `flows`, `validate`, `open_threats`, `summary`.
- [cairis_explore.py](cairis_explore.py): `risks` (likelihood × severity using CAIRIS-like scales), `attacker_paths`, `unprotected_assets`, `persona_tasks_at_risk`. CAIRIS links **usability** (personas, tasks) with security per **environment**, which is why the persona question exists.
- `safe_parse` refuses any `DOCTYPE`/`ENTITY`: model files are XML, and XML parsers can be attacked (XXE, billion laughs). Use `defusedxml` in real code.

## Steps

```text
.venv/Scripts/python appsec-course/06-threat-model-tools-reporting-and-ai/labs/threat-dragon-and-cairis-models/demo.py
.venv/Scripts/python -m pytest appsec-course/06-threat-model-tools-reporting-and-ai/labs/threat-dragon-and-cairis-models -q -p no:cacheprovider
```

1. Fix the Threat Dragon file until `validate()` returns nothing: add a threat to Orders DB, a reason for the CDN, fix `hasOpenThreats`, change "Gremlins" to "Denial of service", point the SQL flow at `c-db`, encrypt "Order calls".
2. Open the same JSON in Threat Dragon (desktop or web). If it does not load, compare its fields with a model you save from the tool: that is the format drift the hedge warns about.
3. In the CAIRIS XML add `<requirement name="Break-glass access with audit" asset="Patient records"/>`. `unprotected_assets` becomes empty.

## Expected output (real run of demo.py)

```text
== OWASP Threat Dragon 2.x-style model: fixtures/threat_dragon_shop.json ==
  summary: {'elements': 5, 'flows': 3, 'threats': 7, 'by_status': {'Mitigated': 3, 'Open': 4}, 'by_type': {'Repudiation': 1, 'Spoofing': 1, 'Tampering': 1, 'Elevation of privilege': 1, 'Gremlins': 1, 'Information disclosure': 2}}
  validation problems:
   - Orders API: threat 'Rate limit missing' has non-STRIDE type 'Gremlins'
   - Orders API: hasOpenThreats flag does not match the threat list
   - Orders DB: in scope but no threats recorded (not analysed?)
   - CDN: out of scope without a reason
   - Order calls: crosses a public network unencrypted
   - SQL: flow target points to a missing cell
  open High threats:
   - Web App: [Tampering] Stored XSS in product reviews
   - Orders API: [Elevation of privilege] BOLA on /orders/{id}
   - Order calls: [Information disclosure] Order data sniffed between data centres

== Exploring a completed CAIRIS-style model: fixtures/cairis_clinic.xml ==
  environments: ['Day', 'Night']
  risks (likelihood x severity):
   - 16  R1 Ransomware via reception PC [Day] asset=Reception PC
   -  9  R2 Snooping on records [Night] asset=Patient records
   -  4  R3 Scraping [Day] asset=Appointment API
  attacker paths:
   - Ransomware crew -> Phishing leads to ransomware -> Reception PC (Day, score 16)
   - Curious insider -> Browsing records without a reason -> Patient records (Night, score 9)
   - Ransomware crew -> Appointment API scraped -> Appointment API (Day, score 4)
  assets at risk with no requirement or countermeasure: ['Patient records']
  persona tasks touching high-risk assets:
   - Priya (receptionist): 'Book appointment' uses high-risk ['Reception PC']

== XML safety ==
  rejected: DOCTYPE/ENTITY not allowed (XXE and billion-laughs protection)
```

## Run the real tool (hedged)

- **Threat Dragon:** download the desktop app or run the web version (see [real-tools/owasp-threat-dragon.md](../../real-tools/owasp-threat-dragon.md)). Draw the three-tier shop, add STRIDE threats, save the JSON into your repository, and run `tdmodel.validate` on it in CI (adjust field names if needed).
- **CAIRIS:** run the documented Docker image or the hosted demo, open an example model (for example the NeuroGrid or ACME Water examples that have shipped with CAIRIS; verify), and answer the same five questions in its UI. See [real-tools/cairis.md](../../real-tools/cairis.md).

## What you learned

- A GUI tool's model file is still code: validate it in CI.
- Reading a completed model is a skill: start from the highest risks, follow attacker → threat → asset, and look for assets with no requirement.
- Parse model files safely.
