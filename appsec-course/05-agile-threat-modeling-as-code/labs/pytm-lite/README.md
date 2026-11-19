# Lab: Threat models with code and as code (pytm-lite), with custom reports

**Course exercises:** [CTMP 3] "Creating Threat Models With Pytm", "Customizing Reporting Capabilities Of Pytm", "Writing Threat Models With Code", "Writing Threat Models As Code", "Writing Requirements in Threat Modeling". Lesson: [02 Threat modeling as code](../../02-threat-modeling-as-code-pytm-and-diagrams.md).

**Time:** 75 minutes. **Tests:** 12, all offline. **Safety:** a fictional shop. Nothing is scanned. Only test systems you own or have written permission to test.

## Goal

Describe one system twice: **with code** (Python objects, the way OWASP pytm works) and **as code** (a declarative JSON file, the way Threagile works). Run a threat library over it, get findings and security requirements, and print three different reports from the same model by changing only the template.

## Concept

[pytmlite.py](pytmlite.py) is a small, dependency-free imitation of **OWASP pytm** (verify the real API in the pytm README):

| pytm idea | pytm-lite |
|---|---|
| `TM`, `Actor`, `Server`, `Process`, `Datastore`, `Dataflow`, `Boundary`, `Data` | same names; elements register themselves inside `with TM(...)` |
| Threat library (JSON) with `SID`, `target`, `condition`, `severity`, `mitigations` | [fixtures/threatlib.json](fixtures/threatlib.json), plus a **`requirement`** id per threat |
| `tm.process()` / `--report template.md` | `tm.process()` and `tm.report(template)` |
| `--dfd` (Graphviz) and `--seq` (PlantUML) | `tm.dfd()` and `tm.seq()` |
| report template with `{findings:repeat:...}` | same idea: `repeat`, `if` and `ifnot` filters ([templates/](templates)) |

Two deliberate differences:

- **Safe conditions.** Real pytm evaluates conditions as Python. pytm-lite uses a tiny expression language (`target.isEncrypted is False and target.crossesBoundary is True`), so a malicious threat library cannot run code. A test proves it.
- **Derived facts.** `receivesUntrustedInput` and `crossesBoundary` are computed from the data flows, not typed by hand. Draw the flow and the rule fires.

Files:

- [model_shop.py](model_shop.py): the model **with code**. `build(secure=False)` is the first draft; `build(secure=True)` is the design after the sprint added controls. It also has a pytm-like CLI: `--dfd`, `--seq`, `--report <template>`.
- [fixtures/shop_model.json](fixtures/shop_model.json): the same draft **as code** (declarative data). A test proves both produce identical findings.
- [templates/full_report.md](templates/full_report.md) (pytm-like default), [templates/exec_summary.md](templates/exec_summary.md) (sprint review summary and requirement checklist), [templates/findings.csv](templates/findings.csv) (for a spreadsheet or ticket import).

## Steps

```text
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/pytm-lite/demo.py
.venv/Scripts/python -m pytest appsec-course/05-agile-threat-modeling-as-code/labs/pytm-lite -q -p no:cacheprovider
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/pytm-lite/model_shop.py --report appsec-course/05-agile-threat-modeling-as-code/labs/pytm-lite/templates/full_report.md
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/pytm-lite/model_shop.py --dfd
```

1. Run the demo. Read the 13 findings of the draft and the 8 High ones in the summary.
2. In `model_shop.py`, change the `Login and browse` flow to `isEncrypted=True`. Two findings (`DF01`, `DF02`) disappear. That is the threat model reacting to a design change.
3. Add a new `Datastore("Reports bucket", inBoundary=internet, storesPII=True)` and a flow to it. Run again: new findings appear without anyone remembering to "think of it".
4. **Customize the report:** copy `exec_summary.md` to `jira.md` and write one line per finding in a format your ticket tool imports. Only the template changes; the model and rules stay the same.
5. Add a rule to `threatlib.json` (for example a Datastore that `isBackedUp is False and storesPII is True` gets High). Re-run and check the gate.
6. Write `Server("x", sanitisesInput=True)` (British spelling). pytm-lite rejects unknown attributes, so a typo cannot silently turn a control off.

## Expected output (real run of demo.py)

```text
== 1. Threat model WITH code (model_shop.py, first draft) ==
  High   AC01   Orders API        Elevation of Privilege
  High   AC01   Web App           Elevation of Privilege
  High   AU01   Web App           Spoofing
  High   DF01   HTML page         Information Disclosure
  High   DF01   Login and browse  Information Disclosure
  High   DF02   Login and browse  Spoofing
  High   DS01   Orders DB         Information Disclosure
  High   INP01  Web App           Tampering
  Medium DOS01  Web App           Denial of Service
  Medium LOG01  Orders API        Repudiation
  Medium LOG01  Web App           Repudiation
  Medium OUT01  Web App           Tampering
  Low    DS03   Orders DB         Denial of Service
  model checks: ok
  gate exit code: 1

== 2. Threat model AS code (fixtures/shop_model.json, same system as data) ==
  same findings as the Python model: True

== 3. Custom report template (templates/exec_summary.md) ==
# Shop: security summary for the sprint review

High-severity findings: **8** of 13.
Do not release until each high finding below is fixed or formally accepted.

- **Orders API**: No object- or function-level authorization check -> fix: Deny by default; check owner and role on every object and function (REQ-AUTHZ-01)
- **Web App**: No object- or function-level authorization check -> fix: Deny by default; check owner and role on every object and function (REQ-AUTHZ-01)
- **Web App**: A process that receives untrusted input does not authenticate the caller -> fix: Authenticate every request (session, OIDC or API token) before business logic (REQ-AUTH-01)
- **HTML page**: Data crosses a trust boundary in clear text and can be sniffed or changed in transit -> fix: Use TLS 1.2+ (prefer 1.3) on every flow that crosses a boundary (REQ-TLS-01)
- **Login and browse**: Data crosses a trust boundary in clear text and can be sniffed or changed in transit -> fix: Use TLS 1.2+ (prefer 1.3) on every flow that crosses a boundary (REQ-TLS-01)
- **Login and browse**: Credentials or tokens travel unencrypted and can be replayed -> fix: Encrypt the channel and use short-lived, sender-constrained tokens (REQ-AUTH-03)
- **Orders DB**: Personal data is stored without encryption at rest -> fix: Encrypt at rest (TDE or storage encryption) with managed keys (REQ-DATA-01)
- **Web App**: Untrusted input reaches the process without validation (injection risk) -> fix: Validate input with an allowlist schema; use bind variables for SQL (REQ-INPUT-01)

## Security requirements for the backlog

- [ ] REQ-AUTH-01 applies to: Web App
- [ ] REQ-AUTH-03 applies to: Login and browse
- [ ] REQ-AUTHZ-01 applies to: Orders API, Web App
- [ ] REQ-AVAIL-01 applies to: Web App
- [ ] REQ-AVAIL-02 applies to: Orders DB
- [ ] REQ-DATA-01 applies to: Orders DB
- [ ] REQ-INPUT-01 applies to: Web App
- [ ] REQ-LOG-01 applies to: Orders API, Web App
- [ ] REQ-OUTPUT-01 applies to: Web App
- [ ] REQ-TLS-01 applies to: HTML page, Login and browse

== 4. Custom CSV template (templates/findings.csv), first 4 lines ==
sid,severity,stride,target,requirement
AC01,High,Elevation of Privilege,Orders API,REQ-AUTHZ-01
AC01,High,Elevation of Privilege,Web App,REQ-AUTHZ-01
AU01,High,Spoofing,Web App,REQ-AUTH-01

== 5. Diagrams as code: PlantUML sequence diagram ==
@startuml
actor "Customer" as Customer
entity "Web App" as Web_App
entity "Orders API" as Orders_API
database "Orders DB" as Orders_DB
Customer -> Web_App: Login and browse
Web_App -> Orders_API: Place order
Orders_API -> Orders_DB: SQL query
Orders_DB -> Orders_API: Result rows
Web_App -> Customer: HTML page
@enduml

== 6. After the sprint: controls added (build(secure=True)) ==
  findings: 0 | gate exit code: 0
```

## Run the real tool (hedged)

OWASP pytm is the real thing. Check the README of the pytm repository for the current install method and options; the commands below are the documented shape at the time of writing.

```text
pip install pytm                                   # or install from the GitHub repository
python tm.py --report docs/basic_template.md > report.md
python tm.py --dfd | dot -Tpng -o dfd.png          # needs Graphviz
python tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > seq.png   # needs Java + PlantUML
python tm.py --list                                # list the threats in the library
```

- Copy the sample `tm.py` from the repository and replace the elements with your system.
- Custom reports: pytm's templates use the same `{findings:repeat:...}` idea as this lab. Copy `docs/basic_template.md` and edit it.
- Custom threats: pytm can load your own threat library JSON. Remember that its conditions are Python expressions, so **review a threat library like code**.
- **Threagile** is the "as code" alternative (YAML model, built-in risk rules, JSON risk output). See [real-tools/pytm-threagile-and-diagram-tools.md](../../real-tools/pytm-threagile-and-diagram-tools.md).

## What you learned

- "With code" (Python objects) and "as code" (declarative data) are two notations for the same model. Both live in git and are reviewed in merge requests.
- Rules turn design facts (encrypted? crosses a boundary? stores PII?) into findings, and findings into **security requirements** with ids.
- Reports are templates. Change the template for each audience; never hand-edit a generated report.
- A gate fails on High findings that are neither fixed nor formally accepted.
