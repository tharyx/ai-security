# Real tools: pytm, Threagile, Threat Dragon and friends

> **Hedged guide.** Commands and options change between versions. Everything here is "verify at source": read the project's README first. Nothing in the course tests needs these tools. Use fictional data in any experiment and never upload a real system's model to a service you have not approved.

## OWASP pytm (Python, model as code)

You describe elements in Python; pytm generates a DFD, a sequence diagram and a list of threats from its rules.

```python
# model.py (sketch, check the pytm README for the current API)
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor

tm = TM("Shop")
internet = Boundary("Internet")
user = Actor("Customer", inBoundary=internet)
web = Server("Web server")
db = Datastore("Orders DB")
Dataflow(user, web, "HTTPS request")
Dataflow(web, db, "SQL query")
tm.process()
```

Typical usage (verify): `python model.py --report docs/template.md`, `python model.py --dfd | dot -Tpng -o dfd.png` (needs Graphviz). In CI: run the model, publish the report as an artifact, fail when a rule you care about fires.

## Threagile (YAML model, Go)

You write a YAML file describing data assets, technical assets, communication links and trust boundaries. Threagile applies built-in risk rules and writes a report, diagrams and a JSON risk list.

Typical usage (verify): run the Docker image or binary with `-model threagile.yaml -output out/`. Threagile is attractive in CI because the model is declarative and the output is machine-readable (for example risks with a status you can track).

## OWASP Threat Dragon

Web and desktop application for drawing DFDs and recording threats (STRIDE and other rule sets). Models are stored as JSON, so they can live in git. Good for workshops; weaker for fully automated checks.

## Microsoft Threat Modeling Tool and IriusRisk

- **Microsoft Threat Modeling Tool:** free Windows desktop app with built-in STRIDE rules. Check the current distribution and support status; model files are not designed for easy diffs.
- **IriusRisk:** commercial platform with questionnaires, libraries and integrations. Strong for compliance and scale; the model lives in the product (export via API).

## ThreatSpec (legacy)

Annotations in source comments (`@exposes`, `@mitigates`, `@accepts`, `@connects`, plus others). Little or no development since about 2020, so treat it as a **concept** and use pytm, Threagile or Threat Dragon for new work. The lab in this chapter is a small pure-Python imitation of the idea.

## How to run any of these in CI (pattern)

1. Keep the model file in the application repository.
2. Add a job that runs the tool and **fails on a rule you define** (for example: any risk with status `unchecked` and severity high).
3. Publish report and diagram as artifacts so reviewers see them in the merge request.
4. Review the model whenever a new component, data flow or trust boundary appears.
5. Link risks to requirement ids and test names (see [lesson 03](../03-security-requirements-as-code.md)).
