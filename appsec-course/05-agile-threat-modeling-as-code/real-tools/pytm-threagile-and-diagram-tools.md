# Real tools: pytm, Threagile, PlantUML, Graphviz, Mermaid and attack tree tools

> **Hedged guide.** Commands and options change between versions: read each project's README first. Nothing in the course tests needs these tools. Use fictional systems in experiments. Only test systems you own or have written permission to test.

## OWASP pytm

1. Install: `pip install pytm` (or clone the GitHub repository; verify which is current). Install **Graphviz** for DFDs and **Java + PlantUML** for sequence diagrams.
2. Copy the sample `tm.py` from the repository and replace its elements with your system (see [lesson 02 section 2](../02-threat-modeling-as-code-pytm-and-diagrams.md#2-creating-threat-models-with-pytm-and-customizing-its-reports)).
3. Run (verify flags with `python tm.py --help`):

```text
python tm.py --dfd | dot -Tpng -o dfd.png
python tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > seq.png
python tm.py --report docs/basic_template.md > report.md
python tm.py --json model.json
python tm.py --list
```

4. **Customize reporting:** copy `docs/basic_template.md`, edit the `{findings:repeat:...}` block, add sections, and point `--report` at your template. Keep templates in the repository.
5. **Custom threats:** pytm can load your own threat library JSON (verify the option). Conditions are Python expressions: review a threat library like code.
6. **CI:** run the model in a job, publish `report.md` and `dfd.png` as artifacts, parse `model.json` and fail on High findings without a mitigation.

## Threagile (as code, YAML)

- Write `threagile.yaml` with data assets, technical assets, communication links and trust boundaries. Run the binary or the container image with the model and an output folder (for example `-model threagile.yaml -output out/`; verify flags and image name).
- Output: PDF/Excel reports, DFD and data-asset diagrams, and a JSON risk list. Track risk status (`unchecked`, `in-discussion`, `accepted`, `mitigated`, `false-positive`) in the YAML so the decision is versioned. Check the project's current activity before adopting it.

## Diagram tools

| Tool | Command (verify) |
|---|---|
| PlantUML | `java -jar plantuml.jar file.puml` (PNG next to the file); `-tsvg` for SVG |
| Graphviz | `dot -Tsvg dfd.dot -o dfd.svg` |
| Mermaid | GitHub/GitLab render ```` ```mermaid ```` blocks; `npx @mermaid-js/mermaid-cli -i in.mmd -o out.svg` (needs Node) |
| Structurizr | Structurizr DSL for C4 models (verify current tooling) |

## Attack tree tools

- **ADTool** (attack-defence trees; Java desktop; verify maintenance).
- Mermaid or DOT generated from your own DSL (as in the [diagrams lab](../labs/diagrams-and-attack-trees-as-code/README.md)).
- **STRIDE GPT** can draft attack trees in Mermaid (see [chapter 06](../../06-threat-model-tools-reporting-and-ai/README.md)); review every node.

## ThreatSpec (legacy)

Study the annotation idea in the [devsecops-course lab](../../../devsecops-course/03-security-requirements-and-threat-modeling/labs/threat-modeling-as-code/README.md). Little or no development since about 2020 (verify); prefer pytm or Threagile for new work.
