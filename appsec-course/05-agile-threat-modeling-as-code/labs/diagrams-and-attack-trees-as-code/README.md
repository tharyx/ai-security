# Lab: Diagrams as code, UML as code and attack trees as code

**Course exercises:** [CTMP 3] "Threat Modeling Diagrams as Code", "Exploring UML as Code", "Creating Attack Trees Using Code". Lesson: [02 sections 2 to 4](../../02-threat-modeling-as-code-pytm-and-diagrams.md#3-diagrams-as-code-and-uml-as-code).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** text generation only. Only test systems you own or have written permission to test.

## Goal

Generate threat modeling diagrams from text so they can be diffed, reviewed and checked in CI: a UML sequence diagram, a UML class diagram, a use/misuse case diagram, and an attack tree that you can **compute** (cheapest attack, success probability) as well as draw.

## Concept

[diagrams.py](diagrams.py) has three parts:

| Part | Functions | Output |
|---|---|---|
| UML as code | `sequence_diagram`, `class_diagram`, `misuse_case_diagram` | PlantUML text |
| Diagram linter | `lint_plantuml` | problems: missing `@startuml`/`@enduml`, undeclared participants, duplicate aliases |
| Attack trees as code | `parse_tree`, `cheapest`, `probability`, `mitigate`, `to_mermaid`, `to_dot` | numbers plus Mermaid or Graphviz text |

The attack tree DSL ([fixtures/steal_customer_data.tree](fixtures/steal_customer_data.tree)) is indented text, two spaces per level:

```text
OR: Read another customer's order history
  AND: Take over a customer account
    LEAF: Get the customer's password from a breach list [id=L1, cost=50, p=0.30]
    LEAF: Log in without a second factor [id=L2, cost=0, p=0.90]
  LEAF: Change order_id in the API call (BOLA) [id=L3, cost=10, p=0.60]
```

`OR` means any child is enough (take the cheapest); `AND` means all children are needed (add the costs). `mitigate(tree, {"L3"})` marks a leaf as blocked by a control. The DFD as code (Graphviz) is produced by the [pytm-lite lab](../pytm-lite/README.md) (`tm.dfd()`).

## Steps

```text
.venv/Scripts/python appsec-course/05-agile-threat-modeling-as-code/labs/diagrams-and-attack-trees-as-code/demo.py
.venv/Scripts/python -m pytest appsec-course/05-agile-threat-modeling-as-code/labs/diagrams-and-attack-trees-as-code -q -p no:cacheprovider
```

1. Run the demo. Paste the PlantUML blocks into a PlantUML renderer and the Mermaid block into a Mermaid renderer (GitHub renders Mermaid in Markdown) if you want pictures.
2. Read the attack tree table: each control pushes the cheapest attack to a costlier path (10 → 50 → 300 → 2000). This is how you **justify** a control's priority: block the cheapest path first.
3. Add a leaf under the `OR` root: `LEAF: Buy a session cookie from an infostealer log [id=L7, cost=100, p=0.2]`. Which control set is now enough?
4. Break the sequence diagram (remove `@enduml` or use a participant you did not declare). The linter catches it, so CI can fail on a broken diagram.

## Expected output (real run of demo.py)

```text
== 1. UML as code: sequence diagram of the password reset flow ==
@startuml
title Password reset
actor "User" as User
participant "Web App" as Web_App
database "Users DB" as Users_DB
participant "Mailer" as Mailer
User -> Web_App: POST /reset {email}
Web_App -> Users_DB: store hash(token), expiry 15 min
Web_App -> Mailer: send link with token
Web_App --> User: return same message for every email
@enduml
lint: ok

== 2. Use and misuse cases as code ==
@startuml
left to right direction
skinparam usecase {
  BackgroundColor<<misuse>> Black
  FontColor<<misuse>> White
}
actor "Customer" as Customer
actor "Attacker" as Attacker #black
usecase "Reset password" as Reset_password
usecase "View orders" as View_orders
usecase "Enumerate accounts" as Enumerate_accounts <<misuse>>
usecase "Read other orders (BOLA)" as Read_other_orders__BOLA_ <<misuse>>
Customer --> Reset_password
Customer --> View_orders
Attacker --> Enumerate_accounts
Attacker --> Read_other_orders__BOLA_
Enumerate_accounts ..> Reset_password : <<threatens>>
Read_other_orders__BOLA_ ..> View_orders : <<threatens>>
@enduml
lint: ok

== 3. A broken diagram is caught ==
['last line must be @enduml', 'undeclared participant: B']

== 4. Attack tree as code ==
  blocked -: cheapest attack 10 via ['L3'], P(success) 0.77
  blocked ['L3']: cheapest attack 50 via ['L1', 'L2'], P(success) 0.42
  blocked ['L2', 'L3']: cheapest attack 300 via ['L4', 'L5'], P(success) 0.20
  blocked ['L2', 'L3', 'L5']: cheapest attack 2000 via ['L6'], P(success) 0.05
  blocked ['L2', 'L3', 'L5', 'L6']: cheapest attack inf via -, P(success) 0.00

== 5. Mermaid for the tree with L3 blocked ==
graph TD
  N1["Read another customer's order history<br/>OR"]
  N2{"Take over a customer account<br/>AND"}
  L1["Get the customer's password from a breach list<br/>cost 50, p 0.3"]
  N2 --> L1
  L2["Log in without a second factor<br/>cost 0, p 0.9"]
  N2 --> L2
  N1 --> N2
  L3["Change order_id in the API call (BOLA)<br/>cost 10, p 0.6"]
  class L3 blocked
  N1 --> L3
  N6{"Read the database directly<br/>AND"}
  L4["Phish a support engineer<br/>cost 300, p 0.2"]
  N6 --> L4
  L5["Use the shared read-only DB login<br/>cost 0, p 0.8"]
  N6 --> L5
  N1 --> N6
  L6["Restore a stolen unencrypted backup<br/>cost 2000, p 0.05"]
  N1 --> L6
  classDef blocked fill:#dcfce7,stroke:#16a34a,stroke-dasharray: 4
```

## Run the real tool (hedged)

- **PlantUML** (needs Java): `java -jar plantuml.jar diagram.puml` writes a PNG. The PlantUML server and IDE plugins also render it. Check plantuml.com for the current release.
- **Graphviz:** `dot -Tsvg attack_tree.dot -o attack_tree.svg`.
- **Mermaid:** GitHub, GitLab and many wikis render ```` ```mermaid ```` blocks; `mmdc` (mermaid-cli, Node) renders files.
- **Attack tree tools** (verify status): ADTool (attack-defence trees), and the attack tree support in Threagile and some commercial platforms. STRIDE GPT can draft attack trees in Mermaid (see [chapter 06](../../../06-threat-model-tools-reporting-and-ai/README.md)).
- More in [real-tools/pytm-threagile-and-diagram-tools.md](../../real-tools/pytm-threagile-and-diagram-tools.md).

## What you learned

- A diagram in text is reviewable: a new arrow in a sequence diagram shows up in the merge request.
- Misuse cases sit next to use cases and point at what they threaten.
- An attack tree in code is not only a picture: you can compute the cheapest attack and show how each control changes it.
- Lint diagrams in CI so a broken diagram fails loudly.
