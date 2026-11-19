import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diagrams as d  # noqa: E402

print("== 1. UML as code: sequence diagram of the password reset flow ==")
seq = d.sequence_diagram(
    "Password reset",
    [("actor", "User"), ("participant", "Web App"), ("database", "Users DB"), ("participant", "Mailer")],
    [("User", "Web App", "POST /reset {email}"), ("Web App", "Users DB", "store hash(token), expiry 15 min"),
     ("Web App", "Mailer", "send link with token"), ("Web App", "User", "return same message for every email")],
)
print(seq)
print("lint:", d.lint_plantuml(seq) or "ok")

print("\n== 2. Use and misuse cases as code ==")
uc = d.misuse_case_diagram(["Customer"], ["Attacker"], ["Reset password", "View orders"],
                           [("Enumerate accounts", "Reset password"), ("Read other orders (BOLA)", "View orders")],
                           [("Customer", "Reset password"), ("Customer", "View orders"),
                            ("Attacker", "Enumerate accounts"), ("Attacker", "Read other orders (BOLA)")])
print(uc)
print("lint:", d.lint_plantuml(uc) or "ok")

print("\n== 3. A broken diagram is caught ==")
print(d.lint_plantuml("@startuml\nactor A\nA -> B: hi\n"))

print("\n== 4. Attack tree as code ==")
tree = d.parse_tree((HERE / "fixtures" / "steal_customer_data.tree").read_text(encoding="utf-8"))
for controls in [set(), {"L3"}, {"L3", "L2"}, {"L3", "L2", "L5"}, {"L3", "L2", "L5", "L6"}]:
    d.mitigate(tree, controls)
    cost, path = d.cheapest(tree)
    print(f"  blocked {sorted(controls) or '-'}: cheapest attack {cost:g} via {path or '-'}, "
          f"P(success) {d.probability(tree):.2f}")

print("\n== 5. Mermaid for the tree with L3 blocked ==")
d.mitigate(tree, {"L3"})
print(d.to_mermaid(tree))
