from hitl_gate import Gate, GateError, Workflow, World

w = World()
g = Gate(w)
cards = Workflow(g, "alice").run(
    [("draft_email", {"to": "x"}), ("update_record", {"id": "r1", "value": "new"}), ("transfer_funds", {"to": "acct-A", "amount": 500})],
    now=0,
)
for c in cards:
    print(f"card {c.id}: {c.action:<15} risk={c.risk:<12} status={c.status}")
print("transfers so far:", w.transfers)
try:
    g.approve(3, "alice", cards[2].hash, 5)
except GateError as e:
    print("alice approving her own request ->", e)
g.approve(3, "bob", cards[2].hash, 5)
print("after bob approves:", w.transfers)
g.veto(2, "bob")
print("HOTL veto restored record r1 ->", w.records["r1"])
print("audit:", g.audit)
