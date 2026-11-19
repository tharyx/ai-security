from deputy_chain import INJECTED_DOC, Denied, build

for secure in (False, True):
    asst, ledger = build(secure)
    ctx = asst.start("alice", {"read_docs"})
    label = "SECURE    " if secure else "VULNERABLE"
    try:
        asst.read_document(ctx, INJECTED_DOC)
        res = "executed"
    except Denied as e:
        res = f"denied ({e})"
    print(f"{label} alice reads injected doc -> {res}; ledger={ledger.entries}")

asst, ledger = build(True)
ctx = asst.start("bob", {"read_docs", "transfer"})
print("SECURE     bob explicit transfer ->", asst.explicit_request(ctx, "transfer", {"to": "acct-A", "amount": 50}))
try:
    asst.read_document(ctx, INJECTED_DOC)
except Denied as e:
    print("SECURE     bob reads injected doc ->", e)
