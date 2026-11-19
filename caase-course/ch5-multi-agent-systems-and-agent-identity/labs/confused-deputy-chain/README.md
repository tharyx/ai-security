# Lab: Exploiting a Confused-Deputy Chain

**Syllabus exercise:** Exploiting a Confused-Deputy Chain Across Delegated Agents · **Lesson:** [03](../../03-collusion-and-confused-deputies.md) · **Offline, 9 tests.**

Chain: `user -> Assistant -> Researcher -> FinanceAgent`. An injected document makes the Assistant's (gullible mock) model emit a transfer. The vulnerable deputy checks only its own permissions. The secure deputy checks the intersection of its permissions, the principal's permissions and the delegated scopes, and requires approval for tainted high-value actions. The "ledger" is an in-memory list.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/confused-deputy-chain
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/confused-deputy-chain/demo.py
```

Real output of `demo.py`:

```text
VULNERABLE alice reads injected doc -> executed; ledger=[('acct-FAKE-EVIL', 5000, 'alice')]
SECURE     alice reads injected doc -> denied (action not in delegated scopes); ledger=[]
SECURE     bob explicit transfer -> transferred
SECURE     bob reads injected doc -> tainted high-value action needs human approval
```

Alice cannot transfer money, yet the vulnerable system moved 5000 in her name through the deputy. Even Bob, who *may* transfer, is stopped when the request was caused by document content.

## Tests worth reading

- `test_downscoping_on_a_hop_removes_authority_bob_has`: narrowing scope on a hop removes authority even for an authorized principal.
- `test_scopes_only_shrink`, `test_chain_depth_limit`, `test_deputy_own_permissions_still_checked`.

## Break it yourself

1. Delete the `ctx.tainted` check: which test fails? Who is now the only barrier?
2. Make `Researcher.forward` pass `scopes=None` always. Do you still catch Alice?
3. Stretch: add a payee allowlist to the deputy and test an injected payee.
