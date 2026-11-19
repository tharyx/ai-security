# Lab: Dependency confusion

**Course exercise:** "Dependency confusion". Lessons: [03 section 7-8](../../03-supply-chain-attacks-on-package-managers.md#7-dependency-confusion), [SVG](../../../../images/csse-ch2-dependency-confusion.svg). Related: [CAISP ch6 package-vetting](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/depconfusion.py) (this lab is self-contained and course-style).

**Time:** 30 minutes. **Safety:** everything is in memory. No package manager, no network. The "attacker install script" only appends a canary string.

## The setup

Two indexes: **private** (your company, has `acme-billing-utils 1.2.0`) and **public** (anyone can publish, has an attacker's `acme-billing-utils 99.0.0`). Four resolver policies are compared:

| Policy | Idea | Result |
|---|---|---|
| `resolve_highest_version` | merge all indexes, take the highest version (the "extra index" pattern) | **attacker wins** |
| `resolve_pinned_index` | each package is routed to exactly one index | safe, if the routing rule exists |
| `resolve_reserved_prefix` | internal prefix (`acme-`) may only come from private | safe, and public packages still work |
| `resolve_with_lock` | only a file with the locked sha256 is accepted | safe, even if the name is squatted |

`ide_quick_fix` models (hedged) an IDE "install the missing package" helper that looks a name up on the public index only.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/dependency-confusion/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/dependency-confusion
```

## Expected output (real run)

```text
highest-version (vulnerable)   -> 99.0.0 from public   canary_ran=True  (highest version across all indexes)
pinned index                   -> 1.2.0 from private  canary_ran=False  (routed to private)
reserved prefix 'acme-'        -> 1.2.0 from private  canary_ran=False  (routed to private)
hash-locked                    -> 1.2.0 from private  canary_ran=False  (hash matches lock)
IDE quick fix: pip install acme-billing-utils==99.0.0
```

## Break it yourself

1. Predict: what happens if the routing table forgets `acme-billing-utils`? (The test `test_pinned_index_misrouted_is_still_vulnerable` shows the attacker wins again: a default of "public" is the bug.)
2. Add a second internal package and forget to put it under the reserved prefix. Which policy still protects it? (Only the lock file.)
3. Register your internal names on the public index yourself (a placeholder). Which policy does that replace? (A weaker version of reserved prefix.)

## Real tools

Real package managers differ: some pick the highest version across indexes, some stop at the first index that has the name. Settings, scopes and proxy rules change: see [real-tools/osv-scanner-and-syft.md](../../real-tools/osv-scanner-and-syft.md) and the lesson. Verify at the source.
