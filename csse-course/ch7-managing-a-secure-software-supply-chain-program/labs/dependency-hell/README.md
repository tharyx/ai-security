# Lab: Handling Dependency Hell

**Course exercise:** "Handling Dependency Hell". Lessons: [02 section 5](../../02-vetting-process-and-automation.md#5-dependency-hell-and-the-security-trade-off). Related: [CAISP package-vetting](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/) (hash pinning), [third-party vulnerabilities](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/).

**Time:** 75 minutes. **Safety:** fixture registry, fictional packages and advisory ids.

## The scenario

```text
app -> web-framework ^2.0.0 -> json-lib ^2.0.0
app -> report-gen   ~1.3.0  -> json-lib ^1.0.0        (diamond: two incompatible ranges)
json-lib < 2.1.0 has a (fixture) high advisory, and 1.x will never get a fix.
```

A pip-style installer (one version per package) **fails**. An npm-style installer **succeeds** by installing both. Which is safer? Neither, automatically.

| Strategy | Result in this fixture | Security note |
|---|---|---|
| Plain flat resolve | fails, with a readable explanation | honest, but blocks the build |
| Nested install | works, 2 copies of json-lib | the vulnerable 1.9.0 copy is still shipped |
| Pin `json-lib==1.9.0` (constraint) | still fails | pins add a limit, they do not remove other limits |
| Override `json-lib -> ==1.9.0` | works | forces the **vulnerable** version on web-framework |
| Override `json-lib -> ^2.0.0` | works, no advisory | report-gen runs outside its declared range: test it |
| **Upgrade `report-gen` to 1.5.0** | works, no advisory, no violations | the clean fix: the maintainer already supports json-lib 2 |
| Lockfile | freezes the result and checks integrity | a lock also freezes a vulnerable version until someone updates it |
| Vendoring | immune to registry changes | no automatic updates or advisories: it goes stale |

Semver ranges in the lab: `^` (compatible, same major), `~` (same minor), `>=,<`, `==`, `*`, `||`.

## Steps

```text
.venv/Scripts/python csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/dependency-hell/demo.py
.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/dependency-hell -v
```

1. Read the conflict explanation. Which two dependents disagree?
2. Predict each strategy's row in the table before running the demo; then check.
3. Edit `registry.json`: remove report-gen 1.5.0. Which strategies are left? (Override with testing, or fork/patch report-gen, or replace it.)
4. Add a release `json-lib 2.2.1` and run the lockfile steps in the demo: the lock keeps 2.2.0, a fresh resolve takes 2.2.1. Which behaviour do you want in CI? In production? (Reproducible installs from the lock; a scheduled job that updates the lock and runs tests.)
5. Tamper with a lockfile integrity value: the install must fail (`test_lockfile_detects_changed_artifact`).

## Expected output (real run, trimmed)

```text
1. flat resolve -> FAILED
   no version of json-lib satisfies all of: report-gen@1.3.0 needs ^1.0.0; web-framework@2.0.0 needs ^2.0.0

strategy                             ok    vuln violated dup
plain flat resolve (pip-style)       False    0        0   0
nested install (npm-style)           True     1        0   1
pin json-lib==1.9.0 (constraint)     False    0        0   0
override json-lib -> 1.9.0           True     1        1   0
override json-lib -> ^2.0.0          True     0        1   0
upgrade report-gen to 1.5.0          True     0        0   0

lockfile install still uses: 2.2.0
fresh resolve now picks    : 2.2.1
vendored staleness         : ['json-lib: vendored 2.2.0, registry has 2.2.1']
```

Tests: 34.
