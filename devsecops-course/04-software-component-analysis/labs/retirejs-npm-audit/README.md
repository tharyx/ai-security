# Lab: Using RetireJS and npm to scan third-party component vulnerabilities in a JavaScript code base

**Course exercise:** "using RetireJS and NPM to scan third party component vulnerabilities in Javascript Code Base." Lessons: [01 basics](../../01-software-component-analysis-basics.md), [02 tools in the pipeline](../../02-sca-tools-in-the-pipeline.md). Related: [CSE ch2 sca lab](../../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca/README.md).

**Time:** 60 minutes. **Tests:** 11, all offline. **Safety:** package names and advisories are FICTIONAL (`DSO-OSV-nnnn`); nothing is installed, downloaded or executed. **No Node or network is needed.**

## What it does

[jsscan.py](jsscan.py) has two offline twins that read the shared OSV-format database ([../_shared/advisories.osv.json](../_shared/advisories.osv.json)):

| Twin | Mimics | Input | How it finds things |
|---|---|---|---|
| `npm_audit()` | `npm audit` | [fixtures/package-lock.json](fixtures/package-lock.json) (lockfile v3 `packages` map) | Resolves the dependency graph **like Node does**, finds the shortest path from the root, reports direct or transitive, dev flag, fixed version and **whether the fix is inside your declared range** or a major bump |
| `retire_scan()` | RetireJS | JS files under [fixtures/webapp](fixtures/webapp) and [fixtures/retire_extractors.json](fixtures/retire_extractors.json) | Recognises a library by **file name** or **banner comment** (a RetireJS-style repository entry with a version placeholder), then looks it up |

Also in the shared helper [../_shared/osv_common.py](../_shared/osv_common.py): numeric version compare, OSV `introduced`/`fixed` ranges, an **ignore list** with reason and expiry (`apply_ignores`), and the **break-build gate** (`gate`: severity floor, CVSS floor, count cap).

## Run

```text
.venv/Scripts/python devsecops-course/04-software-component-analysis/labs/retirejs-npm-audit/demo.py
.venv/Scripts/python -m pytest devsecops-course/04-software-component-analysis/labs/retirejs-npm-audit -v
```

## Expected output (real run)

```text
== npm audit style (package-lock.json)
[CRITICAL  9.8] DSO-OSV-0002  acme-templ@2.1.0 (via (root) > webkit-lite)  fix: 2.1.5  acme-templ compiles attacker-controlled templates (code injection)  NOTE: fix is inside your declared range
[HIGH      7.5] DSO-OSV-0001  fakequery@1.8.2 (direct)  fix: 1.9.0  FakeQuery html() does not escape script content (XSS)  NOTE: fix is inside your declared range
[MEDIUM    5.3] DSO-OSV-0003  tinyparse@0.9.1 (direct dev)  fix: 1.0.0  tinyparse regular expression denial of service (ReDoS)  NOTE: fix needs a MAJOR upgrade (breaking)

== npm audit --omit=dev
[CRITICAL  9.8] DSO-OSV-0002  acme-templ@2.1.0 (via (root) > webkit-lite)  fix: 2.1.5  acme-templ compiles attacker-controlled templates (code injection)  NOTE: fix is inside your declared range
[HIGH      7.5] DSO-OSV-0001  fakequery@1.8.2 (direct)  fix: 1.9.0  FakeQuery html() does not escape script content (XSS)  NOTE: fix is inside your declared range

== RetireJS style (files under webapp/)
[HIGH    ] DSO-OSV-0001 fakequery@1.8.2 in static/js/fakequery-1.8.2.min.js (found by filename+filecontent)
[MEDIUM  ] DSO-OSV-0004 chartlet@3.0.1 in static/js/vendor/bundle.js (found by filecontent)

== who found what
both         [('fakequery', 'DSO-OSV-0001')]
retire_only  [('chartlet', 'DSO-OSV-0004')]
audit_only   [('acme-templ', 'DSO-OSV-0002'), ('tinyparse', 'DSO-OSV-0003')]

== break-build gate (today = 2026-11-19)
WARN ignore for DSO-OSV-0004 EXPIRED on 2026-01-31: finding is active again
WARN ignore for DSO-OSV-0001 rejected: no reason
suppressed: ['DSO-OSV-0003/tinyparse']
fail-on critical -> exit 1
fail-on high     -> exit 1
fail-on medium   -> exit 1
fail-cvss 9.0     -> exit 1

== after upgrading acme-templ and fakequery (only the MEDIUM chartlet finding is left)
fail-on critical -> exit 0
fail-on high     -> exit 0
fail-on medium   -> exit 1
```

## Steps

1. **npm audit style:** `acme-templ` is **transitive** (path `webkit-lite` > `acme-templ`) and critical. The fix (2.1.5) is inside the range `^2.1.0`, so a plain update helps. `tinyparse` is dev only and its fix needs a **major** upgrade.
2. **`--omit=dev`:** the dev-only finding disappears. In real life decide deliberately whether dev tools are in scope.
3. **RetireJS style:** `chartlet 3.0.1` lives in `vendor/bundle.js`, copied by hand. It is **not in the lock file**, so only the file scanner sees it. `old/fq.js` is renamed, yet the banner shows 1.9.1, which is fixed, so it is not reported.
4. **Who found what:** `fakequery` by both, `chartlet` only by retire, `acme-templ` and `tinyparse` only by audit. Neither tool alone is enough.
5. **Gates and ignores:** the ignore file has three entries: a valid one (suppressed), an **expired** one (finding active again, with a warning) and one with **no reason** (rejected). Try changing the dates in the demo.
6. **Exercise:** add a new library banner for `webkit-lite` to the extractors and a matching file; add an advisory range with `last_affected` instead of `fixed`; change the lock file so `webkit-lite` is `4.1.0` and see `DSO-OSV-0005` appear.

## Limits

- Real `npm audit` asks the registry (GitHub advisories) and handles many more lock file shapes; the offline twin shows the logic, not the service.
- Real RetireJS has a large community repository and also matches file hashes.
- A banner can lie (someone edits it). File hashes are stronger evidence.

## Run the real tool (hedged, verify at source)

```text
npm ci && npm audit --audit-level=high --omit=dev
npx retire --path ./webapp --severity high
```

See [real-tools/sca-cli-tools.md](../../real-tools/sca-cli-tools.md). Run them only on your own projects.
