# Lab: Using Safety/pip to scan third-party component vulnerabilities in a Python code base

**Course exercise:** "using Safety/pip to scan third party component vulnerabilities in Python Code Base." Lessons: [01 basics](../../01-software-component-analysis-basics.md), [02 tools in the pipeline](../../02-sca-tools-in-the-pipeline.md). Related: [CAISP ch4 third-party-vulns lab](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md) (AI-flavoured twin).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** fictional packages and advisories; the application code is only parsed with `ast`, never imported or run. No pip, no network.

> **Outdated to current.** **Safety** (pyup) has a free database with limits and licence terms, and newer versions changed commands (`safety scan`, account may be required). **pip-audit** (PyPA) and **osv-scanner** are current free alternatives. Verify at source. See [real-tools/sca-cli-tools.md](../../real-tools/sca-cli-tools.md).

## What it does

[pyscan.py](pyscan.py):

1. **Parses requirements** ([fixtures/requirements.txt](fixtures/requirements.txt)): pins (`==`), ranges (`>=`, assumed lowest allowed, with a warning), extras (`pkg[extra]`), environment markers, `--hash` options, comments, and **`-r` includes** (with loop protection). Names are normalised like PEP 503.
2. **Matches advisories** in the shared OSV-format database, with numeric version ranges. The same pin in two files is **one finding**.
3. **Reachability triage (heuristic):** parses [fixtures/src/app.py](fixtures/src/app.py) with `ast`, resolves import aliases (`from pdfmake import extract as pdf_extract`) and checks whether the advisory's `affected_functions` are ever **called**. Not reachable means: package never imported, or the vulnerable function is never called.
4. **Gates:** a naive gate (any finding at or above a floor) and a reachability-aware gate.

## Run

```text
.venv/Scripts/python devsecops-course/04-software-component-analysis/labs/safety-pip-python/demo.py
.venv/Scripts/python -m pytest devsecops-course/04-software-component-analysis/labs/safety-pip-python -v
```

## Expected output (real run)

```text
== parsed 8 requirements
WARN requirements.txt:5: imgbox is not pinned (>=1.1); assuming lowest allowed 1.1

== safety / pip-audit style findings
[CRITICAL  9.8] DSO-OSV-0102  yamlish@5.3.0 (direct)  fix: 5.4.0  yamlish.unsafe_load builds arbitrary objects (deserialization)
[HIGH      7.4] DSO-OSV-0101  reqwise@2.18.0 (direct)  fix: 2.20.0  reqwise sends credentials to the proxy on redirect
[MEDIUM    5.5] DSO-OSV-0103  pdfmake-py@1.3.0 (direct)  fix: 1.3.1  pdfmake-py extract() allows path traversal from archive names
[LOW       3.7] DSO-OSV-0104  imgbox@1.1 (direct)  fix: 1.2.3  imgbox thumbnail leaks image metadata  NOTE: version not pinned, matched against the lowest allowed version

== reachability triage (heuristic, uses ast on fixtures/src)
fix first:
[HIGH      7.4] DSO-OSV-0101  reqwise@2.18.0 (direct)  fix: 2.20.0  reqwise sends credentials to the proxy on redirect  NOTE: reachability unknown (no function data)
[MEDIUM    5.5] DSO-OSV-0103  pdfmake-py@1.3.0 (direct)  fix: 1.3.1  pdfmake-py extract() allows path traversal from archive names  NOTE: REACHABLE: pdfmake.extract is called
deprioritise (still upgrade, but not an emergency):
[CRITICAL  9.8] DSO-OSV-0102  yamlish@5.3.0 (direct)  fix: 5.4.0  yamlish.unsafe_load builds arbitrary objects (deserialization)  NOTE: NOT reachable: yamlish.unsafe_load is never called
[LOW       3.7] DSO-OSV-0104  imgbox@1.1 (direct)  fix: 1.2.3  imgbox thumbnail leaks image metadata  NOTE: version not pinned, matched against the lowest allowed version; NOT reachable: package is never imported (maybe transitive or dev-only)

== break-build gates
fail-on high, all findings       -> exit 1
fail-on high, reachable only     -> exit 1
fail-on critical, reachable only -> exit 0
fail-on low, anything at all     -> exit 1
```

## Steps

1. Read the findings. `yamlish` is **critical** (unsafe deserialization), listed in two requirement files but reported once.
2. Read the reachability section. The app calls `yamlish.safe_load`, not `unsafe_load`, so the critical finding moves to "deprioritise". It is still worth upgrading, but it is not an emergency. `pdfmake.extract` **is** called, so the medium finding is reachable and moves up.
3. Compare the gates: the naive gate at `critical` fails; the reachability-aware gate at `critical` passes but still fails at `high` because of `reqwise`.
4. Change `imgbox>=1.1` to `imgbox==1.2.3` and the warning and the finding disappear. Pin your dependencies.
5. In `app.py` change `yamlish.safe_load` to `yamlish.unsafe_load` and rerun: the critical finding becomes reachable.
6. Think about what the heuristic misses: dynamic imports, `getattr`, calls from other modules, and transitive packages whose code your dependencies call.

## Limits

- **Reachability is a heuristic**; real tools combine call graphs and curated function data. A "not reachable" answer lowers urgency; it never removes the finding.
- A lock file with hashes (pip-tools, uv, Poetry) gives better inputs than a hand-written requirements file.

## Run the real tool (hedged, verify at source)

```text
pip-audit -r requirements.txt
safety check -r requirements.txt       # or `safety scan` in newer versions
osv-scanner scan source -L requirements.txt
```

Use the output exit code as your gate. Run them only on your own projects and keep any tokens in CI secrets.
