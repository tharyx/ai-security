# Demo lab: Using OWASP Dependency-Check to scan third-party component vulnerabilities in a Java code base

**Course exercise (Demo):** "Using OWASP Dependency Checker to scan third party component vulnerabilities in Java Code Base." Lessons: [01 basics](../../01-software-component-analysis-basics.md), [02 tools in the pipeline](../../02-sca-tools-in-the-pipeline.md). Real tool notes: [real-tools/dependency-check.md](../../real-tools/dependency-check.md).

**Time:** 45 minutes (a demo-level lab). **Tests:** 10, all offline. **Safety:** fictional coordinates and advisories; the `pom.xml` is only parsed. **No Java, Maven, NVD download or network is needed.**

> **Outdated to current.** OWASP Dependency-Check needs an **NVD API key** since the NVD API 2.0 changes, downloads a large database on first run, and produces name-matching false positives. Verify at source.

## What it does

[mvnscan.py](mvnscan.py) imitates the two ideas behind Dependency-Check:

1. **Read the pom.** [fixtures/pom.xml](fixtures/pom.xml): `${property}` versions are resolved, a missing version is taken from `dependencyManagement`, scopes are kept, and an unresolvable property is **reported, not guessed**.
2. **Match by CPE-style name.** It guesses vendor and product from `groupId` and `artifactId` (stripping suffixes such as `-core` or `-test-utils`) and compares them with the `cpe` field in the advisories. It assigns a **confidence**: vendor and full product match is `HIGHEST`; a suffix-stripped product with a matching vendor is `MEDIUM`; weaker matches are `LOW`.
3. **Contrast with coordinate matching** (the OSV way): exact `groupId:artifactId`.
4. **Break the build** on a CVSS threshold (`failBuildOnCVSS`) and a confidence floor. A **suppression file** ([fixtures/suppressions.json](fixtures/suppressions.json)) removes known false positives; it needs a reason and an expiry.

## Run

```text
.venv/Scripts/python devsecops-course/04-software-component-analysis/labs/dependency-check-java/demo.py
.venv/Scripts/python -m pytest devsecops-course/04-software-component-analysis/labs/dependency-check-java -v
```

## Expected output (real run)

```text
== dependencies read from pom.xml (properties and dependencyManagement resolved)
  com.example.widget:widgetlib-core:2.4.1  scope=compile
  com.example.widget:widgetlib-docs:2.4.1  scope=runtime
  com.example.widget:widgetlib-test-utils:2.4.1  scope=test
  org.sample:jsonmark:1.2.0  scope=compile
  com.acme.web:acme-web:3.1.0  scope=compile
  org.sample:mystery-lib:None  scope=compile
WARN org.sample:mystery-lib: version unknown, cannot be analysed
WARN unresolved property ${mystery.version} for org.sample:mystery-lib

== CPE-style matching (Dependency-Check approach), test scope skipped
[HIGH      8.1] DSO-OSV-0201  com.example.widget:widgetlib-core@2.4.1 (direct)  fix: 2.4.3  widgetlib-core deserializes untrusted widget state  NOTE: matched CPE cpe:2.3:a:example:widgetlib with MEDIUM confidence (scope compile)
[HIGH      8.1] DSO-OSV-0201  com.example.widget:widgetlib-docs@2.4.1 (direct)  fix: 2.4.3  widgetlib-core deserializes untrusted widget state  NOTE: matched CPE cpe:2.3:a:example:widgetlib with MEDIUM confidence (scope runtime)
[HIGH      7.5] DSO-OSV-0202  org.sample:jsonmark@1.2.0 (direct)  fix: 1.2.4  jsonmark parser allows unbounded nesting (denial of service)  NOTE: matched CPE cpe:2.3:a:sample:jsonmark with HIGHEST confidence (scope compile)

== same pom with test scope included (skipTestScope=false)
[HIGH      8.1] DSO-OSV-0201  com.example.widget:widgetlib-core@2.4.1 (direct)  fix: 2.4.3  widgetlib-core deserializes untrusted widget state  NOTE: matched CPE cpe:2.3:a:example:widgetlib with MEDIUM confidence (scope compile)
[HIGH      8.1] DSO-OSV-0201  com.example.widget:widgetlib-docs@2.4.1 (direct)  fix: 2.4.3  widgetlib-core deserializes untrusted widget state  NOTE: matched CPE cpe:2.3:a:example:widgetlib with MEDIUM confidence (scope runtime)
[HIGH      8.1] DSO-OSV-0201  com.example.widget:widgetlib-test-utils@2.4.1 (direct)  fix: 2.4.3  widgetlib-core deserializes untrusted widget state  NOTE: matched CPE cpe:2.3:a:example:widgetlib with MEDIUM confidence (scope test)
[HIGH      7.5] DSO-OSV-0202  org.sample:jsonmark@1.2.0 (direct)  fix: 1.2.4  jsonmark parser allows unbounded nesting (denial of service)  NOTE: matched CPE cpe:2.3:a:sample:jsonmark with HIGHEST confidence (scope compile)

== exact coordinate matching (OSV approach)
[HIGH      8.1] DSO-OSV-0201  com.example.widget:widgetlib-core@2.4.1 (direct)  fix: 2.4.3  widgetlib-core deserializes untrusted widget state  NOTE: exact groupId:artifactId match
[HIGH      7.5] DSO-OSV-0202  org.sample:jsonmark@1.2.0 (direct)  fix: 1.2.4  jsonmark parser allows unbounded nesting (denial of service)  NOTE: exact groupId:artifactId match

== suppress the false positive, then break the build on CVSS >= 7.0
suppressed: ['DSO-OSV-0201/com.example.widget:widgetlib-docs']
failBuildOnCVSS=7  -> exit 1
failBuildOnCVSS=9  -> exit 0
failBuildOnCVSS=7, min confidence HIGHEST -> exit 1
```

## Steps

1. Read the resolved dependencies. `acme-web` got its version from `dependencyManagement`; `mystery-lib` has an unresolved `${mystery.version}` and is skipped with a warning.
2. CPE mode finds `widgetlib-core` (a true positive) **and** `widgetlib-docs` (a **false positive**: the product name `widgetlib` matches, but the docs jar does not contain the vulnerable class). `jsonmark` matches with `HIGHEST` confidence.
3. Test scope is skipped by default (`skipTestScope`). Turn it on and `widgetlib-test-utils` appears too.
4. Coordinate mode reports only the two real findings. This is why OSV-based tools have fewer name-collision false positives, and why CPE tools can still find things that have no clean coordinates.
5. Apply the suppression: only the false positive is removed, and an expiry date forces a re-review.
6. Change `failBuildOnCVSS` to 9 and watch the build pass; raise the confidence floor to `HIGHEST` and see which findings stop counting.

## Limits

- This is a **demo-level twin**. Real Dependency-Check inspects jar contents, manifests and hashes, and uses NVD CPE ranges, which are messier than these records.
- A suppression is a decision to take responsibility. Keep reasons and dates.

## Run the real tool (hedged, verify at source)

```text
dependency-check.sh --project shop-service --scan . --format HTML --failOnCVSS 7 --nvdApiKey "$NVD_API_KEY"
mvn org.owasp:dependency-check-maven:check
```

The key belongs in a CI secret. See [real-tools/dependency-check.md](../../real-tools/dependency-check.md).
