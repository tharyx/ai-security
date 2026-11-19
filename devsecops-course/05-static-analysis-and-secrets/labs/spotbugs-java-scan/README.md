# Lab: Using SpotBugs to scan Java code

**Course exercise:** "using SpotBugs to scan Java code." Lessons: [01 SAST basics and tools](../../01-sast-basics-and-tools.md#3-tools-by-language). Related: [CSE ch6 sast-in-pipeline lab](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/sast-in-pipeline/README.md) (SARIF and baseline ideas).

**Time:** 60 minutes. **Tests:** 8, all offline. **Safety:** the fixtures are **report files** for a fictional Java app. No Java, Maven or SpotBugs install is needed; no Java code is compiled or run.

> **Outdated to current.** The syllabus says "Find Bugs" in the lesson and SpotBugs in the lab. **FindBugs is dead; SpotBugs is its successor**, and **find-sec-bugs** is the plugin that adds the security patterns (with CWE ids). Verify versions at source.

## What it does

[sbscan.py](sbscan.py) parses a SpotBugs report in two formats and triages it:

| Step | Detail |
|---|---|
| **Parse XML** | [fixtures/spotbugsXml.xml](fixtures/spotbugsXml.xml) in the shape of a `BugCollection` with `BugInstance` (type, rank, category), `Class`, `Method`, `SourceLine` |
| **Parse SARIF** | [fixtures/results.sarif](fixtures/results.sarif) with rules, results and CWE tags (`external/cwe/cwe-89`) |
| **Map to CWE** | XML has no CWE field, so a small table maps bug types (SQL_INJECTION_JDBC to CWE-89 and so on); SARIF carries it in rule tags |
| **Filter** | Drops test code (`src/test/`) and non-security categories (I18N, CORRECTNESS) with [fixtures/triage.json](fixtures/triage.json) |
| **Decide** | A decision file keyed by a **line-independent fingerprint** (`type|class|method`) records `false_positive` or `accepted` with reason, owner and **expiry**. Expired decisions reactivate the finding |
| **Group and gate** | Group by CWE; fail when any active bug has rank at or below a threshold (1-4 scariest, 5-9 scary, 10-14 troubling, 15-20 of concern) |

## Run

```text
.venv/Scripts/python devsecops-course/05-static-analysis-and-secrets/labs/spotbugs-java-scan/demo.py
.venv/Scripts/python -m pytest devsecops-course/05-static-analysis-and-secrets/labs/spotbugs-java-scan -v
```

## Expected output (real run)

```text
== parsed 10 bug instances from spotbugsXml.xml

== dropped by triage
  HARD_CODE_PASSWORD       com.acme.shop.config.DbConfig.<clinit>  -> false_positive: value is the literal 'changeme-at-deploy' placeholder; the real secret is injected at runtime
  SQL_INJECTION_JDBC       com.acme.shop.test.FixtureLoader.load  -> excluded path (test or generated code)
  DM_DEFAULT_ENCODING      com.acme.shop.report.Reports.write  -> category I18N is not in scope for the security gate
  NP_NULL_ON_SOME_PATH     com.acme.shop.web.CartController.total  -> category CORRECTNESS is not in scope for the security gate

== active findings (worst first)
  rank 2  scariest   COMMAND_INJECTION        CWE-78  com/acme/shop/job/Exporter.java:61
  rank 3  scariest   SQL_INJECTION_JDBC       CWE-89  com/acme/shop/dao/UserDao.java:42
  rank 4  scariest   XSS_SERVLET              CWE-79  com/acme/shop/web/ProfileServlet.java:31
  rank 7  scary      PATH_TRAVERSAL_IN        CWE-22  com/acme/shop/web/FileController.java:55
  rank 9  scary      WEAK_MESSAGE_DIGEST_MD5  CWE-327  com/acme/shop/util/Hashing.java:20
  rank 12 troubling  PREDICTABLE_RANDOM       CWE-330  com/acme/shop/auth/TokenFactory.java:18  [expired-decision: accepted decision expired 2026-03-31; re-review]

== grouped by CWE
  CWE-78 OS Command Injection: 1
  CWE-89 SQL Injection: 1
  CWE-79 Cross-site Scripting: 1
  CWE-22 Path Traversal: 1
  CWE-327 Broken or Risky Crypto: 1
  CWE-330 Insufficiently Random Values: 1

== gate
fail on rank <= 9  -> exit 1
fail on rank <= 4  -> exit 1

SARIF and XML describe the same bugs: True
```

## Steps

1. Ten bug instances come in; four are dropped (one false positive with a reason, one test-code finding, two non-security categories). Six are active.
2. Look at `PREDICTABLE_RANDOM`: an earlier **accepted** decision expired on 2026-03-31 (the demo's "today" is 2026-11-19), so it is active again with a re-review note. Change the date in `triage.json` to 2027 and the finding is dropped again.
3. Change the gate to `rank <= 4`: still fails, because command injection, SQL injection and XSS are all "scariest". Fix them in your head: what mitigation would you ask for in each?
4. The SARIF and XML describe the same bugs (the last line of the demo). In real life, prefer SARIF because many UIs read it.
5. Move a bug's `start` line in the XML. Its fingerprint stays the same, so the decision still applies. That is why decisions use class and method, not line numbers.
6. Add a new `BugInstance` of type `COMMAND_INJECTION` in a different class and watch it appear as a **new** finding.

## Limits

- Only the findings are parsed. Real triage reads the code. The CWE table covers a handful of patterns; consult the find-sec-bugs documentation for the full list.
- Rank is SpotBugs' own scale. Combine it with your own severity policy.

## Run the real tool (hedged, verify at source)

```text
mvn compile spotbugs:check          # with find-sec-bugs configured as a plugin
mvn spotbugs:spotbugs               # writes target/spotbugsXml.xml
```

Maven plugin sketch, exclusion filter and CI pattern: [real-tools/sast-tools.md](../../real-tools/sast-tools.md). Run the real tool only on Java code you own.
