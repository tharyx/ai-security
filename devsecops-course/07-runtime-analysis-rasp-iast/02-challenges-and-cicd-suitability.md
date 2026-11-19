# Lesson 02: Challenges of runtime analysis, and suitability in CI/CD

> **Sources merged:** [CDE 5] Runtime Analysis and challenges; RASP/IAST and its suitability in CI/CD pipeline.
> **Time:** about 2 hours. **Labs:** [iast-instrumentation](labs/iast-instrumentation/README.md) (coverage and false negatives), [rasp-blocking](labs/rasp-blocking/README.md) (overhead).

## 1. The challenges

### 1.1 Language and framework support

An agent must understand the runtime. Mature support exists for Java and .NET; others (Node.js, Python, Ruby, Go, PHP) vary by vendor, and **compiled languages like Go and Rust are hard** because there is no bytecode layer to hook. A new framework version can break an agent. Always check: *language, version, framework, app server, container base image, architecture (ARM or x86)*.

### 1.2 Performance overhead

Every wrapped call does extra work: marking data, checking sinks, building traces. Typical effects: more CPU, more memory, extra latency per request, slower startup. IAST can be heavy because it records detail, but it only runs in test. **RASP overhead matters more** because it runs in production on every request.

The lab measures it on a toy app (your numbers will differ; the *method* is the point):

```text
no agent         13.6 us   x1.00
IAST report      27.6 us   x2.03
RASP block       24.1 us   x1.77
```

In a toy app the app work is tiny, so the **relative** overhead looks large. In a real app, the database and network dominate and the agent's cost is a small slice. Always **measure on your own app, with your own load test**, p50 and p99 latency, before and after. Vendors publish numbers; verify them yourself.

### 1.3 Coverage depends on tests

IAST sees only the code that runs. If the test suite never calls the file-download endpoint, IAST never sees the path-traversal flow. The lab proves it: the nightly suite finds 2 flows; adding **one** more functional test (`test_read_doc`) finds a third (path traversal). Therefore:

- measure **code and endpoint coverage** of your test suite;
- combine IAST with DAST traffic and API tests so more paths are exercised;
- treat "IAST found nothing" as "nothing in the tested paths".

### 1.4 False negatives from lost taint

The toy agent loses taint in an f-string. Real agents have similar gaps: unsupported libraries, native code, data going through a cache or a message queue, custom sanitizers the agent does not know. This causes **false negatives** (missed bugs) and, when a custom sanitizer is unknown, **false positives**. Check which sinks and sanitizers your agent supports, and teach it your own.

### 1.5 False blocks (RASP)

Blocking a legitimate request is an outage. Examples: a user whose name is `O'Brien`, a search box where people type SQL for a database tutorial site, a JSON field containing `<script>` that is stored safely. Mitigation: monitor mode first, tune rules, allowlists per endpoint, and a **bypass switch** that disables blocking without a redeploy.

### 1.6 Operational and security risks

- The agent is **privileged code inside your process**. A flaw in it is a flaw in your app. Update it like any dependency.
- It sends data (stack traces, request fragments) to a vendor server. Check **privacy and data residency**; mask secrets and PII.
- Extra moving parts: licences, agent versions per app, rollout, upgrades, and a support relationship.
- Debugging gets harder: "is it my code or the agent?"
- Cost: usually priced per application or per server or per usage; verify.

## 2. Suitability in CI/CD

| Question | IAST | RASP |
|---|---|---|
| Fits in the pipeline? | **Yes**: runs in the test stage of CI | Not a pipeline test; a **runtime control** you deploy |
| Gate on results? | Yes: fail on new Critical/High flows | Gate on "agent present and in block mode" and on blocked-attack alerts after deploy |
| Speed | adds time to test runs; runs while tests run, so no extra stage | no pipeline time; adds request latency |
| Needs | good functional tests, a test environment with agent-enabled build | production rollout plan, SOC integration |
| Feedback to dev | fast, with file and line | alerts; a backlog of what attackers try |

How IAST fits into a pipeline:

```text
build -> deploy to test env WITH agent -> run functional + API tests (+ DAST) -> collect IAST findings
      -> gate (new High fails) -> findings tracker -> promote build (without agent or with it, per policy)
```

Good practice:

1. Run IAST **on the test environment** only, with the agent enabled by an environment variable, so the same artifact can go on to production.
2. Keep **one build artifact**; the agent is attached at deploy, not baked into a separate "IAST build" that differs from production.
3. Mark each test run so findings link to **build and commit**.
4. Triage in the same place as SAST/DAST/SCA findings ([chapter 14](../14-vulnerability-management/README.md)).
5. Decide the **gate** early. Start by only reporting, then block on new High.

How RASP fits: you deploy the agent with the app (or the platform), start in **monitor mode**, send alerts to the SIEM, review a week of data, then enforce on the highest-confidence rules (SQLi, command injection, deserialization) first. In the lab: `block_kinds` lets you block some classes and only monitor others.

## 3. Where runtime analysis is a poor fit

- Very small teams with no functional test suite (IAST has nothing to observe).
- Languages or frameworks the vendor does not support.
- Strict latency budgets where even a small overhead is not accepted.
- Environments where an agent in the process is not allowed (some regulated or hardened platforms).
- Serverless with short invocations: cold-start overhead and agent support need checking.

## 4. Positioning with other controls

| Control | Best at |
|---|---|
| SAST (chapter 05) | early, in the IDE and on commit; all code |
| SCA (chapter 04) | known vulnerable libraries |
| DAST (chapter 06) | configuration and runtime issues from outside |
| **IAST** | accurate findings with code location during tests |
| **RASP / WAF** | blocking attacks in production while fixes are prepared |

No single tool is enough. IAST reduces triage cost for what SAST and DAST find; RASP buys time.

## 5. Summary

- Challenges: language support, overhead, test coverage, lost taint (false negatives), false blocks, agent risk, vendor data sharing, cost.
- IAST is a good CI fit (runs while tests run, gives code traces). RASP is a production control, rolled out monitor-first.
- Measure overhead and coverage on your own application; do not trust a brochure number.
- "IAST found nothing" means "nothing on the paths the tests exercised".
