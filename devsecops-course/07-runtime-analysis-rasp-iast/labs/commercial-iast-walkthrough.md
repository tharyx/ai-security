# Walkthrough: deploying a commercial IAST (Contrast-style), step by step

**Course exercise:** "A commercial implementation of the IAST tool". **Lessons:** [03 commercial implementations](../03-commercial-implementations.md), [02 CI/CD suitability](../02-challenges-and-cicd-suitability.md#2-suitability-in-cicd).

> **Hedged and generic.** This is a **guide, not a tested lab**: it needs a vendor account, an agent download and a server, none of which the course tests use. Contrast Security is used as a **shape** (agent, server, CI gate) because the syllabus line says "a commercial implementation". Other vendors (for example Datadog Code Security or Seeker) follow the same pattern with different names and steps. **Verify every command, variable and property name in the vendor's current documentation.** Never put real keys in files; the placeholders below are fake.

## 0. What you need

- A vendor account or trial (SaaS) or a self-hosted server.
- An application you own, in a **test environment**, with a functional test suite.
- A CI system that can run the test stage and call an API.
- A secret store for the agent's API credentials.

## 1. Choose where the agent runs

Only **test/QA or a review environment**. The same build artifact goes to production **without** the IAST agent (or with the RASP/protect mode, per policy). Do not run an IAST agent against production traffic unless your policy and the vendor documentation allow it.

## 2. Get agent credentials from the server

In the vendor console, create an **application** entry (name, language, environment = QA) and copy the agent credentials. They usually include a server URL, an organisation id, an API key and a service key (names vary). Put them in the CI secret store as variables, for example `IAST_SERVER_URL`, `IAST_API_KEY`, `IAST_SERVICE_KEY` (placeholders; the real names differ).

## 3. Attach the agent

Language examples, in shape only (verify):

| Stack | How the agent is attached |
|---|---|
| Java | add `-javaagent:/opt/agent/agent.jar` to the JVM options and set the config properties or environment variables |
| .NET | install the agent package, set the profiler environment variables |
| Node.js | add the agent package and `require` it as the first line (or use a preload option) |
| Python | install the agent package and start the app through the agent's launcher or import it first |

In a container, add the agent in the image build or an init container and pass credentials as environment variables at **runtime**, not baked into the image.

Example (Kubernetes deployment fragment, shape only):

```yaml
env:
  - name: IAST_ENABLED
    value: "true"
  - name: IAST_APP_NAME
    value: orders-service
  - name: IAST_APP_ENV
    value: QA
  - name: IAST_API_KEY
    valueFrom: {secretKeyRef: {name: iast-agent, key: api-key}}
```

## 4. Start the app and confirm the agent connected

Look for the app in the console (status: connected, agent version, language). If it does not appear, check outbound network access to the server, proxy settings, and the agent's own log.

## 5. Drive traffic

Run what you already have:

1. the **functional and API test suite**;
2. optionally a **DAST scan** (ZAP or others) from [chapter 06](../../06-dynamic-analysis/README.md), which exercises many more inputs and paths;
3. do not run load tests against an agent build and call it security testing.

The agent sees each request, tracks tainted data and raises a finding when tainted data reaches an unsafe sink: exactly what [`agent.py`](iast-instrumentation/agent.py) does in the toy lab.

## 6. Read a finding

A good finding shows:

- **rule** (for example SQL injection) and severity;
- the **source** (which parameter or header);
- the **trace** (methods and lines the data passed through);
- the **sink** and a **code location**;
- the **request** that triggered it (mask secrets);
- advice on the fix (parameterised query, encoding, validation).

Compare with the lab trace:

```text
[SQL_INJECTION] during test_find_user_by_name
    SOURCE   request.args['name']
    PROPAGATE concat at tinyapp.py:user_by_name:65
    SINK     Database.execute called at tinyapp.py:user_by_name:66
```

## 7. Add the CI gate

At the end of the test stage, call the vendor's API (or use their CI plugin) to ask for **new findings for this build or branch** above a severity, and fail the job on policy breach. Shape:

```text
pytest / mvn verify (tests run with agent enabled)
  -> call: GET <server>/findings?build=$CI_COMMIT_SHA&severity>=HIGH&status=new
  -> exit 1 if any
```

Gate rules (same as for other scanners): fail on **new** High/Critical, keep known debt in a baseline or suppression list with an owner and expiry, and **fail if the agent never connected** (otherwise a broken agent looks like a clean build).

## 8. Triage and track

- Send findings to your tracker, or import them into the findings database ([chapter 14](../../14-vulnerability-management/README.md)).
- Mark false positives (for example a custom sanitizer the agent did not know) and **teach the agent** through a custom sanitizer or validator rule.
- Track MTTR and recurrence like other findings.

## 9. Production and RASP (optional)

If the same vendor offers a protect mode, deploy it with the production build in **monitor** mode, feed alerts to the SIEM, review a week, then enforce on the highest-confidence rules. Keep a **bypass switch**. Compare with [rasp-blocking](rasp-blocking/README.md).

## 10. Checklist

- [ ] Agent only in test (and protect mode in production by policy)
- [ ] Credentials in a secret store, injected at runtime
- [ ] Test suite covers the main endpoints (coverage measured)
- [ ] Gate fails on new High and on "agent not connected"
- [ ] Overhead measured under load
- [ ] Data handling reviewed (what the agent sends to the server)
- [ ] Findings flow into the tracker with owners and due dates
- [ ] A plan for agent upgrades
