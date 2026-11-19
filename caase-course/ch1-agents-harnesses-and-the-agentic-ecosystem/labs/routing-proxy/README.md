# Lab: Routing proxy (local vs cloud by policy)

**Course exercise:** Routing Agent Requests to a Large Cloud Model via a Proxy and Comparing It to a Local Model.
**Time:** 45 minutes. Standard library plus `aisec_lab`. Offline. **Latency and cost are simulated.**

## What it shows

`router.py` is a small policy router between two **mock** models:

- `LocalModel`: private, free, short context (2000 tokens), faster for small tasks.
- `CloudModel`: large, billed per token, higher latency, and the provider **keeps what it is sent** (`provider_log`, to make "data leaves the boundary" visible). It can **substitute** another model to simulate a routing layer's silent fallback.

Policy:

1. **Scan** the prompt for fake secret-shaped values (a FAKE key, an email on a reserved domain, a customer id, a canary). A match raises the classification to at least confidential. **The caller's label is never trusted downward.** An unknown label is treated as the strictest.
2. Confidential or restricted data: local only. If it also needs a bigger model: **refuse** and say to use an approved private deployment.
3. Public or internal data: local if the task is small; cloud if it is large or complex.
4. Check the **served model** against the requested one and flag substitution.
5. Write an audit entry without the prompt text.

## Files

| File | Purpose |
|---|---|
| `router.py` | `Router`, `Request`, `LocalModel`, `CloudModel`, `scan`, `effective_classification`, `Router.compare` |
| `demo.py` | Five routed requests, a comparison, a substitution check |
| `test_caase_ch1_router.py` | 10 tests, including "no confidential data to cloud" |

## Run

```text
.venv/Scripts/python caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/routing-proxy/demo.py
.venv/Scripts/python -m pytest caase-course/ch1-agents-harnesses-and-the-agentic-ecosystem/labs/routing-proxy -v
```

Real output:

```text
case                                      decision class             ms      cost  reason
short public question                     local    public           404       0.0  small task, run locally
long public report                        cloud    public          1130     0.025  task exceeds local capacity and data is not confidential
confidential, labelled correctly          local    confidential     405       0.0  confidential data stays local
label says public but contains a FAKE key local    confidential     408       0.0  confidential data stays local
confidential and too big                  refuse   confidential       -         -  needs a bigger model but data is confidential: use an approved private deployment

cloud calls: 1 | prompts the provider could see: 1
no confidential prompt reached the cloud: OK

compare: [local-small] Explain RAG in two sentences | [cloud-large] detailed answer about: Explain RAG in two sentences
latency x2.21, extra cost $0.00207

model substitution detected: True served: cheaper-model-x
```

## The key tests

| Test | What it proves |
|---|---|
| `test_confidential_data_never_reaches_the_cloud` | Four confidential and restricted requests (some oversized): `cloud.calls == []` and `provider_log == []` |
| `test_a_false_public_label_is_overridden_by_the_dlp_scan` | A "public" request with a FAKE key is reclassified and refused when it needs the cloud |
| `test_cloud_provider_sees_what_it_is_sent_data_leaves_the_boundary` | The provider log holds the prompt: a public request still leaves your boundary |
| `test_model_substitution_is_detected` | A served model different from the requested one is flagged in the result and the audit log |

## Exercises

1. Add a DLP pattern (for example a fake AWS-style key shape marked FAKE) and a test that a prompt with it never reaches the cloud mock.
2. Add a **budget**: stop routing to cloud after a simulated spend of 0.05, and test it (LLM06).
3. Add a per-request `pin_model` option and refuse the response if the served model differs.
4. Compare the lab with the [LiteLLM guide](../../real-tools/litellm-proxy-cloud-routing.md): which of your rules would need a plugin or a separate layer there?

## Limits

- Regex DLP misses a lot (paraphrased secrets, personal data without a fixed shape) and has false positives. Real programs combine classifiers, labels from the data source and contracts.
- Latency and cost are made-up numbers that show the shape of the trade-off, not real prices.
