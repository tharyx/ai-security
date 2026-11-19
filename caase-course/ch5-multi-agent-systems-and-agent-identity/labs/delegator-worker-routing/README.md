# Lab: Delegator/Worker Pair with Local and Cloud-Routed Models

**Syllabus exercise:** Orchestrating a Local and Cloud-Routed Agent Pair in a Delegator/Worker Setup · **Lesson:** [01](../../01-multi-agent-architectures-and-protocols.md) · **Offline, no keys, 8 tests.**

A delegator splits a task into subtasks, a worker runs each one, and a **router** decides whether a mock *local* model or a mock *cloud* model gets it, based on a deterministic data classification (public / internal / restricted). The cloud mock records everything it receives, like a real provider's logs. Secrets are FAKE canaries.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/delegator-worker-routing
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/delegator-worker-routing/demo.py
```

Real output of `demo.py`:

```text
NAIVE router
  [unclassified] -> cloud Summarize public release notes about the framework
  [unclassified] -> cloud Draft a note for employee Alice about the internal
  [unclassified] -> cloud Check patient record FAKE-SSN-123 against the form
  restricted data seen by cloud provider: True

CLASSIFYING router
  [public      ] -> cloud Summarize public release notes about the framework
  [internal    ] -> local Draft a note for employee Alice about the internal
  [restricted  ] -> local Check patient record FAKE-SSN-123 against the form
  restricted data seen by cloud provider: False
```

## What the tests prove (impact, not "the model said no")

- Restricted data is never in the cloud mock's `seen` log; internal data stays local by default.
- With `allow_cloud_for_internal=True`, internal data reaches the cloud only **redacted**.
- If the local model is down, restricted work is **refused** (fail closed); public work falls back to local.
- The naive router leaks (the vulnerable case is tested too).

## Break it yourself

1. Add a restricted marker the classifier does not know (e.g. a new ID format). Predict: where does it go? Then extend `RESTRICTED_RE` and add a test.
2. Make the router trust a label the *subtask text* claims ("PUBLIC: ..."). Why is that unsafe?
3. Stretch: log a classification decision per subtask and hash the prompt (never log restricted text).

Real-tool version: [06 guide A](../../06-real-tool-guides.md#a-a-local-plus-cloud-routed-agent-pair-exercise-1).
