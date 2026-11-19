# Lab: An Observability Dashboard for Agent Reasoning Traces

**Syllabus exercise:** Building an Observability Dashboard for Agent Reasoning Traces · **Lesson:** [02](../../02-observability-and-anomaly-detection.md) · **Offline, 8 tests.**

`trace_dashboard.py` loads trace JSON (spans of kind `plan`, `llm`, `tool`, `decision`), builds a baseline profile (tool mix, mean/std of steps, known decisions), detects drift (new tool, total variation distance, step outlier, unseen decision) and renders a static **Markdown** and **HTML** dashboard. All trace text is HTML-escaped, because it is untrusted.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch6-operationalizing-agentic-ai-security/labs/agent-observability-dashboard
.venv/Scripts/python caase-course/ch6-operationalizing-agentic-ai-security/labs/agent-observability-dashboard/demo.py
```

`demo.py` writes `sample_traces.json`, `dashboard.md` and `dashboard.html` next to the code. Open the HTML in a browser.

Real output:

```text
[new_tool] odd-1: tool 'http_post' never seen in baseline
[new_tool] odd-1: tool 'run_shell' never seen in baseline
[new_decision] odd-1: decision 'override_policy' never seen in baseline
[new_tool] odd-2: tool 'http_post' never seen in baseline
[new_tool] odd-2: tool 'run_shell' never seen in baseline
[step_outlier] odd-2: 22 spans (z=11.3)
[new_tool] odd-3: tool 'http_post' never seen in baseline
[new_tool] odd-3: tool 'run_shell' never seen in baseline
[tool_mix_drift] window: total variation distance 0.93 > 0.3
wrote dashboard.md and dashboard.html (open the HTML in a browser)
```

## What the tests prove

Normal traffic has no findings; the drifted traces trigger all four rule types; orphan spans are rejected on load; an XSS string in a span attribute appears as escaped text (no `<script>` in the page); the Markdown has the finding list, tool counts and an indented span tree.

## Break it yourself

1. Remove `html.escape` for attributes: which test fails?
2. Tune `tvd_limit` and `z_limit` until the baseline traffic starts raising false alarms. What does that tell you about threshold choice?
3. Stretch: export the same spans as OpenTelemetry-style JSON (check current GenAI semantic conventions) and view them in a free local tracing UI (optional, hedged).
