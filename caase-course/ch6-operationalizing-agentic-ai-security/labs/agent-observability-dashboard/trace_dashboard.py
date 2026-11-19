"""Observability for agent reasoning traces: static dashboard + drift detection.

Trace format (JSON, OpenTelemetry-like; this is NOT the OTel wire format):
  {"traces": [{"trace_id": "t1", "agent": "support-agent", "spans": [
      {"id": "s1", "parent": null, "kind": "plan|tool|decision|llm",
       "name": "...", "start": 0.0, "end": 0.4, "attrs": {...}}]}]}

Span kinds: ``plan`` (the agent's stated plan step), ``tool`` (a tool call),
``decision`` (a branch/approve/escalate outcome), ``llm`` (a model call).

Drift detection compares a window of recent traces with a baseline profile:
new tools, change in tool-usage mix (total variation distance), step-count
outliers (z-score) and never-seen decisions. Trace text is UNTRUSTED (it can
contain attacker content), so every value is HTML-escaped when rendered.
"""

from __future__ import annotations

import html
import json
import statistics
from collections import Counter
from dataclasses import dataclass, field


def load(text: str) -> list[dict]:
    data = json.loads(text)
    traces = data["traces"]
    for t in traces:
        ids = {s["id"] for s in t["spans"]}
        for s in t["spans"]:
            if s["parent"] is not None and s["parent"] not in ids:
                raise ValueError(f"trace {t['trace_id']}: span {s['id']} has unknown parent")
    return traces


def tool_counts(traces: list[dict]) -> Counter:
    return Counter(s["name"] for t in traces for s in t["spans"] if s["kind"] == "tool")


def decision_counts(traces: list[dict]) -> Counter:
    return Counter(s["name"] for t in traces for s in t["spans"] if s["kind"] == "decision")


@dataclass
class Profile:
    tools: Counter
    decisions: Counter
    mean_steps: float
    std_steps: float

    @property
    def tool_dist(self) -> dict[str, float]:
        n = sum(self.tools.values()) or 1
        return {k: v / n for k, v in self.tools.items()}


def build_profile(traces: list[dict]) -> Profile:
    steps = [len(t["spans"]) for t in traces]
    return Profile(tool_counts(traces), decision_counts(traces), statistics.mean(steps), statistics.pstdev(steps) or 1.0)


@dataclass
class Finding:
    scope: str  # trace id or "window"
    rule: str
    detail: str


def tvd(p: dict[str, float], q: dict[str, float]) -> float:
    keys = set(p) | set(q)
    return 0.5 * sum(abs(p.get(k, 0.0) - q.get(k, 0.0)) for k in keys)


def detect(window: list[dict], base: Profile, tvd_limit: float = 0.30, z_limit: float = 3.0) -> list[Finding]:
    out: list[Finding] = []
    for t in window:
        tools = {s["name"] for s in t["spans"] if s["kind"] == "tool"}
        for new in sorted(tools - set(base.tools)):
            out.append(Finding(t["trace_id"], "new_tool", f"tool '{new}' never seen in baseline"))
        for s in t["spans"]:
            if s["kind"] == "decision" and s["name"] not in base.decisions:
                out.append(Finding(t["trace_id"], "new_decision", f"decision '{s['name']}' never seen in baseline"))
        z = (len(t["spans"]) - base.mean_steps) / base.std_steps
        if z > z_limit:
            out.append(Finding(t["trace_id"], "step_outlier", f"{len(t['spans'])} spans (z={z:.1f})"))
    wc = tool_counts(window)
    n = sum(wc.values()) or 1
    d = tvd(base.tool_dist, {k: v / n for k, v in wc.items()})
    if d > tvd_limit:
        out.append(Finding("window", "tool_mix_drift", f"total variation distance {d:.2f} > {tvd_limit}"))
    return out


# ---------------------------------------------------------------- rendering
def _tree(spans: list[dict]) -> list[tuple[int, dict]]:
    kids: dict = {}
    for s in spans:
        kids.setdefault(s["parent"], []).append(s)
    out: list[tuple[int, dict]] = []

    def walk(pid, depth):
        for s in sorted(kids.get(pid, []), key=lambda x: x["start"]):
            out.append((depth, s))
            walk(s["id"], depth + 1)

    walk(None, 0)
    return out


def render_markdown(traces: list[dict], findings: list[Finding]) -> str:
    lines = ["# Agent trace dashboard", "", f"Traces: {len(traces)}", "", "## Findings", ""]
    lines += [f"- **{f.rule}** ({f.scope}): {f.detail}" for f in findings] or ["- none"]
    lines += ["", "## Tool usage", "", "| tool | calls |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in tool_counts(traces).most_common()]
    for t in traces:
        lines += ["", f"### {t['trace_id']} ({t['agent']})", ""]
        for depth, s in _tree(t["spans"]):
            dur = (s["end"] - s["start"]) * 1000
            lines.append(f"{'  ' * depth}- `{s['kind']}` {s['name']} ({dur:.0f} ms)")
    return "\n".join(lines) + "\n"


def render_html(traces: list[dict], findings: list[Finding]) -> str:
    e = html.escape
    rows = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in tool_counts(traces).most_common())
    fl = "".join(f"<li><b>{e(f.rule)}</b> ({e(f.scope)}): {e(f.detail)}</li>" for f in findings) or "<li>none</li>"
    blocks = []
    for t in traces:
        items = "".join(
            f"<div style='margin-left:{d * 18}px'><code>{e(s['kind'])}</code> {e(str(s['name']))} "
            f"<small>{e(json.dumps(s.get('attrs', {}), sort_keys=True))}</small></div>"
            for d, s in _tree(t["spans"])
        )
        blocks.append(f"<h3>{e(t['trace_id'])} ({e(t['agent'])})</h3>{items}")
    return (
        "<!doctype html><meta charset='utf-8'><title>Agent trace dashboard</title>"
        "<body style='font-family:sans-serif;max-width:860px;margin:2em auto'>"
        f"<h1>Agent trace dashboard</h1><p>Traces: {len(traces)}</p><h2>Findings</h2><ul>{fl}</ul>"
        f"<h2>Tool usage</h2><table border=1 cellpadding=4><tr><th>tool</th><th>calls</th></tr>{rows}</table>"
        f"{''.join(blocks)}</body>"
    )


# ------------------------------------------------------------- sample data
def _trace(tid: str, tools: list[str], decision: str = "answer", extra_attrs: dict | None = None) -> dict:
    spans = [{"id": "p", "parent": None, "kind": "plan", "name": "plan: handle ticket", "start": 0.0, "end": 0.1, "attrs": {}}]
    t = 0.1
    for i, tool in enumerate(tools):
        spans.append({"id": f"l{i}", "parent": "p", "kind": "llm", "name": "model", "start": t, "end": t + 0.2, "attrs": {}})
        spans.append({"id": f"c{i}", "parent": f"l{i}", "kind": "tool", "name": tool, "start": t + 0.2, "end": t + 0.3, "attrs": dict(extra_attrs or {})})
        t += 0.3
    spans.append({"id": "d", "parent": "p", "kind": "decision", "name": decision, "start": t, "end": t + 0.01, "attrs": {}})
    return {"trace_id": tid, "agent": "support-agent", "spans": spans}


def sample_baseline() -> list[dict]:
    mixes = [["search_kb"], ["search_kb", "read_ticket"], ["read_ticket", "search_kb", "draft_reply"], ["search_kb", "draft_reply"]]
    return [_trace(f"base-{i}", mixes[i % 4]) for i in range(24)]


def sample_drifted() -> list[dict]:
    return [
        _trace("odd-1", ["search_kb", "run_shell", "http_post"], decision="override_policy"),
        _trace("odd-2", ["run_shell"] * 6 + ["http_post"] * 4, extra_attrs={"note": "<script>alert('FAKE-XSS')</script>"}),
        _trace("odd-3", ["http_post", "run_shell"]),
    ]
