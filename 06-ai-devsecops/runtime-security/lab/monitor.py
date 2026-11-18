"""AI runtime monitor: turn gateway spans into security alerts.

It reads the span dicts that ``SecureModelGateway.tracer.export()`` produces (the same
shape an OpenTelemetry collector would forward to a SIEM) and applies detection rules.

Design ideas worth copying:

* **Detect on telemetry, not on raw prompts.** The spans carry identity, deployment,
  decision, token counts and guardrail events. No prompt text is needed.
* **Severity is decided by code, not by a model.** Each rule has a fixed severity and a
  fixed list of containment actions. An AI assistant may summarize an alert later; it
  does not decide how bad it is.
* **One weak signal is a lead; several together are an incident.** RT-006 only fires when
  a new source, model probing AND a usage spike happen for the same identity.
* **Watch the watcher.** RT-007 fires when telemetry stops or loses required fields.

    python monitor.py spans.json [--now 1700000000] [--window 300]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Containment actions, ordered from least to most disruptive to the business.
CONTAINMENT_LADDER = (
    "rate-limit or block the identity or source",
    "tighten guardrail thresholds",
    "revoke and rotate the key or token (from a clean admin path)",
    "disable tools or switch the agent to read-only",
    "quarantine affected data sources or documents",
    "isolate the endpoint (internal-only or offline)",
    "roll back to the last known-good model and config",
    "kill switch: stop agents and suspend pipelines",
)

RULES: dict[str, tuple[str, str, tuple[int, ...]]] = {
    # rule id: (severity, title, indexes into CONTAINMENT_LADDER)
    "RT-001": ("MEDIUM", "Burst of failed authentications (key guessing or a leaked old key)", (0,)),
    "RT-002": ("MEDIUM", "One identity probing many model deployments (enumeration)", (0,)),
    "RT-003": ("MEDIUM", "Usage far above baseline, or repeated rate/quota limit hits", (0, 2)),
    "RT-004": ("MEDIUM", "High rate of prompt-injection guardrail hits from one identity", (0, 1)),
    "RT-005": ("HIGH", "Output guard blocked a secret or canary (attempted exfiltration)", (1, 2, 3)),
    "RT-006": ("CRITICAL", "Likely stolen client key: new source + model probing + usage spike", (2, 0)),
    "RT-007": ("HIGH", "Telemetry gap or missing security fields (the monitor is blind)", ()),
}


@dataclass
class Alert:
    rule_id: str
    entity: str
    summary: str
    evidence: list[str] = field(default_factory=list)     # trace IDs, never prompt text

    @property
    def severity(self) -> str:
        return RULES[self.rule_id][0]

    @property
    def containment(self) -> list[str]:
        return [CONTAINMENT_LADDER[i] for i in RULES[self.rule_id][2]]

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "severity": self.severity, "entity": self.entity,
                "summary": self.summary, "evidence": self.evidence[:5], "containment": self.containment}


@dataclass
class MonitorConfig:
    window_seconds: float = 300.0
    auth_fail_threshold: int = 5
    enumeration_threshold: int = 3          # distinct denied deployments
    spike_factor: float = 5.0               # x baseline tokens per window
    spike_floor_tokens: int = 2000          # ignore small absolute numbers
    injection_min_hits: int = 5
    injection_min_rate: float = 0.3
    telemetry_gap_seconds: float = 600.0
    baseline_tokens: dict[str, int] = field(default_factory=dict)      # principal -> normal tokens per window
    default_baseline_tokens: int = 1000
    known_sources: dict[str, set[str]] = field(default_factory=dict)   # principal -> usual client addresses


def _roots(spans: list[dict]) -> list[dict]:
    return [s for s in spans if s.get("name") == "gateway.request"]


def _attr(span: dict, name: str, default=None):
    return (span.get("attributes") or {}).get(name, default)


def _events(span: dict) -> list[str]:
    return [e.get("name", "") for e in span.get("events") or []]


def detect(spans: list[dict], *, now: float, config: MonitorConfig | None = None,
           expect_traffic: bool = True) -> list[Alert]:
    cfg = config or MonitorConfig()
    roots = _roots(spans)
    recent = [s for s in roots if now - cfg.window_seconds <= s.get("start", 0) <= now]
    alerts: list[Alert] = []

    # RT-007 first: if telemetry is missing, every other "no alert" result means nothing.
    last = max((s.get("start", 0) for s in roots), default=None)
    if expect_traffic and (last is None or now - last > cfg.telemetry_gap_seconds):
        alerts.append(Alert("RT-007", "gateway", "no gateway spans received in the gap window"))
    for s in recent:
        if _attr(s, "aisec.decision") == "allowed" and (
                _attr(s, "aisec.principal") is None or _attr(s, "gen_ai.usage.input_tokens") is None):
            alerts.append(Alert("RT-007", "gateway", "allowed request without identity or token usage fields",
                                [s["trace_id"]]))
            break

    by_principal: dict[str, list[dict]] = defaultdict(list)
    for s in recent:
        if _attr(s, "aisec.principal"):
            by_principal[_attr(s, "aisec.principal")].append(s)

    # RT-001: failed authentications grouped by key fingerprint and by source address
    fails = [s for s in recent if _attr(s, "aisec.decision") == "auth_failed"]
    for key_name in ("aisec.key.fingerprint", "client.address"):
        groups: dict[str, list[dict]] = defaultdict(list)
        for s in fails:
            groups[str(_attr(s, key_name, "unknown"))].append(s)
        for entity, group in groups.items():
            if len(group) >= cfg.auth_fail_threshold:
                alerts.append(Alert("RT-001", f"{key_name}={entity}", f"{len(group)} failed authentications",
                                    [g["trace_id"] for g in group]))

    signals: dict[str, set[str]] = defaultdict(set)
    for principal, group in by_principal.items():
        # RT-002: model enumeration
        denied = {_attr(s, "gen_ai.request.model") for s in group if _attr(s, "aisec.decision") == "model_denied"}
        if len(denied) >= cfg.enumeration_threshold:
            signals[principal].add("enumeration")
            alerts.append(Alert("RT-002", principal, f"denied on {len(denied)} deployments: {sorted(denied)}",
                                [s["trace_id"] for s in group if _attr(s, "aisec.decision") == "model_denied"]))
        # RT-003: cost spike against this identity's own baseline
        tokens = sum((_attr(s, "gen_ai.usage.input_tokens", 0) or 0) + (_attr(s, "gen_ai.usage.output_tokens", 0) or 0)
                     for s in group)
        baseline = cfg.baseline_tokens.get(principal, cfg.default_baseline_tokens)
        limited = sum(1 for s in group if _attr(s, "aisec.decision") in ("rate_limited", "quota_exceeded"))
        if tokens > max(cfg.spike_floor_tokens, cfg.spike_factor * baseline) or limited >= 3:
            signals[principal].add("spike")
            alerts.append(Alert("RT-003", principal,
                                f"{tokens} tokens in window (baseline {baseline}); {limited} requests limited",
                                [s["trace_id"] for s in group]))
        # RT-004: injection-rate spike
        allowed = [s for s in group if _attr(s, "aisec.guardrail.input_hits") is not None]
        hits = sum(_attr(s, "aisec.guardrail.input_hits", 0) or 0 for s in allowed)
        if hits >= cfg.injection_min_hits and hits / max(1, len(allowed)) >= cfg.injection_min_rate:
            alerts.append(Alert("RT-004", principal, f"{hits} injection hints in {len(allowed)} requests",
                                [s["trace_id"] for s in allowed if _attr(s, "aisec.guardrail.input_hits")]))
        # RT-005: a secret tried to leave
        blocked = [s for s in group if "output_blocked" in _events(s)]
        if blocked:
            alerts.append(Alert("RT-005", principal, f"{len(blocked)} responses blocked by the output guard",
                                [s["trace_id"] for s in blocked]))
        # new source address for this identity
        known = cfg.known_sources.get(principal)
        if known is not None and {str(_attr(s, "client.address")) for s in group} - known:
            signals[principal].add("new_source")

    # RT-006: correlation. Each signal alone is only a lead.
    for principal, found in signals.items():
        if {"new_source", "enumeration", "spike"} <= found:
            alerts.append(Alert("RT-006", principal,
                                "new source address + model enumeration + usage spike for one client key",
                                [s["trace_id"] for s in by_principal[principal]]))

    return sorted(alerts, key=lambda a: (-SEVERITY_ORDER[a.severity], a.rule_id, a.entity))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI runtime monitor over exported spans")
    parser.add_argument("spans")
    parser.add_argument("--now", type=float, help="evaluation time (default: last span start)")
    parser.add_argument("--window", type=float, default=300.0)
    args = parser.parse_args(argv)
    spans = json.loads(Path(args.spans).read_text(encoding="utf-8"))
    now = args.now if args.now is not None else max((s.get("start", 0) for s in spans), default=0)
    alerts = detect(spans, now=now, config=MonitorConfig(window_seconds=args.window))
    for a in alerts:
        print(f"{a.severity:8} {a.rule_id}  {a.entity}: {a.summary}")
    print(f"\n{len(alerts)} alert(s)")
    return 1 if any(SEVERITY_ORDER[a.severity] >= 3 for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
