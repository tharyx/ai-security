"""Scorecard for the runtime-security lab: gateway attacks, the monitor, and the vuln register.

From the repository root:
    python 06-ai-devsecops/runtime-security/lab/demo.py
    python 06-ai-devsecops/runtime-security/lab/demo.py --trace     # one request's spans as JSON
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import attacks as A
import monitor as mon
import secure_gateway as sg
import vuln_register as vr
from vulnerable_gateway import VulnerableModelGateway

LAB = Path(__file__).parent


class FakeClock:
    def __init__(self) -> None:
        self.t = 1_000.0

    def __call__(self) -> float:
        return self.t


def fresh():
    clock = FakeClock()
    gateway, info = sg.build_lab_gateway(clock=clock)
    vuln = VulnerableModelGateway(provider_key=info["provider_key"], provider=info["provider"])
    return clock, gateway, vuln, info


def served(responses: list[dict]) -> int:
    return sum(1 for r in responses if r["status"] == 200)


def gateway_scorecard() -> None:
    rows = []

    _, g, v, info = fresh()
    r_v, r_s = v.handle(A.no_auth_spoof()[0]), g.handle(A.no_auth_spoof()[0])
    rows.append(("no key, body claims tenant 'globex'", f"served, billed to {r_v['tenant']}", f"{r_s['status']} blocked"))

    _, g, v, info = fresh()
    leak_v = info["provider_key"] in v.handle(A.key_leak_via_injection(None)[0])["output"]
    out_s = g.handle(A.key_leak_via_injection(info["client_keys"]["alice"])[0])["output"]
    rows.append(("injection asks for the provider key", "KEY LEAKED" if leak_v else "ok",
                 "KEY LEAKED" if info["provider_key"] in out_s else "ok (key never in prompt)"))

    _, g, v, info = fresh()
    r_v, r_s = v.handle(A.huge_payload(None)[0]), g.handle(A.huge_payload(info["client_keys"]["alice"])[0])
    rows.append(("200k-char prompt, max_tokens=100000", f"served, {v.billed_tokens['default']} tokens exposed",
                 f"{r_s['status']} blocked"))

    _, g, v, info = fresh()
    n = 30
    rows.append((f"{n} requests, rotating X-Forwarded-For", f"{served([v.handle(r) for r in A.flood(None, n)])}/{n} served",
                 f"{served([g.handle(r) for r in A.flood(info['client_keys']['alice'], n)])}/{n} served"))

    _, g, v, info = fresh()
    r_s = g.handle(A.cross_team_model(info["client_keys"]["alice"])[0])
    rows.append(("support key calls 'research-large'", "served", f"{r_s['status']} blocked"))

    _, g, v, info = fresh()
    enum_v = served([v.handle(r) for r in A.model_enumeration(None)])
    enum_s = served([g.handle(r) for r in A.model_enumeration(info["client_keys"]["alice"])])
    rows.append(("probe 5 deployment names", f"{enum_v}/5 answered", f"{enum_s}/5 answered"))

    _, g, v, info = fresh()
    keys = [info["provider_key"], *info["client_keys"].values()]
    v.handle(A.benign(info["client_keys"]["alice"])[0])
    g.handle(A.benign(info["client_keys"]["alice"])[0])
    g.handle(A.pasted_secret(info["client_keys"]["bob"])[0])
    in_v = sum(1 for k in keys if k in "\n".join(v.log_lines))
    in_s = sum(1 for k in keys if k in "\n".join(g.log_lines)) + ("dev@corp.example" in "\n".join(g.log_lines))
    rows.append(("secrets found in gateway logs", f"{in_v} key(s)", f"{in_s} secret(s)"))

    _, g, v, info = fresh()
    info["store"].rotate("provider/api-key", "sk-lab-rotated-0001")
    info["provider"].issue("sk-lab-rotated-0001")
    info["provider"].revoke(info["provider_key"])
    r_v = v.handle(A.benign(None)[0])
    r_s = g.handle(A.benign(info["client_keys"]["alice"])[0])
    rows.append(("provider key rotated and old one revoked", f"{r_v['status']} outage", f"{r_s['status']} ok"))

    _, g, v, info = fresh()
    g.handle(A.benign(info["client_keys"]["alice"])[0])
    rows.append(("telemetry for one request", "0 spans, no usage per user", f"{len(g.tracer.spans)} spans, tokens per principal"))

    print(f"{'attack / check':42} {'vulnerable':34} secure")
    print("-" * 104)
    for case, vul, sec in rows:
        print(f"{case:42} {vul:34} {sec}")


def monitor_scorecard() -> None:
    clock, g, _, info = fresh()
    keys = info["client_keys"]
    cfg = mon.MonitorConfig(known_sources={"alice": {A.OFFICE_IP}, "bob": {A.OFFICE_IP}, "mallory": {A.OFFICE_IP}})

    def play(requests: list[dict], step: float) -> None:
        for r in requests:
            g.handle(r)
            clock.t += step

    # A normal morning, then mallory's key is stolen and used from somewhere new.
    play(A.benign(keys["alice"], 3) + A.benign(keys["bob"], 3) + A.benign(keys["mallory"], 2), step=20)
    play(A.wrong_keys(6), step=2)                                   # someone replays old keys
    play(A.injection_probe(keys["bob"], 5), step=3)                 # bob's account probes guardrails
    play(A.model_enumeration(keys["mallory"]), step=1)              # stolen key: what can it reach?
    play(A.flood(keys["mallory"], 12, rotate_ip=False), step=0)     # ...and use as much as possible

    alerts = mon.detect(g.tracer.export(), now=clock.t, config=cfg)
    print(f"\n{'sev':9}{'rule':8}{'entity':30} first containment step")
    print("-" * 104)
    for a in alerts:
        print(f"{a.severity:9}{a.rule_id:8}{a.entity:30} {a.containment[0] if a.containment else 'restore telemetry first'}")
    print(f"\n{len(g.tracer.spans)} spans analysed; no prompt text was needed or stored.")


def register_scorecard() -> None:
    today = date(2026, 11, 18)
    assets, advisories = vr.load(LAB / "fixtures" / "inventory.json", LAB / "fixtures" / "advisories.json")
    print()
    print(vr.report(vr.intake(advisories, assets, today), today))


def print_trace() -> None:
    """Show what one request leaves behind: a span tree, with IDs shortened for reading."""
    clock, g, _, info = fresh()
    clock.t = 1_700_000_000.0
    g.handle(A.benign(info["client_keys"]["alice"])[0])
    spans = g.tracer.export()
    ids = {s["span_id"]: f"span-{i}" for i, s in enumerate(spans)}
    real_trace = spans[0]["trace_id"]
    for s in spans:
        s["trace_id"] = "trace-1"
        s["span_id"], s["parent_id"] = ids[s["span_id"]], ids.get(s["parent_id"])
    root = spans[0]
    print(json.dumps(root, indent=2))
    for s in spans[1:]:
        print(f"  child {s['span_id']}: {s['name']:18} status={s['status']:5} attributes={s['attributes']}")
    print("\nLog line:", g.log_lines[-1].replace(real_trace, "trace-1"))


def main() -> None:
    if "--trace" in sys.argv:
        print_trace()
        return
    gateway_scorecard()
    monitor_scorecard()
    register_scorecard()
    print("\nTip: build_lab_gateway(keep_secrets_out_of_prompt=False) puts the key back in the prompt;")
    print("watch the output guard (L6) block it and the monitor raise RT-005.")


if __name__ == "__main__":
    main()
