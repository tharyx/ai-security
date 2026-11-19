"""Capstone threat model, SOC telemetry/detections/playbooks and architecture review (Brightix module 8)."""

import json
import sys
import tempfile
from pathlib import Path

from aisec_lab import load_lab_module

app = load_lab_module(__file__, "enterprise_app")
rt = load_lab_module(__file__, "redteam")
det = load_lab_module(__file__, "detections")
tm = load_lab_module(__file__, "threat_model")
rv = load_lab_module(__file__, "review")
demo = load_lab_module(__file__, "demo")

EXPECTED_RULE = {"AT-01": "untrusted_tool_call", "AT-02": "cross_tenant_access", "AT-03": "tool_integrity",
                 "AT-04": "tool_integrity", "AT-05": "untrusted_tool_call", "AT-06": "entitlement_gap",
                 "AT-07": "egress_violation", "AT-08": "canary_exposure"}


# ------------------------------------------------------------------ threat model
def test_every_attack_maps_to_exactly_one_threat():
    for a in rt.ATTACKS:
        assert len([t for t in tm.THREATS if t.get("attack") == a.id]) == 1


def test_threats_are_fully_tagged_and_controls_exist():
    toggles = set(app.SOFT + app.HARD) | set(tm.EXTERNAL_CONTROLS)
    for t in tm.THREATS:
        assert t["stride"] in "STRIDE" and t["atlas"] and t["owasp_llm"] and t["owasp_agentic"].startswith("ASI")
        assert set(t["controls"]) <= toggles
        assert t["boundary"] in {b["id"] for b in tm.BOUNDARIES}


def test_threat_model_reports_the_one_honest_gap():
    assert tm.validate() == ["TH-10: no test and no verification (coverage gap)"]


def test_threat_controls_match_the_attack_controls():
    for a in rt.ATTACKS:
        t = next(t for t in tm.THREATS if t.get("attack") == a.id)
        hard = [c for c in a.controls if c in app.HARD]
        assert set(hard) <= set(t["controls"]), a.id


def test_generated_report_has_all_sections_and_residuals():
    md = tm.report(rt.scorecard())
    for h in ("## Assets", "## Trust boundaries", "## Data flows crossing a boundary", "## Threats", "## Open issues"):
        assert h in md
    assert md.count("Low (tested: blocked even with soft layers off)") == len(rt.ATTACKS)
    assert "Medium (UNTESTED: accept or fund)" in md


# ------------------------------------------------------------------ telemetry + detection
def _incidents(cfg):
    log = rt.campaign(cfg)
    return log, det.correlate(log, det.detect(log))


def test_baseline_every_attack_is_detected_as_an_incident_with_impact():
    _, incs = _incidents(app.Config.baseline())
    by_trace = {i.trace: i for i in incs}
    for aid, rule in EXPECTED_RULE.items():
        inc = by_trace[f"{aid}-01"]
        assert rule in inc.rules and inc.impact, aid
    assert not any(t.startswith("BN-") for t in by_trace)  # benign traffic is quiet


def test_hardened_attempts_are_still_visible_but_without_impact():
    _, incs = _incidents(app.Config.hardened())
    assert {i.trace for i in incs} == {f"{a}-01" for a in EXPECTED_RULE}
    assert not any(i.impact for i in incs)


def test_telemetry_is_useful_and_has_no_secrets():
    log = rt.campaign(app.Config.baseline())
    assert "CANARY-" not in json.dumps(log)  # hashes and lengths, never raw prompts or answers
    for e in log:
        if e["kind"] == "tool_call":
            assert e["user"] and e["agent"] and e["provenance"] and e["decision"] and len(e["args_sha"]) == 16
        if e["kind"] == "llm_call":
            assert len(e["prompt_sha"]) == 32 and e["prompt_tokens"] > 0


def test_playbook_outputs_put_evidence_first_and_gate_containment():
    _, incs = _incidents(app.Config.baseline())
    for inc in incs:
        out = det.playbook_output(inc)
        assert out["steps"][0]["action"] == det.EVIDENCE_STEP and not out["steps"][0]["needs_approval"]
        flags = [s["needs_approval"] for s in out["steps"]]
        assert flags == sorted(flags)  # no gated step before a safe one
        assert out["atlas"] and out["owasp"]
    exfil = det.playbook_output(next(i for i in incs if i.trace == "AT-01-01"))
    assert any("block the destination" in s["action"] and s["needs_approval"] for s in exfil["steps"])


# ------------------------------------------------------------------ architecture review
def test_review_verdicts():
    items, score_b, verdict_b = rv.review(app.Config.baseline())
    assert verdict_b == "NOT READY" and score_b < 40
    _, score_s, verdict_s = rv.review(app.Config.soft_only())
    assert verdict_s == "NOT READY"  # guardrails alone do not pass a review
    items_h, score_h, verdict_h = rv.review(app.Config.hardened())
    assert verdict_h == "READY WITH CONDITIONS" and score_h > 90
    assert [i.id for i in items_h if i.status != "PASS"] == ["AR-12"]


def test_review_catches_a_build_that_leans_on_soft_layers():
    cfg = app.Config.hardened()
    cfg.output_dlp = False  # AT-08 is now blocked only by the guardrails
    items, _, verdict = rv.review(cfg)
    ar13 = next(i for i in items if i.id == "AR-13")
    assert ar13.status == "PARTIAL" and "AT-08" in ar13.evidence


def test_demo_writes_the_deck_inputs(monkeypatch, capsys):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setattr(sys, "argv", ["demo.py", "--write", d])
        demo.main()
        names = sorted(p.name for p in Path(d).iterdir())
        deck = json.loads((Path(d) / "deck-numbers.json").read_text(encoding="utf-8"))
    assert names == ["deck-numbers.json", "incidents.json", "review.md", "scorecard.md", "threat-model.md"]
    assert deck["blocked_hardened_pct"] == 100.0 and deck["untested_threats"] == ["TH-10"]
    assert "READY WITH CONDITIONS" in capsys.readouterr().out
