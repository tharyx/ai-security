"""Tests for the AI SOC + SOAR lab (Brightix module 6).

Run from the repository root:
    .venv/Scripts/python -m pytest brightix-course/m06-ai-security-monitoring-and-soc/labs/ai-soar-playbooks -v -p no:cacheprovider
"""

import copy
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

pl = load_lab_module(__file__, "pipeline")
soar = load_lab_module(__file__, "soar")
irr = load_lab_module(__file__, "ir_report")
gen = load_lab_module(__file__, "make_fixtures")
demo = load_lab_module(__file__, "demo")

EVENTS = pl.load_events()
WL = pl.load_json("watchlists.json")
TRUTH = pl.load_json("ground_truth.json")
PBS = pl.load_json("playbooks.json")
BY_ID = {e.id: e.to_dict() for e in EVENTS}


def approve_all(step, ctx):
    return "approve"


def rules_fired(alerts):
    return {a.rule for a in alerts}


# ------------------------------------------------------------------ fixtures + normaliser
def test_fixtures_are_reproducible():
    with tempfile.TemporaryDirectory() as d:
        fresh = gen.write(Path(d))
    for name, text in fresh.items():
        assert (pl.FIX / name).read_text(encoding="utf-8") == text, name


def test_normaliser_maps_three_formats_to_one_schema():
    by_source = {e.source for e in EVENTS}
    assert by_source == {"llm_app", "agent_runtime", "mcp_gateway"}
    exfil = next(e for e in EVENTS if e.kind == "tool_call" and e.trace == "t-9001" and e.tool == "http_post")
    assert exfil.dest == "collect.evil.example" and exfil.ts.tzinfo is not None  # epoch -> UTC, URL -> host
    rug = next(e for e in EVENTS if e.kind == "mcp_list" and e.desc_sha != e.pinned_sha)
    assert rug.tool == "crm-tools/read_crm"


def test_what_to_log_hash_and_length_not_raw_prompts():
    reqs = [e for e in EVENTS if e.kind == "llm_request"]
    assert all(len(e.prompt_sha) == 32 and e.prompt_chars > 0 for e in reqs)
    assert all(len(e.preview) <= 60 for e in reqs)  # short, redacted preview only
    assert all(e.user and e.session and e.tenant for e in reqs)  # who, which session, which tenant


# ------------------------------------------------------------------ naive vs tuned
def test_naive_rules_are_noisy_and_miss_two_incidents():
    r = pl.evaluate(pl.run_rules(EVENTS, "naive", WL), TRUTH)
    assert r["fp"] >= 5
    assert set(r["fn"]) == {"TRUE-B-costdos", "TRUE-C-leak"}
    assert r["alerts_per_true_incident"]["TRUE-D-ragdoc"] >= 5  # one alert per retrieval = alert storm


def test_tuned_rules_catch_all_five_incidents_without_false_positives():
    r = pl.evaluate(pl.run_rules(EVENTS, "tuned", WL), TRUTH)
    assert r["fn"] == [] and r["fp"] == 0 and r["precision"] == 1.0


def test_every_tuned_alert_carries_atlas_and_owasp_tags():
    for a in pl.run_rules(EVENTS, "tuned", WL):
        assert a.atlas and a.owasp
        assert all(t in pl.ATLAS_ID_HINTS for t in a.atlas)


def test_redteam_watchlist_suppresses_approved_tests_only():
    assert "repeated_guard_blocks" not in rules_fired(pl.run_rules(EVENTS, "tuned", WL))
    wl = copy.deepcopy(WL)
    wl["redteam_accounts"] = {}
    alerts = [a for a in pl.run_rules(EVENTS, "tuned", wl) if a.rule == "repeated_guard_blocks"]
    assert [a.context["user"] for a in alerts] == ["redteam-svc@acme.example"]  # eve's single block never alerts


def test_partner_api_is_quiet_until_removed_from_egress_allowlist():
    wl = copy.deepcopy(WL)
    wl["egress_allowlist"] = ["corp.example"]
    frank = [a for a in pl.run_rules(EVENTS, "tuned", wl) if "dest:api.partner.example" in a.entities]
    assert len(frank) == 1 and frank[0].severity == "high"  # not tainted -> high, not critical


def test_indirect_injection_exfil_is_critical_because_the_trace_was_tainted():
    a = next(a for a in pl.run_rules(EVENTS, "tuned", WL) if "trace:t-9001" in a.entities)
    assert a.severity == "critical" and "doc:mail-4411" in a.entities


def test_token_burst_uses_behaviour_baseline_not_per_request_size():
    alerts = [a for a in pl.run_rules(EVENTS, "tuned", WL) if a.rule == "token_burst"]
    assert [a.context["user"] for a in alerts] == ["svc-integration@globex.example"]  # dave's 14k doc is fine
    assert alerts[0].ts < pl.load_events()[0].ts.replace(hour=10, minute=5)  # caught within 5 minutes


def test_poisoned_doc_fires_at_third_distinct_user_and_ignores_single_flag():
    a = next(a for a in pl.run_rules(EVENTS, "tuned", WL) if a.rule == "shared_poisoned_doc")
    assert a.entities == ["doc:kb-212"] and len(a.affected) == 3
    assert f"{a.ts:%H:%M}" == "10:58"


def test_approved_mcp_update_is_not_a_rug_pull():
    pins = [a for a in pl.run_rules(EVENTS, "tuned", WL) if a.rule == "mcp_pin_mismatch"]
    assert [a.context["mcp"] for a in pins] == ["crm-tools/read_crm"]
    naive = [a for a in pl.run_rules(EVENTS, "naive", WL) if a.rule == "naive_mcp_desc_changed"]
    assert "mcp:docs-tools/search_docs" in {k for a in naive for k in a.entities}


def test_hourly_drift_flags_the_cost_dos_hour():
    rows = {r["hour"]: r["drift"] for r in pl.hourly_profile(EVENTS)}
    assert rows["10:00"] == "ANOMALY" and rows["08:00"] == rows["11:00"] == "ok"


# ------------------------------------------------------------------ risk scoring
def test_risk_decays_with_half_life_and_patterns_accumulate():
    alerts = pl.run_rules(EVENTS, "tuned", WL)
    book = pl.build_risk(EVENTS, alerts, WL, half_life_min=30)
    peak, t = book.peak("user:alice@acme.example")
    assert pl.band(peak) == "CONTAIN"
    assert book.score("user:alice@acme.example", t + timedelta(minutes=30)) == pytest.approx(peak / 2, abs=0.2)
    assert pl.band(book.peak("user:eve@acme.example")[0]) == "MONITOR"        # one blocked attempt
    assert book.peak("user:redteam-svc@acme.example")[0] == 0.0                # watch-listed
    assert book.peak("mcp:crm-tools/read_crm")[0] > 80               # three alerts stack up


# ------------------------------------------------------------------ correlation
def test_correlation_turns_seven_alerts_into_five_incidents():
    incs = pl.correlate(pl.run_rules(EVENTS, "tuned", WL))
    assert len(incs) == 5
    rug = next(i for i in incs if "mcp_pin_mismatch" in i.rules)
    assert set(rug.rules) == {"mcp_pin_mismatch", "bulk_tool_read", "exfil_untrusted_egress"}
    alice = next(i for i in incs if "trace:t-9001" in i.entities)
    assert "doc:kb-212" not in alice.entities  # victims of kb-212 are not correlation keys


# ------------------------------------------------------------------ SOAR engine
def test_shipped_playbooks_pass_lint_and_naive_one_fails():
    assert all(soar.lint(pb) == [] for pb in PBS["playbooks"])
    problems = soar.lint(PBS["naive_examples"][0])
    assert any("no approval gate" in p for p in problems)
    assert any("before evidence" in p for p in problems)


def test_safe_engine_refuses_to_run_a_playbook_that_fails_lint():
    eng = soar.Engine(soar.Platform(), soar.EvidenceStore(), BY_ID, WL, approver=approve_all)
    with pytest.raises(ValueError):
        eng.run({"incident": "X", "doc": "kb-212"}, PBS["naive_examples"][0], EVENTS[0].ts)


def test_full_response_contains_every_incident():
    run = demo.run_soc(approver=approve_all)
    p = run["platform"]
    assert not p.retrievable("kb-212") and p.reindex_runs >= 1
    assert p.mcp_tools["crm-tools/read_crm"] == "disabled"
    assert p.agent_tokens["mail-assistant"] == p.agent_tokens["sales-assistant"] == "revoked"
    assert p.agent_tokens["soc-automation"] == "active"
    assert {"collect.evil.example", "telemetry.evil.example"} <= p.egress_blocklist
    assert p.active_prompt == "v6" and p.guardrail_level == "strict"
    assert p.api_keys["svc-integration@globex.example"] == "revoked"
    assert p.mcp_tools["docs-tools/search_docs"] == "enabled"  # approved update untouched


def test_no_answer_means_pending_and_nothing_changes():
    run = demo.run_soc()  # lab approver: service owner never answers
    steps = next(s for i, _, s in run["runs"] if "token_burst" in i.rules)
    gated = next(s for s in steps if s.action == "revoke_api_key")
    assert gated.status == "pending_approval"
    assert run["platform"].api_keys["svc-integration@globex.example"] == "active"
    assert run["platform"].quotas["svc-integration@globex.example"] == 20000  # safe step still ran


def test_denied_approval_blocks_destructive_steps_only():
    run = demo.run_soc(approver=lambda step, ctx: "deny")
    p = run["platform"]
    assert p.retrievable("kb-212") and p.agent_tokens["mail-assistant"] == "active"
    assert len(run["engine"].notifications) == 5 and run["evidence"].items  # notify + evidence still ran


def test_evidence_is_preserved_before_any_destructive_step():
    run = demo.run_soc(approver=approve_all)
    for _, _, steps in run["runs"]:
        done = [s.action for s in steps if s.status == "done"]
        first_destructive = min((i for i, a in enumerate(done) if a in soar.DESTRUCTIVE), default=len(done))
        assert "preserve_evidence" in done[:first_destructive]
    snap = next(i for i in run["evidence"].items if i["kind"] == "document_snapshot" and i["ref"] == "kb-212")
    assert "lab-only injected text" in snap["content"]["text"]


def test_evidence_chain_detects_tampering():
    run = demo.run_soc(approver=approve_all)
    store = run["evidence"]
    assert store.verify()
    store.items[1]["content"] = [{"edited": True}]
    assert not store.verify()


def test_naive_engine_destroys_evidence():
    inc = next(i for i in pl.correlate(pl.run_rules(EVENTS, "tuned", WL)) if "shared_poisoned_doc" in i.rules)
    eng = soar.Engine(soar.Platform(), soar.EvidenceStore(), BY_ID, WL, safe=False)
    eng.run(soar.incident_context(inc, BY_ID), PBS["naive_examples"][0], inc.detected_at)
    assert eng.evidence_gaps == ["kb-212"]


def test_protected_and_empty_targets_are_refused_even_if_approved():
    pb = next(p for p in PBS["playbooks"] if p["id"] == "PB-01-injection-exfil")
    platform = soar.Platform()
    eng = soar.Engine(platform, soar.EvidenceStore(), BY_ID, WL, approver=approve_all)
    ctx = {"incident": "INC-T", "agent": "soc-automation", "dest": "", "user": "x", "traces": [], "docs": []}
    steps = {s.action: s for s in eng.run(ctx, pb, EVENTS[0].ts)}
    assert steps["revoke_agent_token"].status == "refused" and "protected" in steps["revoke_agent_token"].detail
    assert steps["block_egress"].status == "refused" and "empty target" in steps["block_egress"].detail
    assert platform.agent_tokens["soc-automation"] == "active" and not platform.egress_blocklist


# ------------------------------------------------------------------ report
def test_report_maps_to_both_nist_revisions_and_measures_exposure():
    run = demo.run_soc(approver=approve_all)
    inc, pb, steps = next(r for r in run["runs"] if "shared_poisoned_doc" in r[0].rules)
    md = irr.render(inc, steps, pb, True, run["evidence"].head(), EVENTS)
    for phase in ("Preparation", "Detection & Analysis", "Containment, Eradication & Recovery", "Post-Incident Activity"):
        assert phase in md
    for csf in ("DE.AE", "RS.MA", "RS.AN", "RS.CO", "RS.MI", "RC.RP", "ID.IM"):
        assert csf in md
    m = irr.metrics(inc, steps, EVENTS)
    assert m["time_to_detect_min"] == 18.0
    assert m["exposure"] == {"after_detection": 2, "before_containment": 1, "prevented_by_containment": 1}
