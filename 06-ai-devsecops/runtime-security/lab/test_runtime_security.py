"""Runtime security lab tests: each attack works on the vulnerable gateway and fails on the
secure one, hard layers hold alone, and the monitor and vulnerability register do their jobs.

Run from the repository root:
    python -m pytest 06-ai-devsecops/runtime-security -v
"""

from datetime import date
from pathlib import Path

import pytest

from aisec_lab import MockLLM, load_lab_module, make_canary

sg = load_lab_module(__file__, "secure_gateway")
vg = load_lab_module(__file__, "vulnerable_gateway")
A = load_lab_module(__file__, "attacks")
mon = load_lab_module(__file__, "monitor")
vr = load_lab_module(__file__, "vuln_register")
FIX = Path(__file__).parent / "fixtures"


class FakeClock:
    def __init__(self, t: float = 1_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def lab(clock):
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM())
    return gateway, info


@pytest.fixture
def vuln(lab):
    _, info = lab
    return vg.VulnerableModelGateway(provider_key=info["provider_key"], provider=info["provider"], llm=MockLLM())


def run(gateway, requests, clock=None, step=0.0):
    out = []
    for r in requests:
        out.append(gateway.handle(r))
        if clock:
            clock.tick(step)
    return out


# ---------- Part 1: benign path ----------------------------------------------------------

def test_benign_request_works_on_both(lab, vuln):
    gateway, info = lab
    assert run(gateway, A.benign(info["client_keys"]["alice"]))[0]["status"] == 200
    assert run(vuln, A.benign(None))[0]["status"] == 200


# ---------- Part 2: authentication (VULN 1 / L1) ------------------------------------------

def test_vulnerable_trusts_identity_from_the_body(vuln):
    resp = run(vuln, A.no_auth_spoof())[0]
    assert resp["status"] == 200 and resp["tenant"] == "globex"      # billed to someone else
    assert vuln.billed_tokens["globex"] > 0


def test_secure_rejects_missing_or_wrong_keys(lab):
    gateway, info = lab
    assert run(gateway, A.no_auth_spoof())[0]["status"] == 401
    assert all(r["status"] == 401 for r in run(gateway, A.wrong_keys()))
    assert info["provider"].calls == []                                   # nothing reached the model


def test_identity_comes_from_the_key_not_the_body(lab):
    gateway, info = lab
    req = {**A.benign(info["client_keys"]["alice"])[0], "user": "ceo", "tenant": "globex"}
    assert gateway.handle(req)["status"] == 200
    root = [s for s in gateway.tracer.export() if s["name"] == "gateway.request"][-1]
    assert root["attributes"]["aisec.principal"] == "alice"
    assert root["attributes"]["aisec.tenant"] == "acme"
    assert {"name": "identity_claim_ignored"} in root["events"]


def test_revoked_client_key_stops_working(lab):
    gateway, info = lab
    key = info["client_keys"]["mallory"]
    assert run(gateway, A.benign(key))[0]["status"] == 200
    gateway.revoke_client(key)
    assert run(gateway, A.benign(key))[0]["status"] == 401


# ---------- Part 3: model access control (VULN 3 / L2) ------------------------------------

def test_vulnerable_lets_anyone_use_any_deployment(vuln):
    assert all(r["status"] == 200 for r in run(vuln, A.model_enumeration(None)))


def test_secure_enforces_team_entitlements(lab):
    gateway, info = lab
    keys = info["client_keys"]
    assert run(gateway, A.cross_team_model(keys["alice"]))[0]["status"] == 403   # support team
    assert run(gateway, A.cross_team_model(keys["bob"]))[0]["status"] == 200     # research team
    assert all(r["status"] == 403 for r in run(gateway, A.model_enumeration(keys["alice"])))


# ---------- Part 4: limits (VULN 4 / L3) ----------------------------------------------------

def test_vulnerable_accepts_huge_payloads_and_floods(vuln):
    assert run(vuln, A.huge_payload(None))[0]["status"] == 200
    assert all(r["status"] == 200 for r in run(vuln, A.flood(None, 30)))
    assert vuln.billed_tokens["default"] > 100_000                         # cost exposure


def test_secure_rejects_oversized_payload_before_the_model(lab):
    gateway, info = lab
    assert run(gateway, A.huge_payload(info["client_keys"]["alice"]))[0]["status"] == 413
    assert info["provider"].calls == []


def test_max_tokens_is_capped_per_deployment(lab):
    gateway, info = lab
    req = {**A.benign(info["client_keys"]["alice"])[0], "max_tokens": 100_000}
    assert gateway.handle(req)["status"] == 400


def test_rate_limit_is_keyed_on_identity_so_rotating_ip_headers_does_not_help(lab):
    gateway, info = lab
    statuses = [r["status"] for r in run(gateway, A.flood(info["client_keys"]["alice"], 20, rotate_ip=True))]
    assert statuses.count(200) == 5 and statuses.count(429) == 15


def test_tenant_bucket_caps_many_keys_of_one_tenant(clock):
    limits = sg.Limits(principal_burst=50, tenant_burst=8, tenant_refill_per_sec=0.0,
                       team_token_quota={"support": 10**9, "research": 10**9})
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), limits=limits)
    keys = info["client_keys"]                       # alice and bob are both tenant "acme"
    mixed = A.benign(keys["alice"], 6) + A.benign(keys["bob"], 6)
    assert [r["status"] for r in run(gateway, mixed)].count(200) == 8


def test_team_quota_stops_runaway_cost(clock):
    limits = sg.Limits(principal_burst=1000, tenant_burst=1000, team_token_quota={"support": 1000})
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), limits=limits)
    statuses = [r["status"] for r in run(gateway, A.benign(info["client_keys"]["alice"], 20))]
    assert 429 in statuses
    assert gateway.used_tokens["support"] <= 1000


def test_limits_refill_over_time(lab, clock):
    gateway, info = lab
    key = info["client_keys"]["alice"]
    run(gateway, A.benign(key, 5))
    assert run(gateway, A.benign(key))[0]["status"] == 429
    clock.tick(10)                                    # 0.5 tokens/s refill
    assert run(gateway, A.benign(key))[0]["status"] == 200


# ---------- Part 5: secrets (VULN 2, 5, 6 / L4, L6, L7) ------------------------------------

def test_vulnerable_leaks_provider_key_through_prompt_injection(vuln, lab):
    _, info = lab
    out = run(vuln, A.key_leak_via_injection(None))[0]["output"]
    assert info["provider_key"] in out


def test_vulnerable_writes_keys_into_logs(vuln, lab):
    _, info = lab
    run(vuln, A.benign(info["client_keys"]["alice"]))
    logs = "\n".join(vuln.log_lines)
    assert info["provider_key"] in logs and info["client_keys"]["alice"] in logs


def test_secure_never_puts_the_key_in_the_prompt(lab):
    gateway, info = lab
    out = run(gateway, A.key_leak_via_injection(info["client_keys"]["alice"]))[0]
    assert info["provider_key"] not in out["output"]
    sent = "\n".join(m["content"] for call in gateway.provider.llm.calls for m in call)
    assert info["provider_key"] not in sent                               # the model never saw it


def test_output_guard_alone_blocks_the_leak(clock):
    """Hard layer alone: even if someone puts the key in the prompt, it cannot leave."""
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), keep_secrets_out_of_prompt=False,
                                         input_guard=False)
    out = run(gateway, A.key_leak_via_injection(info["client_keys"]["alice"]))[0]
    assert out["status"] == 502 and info["provider_key"] not in out["output"]


def test_without_any_secret_layer_the_leak_is_real(clock):
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), keep_secrets_out_of_prompt=False,
                                         output_guard=False)
    assert info["provider_key"] in run(gateway, A.key_leak_via_injection(info["client_keys"]["alice"]))[0]["output"]


def test_output_guard_blocks_canaries(clock):
    canary = make_canary()
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), canaries=(canary,))
    req = {**A.benign(info["client_keys"]["alice"])[0], "prompt": f"Say: {canary}"}
    # MockLLM echoes the prompt in its generic answer, so the canary would leave without the guard.
    assert canary not in gateway.handle(req)["output"]


def test_secure_logs_have_no_secrets_no_raw_prompt_no_email(lab):
    gateway, info = lab
    run(gateway, A.pasted_secret(info["client_keys"]["bob"]) + A.key_leak_via_injection(info["client_keys"]["alice"])
        + A.wrong_keys(2))
    logs = "\n".join(gateway.log_lines)
    for value in (info["provider_key"], *info["client_keys"].values(), "eyJhbGciOiJIUzI1NiJ9", "dev@corp.example",
                  A.PASTED_SECRET_PROMPT[:20]):
        assert value not in logs
    assert "prompt_sha256" in logs


def test_turning_redaction_off_shows_why_it_matters(clock):
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), redact_logs=False)
    run(gateway, A.pasted_secret(info["client_keys"]["bob"]))
    assert "dev@corp.example" in "\n".join(gateway.log_lines)


def test_rotation_works_for_secure_and_breaks_hardcoded_key(lab, vuln):
    gateway, info = lab
    store, provider, old = info["store"], info["provider"], info["provider_key"]
    new = "sk-lab-rotated-0001"
    store.rotate("provider/api-key", new)
    provider.issue(new)
    provider.revoke(old)                     # end of the grace period at the provider
    store.retire("provider/api-key", 1)
    assert run(gateway, A.benign(info["client_keys"]["alice"]))[0]["status"] == 200
    assert run(vuln, A.benign(None))[0]["status"] == 502      # VULN 6: key copied at start-up
    assert provider.calls[-1]["key"] == sg.fingerprint(new)


def test_secret_reads_are_audited_without_values(lab):
    gateway, info = lab
    run(gateway, A.benign(info["client_keys"]["alice"]))
    entry = info["store"].access_log[-1]
    assert entry["accessor"] == "gateway" and entry["version"] == 1
    assert info["provider_key"] not in str(info["store"].access_log)


# ---------- Part 6: telemetry (VULN 7 / L8) -------------------------------------------------

def test_spans_form_a_trace_with_genai_attributes(lab):
    gateway, info = lab
    run(gateway, A.benign(info["client_keys"]["alice"]))
    spans = gateway.tracer.export()
    root = next(s for s in spans if s["name"] == "gateway.request")
    children = {s["name"] for s in spans if s["parent_id"] == root["span_id"]}
    assert {"gateway.auth", "gateway.policy", "gateway.ratelimit", "gen_ai.chat"} <= children
    assert all(s["trace_id"] == root["trace_id"] for s in spans)
    assert root["attributes"]["gen_ai.usage.input_tokens"] > 0
    assert root["attributes"]["aisec.decision"] == "allowed"


def test_spans_carry_no_prompt_text_or_keys(lab):
    gateway, info = lab
    run(gateway, A.pasted_secret(info["client_keys"]["bob"]) + A.wrong_keys(1))
    dump = str(gateway.tracer.export())
    assert "dev@corp.example" not in dump and info["client_keys"]["bob"] not in dump
    assert "gw-guess-0000" not in dump                     # failed keys appear only as fingerprints


# ---------- Part 7: the runtime monitor -----------------------------------------------------

def _rules(alerts):
    return {a.rule_id for a in alerts}


def test_quiet_normal_traffic_raises_no_alerts(lab, clock):
    gateway, info = lab
    run(gateway, A.benign(info["client_keys"]["alice"], 4), clock, step=30)
    assert mon.detect(gateway.tracer.export(), now=clock.t) == []


def test_monitor_detects_key_guessing_enumeration_and_injection_probing(lab, clock):
    gateway, info = lab
    keys = info["client_keys"]
    run(gateway, A.wrong_keys(6) + A.model_enumeration(keys["alice"]) + A.injection_probe(keys["bob"], 5),
        clock, step=1)
    assert {"RT-001", "RT-002", "RT-004"} <= _rules(mon.detect(gateway.tracer.export(), now=clock.t))


def test_monitor_flags_blocked_exfiltration(clock):
    gateway, info = sg.build_lab_gateway(clock=clock, llm=MockLLM(), keep_secrets_out_of_prompt=False)
    run(gateway, A.key_leak_via_injection(info["client_keys"]["alice"]))
    alerts = mon.detect(gateway.tracer.export(), now=clock.t)
    rt005 = next(a for a in alerts if a.rule_id == "RT-005")
    assert rt005.severity == "HIGH" and rt005.entity == "alice"


def test_single_signals_stay_leads_but_correlation_is_critical(lab, clock):
    gateway, info = lab
    key = info["client_keys"]["mallory"]
    cfg = mon.MonitorConfig(known_sources={"mallory": {A.OFFICE_IP}})
    # Only a new source address: no RT-006.
    run(gateway, A.benign(key, 2, ip=A.ATTACKER_IP), clock, step=1)
    assert "RT-006" not in _rules(mon.detect(gateway.tracer.export(), now=clock.t, config=cfg))
    # New source + enumeration + flood for the same key: RT-006.
    run(gateway, A.model_enumeration(key), clock, step=1)
    run(gateway, A.flood(key, 12, rotate_ip=False))          # a burst, no time between requests
    alerts = mon.detect(gateway.tracer.export(), now=clock.t, config=cfg)
    top = alerts[0]
    assert top.rule_id == "RT-006" and top.severity == "CRITICAL" and top.entity == "mallory"
    assert "revoke and rotate" in top.containment[0]


def test_monitor_reports_telemetry_gap(lab, clock):
    gateway, info = lab
    run(gateway, A.benign(info["client_keys"]["alice"]))
    clock.tick(3600)
    assert "RT-007" in _rules(mon.detect(gateway.tracer.export(), now=clock.t))
    assert "RT-007" in _rules(mon.detect([], now=clock.t))


def test_monitor_reports_spans_missing_security_fields(lab, clock):
    gateway, info = lab
    run(gateway, A.benign(info["client_keys"]["alice"]))
    spans = gateway.tracer.export()
    for s in spans:
        s["attributes"].pop("aisec.principal", None)
    assert "RT-007" in _rules(mon.detect(spans, now=clock.t))


def test_alerts_never_contain_prompt_text(lab, clock):
    gateway, info = lab
    run(gateway, A.injection_probe(info["client_keys"]["bob"], 5), clock, step=1)
    dump = str([a.to_dict() for a in mon.detect(gateway.tracer.export(), now=clock.t)])
    assert "Ignore previous instructions" not in dump


# ---------- Part 8: AI vulnerability management ---------------------------------------------

@pytest.fixture
def register():
    assets, advisories = vr.load(FIX / "inventory.json", FIX / "advisories.json")
    return assets, advisories, vr.intake(advisories, assets, date(2026, 11, 18))


def test_intake_maps_advisories_to_affected_assets_only(register):
    _, _, findings = register
    pairs = {(f.advisory.id, f.asset.id) for f in findings}
    assert ("LAB-ADV-001", "support-chat-api") in pairs and ("LAB-ADV-001", "research-sandbox") in pairs
    assert ("LAB-ADV-001", "hr-rag-bot") not in pairs           # already on the fixed version
    assert not any(f.advisory.id == "LAB-ADV-005" for f in findings)   # tokenizer already patched
    assert {f.advisory.kind for f in findings} == {"dependency", "model", "prompt"}


def test_priority_uses_exposure_and_consequence_not_just_severity(register):
    _, _, findings = register
    by = {(f.advisory.id, f.asset.id): f for f in findings}
    assert by[("LAB-ADV-001", "support-chat-api")].priority == "critical"   # exploited + public + tools
    assert by[("LAB-ADV-001", "research-sandbox")].priority == "high"       # exploited, but isolated
    assert by[("LAB-ADV-002", "support-chat-api")].priority == "high"       # medium raised by exposure


def test_sla_and_overdue(register):
    _, _, findings = register
    crit = next(f for f in findings if f.priority == "critical")
    assert crit.due == date(2026, 11, 25)
    assert not crit.overdue(date(2026, 11, 25)) and crit.overdue(date(2026, 11, 26))


def test_risk_acceptance_needs_controls_and_expires(register):
    _, _, findings = register
    nofix = next(f for f in findings if f.advisory.id == "LAB-ADV-004")
    with pytest.raises(ValueError):
        vr.accept_risk(nofix, date(2027, 3, 1), " ")
    vr.accept_risk(nofix, date(2027, 3, 1), "per-tenant indexes; filter re-check after retrieval")
    assert not nofix.overdue(date(2027, 2, 28))
    assert nofix.overdue(date(2027, 3, 2))                                 # the exception ran out


def test_intake_is_idempotent(register):
    assets, advisories, findings = register
    again = vr.intake(advisories, assets, date(2026, 11, 19), existing=findings)
    assert len(again) == len(findings)
