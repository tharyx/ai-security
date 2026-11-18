"""Tests for the architecture-as-code reviewer.

Part 1 proves the vulnerable design really fails. Part 2 proves the secure designs pass
on all three clouds. Part 3 is *mutation testing*: break exactly one control in a secure
design and check that the reviewer catches exactly that control. If a check is weak (it
passes a broken design), a mutation test fails. Part 4 covers exceptions and edge cases.

Run from the repository root:
    python -m pytest 09-enterprise-architecture -v
"""

import copy
from datetime import date

import pytest
import yaml
from pydantic import ValidationError

from aisec_lab import load_lab_module

reviewer = load_lab_module(__file__, "reviewer")
MATRIX = reviewer.load_matrix()
SECURE = ["secure_aws", "secure_azure", "secure_gcp"]
REVIEW_DATE = date(2026, 6, 1)


def raw(name: str) -> dict:
    return yaml.safe_load((reviewer.ARCH_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def run(data: dict, today: date = REVIEW_DATE, **kw):
    return reviewer.review(reviewer.parse_architecture(data), MATRIX, today=today, **kw)


def comp(data: dict, ctype: str) -> dict:
    return next(c for c in data["components"] if c["type"] == ctype)


def failed(report) -> set[str]:
    return {f.control_id for f in report.open_findings}


# ---------- Part 1: the hackathon design really is vulnerable ---------------------

def test_vulnerable_design_fails_the_gate_with_three_criticals():
    report = run(raw("vulnerable_aws"))
    assert not report.gate_passed
    crit = {f.control_id for f in report.open_findings if f.severity == "critical"}
    assert crit == {"IAM-04", "NET-04", "DATA-03"}


def test_vulnerable_design_debug_endpoint_is_found_by_the_graph_check():
    f = next(f for f in run(raw("vulnerable_aws")).findings if f.control_id == "NET-04")
    assert f.status == "FAIL" and "rag" in f.detail


def test_remediation_is_specific_to_the_cloud_of_the_design():
    f = next(f for f in run(raw("vulnerable_aws")).findings if f.control_id == "NET-01")
    assert f.remediation.startswith("On aws:") and "PrivateLink" in f.remediation


# ---------- Part 2: the secure designs pass on every cloud ------------------------

@pytest.mark.parametrize("name", SECURE)
def test_secure_design_passes_with_no_open_findings(name):
    report = run(raw(name))
    assert report.gate_passed
    assert report.open_findings == []


# ---------- Part 3: mutation testing - every check must catch its own break -------

def _add_flow(src, dst):
    return lambda d: d["flows"].append({"from": src, "to": dst})


MUTATIONS = {
    "IAM-01": lambda d: d["identities"][0].update(credential="static_key"),
    "IAM-02": lambda d: d["identities"][0]["permissions"].append("bedrock:*"),
    "IAM-03": lambda d: comp(d, "rag_service").update(identity=comp(d, "ai_gateway")["identity"]),
    "IAM-04": lambda d: comp(d, "ai_gateway").update(user_auth="api_key"),
    "IAM-05": lambda d: d["identities"][2].pop("owner"),
    "IAM-06": lambda d: comp(d, "agent_runtime").update(downstream_auth="passthrough"),
    "NET-01": lambda d: comp(d, "model_endpoint").update(public_network_access=True),
    "NET-02": lambda d: comp(d, "vector_store").update(public_network_access=True),
    "NET-03": lambda d: comp(d, "agent_runtime").update(egress="allow_all"),
    "NET-04": _add_flow("internet", "agent"),
    "DATA-01": lambda d: comp(d, "vector_store").pop("encryption_key"),
    "DATA-02": lambda d: d["keys"][0].update(rotation=False),
    "DATA-03": lambda d: comp(d, "rag_service").update(retrieval_authz="prompt_only"),
    "DATA-04": lambda d: comp(d, "model_endpoint")["data_use"].update(training_opt_out=False),
    "GR-01": lambda d: comp(d, "ai_gateway")["guardrails"].update(input=[]),
    "GR-02": lambda d: comp(d, "ai_gateway")["guardrails"].update(output=["url_allowlist"]),
    "GW-01": lambda d: comp(d, "ai_gateway").pop("model_routing"),
    "GW-02": lambda d: comp(d, "ai_gateway").update(cache_scope="global"),
    "TOOL-01": _add_flow("agent", "tool-change"),
    "AGT-01": lambda d: comp(d, "agent_runtime").update(approval_required_for=[]),
    "AGT-02": lambda d: comp(d, "agent_runtime").update(kill_switch=False),
    "LOG-01": lambda d: d["logging"].update(model_invocation_logs=False),
    "LOG-02": lambda d: comp(d, "log_store").update(immutable=False),
    "OPS-01": lambda d: comp(d, "ai_gateway").update(rate_limits=False),
    "OPS-02": lambda d: d["assessment"].update(drift_detection=False),
    "SEC-01": lambda d: d["secrets"]["inline"].append("DB_PASSWORD in container env"),
}


def test_every_control_in_the_matrix_has_a_mutation_test():
    assert set(MUTATIONS) == {c.id for c in MATRIX}


@pytest.mark.parametrize("name", SECURE)
@pytest.mark.parametrize("control_id", sorted(MUTATIONS))
def test_breaking_one_control_is_caught_precisely(name, control_id):
    data = copy.deepcopy(raw(name))
    MUTATIONS[control_id](data)
    report = run(data)
    assert failed(report) == {control_id}
    blocking = next(c for c in MATRIX if c.id == control_id).severity in {"critical", "high"}
    assert report.gate_passed is not blocking


# ---------- Part 4: fail closed, exceptions and edge cases ------------------------

def test_a_typo_in_a_setting_is_an_error_not_a_silent_pass():
    data = raw("secure_aws")
    comp(data, "model_endpoint")["public_network_acess"] = False  # note the typo
    with pytest.raises(ValidationError):
        reviewer.parse_architecture(data)


def test_a_flow_to_an_unknown_component_is_an_error():
    data = raw("secure_aws")
    data["flows"].append({"from": "internet", "to": "shadow-notebook"})
    with pytest.raises(ValidationError):
        reviewer.parse_architecture(data)


def test_missing_settings_default_to_the_insecure_cloud_default():
    data = raw("secure_azure")
    model = comp(data, "model_endpoint")
    del model["public_network_access"], model["private_endpoint"]
    assert failed(run(data)) == {"NET-01"}


def test_graph_check_finds_an_indirect_bypass_through_another_component():
    data = raw("secure_gcp")
    data["components"].append({"id": "notebook-proxy", "type": "frontend", "zone": "public"})
    data["flows"] += [{"from": "internet", "to": "notebook-proxy"},
                      {"from": "notebook-proxy", "to": "model"}]
    report = run(data)
    assert failed(report) == {"NET-04"} and not report.gate_passed


def test_drifted_design_valid_exception_is_accepted():
    report = run(raw("drifted_gcp"))
    assert report.status_of("GR-01") == "ACCEPTED"


def test_drifted_design_expired_exception_counts_as_open_again():
    f = next(f for f in run(raw("drifted_gcp")).findings if f.control_id == "NET-03")
    assert f.status == "FAIL" and "EXPIRED" in f.detail


def test_critical_findings_cannot_be_risk_accepted():
    f = next(f for f in run(raw("drifted_gcp")).findings if f.control_id == "NET-04")
    assert f.status == "FAIL" and "cannot be risk-accepted" in f.detail


def test_exceptions_expire_with_time():
    assert run(raw("drifted_gcp"), today=date(2026, 10, 1)).status_of("GR-01") == "FAIL"


def test_accepted_medium_finding_does_not_block_the_gate():
    data = raw("drifted_gcp")
    data["flows"] = [f for f in data["flows"] if not (f["from"] == "internet" and f["to"] == "model")]
    comp(data, "agent_runtime")["egress"] = "deny_by_default"
    report = run(data)
    assert report.gate_passed and report.status_of("GR-01") == "ACCEPTED"


def test_single_tenant_design_marks_tenant_isolation_not_applicable():
    data = raw("secure_aws")
    data["multi_tenant"] = False
    assert run(data).status_of("DATA-03") == "N/A"


def test_review_can_be_scoped_to_some_control_families():
    report = run(raw("vulnerable_aws"), families=["identity"])
    assert {f.family for f in report.findings} == {"identity"}
    assert failed(report) == {"IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06"}


# ---------- Part 5: identity, gateway and continuous-assessment controls ----------

def test_an_agent_identity_without_owner_is_an_orphan():
    data = raw("secure_gcp")
    data["identities"].append({"id": "sa-notebook-agent", "kind": "agent", "credential": "short_lived"})
    f = next(f for f in run(data).findings if f.control_id == "IAM-05")
    assert f.status == "FAIL" and "sa-notebook-agent" in f.detail


def test_a_human_identity_does_not_need_the_nhi_owner_field():
    data = raw("secure_aws")
    data["identities"].append({"id": "alice", "kind": "human", "credential": "short_lived"})
    assert run(data).status_of("IAM-05") == "PASS"


def test_token_passthrough_on_the_tool_gateway_is_caught_too():
    data = raw("secure_azure")
    comp(data, "mcp_gateway")["downstream_auth"] = "passthrough"
    f = next(f for f in run(data).findings if f.control_id == "IAM-06")
    assert f.status == "FAIL" and "mcp-gateway" in f.detail


def test_a_gateway_without_any_cache_is_not_applicable_for_cache_isolation():
    data = raw("secure_aws")
    comp(data, "ai_gateway")["cache_scope"] = "none"
    assert run(data).status_of("GW-02") == "N/A"


def test_missing_assessment_block_defaults_to_no_continuous_assessment():
    data = raw("secure_gcp")
    del data["assessment"]
    f = next(f for f in run(data).findings if f.control_id == "OPS-02")
    assert f.status == "FAIL" and "drift" in f.detail
    assert run(data).gate_passed  # medium: a finding, not a blocker


def test_resource_wildcards_are_not_mistaken_for_action_wildcards():
    assert reviewer.is_broad("bedrock:*")
    assert reviewer.is_broad("roles/editor")
    assert not reviewer.is_broad("cloudformation:CreateChangeSet on ops-assistant-*")


def test_demo_and_cli_run():
    import subprocess
    import sys

    lab = reviewer.HERE
    demo = subprocess.run([sys.executable, "demo.py"], cwd=lab, capture_output=True, text=True, timeout=60)
    assert demo.returncode == 0, demo.stderr
    cli = subprocess.run([sys.executable, "reviewer.py", "architectures/vulnerable_aws.yaml"],
                         cwd=lab, capture_output=True, text=True, timeout=60)
    assert cli.returncode == 1 and "GATE: FAIL" in cli.stdout  # CI would block this merge
