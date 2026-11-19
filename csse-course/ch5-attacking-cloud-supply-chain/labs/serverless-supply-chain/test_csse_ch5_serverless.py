"""Tests for the serverless supply-chain auditor."""

from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "audit")
DOC = a.load(Path(__file__).resolve().parent / "fixtures" / "functions.json")
FN = {f["name"]: f for f in DOC["functions"]}


def rules(findings):
    return {f.rule for f in findings}


def test_env_secrets_flagged_but_secret_manager_reference_is_not():
    assert "ENV-SECRET" in rules(a.audit_env(FN["orders-api"]))
    assert len(a.audit_env(FN["orders-api"])) == 2  # DB_PASSWORD and API_KEY, not STAGE
    assert a.audit_env(FN["clean-fn"]) == []


def test_azure_connection_string_and_gcp_token_detected():
    assert "ENV-SECRET" in rules(a.audit_env(FN["thumbnailer"]))
    assert "ENV-SECRET" in rules(a.audit_env(FN["export-job"]))


def test_untrusted_and_unpinned_layer():
    f = a.audit_layers(FN["orders-api"], set(DOC["trusted_layer_accounts"]))
    assert rules(f) == {"LAYER-THIRD-PARTY", "LAYER-UNPINNED"}


def test_vulnerable_and_malicious_dependency():
    f = a.audit_deps(FN["orders-api"], DOC["advisories"], set(DOC["known_malicious"]))
    assert {"DEP-VULNERABLE", "DEP-MALICIOUS", "DEP-NO-HASH"} <= rules(f)


def test_fixed_version_not_flagged():
    f = a.audit_deps(FN["export-job"], DOC["advisories"], set())
    assert "DEP-VULNERABLE" not in rules(f)


def test_version_compare_is_numeric_not_string():
    assert a._ver("1.10.0") > a._ver("1.9.0")


def test_role_privesc_and_wildcard():
    r = rules(a.audit_role(FN["orders-api"]))
    assert {"ROLE-WILDCARD", "ROLE-PRIVESC"} <= r


def test_broad_builtin_role():
    assert "ROLE-BROAD-BUILTIN" in rules(a.audit_role(FN["export-job"]))


def test_least_privilege_role_is_clean():
    assert a.audit_role(FN["clean-fn"]) == []


def test_unauthenticated_url():
    assert "URL-NO-AUTH" in rules(a.audit_exposure(FN["orders-api"]))
    assert "URL-NO-AUTH" in rules(a.audit_exposure(FN["export-job"]))
    assert a.audit_exposure(FN["clean-fn"]) == []


def test_clean_function_has_only_no_findings_except_none():
    assert [f for f in a.audit(DOC) if f.function == "clean-fn"] == []


def test_overall_sorted_and_blast_radius():
    f = a.audit(DOC)
    assert f[0].severity == "critical"
    assert a.blast_radius(FN["orders-api"]) == "may escalate to other roles"
    assert a.blast_radius(FN["clean-fn"]) == "scoped to its own resources"
