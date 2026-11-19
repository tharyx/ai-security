"""Tests for the deployment-service analyzer and tamper simulation."""

from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "analyzer")
DOC = a.load(Path(__file__).resolve().parent / "fixtures" / "pipelines.json")
P = {p["name"]: p for p in DOC["pipelines"]}


def rules(name):
    return {f.rule for f in a.analyze(DOC) if f.pipeline == name}


def test_codepipeline_admin_role_and_shared_role():
    r = rules("web-release")
    assert {"ROLE-OVERPRIVILEGED", "ROLE-SHARED"} <= r


def test_writable_artifact_bucket_by_contractor():
    assert "ARTIFACT-STORE-WRITABLE" in rules("web-release")


def test_azure_devops_open_service_connection_and_owner():
    r = rules("mobile-backend")
    assert {"CONNECTION-OPEN-TO-ALL", "ROLE-OVERPRIVILEGED", "PLAIN-SECRET-VARIABLE"} <= r


def test_cloud_build_default_sa_editor_and_public_bucket_writer():
    r = rules("data-jobs")
    assert {"ROLE-OVERPRIVILEGED", "ARTIFACT-STORE-WRITABLE"} <= r


def test_missing_approval_flagged():
    assert "NO-PROD-APPROVAL" in rules("api-release")
    assert "NO-PROD-APPROVAL" not in rules("web-release")


def test_hardened_pipeline_has_no_findings():
    assert rules("hardened") == set()


def test_tamper_succeeds_without_digest_check():
    r = a.run_pipeline(P["web-release"], attacker="contractor-role")
    assert r["tampered"] and r["deployed"] == b"CANARY-malicious-build"


def test_digest_check_catches_tamper_even_when_bucket_is_writable():
    p = dict(P["web-release"])
    p["artifact_store"] = dict(p["artifact_store"], digest_verification=True)
    r = a.run_pipeline(p, attacker="contractor-role")
    assert r["tampered"] and r["deployed"] is None and "mismatch" in r["result"]


def test_least_privilege_writers_stop_tamper():
    r = a.run_pipeline(P["hardened"], attacker="contractor-role")
    assert not r["tampered"] and r["deployed"] == b"legit-build-v1"


def test_no_attacker_normal_deploy():
    assert a.run_pipeline(P["hardened"])["result"] == "deployed"


def test_findings_sorted_by_severity():
    f = a.analyze(DOC)
    assert [a.SEV[x.severity] for x in f] == sorted(a.SEV[x.severity] for x in f)
