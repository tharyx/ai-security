import copy
from pathlib import Path

from aisec_lab import load_lab_module

h = load_lab_module(__file__, "hardener")
pr = load_lab_module(__file__, "profiles")
HERE = Path(__file__).parent
VULN = (h.REPO / "06-ai-devsecops/docker/lab/vulnerable/Dockerfile").read_text()
SECURE = (h.REPO / "06-ai-devsecops/docker/lab/secure/Dockerfile").read_text()
SECCOMP = pr.load_seccomp(HERE / "profiles/seccomp-web-app.json")
APPARMOR = (HERE / "profiles/apparmor-web-app").read_text()


def test_vulnerable_dockerfile_is_linted_with_fix_hints():
    rows = h.lint_with_fixes(VULN)
    assert {r[0] for r in rows} == set(h.dockerfile_lint.RULES)
    assert all(r[4] != "see rule" for r in rows)


def test_secure_dockerfile_has_no_high_findings():
    assert not [r for r in h.lint_with_fixes(SECURE, dockerignore=".git\n.env") if r[1] in ("HIGH", "CRITICAL")]


def test_generated_run_command_is_clean():
    cmd = h.harden_run(h.RunProfile(image="app@sha256:" + "e" * 64, port=8080, caps=["NET_BIND_SERVICE"]))
    assert h.run_assess.verdict(h.assess_text(cmd)) == "OK"
    assert "--cap-add NET_BIND_SERVICE" in cmd and "127.0.0.1:8080:8080" in cmd


def test_unpinned_image_is_still_caught_after_hardening():
    cmd = h.harden_run(h.RunProfile(image="app:latest"))
    assert "RUN-017" in {f.rule_id for f in h.assess_text(cmd)}


def test_compose_snippet_matches_run_flags():
    svc = h.harden_compose(h.RunProfile(image="app@sha256:" + "e" * 64, port=8080))["services"]["app"]
    assert svc["read_only"] and svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["ports"] == ["127.0.0.1:8080:8080"]


def test_example_seccomp_profile_is_valid_and_denies_by_default():
    assert pr.validate_seccomp(SECCOMP) == []


def test_seccomp_validator_catches_allow_default_and_risky_calls():
    bad = copy.deepcopy(SECCOMP)
    bad["defaultAction"] = "SCMP_ACT_ALLOW"
    bad["syscalls"][0]["names"] += ["mount", "bpf"]
    problems = " ".join(pr.validate_seccomp(bad))
    assert "defaultAction" in problems and "mount" in problems and "bpf" in problems


def test_example_apparmor_profile_is_valid():
    assert pr.validate_apparmor(APPARMOR) == []


def test_apparmor_validator_catches_missing_rules():
    weak = APPARMOR.replace("deny mount,", "")
    assert any("deny mount" in p for p in pr.validate_apparmor(weak))
    assert any("complain" in p for p in pr.validate_apparmor(APPARMOR.replace("attach_disconnected", "complain,attach_disconnected")))
