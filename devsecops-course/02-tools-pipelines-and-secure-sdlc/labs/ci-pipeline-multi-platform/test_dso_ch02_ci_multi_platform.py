"""Tests: one secure pipeline in five CI syntaxes, checked by one validator."""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "ci_validate")
FIX = Path(__file__).parent / "fixtures"
FILES = ["gitlab-ci.yml", "github-actions.yml", "Jenkinsfile", "circleci-config.yml", "travis.yml"]
PLATFORM = {"gitlab-ci.yml": "gitlab", "github-actions.yml": "github", "Jenkinsfile": "jenkins",
            "circleci-config.yml": "circleci", "travis.yml": "travis"}


def text(name):
    return (FIX / name).read_text(encoding="utf-8")


def run(name, mutate=None):
    t = text(name)
    if mutate:
        new = mutate(t)
        assert new != t, "mutation did not change the fixture"
        t = new
    return v.validate_text(name, t)


@pytest.mark.parametrize("name", FILES)
def test_fixture_is_clean(name):
    r = v.validate_file(FIX / name)
    assert r.platform == PLATFORM[name]
    assert r.ok, [i.message for i in r.issues]
    assert r.issues == []


@pytest.mark.parametrize("name", FILES)
def test_all_seven_stages_found_in_order(name):
    r = v.validate_file(FIX / name)
    assert r.stages_found == v.CANON


@pytest.mark.parametrize("name,needle", [
    ("gitlab-ci.yml", "zap-baseline.py -t http://app:3000 -I"),
    ("github-actions.yml", "zap-baseline.py"),
    ("Jenkinsfile", "zap-baseline.py"),
    ("circleci-config.yml", "zap-baseline.py"),
    ("travis.yml", "zap-baseline.py"),
])
def test_removing_dast_is_reported(name, needle):
    r = run(name, lambda t: t.replace(needle, "echo skipped dynamic testing #"))
    assert any("'dast'" in i.message for i in r.by_check("stages"))


def test_wrong_order_sast_after_build_gitlab():
    r = run("gitlab-ci.yml", lambda t: t.replace("stages: [secrets, sca, sast, build,",
                                                 "stages: [secrets, sca, build, sast,"))
    assert any("'sast' must run before 'build'" in i.message for i in r.by_check("stages"))


def test_github_action_pinned_to_tag_is_flagged():
    r = run("github-actions.yml",
            lambda t: t.replace("actions/checkout@0123456789abcdef0123456789abcdef01234567", "actions/checkout@v4", 1))
    msgs = [i.message for i in r.by_check("pinning")]
    assert any("actions/checkout@v4" in m for m in msgs)


def test_github_branch_ref_is_flagged():
    r = run("github-actions.yml", lambda t: t.replace("gitleaks-action@1111111111111111111111111111111111111111",
                                                      "gitleaks-action@main"))
    assert any("gitleaks-action@main" in i.message for i in r.by_check("pinning"))


def test_github_short_sha_is_not_enough():
    r = run("github-actions.yml", lambda t: t.replace("trivy-action@2222222222222222222222222222222222222222",
                                                      "trivy-action@2222222"))
    assert r.by_check("pinning")


@pytest.mark.parametrize("name,old,new", [
    ("gitlab-ci.yml", "node:20.11.1-alpine3.19", "node:latest"),
    ("gitlab-ci.yml", "semgrep/semgrep:1.56.0", "semgrep/semgrep"),
    ("circleci-config.yml", "cimg/node:20.11.1", "cimg/node:latest"),
    ("Jenkinsfile", "image 'semgrep/semgrep:1.56.0'", "image 'semgrep/semgrep'"),
])
def test_unpinned_container_image_is_flagged(name, old, new):
    r = run(name, lambda t: t.replace(old, new))
    assert r.by_check("pinning")


def test_digest_pin_is_accepted():
    digest = "sha256:" + "ab" * 32
    r = run("gitlab-ci.yml", lambda t: t.replace("semgrep/semgrep:1.56.0", "semgrep/semgrep@" + digest))
    assert r.by_check("pinning") == []


def test_image_in_name_block_is_checked():
    r = run("gitlab-ci.yml", lambda t: t.replace("aquasec/trivy:0.49.1", "aquasec/trivy:latest"))
    assert any("aquasec/trivy:latest" in i.message for i in r.by_check("pinning"))


def test_circleci_orb_must_be_exact_version():
    base = text("circleci-config.yml").replace("version: 2.1\n", "version: 2.1\norbs:\n  node: circleci/node@5\n")
    r = v.validate_text("circleci-config.yml", base)
    assert any("orb" in i.message for i in r.by_check("pinning"))


@pytest.mark.parametrize("name,anchor", [
    ("gitlab-ci.yml", "variables:\n  DB_PASSWORD: \"{secret}\"\n\n"),
    ("github-actions.yml", "env:\n  DB_PASSWORD: {secret}\n\n"),
    ("circleci-config.yml", "# note\nenvironment:\n  API_KEY: {secret}\n"),
    ("travis.yml", "env:\n  global:\n    - API_TOKEN={secret}\n"),
])
def test_literal_secret_in_yaml_is_flagged(name, anchor):
    block = anchor.format(secret="hunter2-example")
    r = run(name, lambda t: block + t)
    assert any("literal value" in i.message for i in r.by_check("secrets"))


def test_literal_secret_in_jenkinsfile_is_flagged():
    r = run("Jenkinsfile", lambda t: t.replace("agent none", "agent none\n  environment { DB_PASSWORD = 'hunter2-example' }"))
    assert r.by_check("secrets")


def test_variable_references_are_not_secrets():
    t = text("github-actions.yml") + "      - run: echo ok\n        env:\n          API_TOKEN: ${{ secrets.API_TOKEN }}\n"
    assert v.validate_text("github-actions.yml", t).by_check("secrets") == []


def test_token_shaped_strings_are_flagged():
    # built at run time so no token-shaped literal sits in the repo
    fake_gh = "gh" + "p_" + "A1b2C3d4E5" * 4
    fake_aws = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
    fake_key = "-----BEGIN " + "RSA PRIVATE KEY-----"
    for fake, label in [(fake_gh, "github token"), (fake_aws, "aws access key id"), (fake_key, "private key")]:
        r = run("gitlab-ci.yml", lambda t: t + f"\n# {fake}\n")
        assert any(label in i.message for i in r.by_check("secrets")), label


def test_github_missing_permissions_is_flagged():
    r = run("github-actions.yml", lambda t: t.replace("permissions:\n  contents: read\n\njobs:", "jobs:"))
    assert any("permissions" in i.message for i in r.by_check("privilege"))


def test_github_write_all_is_flagged():
    r = run("github-actions.yml", lambda t: t.replace("permissions:\n  contents: read\n\njobs:",
                                                      "permissions: write-all\n\njobs:"))
    assert any("write-all" in i.message for i in r.by_check("privilege"))


def test_github_job_write_permission_flagged_but_id_token_allowed():
    r = run("github-actions.yml", lambda t: t.replace("      id-token: write", "      id-token: write\n      packages: write"))
    msgs = [i.message for i in r.by_check("privilege")]
    assert any("packages: write" in m for m in msgs)
    assert not any("id-token" in m for m in msgs)


def test_github_checkout_persisting_credentials_is_a_warning():
    r = run("github-actions.yml", lambda t: t.replace("          persist-credentials: false\n", "", 1))
    w = [i for i in r.by_check("privilege") if i.severity == "warning"]
    assert w and r.ok


def test_docker_socket_and_privileged_flagged():
    r = run("Jenkinsfile", lambda t: t.replace("image 'semgrep/semgrep:1.56.0'",
                                               "image 'semgrep/semgrep:1.56.0'\n args '-v /var/run/docker.sock:/var/run/docker.sock'"))
    assert any("docker.sock" in i.message for i in r.by_check("privilege"))
    r = run("travis.yml", lambda t: t.replace("docker run --rm aquasec", "docker run --privileged --rm aquasec"))
    assert any("privileged" in i.message for i in r.by_check("privilege"))


def test_gitlab_personal_token_flagged():
    r = run("gitlab-ci.yml", lambda t: t.replace("./deploy.sh staging", "curl -H \"PRIVATE-TOKEN: $GITLAB_TOKEN\" x"))
    assert any("personal access token" in i.message for i in r.by_check("privilege"))


def test_jenkins_credentials_outside_deploy_flagged():
    r = run("Jenkinsfile", lambda t: t.replace("sh 'npm ci --ignore-scripts'",
                                               "withCredentials([string(credentialsId: 'x', variable: 'Y')]) { sh 'npm ci' }"))
    assert any("stage 'SCA'" in i.message for i in r.by_check("privilege"))


def test_jenkins_agent_any_is_a_warning():
    r = run("Jenkinsfile", lambda t: t.replace("agent none", "agent any", 1))
    assert any(i.severity == "warning" for i in r.by_check("privilege"))


def test_circleci_deploy_without_context_flagged():
    r = run("circleci-config.yml", lambda t: t.replace("          context: staging-deploy\n", ""))
    assert any("context" in i.message for i in r.by_check("privilege"))


def test_travis_deploy_without_branch_condition_warns():
    r = run("travis.yml", lambda t: t.replace("      if: branch = main\n", ""))
    assert any(i.severity == "warning" for i in r.by_check("privilege"))


def test_platform_detection_by_content():
    assert v.detect_platform("x.yml", text("github-actions.yml")) == "github"
    assert v.detect_platform("x.yml", text("circleci-config.yml")) == "circleci"
    assert v.detect_platform("x.yml", text("travis.yml")) == "travis"
    assert v.detect_platform("x.yml", text("gitlab-ci.yml")) == "gitlab"
    assert v.detect_platform("x", text("Jenkinsfile")) == "jenkins"
    with pytest.raises(ValueError):
        v.detect_platform("x.yml", "a: 1\n")
