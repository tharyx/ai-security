"""Tests for the stage exercise checker."""

from pathlib import Path

from aisec_lab import load_lab_module

sc = load_lab_module(__file__, "stage_checker")
HERE = Path(__file__).parent
STARTER = (HERE / "starter.gitlab-ci.yml").read_text()
SOLUTION = (HERE / "solutions" / "solution.gitlab-ci.yml").read_text()


def by_id(text):
    return {c.id: c for c in sc.check_all(text)}


def test_starter_fails_all_four_exercises():
    r = by_id(STARTER)
    assert [r[k].ok for k in ("EX1", "EX2", "EX3", "EX4")] == [False] * 4


def test_solution_passes_all_four():
    assert all(c.ok for c in sc.check_all(SOLUTION)), [c for c in sc.check_all(SOLUTION) if not c.ok]


def test_stage_order_table():
    order = sc.stage_order(SOLUTION)
    assert list(order) == ["build", "test", "security", "deploy"]
    assert order["security"] == ["secret-scan", "sast"]


def test_test_stage_must_be_between_build_and_deploy():
    wrong = STARTER.replace("  - build\n  - deploy", "  - test\n  - build\n  - deploy") + (
        "\nunit:\n  stage: test\n  script: [x]\n")
    assert not by_id(wrong)["EX1"].ok
    right = STARTER.replace("  - build\n  - deploy", "  - build\n  - test\n  - deploy") + (
        "\nunit:\n  stage: test\n  script: [x]\n")
    assert by_id(right)["EX1"].ok


def test_empty_test_stage_fails():
    text = STARTER.replace("  - build\n  - deploy", "  - build\n  - test\n  - deploy")
    assert "no job" in by_id(text)["EX1"].message


def test_security_stage_after_deploy_fails():
    text = STARTER.replace("  - build\n  - deploy", "  - build\n  - deploy\n  - security") + (
        "\nsast:\n  stage: security\n  script: [x]\n")
    assert not by_id(text)["EX2"].ok


def test_manual_without_main_restriction_fails():
    text = SOLUTION.replace('if: $CI_COMMIT_BRANCH == "main"', "if: $CI_COMMIT_BRANCH")
    assert not by_id(text)["EX3"].ok


def test_manual_only_at_job_level_is_not_enough():
    text = STARTER + "  when: manual\n"
    assert not by_id(text)["EX3"].ok


def test_secret_in_job_variables_detected():
    text = SOLUTION + "\nextra:\n  stage: test\n  script: [x]\n  variables:\n    DB_PASSWORD: hunter2\n"
    assert not by_id(text)["EX4"].ok


def test_empty_variable_declaration_is_fine():
    text = SOLUTION.replace("stages:", "variables:\n  DEPLOY_TOKEN: \"\"\nstages:", 1)
    assert by_id(text)["EX4"].ok
