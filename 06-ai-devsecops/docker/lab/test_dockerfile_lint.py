"""Dockerfile linter tests: every rule fires on the vulnerable file, none on the secure one,
and small edits prove each rule catches the specific problem.

Run from the repository root:
    python -m pytest 06-ai-devsecops/docker -v
"""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

dl = load_lab_module(__file__, "dockerfile_lint")
LAB = Path(__file__).parent
SECURE_TEXT = (LAB / "secure" / "Dockerfile").read_text(encoding="utf-8")
PIN = "@sha256:" + "a" * 64


def rule_ids(text: str, dockerignore: str | None = None) -> set[str]:
    return {f.rule_id for f in dl.lint(text, dockerignore=dockerignore)}


# ---------- Part 1: the vulnerable image is caught ------------------------------------

def test_vulnerable_dockerfile_triggers_every_rule():
    assert {f.rule_id for f in dl.lint_file(LAB / "vulnerable" / "Dockerfile")} == set(dl.RULES)


def test_vulnerable_dockerfile_fails_the_build():
    assert dl.main([str(LAB / "vulnerable" / "Dockerfile")]) == 1


# ---------- Part 2: the secure image passes ---------------------------------------------

def test_secure_dockerfile_is_clean():
    assert dl.lint_file(LAB / "secure" / "Dockerfile") == []
    assert dl.main([str(LAB / "secure" / "Dockerfile")]) == 0


def test_build_tools_in_the_builder_stage_are_fine():
    # gcc is installed in stage 1 of the secure file, but stage 1 is thrown away.
    assert "gcc" in SECURE_TEXT and "DF-008" not in rule_ids(SECURE_TEXT, "*")


def test_build_secret_mount_is_not_a_finding():
    assert "--mount=type=secret" in SECURE_TEXT and "DF-004" not in rule_ids(SECURE_TEXT, "*")


# ---------- Part 3: one edit -> the right rule ---------------------------------------------

def test_removing_user_makes_it_run_as_root():
    text = SECURE_TEXT.replace("USER 65532:65532", "")
    assert "DF-003" in rule_ids(text, "*")


def test_user_root_at_the_end_wins():
    text = SECURE_TEXT.replace("USER 65532:65532", "USER 65532:65532\nUSER root")
    assert "DF-003" in rule_ids(text, "*")


def test_user_in_builder_stage_does_not_count():
    text = f"FROM debian:12{PIN} AS build\nUSER 1000\nFROM debian:12{PIN}\nCMD [\"app\"]\n"
    assert "DF-003" in rule_ids(text)


@pytest.mark.parametrize("line", [
    "ENV HF_TOKEN=hf_aaaaaaaaaaaaaaaaaaaaaaaa",
    "ENV DB_PASSWORD hunter2",                      # legacy 'ENV key value' form
    "ENV MODEL_CONFIG=sk-test-CANARY000000000000",   # innocent name, key-shaped value
    "ARG AWS_SECRET_ACCESS_KEY",
])
def test_secrets_in_env_or_arg_are_caught(line):
    text = f"FROM debian:12{PIN}\n{line}\nUSER 1000\n"
    assert "DF-004" in rule_ids(text)


def test_stage_reference_is_not_treated_as_an_unpinned_image():
    text = f"FROM python:3.11{PIN} AS build\nFROM build\nUSER 1000\n"
    assert rule_ids(text) == set()


def test_copy_all_is_fine_with_a_dockerignore():
    text = f"FROM debian:12{PIN}\nCOPY . /app\nUSER 1000\n"
    assert "DF-012" in rule_ids(text, dockerignore=None)
    assert "DF-012" not in rule_ids(text, dockerignore="*\n!src/\n")


def test_add_with_checksum_is_accepted():
    url = "https://models.example/m.safetensors"
    assert "DF-006" in rule_ids(f"FROM debian:12{PIN}\nADD {url} /m\nUSER 1\n")
    assert "DF-006" not in rule_ids(f"FROM debian:12{PIN}\nADD --checksum=sha256:{'b' * 64} {url} /m\nUSER 1\n")


@pytest.mark.parametrize("cmd, bad", [
    ("pip install torch==2.6.0", False),
    ("pip install torch", True),
    ("pip install -r requirements.txt", True),
    ("pip install --require-hashes -r requirements.lock", False),
    ("python -m pip install --no-cache-dir fastapi==0.115.0 uvicorn", True),
])
def test_pip_pinning(cmd, bad):
    assert ("DF-009" in rule_ids(f"FROM debian:12{PIN}\nRUN {cmd}\nUSER 1\n")) is bad


def test_line_continuations_are_joined_and_reported_at_the_first_line():
    text = f"FROM debian:12{PIN}\nRUN apt-get update && \\\n    curl -fsSL https://x.example/i.sh \\\n    | sh\nUSER 1\n"
    finding = next(f for f in dl.lint(text) if f.rule_id == "DF-007")
    assert finding.line == 2


def test_disabled_rule_is_skipped():
    text = (LAB / "vulnerable" / "Dockerfile").read_text(encoding="utf-8")
    assert "DF-011" not in {f.rule_id for f in dl.lint(text, disabled={"DF-011"})}
