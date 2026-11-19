from pathlib import Path

from aisec_lab import load_lab_module

pl = load_lab_module(__file__, "playbook_linter")
FIX = Path(__file__).parent / "fixtures"
GOOD = (FIX / "playbook_docker_host.yml").read_text()
BAD = (FIX / "playbook_docker_host_bad.yml").read_text()


def ids(findings):
    return {f.rule_id for f in findings}


def test_good_playbook_passes_clean():
    found = pl.lint_text(GOOD)
    assert found == [] and pl.verdict(found) == "PASS"


def test_bad_playbook_fires_every_rule():
    found = pl.lint_text(BAD)
    assert {f"ANS-00{i}" for i in range(1, 9)} <= ids(found)
    assert pl.verdict(found) == "FAIL"


def test_missing_become_is_reported_per_task():
    text = GOOD.replace("  become: true\n", "", 1)
    assert "ANS-001" in ids(pl.lint_text(text))


def test_task_level_become_satisfies_the_rule():
    text = """
- hosts: all
  tasks:
    - name: install
      ansible.builtin.package: {name: chrony, state: present}
      become: true
"""
    assert "ANS-001" not in ids(pl.lint_text(text))


def test_no_log_removal_is_caught():
    assert "ANS-002" in ids(pl.lint_text(GOOD.replace("      no_log: true\n", "")))


def test_digest_pin_removed_is_caught_and_latest_is_high():
    text = GOOD.replace("@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ":1.0")
    found = [f for f in pl.lint_text(text) if f.rule_id == "ANS-003"]
    assert found and found[0].severity == "MEDIUM"
    latest = [f for f in pl.lint_text(BAD) if f.rule_id == "ANS-003" and f.severity == "HIGH"]
    assert latest


def test_daemon_hardening_keys_checked():
    text = GOOD.replace("      no-new-privileges: true\n", "")
    msgs = [f.message for f in pl.lint_text(text) if f.rule_id == "ANS-004"]
    assert any("no-new-privileges" in m for m in msgs)


def test_exposed_tcp_daemon_is_critical():
    crit = [f for f in pl.lint_text(BAD) if f.rule_id == "ANS-004" and f.severity == "CRITICAL"]
    assert crit


def test_docker_without_daemon_task_flagged():
    text = """
- hosts: all
  become: true
  tasks:
    - name: install
      ansible.builtin.package: {name: docker-ce, state: present}
"""
    assert "ANS-004" in ids(pl.lint_text(text))


def test_idempotency_smells():
    msgs = " ".join(f.message for f in pl.lint_text(BAD) if f.rule_id == "ANS-005")
    assert "creates" in msgs and ">>" in msgs and "state: latest" in msgs


def test_vault_tag_is_not_a_literal_secret():
    assert "ANS-007" not in ids(pl.lint_text(GOOD))
    assert "ANS-007" in ids(pl.lint_text(BAD))


def test_freeform_key_value_syntax_is_parsed():
    found = pl.lint_text("- hosts: all\n  tasks:\n    - apt: name=docker.io state=latest\n")
    assert "ANS-001" in ids(found) and "ANS-005" in ids(found)
