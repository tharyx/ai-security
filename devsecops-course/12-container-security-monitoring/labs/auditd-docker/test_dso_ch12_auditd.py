from pathlib import Path

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "auditd_tool")
HERE = Path(__file__).parent
RULES = a.parse_rules((HERE / "docker.rules").read_text())
EVENTS = a.parse_log((HERE / "audit.log").read_text())


def test_rules_cover_all_required_paths():
    assert a.coverage(RULES) == [] and a.lint(RULES) == []


def test_weak_ruleset_reports_gaps():
    weak = a.parse_rules("-w /usr/bin/docker\n-w /etc/docker -p r -k cfg\n")
    out = " | ".join(a.lint(weak))
    assert "no -k key" in out and "does not log writes" in out and "missing watch: /run/docker.sock" in out


def test_parent_directory_watch_covers_children():
    rules = a.parse_rules("-w /var/lib -k x\n")
    assert "/var/lib/docker" not in a.coverage(rules)


def test_log_grouped_by_serial():
    assert len(EVENTS) == 7 and EVENTS["503"]["syscall"]["comm"] == "vim"
    assert [p["nametype"] for p in EVENTS["504"]["paths"]] == ["CREATE"]


def test_docker_sock_access_by_unexpected_process():
    al = [x for x in a.detect(EVENTS) if x["rule"] == "DOCKER_SOCK_ACCESS"]
    assert len(al) == 1 and "python3.12" in al[0]["detail"] and "auid=unset" in al[0]["detail"]


def test_config_change_detected_twice_for_vim_save():
    al = [x for x in a.detect(EVENTS) if x["rule"] == "DOCKER_CONFIG_CHANGE"]
    assert {x["serial"] for x in al} == {"503", "504"}


def test_unapproved_docker_cli_user():
    al = [x for x in a.detect(EVENTS) if x["rule"] == "DOCKER_CLI_UNAPPROVED_USER"]
    assert len(al) == 1 and "1002" in al[0]["detail"]


def test_dockerd_itself_not_flagged():
    assert not any(x["serial"] == "507" for x in a.detect(EVENTS))
