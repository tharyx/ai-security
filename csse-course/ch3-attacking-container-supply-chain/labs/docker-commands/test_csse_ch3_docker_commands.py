import pytest
from aisec_lab import load_lab_module

ra = load_lab_module(__file__, "run_assess")


def ids(cmd):
    return {f.rule_id for f in ra.assess(ra.parse_run(cmd))}


def test_privileged_and_socket_are_critical():
    cmd = "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock alpine:3.20"
    found = ra.assess(ra.parse_run(cmd))
    assert {"RUN-001", "RUN-002"} <= {f.rule_id for f in found}
    assert ra.verdict(found) == "DENY"


def test_host_network_pid_ipc():
    assert {"RUN-007", "RUN-008", "RUN-009"} <= ids("docker run --network=host --pid=host --ipc host alpine:3.20")


def test_cap_add_dangerous():
    assert "RUN-005" in ids("docker run --cap-add SYS_ADMIN --cap-add=CAP_NET_RAW alpine:3.20")


def test_mount_syntax_is_parsed():
    cfg = ra.parse_run("docker run --mount type=bind,source=/etc,target=/host-etc alpine:3.20")
    assert cfg.volumes == ["/etc:/host-etc"]
    assert "RUN-003" in ids("docker run --mount type=bind,source=/etc,target=/h alpine:3.20")


def test_read_only_mount_of_app_dir_is_not_flagged():
    assert "RUN-004" not in ids("docker run -v /srv/app:/app:ro alpine:3.20")
    assert "RUN-004" in ids("docker run -v /srv/app:/app alpine:3.20")


def test_secret_in_env_and_open_port():
    got = ids("docker run -e API_KEY=FAKE123 -p 8080:80 alpine:3.20")
    assert {"RUN-015", "RUN-016"} <= got
    assert "RUN-016" not in ids("docker run -p 127.0.0.1:8080:80 alpine:3.20")


def test_latest_vs_digest():
    assert "RUN-017" in ids("docker run alpine")
    assert "RUN-017" in ids("docker run alpine:latest")
    assert "RUN-017" not in ids("docker run alpine@sha256:" + "b" * 64)


def test_unconfined_security_opt():
    assert "RUN-012" in ids("docker run --security-opt seccomp=unconfined alpine:3.20")


def test_hardened_command_is_ok():
    cmd = ("docker run --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges "
           "--memory 256m --pids-limit 100 -p 127.0.0.1:8080:8080 nginx@sha256:" + "a" * 64)
    findings = ra.assess(ra.parse_run(cmd))
    assert findings == [] and ra.verdict(findings) == "OK"


def test_not_a_run_command():
    with pytest.raises(ValueError):
        ra.parse_run("docker ps")
