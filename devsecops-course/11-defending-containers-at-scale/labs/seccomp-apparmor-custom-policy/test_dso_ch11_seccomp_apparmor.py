import json
from pathlib import Path

from aisec_lab import load_lab_module

pg = load_lab_module(__file__, "policy_gen")
FIX = Path(__file__).parent / "fixtures"


def test_parse_strace_unique_ordered_and_pid_prefixes():
    obs = pg.parse_strace((FIX / "strace_web_app.txt").read_text())
    assert obs[0] == "execve" and obs.count("futex") == 1
    assert {"socket", "bind", "listen", "accept4", "epoll_wait"} <= set(obs)
    assert not any(o.startswith("+++") for o in obs)


def test_generated_seccomp_is_allowlist_and_valid():
    prof, refused = pg.gen_seccomp(pg.parse_strace((FIX / "strace_web_app.txt").read_text()))
    assert prof["defaultAction"] == "SCMP_ACT_ERRNO" and refused == []
    assert "socket" in prof["syscalls"][0]["names"]
    assert pg.validate_seccomp(prof) == []


def test_dangerous_syscalls_never_auto_allowed():
    prof, refused = pg.gen_seccomp(pg.parse_strace((FIX / "strace_with_ptrace.txt").read_text()))
    assert set(refused) == {"ptrace", "mount"}
    assert not {"ptrace", "mount"} & set(prof["syscalls"][0]["names"])


def test_bad_seccomp_flagged():
    p = pg.validate_seccomp(json.loads((FIX / "bad_seccomp.json").read_text()))
    assert any("denylist" in x for x in p) and any("ptrace" in x for x in p)


def test_generated_apparmor_validates_and_contains_denies():
    aa = pg.gen_apparmor("dso-web", pg.parse_accesses((FIX / "file_accesses.txt").read_text()))
    assert "/app/** r," in aa and "deny mount," in aa and "deny /var/run/docker.sock" in aa
    assert pg.validate_apparmor(aa) == []


def test_bad_apparmor_flagged():
    p = " | ".join(pg.validate_apparmor((FIX / "bad_apparmor.profile").read_text()))
    for frag in ("complain", "blanket", "root-wide", "sys_admin", "ptrace", "docker.sock"):
        assert frag in p


def test_parse_accesses_ignores_comments():
    assert pg.parse_accesses("# c\n/a/** r # trailing\n\n") == [("/a/**", "r")]
