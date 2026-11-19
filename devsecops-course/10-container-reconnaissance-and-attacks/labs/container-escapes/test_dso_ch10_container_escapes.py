import json
from pathlib import Path

from aisec_lab import load_lab_module

ea = load_lab_module(__file__, "escape_analyzer")
FIX = Path(__file__).parent / "fixtures"


def load(name):
    cfg = json.loads((FIX / f"{name}.json").read_text())
    return ea.analyze(cfg, cfg.get("_setuid_files"))


def ids(paths):
    return {p.id for p in paths}


def test_risky_config_hits_every_documented_path():
    got = ids(load("risky"))
    assert {"ESC-PRIV", "ESC-SOCK", "ESC-HOSTMOUNT", "ESC-HOSTPID", "ESC-HOSTNET", "ESC-HOSTIPC", "ESC-SETUID",
            "ESC-CAP-SYS_ADMIN", "ESC-CAP-SYS_PTRACE", "ESC-CAP-DAC_READ_SEARCH"} <= got
    assert ea.verdict(load("risky")) == "DENY"


def test_moderate_config_review_not_deny():
    p = load("moderate")
    assert ids(p) >= {"ESC-HOSTPID", "ESC-CAP-NET_ADMIN", "ESC-HOSTMOUNT", "ESC-SETUID"}
    assert ea.verdict(p) == "REVIEW"


def test_hardened_config_is_clean():
    p = load("hardened")
    assert p == [] and ea.verdict(p) == "OK"


def test_every_path_has_explanation_and_fix():
    for p in load("risky"):
        assert len(p.why) > 40 and len(p.fix) > 15


def test_readonly_socket_mount_still_critical():
    cfg = {"HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"]}, "Config": {"User": "1000"}}
    p = ea.analyze(cfg)
    assert p[0].id == "ESC-SOCK" and p[0].severity == "CRITICAL"
    assert "even with :ro" in p[0].why


def test_setuid_severity_drops_with_no_new_privileges():
    base = {"Config": {"User": "1000"}, "HostConfig": {"SecurityOpt": []}}
    hard = {"Config": {"User": "1000"}, "HostConfig": {"SecurityOpt": ["no-new-privileges"]}}
    assert ea.analyze(base, ["/usr/bin/su"])[0].severity == "HIGH"
    assert ea.analyze(hard, ["/usr/bin/su"])[0].severity == "LOW"


def test_root_only_is_low_warn():
    p = ea.analyze({"Config": {}, "HostConfig": {}})
    assert [x.id for x in p] == ["ESC-ROOT"] and ea.verdict(p) == "WARN"


def test_module_contains_no_executable_exploit_code():
    src = open(ea.__file__, encoding="utf-8").read()
    for bad in ("subprocess", "os.system", "socket.", "release_agent", "nsenter", "chroot "):
        assert bad not in src
