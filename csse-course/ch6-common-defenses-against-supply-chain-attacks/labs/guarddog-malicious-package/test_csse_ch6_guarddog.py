"""Tests for the GuardDog-style scanner."""

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "guarddog_lite")


def rules(name):
    return {f.rule for f in g.scan_package(name, g.SAMPLES[name])}


def test_benign_package_is_clean():
    assert g.scan_package("requests-utils", g.SAMPLES["requests-utils"]) == []
    assert g.verdict([]) == "CLEAN"


def test_typosquat_detected_only_for_near_names():
    assert "typosquat" in rules("reqeusts")
    assert "typosquat" not in rules("requests-utils")


def test_python_install_hook_and_obfuscated_exec():
    r = rules("reqeusts")
    assert {"install-hook", "obfuscated-exec", "long-encoded-blob"} <= r


def test_exfiltration_and_credential_path():
    r = rules("reqeusts")
    assert {"env-exfiltration", "credential-path", "unknown-endpoint"} <= r


def test_unregistered_maintainer_domain():
    assert "unregistered-maintainer-domain" in rules("reqeusts")


def test_npm_postinstall_download_and_run():
    r = rules("left-padz-js")
    assert {"install-hook", "download-and-run", "typosquat"} <= r


def test_verdicts():
    assert g.verdict(g.scan_package("reqeusts", g.SAMPLES["reqeusts"])) == "MALICIOUS-LIKELY"
    assert g.verdict(g.scan_package("left-padz-js", g.SAMPLES["left-padz-js"])) == "MALICIOUS-LIKELY"


def test_allowlisted_host_not_flagged():
    pkg = {"meta": {}, "files": {"a.py": "x = 'https://pypi.org/simple'"}}
    assert g.scan_package("zzz-unique-name", pkg) == []


def test_entropy_of_repeated_vs_random_like():
    assert g.entropy("aaaa") < g.entropy("aB3$kL9#qZ")
