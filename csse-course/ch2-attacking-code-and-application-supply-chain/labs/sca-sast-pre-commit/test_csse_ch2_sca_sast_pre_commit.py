from pathlib import Path

from aisec_lab import load_lab_module

sc = load_lab_module(__file__, "scanners")
hr = load_lab_module(__file__, "hookrunner")
CFG = (Path(__file__).resolve().parent / "pre-commit-config.yaml").read_text()

CLEAN = {"app.py": "x = 1\n", "requirements.lock": "examplelib==1.4.2\n"}
BAD_CODE = {"app.py": "import os\nos.system('ls')\n"}
BAD_DEP = {"requirements.lock": "examplelib==1.3.0\nyaml-lite==0.5.0\n"}
BAD_SECRET = {"cfg.py": "api_key = 'FAKE-abcdef-123456'\n"}


def test_clean_commit_allowed():
    ok, out = hr.commit(CLEAN, CFG, sc)
    assert ok and {o.status for o in out} == {"Passed"}


def test_sast_finding_blocks_commit():
    ok, out = hr.commit(BAD_CODE, CFG, sc)
    assert not ok
    by = {o.hook_id: o for o in out}
    assert by["sast-check"].status == "Failed" and by["sca-check"].status == "Skipped"


def test_sca_finding_blocks_commit():
    ok, out = hr.commit(BAD_DEP, CFG, sc)
    assert not ok
    msgs = " ".join(m for o in out for m in o.messages)
    assert "EXAMPLE-2026-0001" in msgs and "EXAMPLE-2026-0002" in msgs


def test_hardcoded_secret_blocks_commit():
    assert not hr.commit(BAD_SECRET, CFG, sc)[0]


def test_hooks_only_see_matching_files():
    ok, out = hr.commit({"README.md": "os.system('x')\n"}, CFG, sc)
    assert ok and {o.status for o in out} == {"Skipped"}


def test_no_verify_bypasses_hook_but_ci_catches_it():
    ok, _ = hr.commit(BAD_CODE, CFG, sc, no_verify=True)
    assert ok  # the commit exists locally
    assert hr.ci_recheck(BAD_CODE, CFG, sc) == 1  # CI re-runs the same hooks on the tree


def test_unknown_entry_fails_closed():
    cfg = "repos:\n  - repo: local\n    hooks:\n      - id: x\n        entry: curl evil.example\n        language: system\n"
    ok, out = hr.commit({"a.py": "x=1\n"}, cfg, sc)
    assert not ok and "refusing to run" in out[0].messages[0]


def test_syntax_error_is_reported_not_ignored():
    assert not hr.commit({"a.py": "def (:\n"}, CFG, sc)[0]


def test_scanner_independent_checks():
    assert sc.sast_check({"a.py": "yaml.load(s)\n"}) and not sc.sast_check({"a.py": "yaml.safe_load(s)\n"})
    assert sc.sca_check({"requirements.txt": "examplelib==2.0.0\n"}) == []
