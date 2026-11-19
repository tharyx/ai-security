import re
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ss = load_lab_module(__file__, "secretscan")
needs_git = pytest.mark.skipif(not ss.git_available(), reason="git is not installed")


def rules(text, path="a.py"):
    return [(f.rule, f.confidence) for f in ss.scan_text(text, path)]


def test_fake_token_is_built_at_runtime_and_has_a_valid_checksum():
    t = ss.make_fake_token("x")
    assert t.startswith("acme_live_") and len(t) == 34
    assert re.fullmatch(r"acme_live_[A-Za-z0-9]{20}[0-9a-f]{4}", t)
    assert ss.checksum(t[10:30]) == t[30:]


def test_source_files_hold_no_literal_token_shaped_strings():
    here = Path(__file__).resolve().parent
    text = (here / "secretscan.py").read_text(encoding="utf-8") + Path(__file__).read_text(encoding="utf-8")
    assert not re.search(r"acme_live_[A-Za-z0-9]{20}", text)
    assert "PRIVATE KEY-----\n" not in text


def test_checksum_decides_between_high_and_low_confidence():
    assert rules(f'x = "{ss.make_fake_token("a")}"') == [("acme-token", "HIGH")]
    assert rules(f'x = "{ss.make_fake_token("a", valid=False)}"') == [("acme-token", "LOW")]


def test_generic_assignment_skips_placeholders_and_low_entropy():
    assert rules('password = "changeme-please"') == []
    assert rules('api_key = "${API_KEY}"') == []
    assert rules('password = "aaaaaaaaaaaa"') == []
    assert rules('password = "q8Zr2xLm9vTbN4"') == [("generic-assignment", "MEDIUM")]


def test_entropy_rule_ignores_uuids_and_hashes_but_flags_random_strings():
    assert rules("id = 123e4567-e89b-12d3-a456-426614174000") == []
    assert rules("sha256 = " + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") == []
    assert rules("blob = " + "Zq8Lm2Xv9TbN4wRk7YcP3sHd5JfG1aEu") == [("high-entropy-string", "LOW")]


def test_allowlist_pragma_suppresses_a_line():
    assert rules(f'x = "{ss.make_fake_token("a")}"  # {ss.ALLOW_PRAGMA}') == []


def test_private_key_header_built_from_pieces_is_found():
    key = ss.make_fake_private_key("k")
    assert ("private-key-block", "HIGH") in rules(key)


def test_filename_signatures_gitrob_style():
    assert ss.scan_filename("deploy/id_rsa") and ss.scan_filename("certs/site.pem") and ss.scan_filename(".env")
    assert ss.scan_filename(".env.example") is None and ss.scan_filename("src/main.py") is None


def test_redaction_never_prints_the_secret():
    t = ss.make_fake_token("z")
    f = ss.scan_text(f'x = "{t}"', "a.py")[0]
    assert t not in f.preview and f.preview.startswith("acme")


def test_entropy_values():
    assert ss.entropy("") == 0.0 and ss.entropy("aaaa") == 0.0
    assert ss.entropy("abcd") == 2.0


@needs_git
def test_history_scan_finds_deleted_secrets_that_the_tree_scan_misses():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        root, home = Path(d) / "r", Path(d) / "h"
        root.mkdir()
        home.mkdir()
        ss.build_demo_repo(root, home)
        head = ss.scan_tree(root)
        assert [f.confidence for f in head] == ["LOW"]           # only the broken-checksum test token
        hist = ss.classify_history(ss.scan_history(root, home), head)
        kinds = {(f.rule, f.path) for f in hist}
        assert ("acme-token", "config.py") in kinds and ("sensitive-filename", "deploy/id_rsa") in kinds
        assert ("acme-token", "notes.txt") in kinds               # secret on an unmerged branch (--all)
        cfg = next(f for f in hist if f.path == "config.py")
        assert cfg.subject == "initial import" and "STILL IN HISTORY" in cfg.note
        assert ss.ci_gate(head) == 0 and ss.ci_gate(hist) == 1


@needs_git
def test_ci_range_scan_only_looks_at_the_merge_request_commits():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        root, home = Path(d) / "r", Path(d) / "h"
        root.mkdir()
        home.mkdir()
        ss.build_demo_repo(root, home)
        mr = ss.scan_history(root, home, "HEAD~1..HEAD")
        assert {f.path for f in mr} == {"tests/test_client.py"}
        assert ss.ci_gate(mr, "MEDIUM") == 0 and ss.ci_gate(mr, "LOW") == 1


@needs_git
def test_git_runs_with_isolated_config():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        env = ss.git_env(Path(d))
        assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"].endswith("empty.gitconfig")
        assert env["HOME"] == d
