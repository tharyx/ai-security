import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "minipc")
CFG_TEXT = (Path(__file__).resolve().parent / "pre-commit-config.example.yaml").read_text()
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
KEY = ("-----BEGIN " + "RSA PRIVATE KEY-----\nFAKEFAKE\n").encode()


def run(files):
    return m.run_hooks(m.load_config(CFG_TEXT), files)


def failed(results):
    return {r.hook_id for r in results if not r.passed}


def test_clean_file_passes():
    assert failed(run({"a.py": b"x = 1\n"})) == set()


def test_trailing_whitespace_detected():
    assert failed(run({"a.py": b"x = 1 \n"})) == {"trailing-whitespace"}


def test_missing_final_newline_detected():
    assert failed(run({"a.py": b"x = 1"})) == {"end-of-file-fixer"}


def test_private_key_detected():
    assert "detect-private-key" in failed(run({"id": KEY}))


def test_large_file_detected():
    assert "check-added-large-files" in failed(run({"big.bin": b"0" * (600 * 1024) + b"\n"}))


def test_merge_conflict_detected():
    assert "check-merge-conflict" in failed(run({"a.txt": b"<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> b\n"}))


def test_bad_yaml_detected():
    assert "check-yaml" in failed(run({"c.yml": b"a: [1, 2\n"}))


def test_exit_code():
    assert m.exit_code(run({"a.py": b"x\n"})) == 0
    assert m.exit_code(run({"a.py": b"x \n"})) == 1


def test_unknown_hook_fails_closed():
    cfg = {"repos": [{"repo": "local", "hooks": [{"id": "mystery"}]}]}
    assert m.exit_code(m.run_hooks(cfg, {"a": b"x\n"})) == 1


def test_files_filter():
    cfg = {"repos": [{"repo": "x", "hooks": [{"id": "trailing-whitespace", "files": r"\.py$"}]}]}
    assert m.exit_code(m.run_hooks(cfg, {"notes.txt": b"x \n"})) == 0


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


def _repo(root):
    repo = Path(root) / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    for k, v in (("user.name", "T"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
        _git(repo, "config", k, v)
    (repo / ".pre-commit-config.yaml").write_text(CFG_TEXT)
    m.install_git_hook(repo)
    return repo


@needs_git
def test_real_git_commit_blocked_then_allowed():
    with tempfile.TemporaryDirectory() as t:
        repo = _repo(t)
        (repo / "a.py").write_text("x = 1 \n")
        _git(repo, "add", "a.py")
        bad = _git(repo, "commit", "-q", "-m", "bad")
        assert bad.returncode != 0
        assert "trailing-whitespace" in (bad.stdout + bad.stderr)
        (repo / "a.py").write_text("x = 1\n")
        _git(repo, "add", "a.py")
        good = _git(repo, "commit", "-q", "-m", "good")
        assert good.returncode == 0, good.stderr


@needs_git
def test_no_verify_bypasses_client_side_hook():
    with tempfile.TemporaryDirectory() as t:
        repo = _repo(t)
        (repo / "a.py").write_text("x = 1 \n")
        _git(repo, "add", "a.py")
        assert _git(repo, "commit", "-q", "--no-verify", "-m", "bypass").returncode == 0  # so CI must re-check
