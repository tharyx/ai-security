import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import minipc  # noqa: E402

if shutil.which("git") is None:
    sys.exit("git not found")


def git(repo, *a):
    p = subprocess.run(["git", *a], cwd=repo, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


with tempfile.TemporaryDirectory(prefix="csse2-pc-") as t:
    repo = Path(t) / "r"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for k, v in (("user.name", "T"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
        git(repo, "config", k, v)
    (repo / ".pre-commit-config.yaml").write_text((HERE / "pre-commit-config.example.yaml").read_text())
    minipc.install_git_hook(repo)
    (repo / "a.py").write_text("x = 1 \n")
    git(repo, "add", "a.py")
    rc, out = git(repo, "commit", "-q", "-m", "bad")
    print("commit with trailing space -> exit", rc)
    print(out)
    (repo / "a.py").write_text("x = 1\n")
    git(repo, "add", "a.py")
    rc, out = git(repo, "commit", "-q", "-m", "good")
    print("after fixing -> exit", rc)
