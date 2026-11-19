import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import secretscan as ss  # noqa: E402


def show(findings):
    for f in findings:
        where = f"{f.path}:{f.line}" if f.line else f.path
        c = f" @{f.commit} '{f.subject}'" if f.commit else ""
        print(f"  [{f.confidence:6}] {f.rule:19} {where:22} {f.preview:24}{c}")
        if f.note:
            print(f"           -> {f.note}")


print("== 1. fake secrets are built at runtime from pieces")
tok_ok, tok_bad = ss.make_fake_token("demo"), ss.make_fake_token("demo", valid=False)
print("valid checksum  ->", [(f.rule, f.confidence) for f in ss.scan_text(f'x = "{tok_ok}"', "a.py")])
print("broken checksum ->", [(f.rule, f.confidence) for f in ss.scan_text(f'x = "{tok_bad}"', "a.py")])
print("placeholder     ->", ss.scan_text('password = "changeme-please"', "a.py"))
print("real-looking pw ->", [(f.rule, f.confidence) for f in ss.scan_text('password = "q8Zr2xLm9vTbN4"', "a.py")])
print("allowlisted     ->", ss.scan_text(f'x = "{tok_ok}"  # {ss.ALLOW_PRAGMA}', "a.py"))
print("entropy of 'aaaaaaaaaaaa' vs random:", round(ss.entropy("aaaaaaaaaaaa"), 2), round(ss.entropy(tok_ok), 2))

if not ss.git_available():
    print("\ngit is not installed: skipping the history demo")
    sys.exit(0)

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
    root, home = Path(d) / "repo", Path(d) / "home"
    root.mkdir()
    home.mkdir()
    ss.build_demo_repo(root, home)

    print("\n== 2. scan only the CURRENT files (what a naive scan does)")
    head = ss.scan_tree(root)
    show(head)
    print("gate (fail on MEDIUM) ->", ss.ci_gate(head))

    print("\n== 3. scan the whole HISTORY on all branches")
    hist = ss.classify_history(ss.scan_history(root, home), head)
    show(hist)
    print("gate (fail on MEDIUM) ->", ss.ci_gate(hist))

    print("\n== 4. CI mode: only the commits of this merge request (HEAD~1..HEAD)")
    mr = ss.scan_history(root, home, "HEAD~1..HEAD")
    show(mr)
    print("gate (fail on MEDIUM) ->", ss.ci_gate(mr), "| gate (fail on LOW) ->", ss.ci_gate(mr, "LOW"))
