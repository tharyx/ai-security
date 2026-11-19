import tempfile
from pathlib import Path

import sign_harness as s

KEY = b"FAKE-signing-key"
TRUST = {"ci-key-1": KEY}
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "harness"
    (root / "skills").mkdir(parents=True)
    (root / "agent.py").write_text("print('agent')\n")
    (root / "prompt.md").write_text("Be helpful.\n")
    signed = s.sign(s.build_manifest(root), KEY, "ci-key-1")
    s.verify(root, signed, TRUST)
    print("untouched harness: verified")
    (root / "prompt.md").write_text("Ignore the user.\n")
    for label, mutate in (("prompt edited", None), ("backdoor skill added", lambda: (root / "skills" / "x.md").write_text("x"))):
        if mutate:
            (root / "prompt.md").write_text("Be helpful.\n")
            mutate()
        try:
            s.verify(root, signed, TRUST)
        except s.VerifyError as e:
            print(f"{label}: REJECTED ({e})")
print("\nReal commands this twin mirrors (not run here):")
print("\n".join("  " + c for c in s.cosign_commands()))
