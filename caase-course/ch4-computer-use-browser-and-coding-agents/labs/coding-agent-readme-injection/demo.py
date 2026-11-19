"""Demo: README + commit-message injection against a mock coding agent (all simulated)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent as a  # noqa: E402

CASES = [
    ("no defence", a.Defenses()),
    ("sanitize repo text", a.Defenses(sanitize=True)),
    ("command allowlist", a.Defenses(allowlist=a.DEFAULT_ALLOWED)),
    ("path policy only", a.Defenses(deny_sensitive_paths=True)),
    ("taint rule + human says no", a.Defenses(taint_needs_approval=True, approve=lambda x: False)),
    ("all layers", a.Defenses(sanitize=True, allowlist=a.DEFAULT_ALLOWED, deny_sensitive_paths=True,
                              taint_needs_approval=True, approve=lambda x: False)),
]
for label, d in CASES:
    w = a.World()
    a.run_agent(w, d)
    print(f"{label:28} simulated curl|sh: {str(w.remote_exec):5}  canary read: {str(bool(w.leaked)):5}  shell log: {w.shell_log}")
    w.close()
