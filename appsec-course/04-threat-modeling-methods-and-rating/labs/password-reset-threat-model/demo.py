"""Threat model -> requirements -> tests for a password reset workflow (offline, fictional)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from aisec_lab import load_lab_module  # noqa: E402

R = load_lab_module(str(HERE / "demo.py"), "requirements")
V = load_lab_module(str(HERE / "demo.py"), "reset_vulnerable").ResetService
S = load_lab_module(str(HERE / "demo.py"), "reset_secure").ResetService

vuln, sec = R.verify(V), R.verify(S)
print(f"{'Req':6} {'STRIDE':6} {'vulnerable':11} {'secure':7} Requirement")
for req in R.REQUIREMENTS:
    mark = lambda ok: "met" if ok else "VIOLATED"  # noqa: E731
    print(f"{req.id:6} {req.stride:6} {mark(vuln[req.id]):11} {mark(sec[req.id]):7} {req.text}")
print()
print(f"vulnerable: {sum(vuln.values())}/{len(vuln)} requirements met")
print(f"secure:     {sum(sec.values())}/{len(sec)} requirements met")
