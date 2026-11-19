import pickle
import pickletools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deser as d  # noqa: E402
import base64  # noqa: E402

evil = d.make_malicious_cookie()
print("== What is inside the malicious cookie (pickletools, GLOBAL/REDUCE opcodes) ==")
ops = [op.name for op, _, _ in pickletools.genops(base64.b64decode(evil))]
print("opcodes include STACK_GLOBAL:", "STACK_GLOBAL" in ops, " REDUCE:", "REDUCE" in ops)

print("\n== Vulnerable: pickle.loads(cookie) ==")
session = d.load_session_vuln(evil)
print("session['prefs'] =", session["prefs"])
print("canary list     =", d.CANARY)

print("\n== Secure 1: JSON + schema ==")
print("normal JSON session ->", d.load_session_json(d.dump_session_json({"user": "alice", "prefs": {"theme": "dark"}})))
try:
    d.load_session_json(evil)
except Exception as e:
    print("pickle blob as JSON ->", type(e).__name__)

print("\n== Secure 2: restricted Unpickler (find_class allowlist) ==")
print("normal pickle session ->", d.load_session_restricted(d.make_normal_cookie()))
d.CANARY.clear()
try:
    d.load_session_restricted(evil)
except pickle.UnpicklingError as e:
    print("malicious ->", e)
print("canary list =", d.CANARY)
