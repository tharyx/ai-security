import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import regattack as ra

cases = [("open registry, no credentials", "open", None),
         ("auth but NO RBAC, a read-only dev's token", "auth-no-rbac", "tok-bob"),
         ("RBAC + immutable tags, same dev token", "rbac", "tok-bob"),
         ("RBAC + immutable tags, CI token", "rbac", "tok-alice")]
for title, mode, tok in cases:
    reg = ra.seed(ra.Registry(mode))
    print(f"== {title} ==")
    for step, res in ra.attack(reg, tok).items():
        print(f"  {step:<24} {res}")
    print()
