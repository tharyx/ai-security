"""Demo: vet packages, then replay a dependency confusion attack against three resolvers.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import depconfusion as dc  # noqa: E402
import vetting as v  # noqa: E402


def main() -> None:
    fx = v.load_fixture()
    print("== 1. Vetting scores (higher = riskier) ==")
    for verdict in v.vet_requested([p["name"] for p in fx["registry"]] + ["totally-made-up-ai-pkg"], fx):
        print(f"{verdict.decision.upper():7} {verdict.score:3}  {verdict.name}")
        for reason in verdict.reasons[:3]:
            print(f"                 - {reason}")

    print("\n== 2. Dependency confusion ==")
    private, public = dc.sample_indexes()
    reqs = "acme-ml-utils\nnumpy\n"
    print("Private index: acme-ml-utils 1.2.0.  Public index: attacker's acme-ml-utils 99.0.0.\n")
    for mode, kw in (("naive", {}), ("scoped", {"internal_scopes": {"acme-*": "private"}})):
        print(f"[{mode}]")
        for r in dc.install(reqs, [private, public], mode, **kw):
            print(f"   {r.name:14} -> {r.version} from {r.index}  ({r.note})")

    lock = dc.lock_line("acme-ml-utils", "1.2.0", private.artifact("acme-ml-utils", "1.2.0"))
    print("\n[locked] requirements line:", lock[:60] + "...")
    for r in dc.install(lock + "\n", [private, public], "locked"):
        print(f"   {r.name:14} -> {r.version} from {r.index}  ({r.note})")
    private.packages["acme-ml-utils"]["1.2.0"] = b"swapped by an attacker"
    print("[locked] after the private artifact is swapped:")
    for r in dc.install(lock + "\n", [private, public], "locked"):
        print(f"   {r.name:14} -> ok={r.ok}  ({r.note})")


if __name__ == "__main__":
    main()
