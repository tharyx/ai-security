"""Demo: a rank-one edit changes one fact; regression tests miss it; the hash catches it.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/rome-model-editing/demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kv_memory as kv  # noqa: E402


def main() -> None:
    m = kv.ToyModel()
    before = [row[:] for row in m.W]
    h0 = m.weights_sha256()
    print("Before the edit:")
    for s, o in m.knowledge().items():
        print(f"   {s:20} -> {o}")

    delta = kv.rome_edit(m, "eiffel tower", "rome")
    print("\nAfter ROME-style edit: eiffel tower -> rome")
    for s, o in m.knowledge().items():
        flag = "  <-- edited" if kv.FACTS[s] != o else ""
        print(f"   {s:20} -> {o}{flag}")

    print("\nHow big and how simple is the change?")
    print("   rank of weight change:", kv.matrix_rank(kv.weight_diff(before, m.W)))
    size = sum(x * x for row in delta for x in row) ** 0.5
    print(f"   size (Frobenius norm) of the change: {size:.3f}")

    golden = {s: o for s, o in kv.FACTS.items() if s != "eiffel tower"}
    print("\nDetection 1: regression suite that does not cover the edited fact")
    print("   accuracy:", kv.regression_suite(m, golden)["accuracy"], " (edit is invisible)")
    print("Detection 2: regression suite that covers it")
    print("  ", kv.regression_suite(m, kv.FACTS))
    print("Detection 3: weight hash against the signed reference")
    print("   before:", h0[:16], "...")
    print("   after: ", m.weights_sha256()[:16], "...  -> MISMATCH")
    print("Detection 4: diff against a trusted copy is rank one (a ROME-style fingerprint, see above)")


if __name__ == "__main__":
    main()
