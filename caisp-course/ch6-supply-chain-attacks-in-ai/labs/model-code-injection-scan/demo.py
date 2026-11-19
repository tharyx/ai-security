"""Demo: inject a harmless payload into a pickled model, scan it, then compare loaders.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-code-injection-scan/demo.py

Everything happens in a temporary directory. The payload only writes a canary file.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_scan as ms  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        canary = tmp_dir / "canary.txt"
        clean = tmp_dir / "clean.pkl"
        trapped = tmp_dir / "trapped.pkl"
        st = tmp_dir / "model.safetensors"
        clean.write_bytes(ms.make_clean_pickle())
        trapped.write_bytes(ms.make_booby_trapped_pickle(str(canary)))
        st.write_bytes(ms.safetensors_dump({"layer1.weight": [0.5, -0.25, 0.125, 1.0]}))

        print("== Static scan (nothing is loaded) ==")
        for p in (clean, trapped):
            r = ms.scan_pickle_bytes(p.read_bytes())
            print(f"{p.name:12} {r.verdict:9} globals={r.globals} calls={r.calls}")
        r = ms.scan_pickle_bytes(ms.NEVER_LOAD_OS_SYSTEM_PICKLE)
        print(f"{'(os.system)':12} {r.verdict:9} globals={r.globals}   <- scanned only, never loaded")
        print("canary exists after scanning:", canary.exists())

        print("\n== Safe loader ==")
        try:
            ms.safe_load_model(str(trapped))
        except ms.RefusedModel as exc:
            print("trapped.pkl refused:", str(exc)[:90])
        print("scanner off, restricted unpickler on:")
        try:
            ms.safe_load_model(str(trapped), scan=False)
        except Exception as exc:
            print("  refused at load time:", type(exc).__name__, str(exc)[:70])
        print("canary exists:", canary.exists())
        print("clean.pkl loads:", ms.safe_load_model(str(clean)) == ms.make_state_dict())

        print("\n== Safetensors ==")
        print("model.safetensors loads:", ms.safe_load_model(str(st)))

        print("\n== The unsafe way (naive pickle.loads) ==")
        ms.naive_load(str(trapped))
        print("canary exists after naive load:", canary.exists(), "->", canary.read_text())
    print("\ntemporary directory removed")


if __name__ == "__main__":
    main()
