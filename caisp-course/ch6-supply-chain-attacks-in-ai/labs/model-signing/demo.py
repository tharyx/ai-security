"""Demo: sign a fake model directory, verify it, then tamper with it.

    python caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/demo.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import model_sign as ms  # noqa: E402

KEY = b"lab-only-secret-key"


def show(title: str, res) -> None:
    print(f"{title:42} ok={res.ok}  {res.problems}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        model = Path(tmp) / "model"
        model.mkdir()
        (model / "model.safetensors").write_bytes(b"\x00weights" * 100)
        (model / "config.json").write_text('{"layers": 2}', encoding="utf-8")

        bundle = ms.sign_manifest(ms.build_manifest(model, "tiny", "1.0", "ci@release.example"), KEY)
        print("signed manifest (first lines):")
        for name, digest in bundle["manifest"]["files"].items():
            print(f"   {name:20} sha256:{digest[:16]}...")
        print("   signature:", bundle["signature"][:24] + "...\n")

        show("1. untouched model", ms.verify_model(model, bundle, KEY, "ci@release.example"))

        w = model / "model.safetensors"
        data = bytearray(w.read_bytes())
        data[3] ^= 1
        w.write_bytes(bytes(data))
        show("2. one bit flipped in the weights", ms.verify_model(model, bundle, KEY))

        (model / "evil_loader.py").write_text("# pretend this is malicious", encoding="utf-8")
        show("3. plus an extra file", ms.verify_model(model, bundle, KEY))

        bundle["manifest"]["files"]["model.safetensors"] = ms.sha256_file(w)
        show("4. attacker also rewrites the manifest hash", ms.verify_model(model, bundle, KEY))
        show("5. verify with the wrong key", ms.verify_model(model, bundle, b"wrong"))


if __name__ == "__main__":
    main()
