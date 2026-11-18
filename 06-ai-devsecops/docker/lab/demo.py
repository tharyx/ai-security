"""Scorecard for the Docker lab: Dockerfile rules, then model files.

From the repository root:
    python 06-ai-devsecops/docker/lab/demo.py

Model-file part: the vulnerable loader is only ever run on the booby-trapped pickle built
from harmless_payload.py (it writes a canary file). The os.system-style samples from
attacks.py are only scanned, never loaded.
"""

from __future__ import annotations

import collections
import io
import pickle
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

import attacks
import dockerfile_lint as dl
import harmless_payload
import pickle_scan as ps
import vulnerable_loader

LAB = Path(__file__).parent


def dockerfile_scorecard() -> None:
    vuln = Counter(f.rule_id for f in dl.lint_file(LAB / "vulnerable" / "Dockerfile"))
    sec = Counter(f.rule_id for f in dl.lint_file(LAB / "secure" / "Dockerfile"))
    print(f"{'rule':7} {'sev':8} {'title':50} {'vulnerable':11} secure")
    print("-" * 85)
    for rule_id, (severity, title, _) in sorted(dl.RULES.items()):
        v = f"FAIL x{vuln[rule_id]}" if vuln[rule_id] else "ok"
        s = f"FAIL x{sec[rule_id]}" if sec[rule_id] else "ok"
        print(f"{rule_id:7} {severity:8} {title[:50]:50} {v:11} {s}")


def model_files_scorecard(work: Path) -> None:
    canary = work / "payload-ran.txt"
    trap = work / "booby_trapped.pkl"
    trap.write_bytes(pickle.dumps(harmless_payload.BoobyTrappedModel(str(canary))))
    benign = work / "state_dict.pkl"
    benign.write_bytes(pickle.dumps(collections.OrderedDict(w=[0.1, 0.2])))
    tensors = work / "support-llm-v3.safetensors"
    ps.write_safetensors(tensors, {"layer0.weight": [0.5, -1.0, 2.0]}, metadata={"format": "pt"})
    zipped = work / "torch_style.pt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", attacks.MALICIOUS_STYLE["stack_global_os_system"])
    zipped.write_bytes(buf.getvalue())
    samples = []
    for name, data in attacks.MALICIOUS_STYLE.items():
        path = work / f"{name}.pkl"
        path.write_bytes(data)
        samples.append(path)

    print(f"\n{'model file':34} {'scanner':10} {'vulnerable loader':20} secure loader")
    print("-" * 85)
    for path in [trap, *samples, zipped, benign, tensors]:
        verdict = ps.scan_file(path).verdict
        if path == trap:
            vulnerable_loader.load_model(path)
            vuln = "CODE RAN" if canary.exists() else "ok"
            canary.unlink(missing_ok=True)
        elif path == benign:
            vuln = "loads"
        elif path == tensors:
            vuln = "n/a (not pickle)"
        else:
            vuln = "(never loaded)"
        try:
            ps.safe_load_model(path, prefer_safetensors=False)
            secure = "loads"
        except (ps.UnsafeModelError, pickle.UnpicklingError, ValueError):
            secure = "REFUSED"
        print(f"{path.name[:34]:34} {verdict:10} {vuln:20} {secure}")
        assert not canary.exists(), "the secure path must never run the payload"


def main() -> None:
    dockerfile_scorecard()
    with tempfile.TemporaryDirectory() as d:
        model_files_scorecard(Path(d))
    print("\nThe secure loader was run with prefer_safetensors=False so you can see the scan layer work.")
    print("With the default (True) it refuses every pickle-based file before even scanning it.")


if __name__ == "__main__":
    main()
