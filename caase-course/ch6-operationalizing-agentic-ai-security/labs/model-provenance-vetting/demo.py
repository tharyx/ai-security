import copy
import tempfile
from pathlib import Path

import model_vetting as v

with tempfile.TemporaryDirectory() as tmp:
    weights = Path(tmp) / "model.safetensors"
    weights.write_bytes(b"FAKE-WEIGHTS" * 100)
    good_hash = v.sha256_file(weights)  # what YOU computed from the download
    card = {
        "name": "tiny-instruct-4b", "source_org": "example-lab", "license": "apache-2.0",
        "files": {"model.safetensors": good_hash}, "model_card_present": True, "training_data_disclosed": True,
        "evals": {"injection_resistance": 0.81, "harmful_refusal": 0.92},
    }
    observed = {"model.safetensors": good_hash}
    cases = {
        "good": (card, observed),
        "tampered weights": (card, {"model.safetensors": "0" * 64}),
        "unknown uploader": ({**copy.deepcopy(card), "source_org": "random-uploader"}, observed),
        "typosquat org": ({**copy.deepcopy(card), "source_org": "examp1e-lab"}, observed),
        "non-commercial licence": ({**copy.deepcopy(card), "license": "cc-by-nc-4.0"}, observed),
        "weak injection eval": ({**copy.deepcopy(card), "evals": {"injection_resistance": 0.3, "harmful_refusal": 0.9}}, observed),
    }
    for name, (c, o) in cases.items():
        d = v.vet(c, o)
        print(f"{name:<24} -> {d.route:<10} {d.reasons[0]}")
