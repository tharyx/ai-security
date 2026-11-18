"""The way many model-serving apps load weights. DO NOT copy this.

    model = pickle.load(f)              # same risk: torch.load(..., weights_only=False),
                                        # joblib.load(...), numpy.load(..., allow_pickle=True)

VULN 1: the file came from outside (a model hub, a shared bucket, a colleague's laptop).
VULN 2: no format check: a pickle file is a program, not data.
VULN 3: no scan, no allowlist, no integrity check (digest) against a model inventory.
"""

from __future__ import annotations

import pickle
from pathlib import Path


def load_model(path: str | Path) -> object:
    with Path(path).open("rb") as fh:
        return pickle.load(fh)  # VULN: runs any GLOBAL + REDUCE inside the file
