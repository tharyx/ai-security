"""Build the sample folder in a temp directory and scan it.

    python caisp-course/ch4-ai-attacks-and-defenses-devops/labs/picklescan/demo.py
"""

from __future__ import annotations

import tempfile

import mini_picklescan as ps
import samples

with tempfile.TemporaryDirectory() as d:
    samples.build(d)
    for r in ps.scan_folder(d):
        name = r.source.replace("\\", "/").split("/")[-1]
        print(f"{r.verdict:<12}{name:<26}{', '.join(r.imports) or '-'}")
print("\nNothing was loaded. The files were only decoded.")
