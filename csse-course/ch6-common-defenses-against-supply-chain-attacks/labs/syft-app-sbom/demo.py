"""Demo: build a CycloneDX SBOM from a requirements file and an npm lockfile fixture."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app_sbom as s  # noqa: E402

comps, unpinned = s.parse_requirements(s.SAMPLE_REQUIREMENTS)
print("pinned:", [f"{c['name']}=={c['version']}" for c in comps])
print("unpinned (not in SBOM, fix these):", unpinned)
doc = s.build("demo-app", s.SAMPLE_REQUIREMENTS, s.SAMPLE_NPM_LOCK)
print("specVersion:", doc["specVersion"], "| components:", len(doc["components"]), "| validation errors:", s.validate(doc))
for c in doc["components"]:
    print(" ", c["purl"], "|", c["scope"], "|", "hash" if c.get("hashes") else "no-hash")
