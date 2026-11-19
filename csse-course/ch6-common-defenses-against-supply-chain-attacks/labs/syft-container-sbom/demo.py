"""Demo: container SBOM from a Debian-like and an Alpine-like fixture."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import container_sbom as c  # noqa: E402

for label, fs in (("debian-app", c.IMAGE_FS), ("alpine-base", c.ALPINE_FS)):
    r = c.scan_image(fs)
    doc = c.to_cyclonedx(label, r)
    print(f"== {label}: {r['os'].get('ID')} {r['os'].get('VERSION_ID')} -> {len(doc['components'])} components")
    for p in r["packages"]:
        print("  ", p["purl"])
