"""Demo: sign, verify, tag-move attack, attestation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import image_signing as s  # noqa: E402

reg = s.Registry()
reg.push("registry.example/shop/api:1.0", b"image-layers-v1")
s.sign(reg, "registry.example/shop/api:1.0", claims={"pipeline": "release"})
print("verify:", s.verify(reg, "registry.example/shop/api:1.0"))
print("verify with wrong key:", s.verify(reg, "registry.example/shop/api:1.0", key=b"other"))
print("required claim ok:", s.verify(reg, "registry.example/shop/api:1.0", required_claims={"pipeline": "release"})[0],
      "| wrong claim:", s.verify(reg, "registry.example/shop/api:1.0", required_claims={"pipeline": "dev"})[0])
reg.push("registry.example/shop/api:1.0", b"image-layers-EVIL")  # attacker repoints the tag
print("after tag repoint:", s.verify(reg, "registry.example/shop/api:1.0"))
reg.push("registry.example/shop/api:1.1", b"image-layers-v2")
s.attest(reg, "registry.example/shop/api:1.1", "https://slsa.dev/provenance/v1", {"builder": "ci.example", "source": "repo.example@abc123"})
print("attestation:", s.verify_attestation(reg, "registry.example/shop/api:1.1", "https://slsa.dev/provenance/v1"))
cert = {"san": "https://ci.example/org/repo/.workflows/release.yml@refs/heads/main", "issuer": "https://oidc.ci.example"}
print("identity pinned:", s.verify_identity(cert, cert["san"], "https://oidc.ci.example"))
