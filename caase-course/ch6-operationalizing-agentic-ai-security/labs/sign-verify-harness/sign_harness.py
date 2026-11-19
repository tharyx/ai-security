"""Sign and verify an agent harness: an HMAC twin of `cosign sign-blob`.

Step 1: build a canonical MANIFEST of the harness directory (path -> SHA-256).
Step 2: sign the manifest. (Here: HMAC-SHA256. Real: `cosign sign-blob`.)
Step 3: before running, verify the signature AND re-hash every file.

Why HMAC is only a twin: HMAC is symmetric. Anyone who can VERIFY can also
FORGE, because they hold the same key. Real signing uses an asymmetric key pair
(or Sigstore keyless identity), so verifiers only need the public part. The
control flow (manifest, sign, verify, reject on any change) is identical.

Hedged real commands (check `cosign --help` and sigstore docs for your version):

    cosign generate-key-pair
    cosign sign-blob --key cosign.key --bundle harness.bundle manifest.json
    cosign verify-blob --key cosign.pub --bundle harness.bundle manifest.json
    # keyless (CI identity) flavour: cosign sign-blob / verify-blob with
    #   --certificate-identity and --certificate-oidc-issuer on verify.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__"}


class VerifyError(Exception):
    pass


def build_manifest(root: Path, builder: str = "ci@example") -> dict:
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            files[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return {"schema": "harness-manifest/1", "builder": builder, "files": files}


def canonical(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def sign(manifest: dict, key: bytes, key_id: str) -> dict:
    sig = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    return {"manifest": manifest, "key_id": key_id, "alg": "HMAC-SHA256", "sig": sig}


def verify(root: Path, signed: dict, trusted_keys: dict[str, bytes]) -> None:
    """Raise VerifyError on ANY problem. Returns None when the harness is exactly what was signed."""
    key = trusted_keys.get(signed.get("key_id", ""))
    if key is None:
        raise VerifyError("signing key not trusted")
    if signed.get("alg") != "HMAC-SHA256":
        raise VerifyError("unexpected algorithm")  # never let the artifact choose a weaker one
    expected = hmac.new(key, canonical(signed["manifest"]), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signed["sig"]):
        raise VerifyError("manifest signature invalid")
    signed_files = signed["manifest"]["files"]
    for rel in signed_files:
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise VerifyError(f"suspicious path in manifest: {rel}")
    actual = build_manifest(root)["files"]
    for rel, h in signed_files.items():
        if rel not in actual:
            raise VerifyError(f"missing file: {rel}")
        if actual[rel] != h:
            raise VerifyError(f"file modified: {rel}")
    extra = sorted(set(actual) - set(signed_files))
    if extra:
        raise VerifyError(f"unsigned extra file(s): {extra}")


def cosign_commands(manifest_path: str = "manifest.json") -> list[str]:
    """The real commands this lab is a twin of (printed for the learner; not executed)."""
    return [
        "cosign generate-key-pair",
        f"cosign sign-blob --key cosign.key --bundle harness.bundle {manifest_path}",
        f"cosign verify-blob --key cosign.pub --bundle harness.bundle {manifest_path}",
    ]
