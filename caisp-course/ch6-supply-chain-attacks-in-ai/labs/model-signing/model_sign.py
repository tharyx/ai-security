"""An offline twin of model signing: hash every file, sign the manifest, verify, detect tampering.

Real tools (Cosign, the OpenSSF model-signing project) do the same three things:

    1. hash every file of the model directory            -> a manifest
    2. sign the manifest                                  -> a signature (bundle)
    3. on download: re-hash the files and verify the signature and the signer identity

The big difference: real signing is ASYMMETRIC (private key signs, public key verifies; or
keyless signing with short-lived certificates tied to an identity like a CI workflow).
This twin uses HMAC-SHA256 from the standard library, which is SYMMETRIC: anyone who can verify
can also forge. Use it to learn the logic, never as a real signature scheme.

Manifest design (so the checks below are possible):
    - the manifest lists EVERY file with its SHA-256 (so added and removed files are noticed)
    - it records the signer identity and the model name/version inside the signed payload
    - the JSON is canonical (sorted keys, no spaces), so the same content always gives the same bytes
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path

CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(model_dir: str | Path, name: str, version: str, signer: str) -> dict:
    root = Path(model_dir)
    files = {
        p.relative_to(root).as_posix(): sha256_file(p)
        for p in sorted(root.rglob("*")) if p.is_file()
    }
    return {"schema": "toy-model-manifest/1", "model": name, "version": version,
            "signer": signer, "files": files}


def canonical(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def sign_manifest(manifest: dict, key: bytes) -> dict:
    """Return a 'bundle': the manifest plus its HMAC tag."""
    tag = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    return {"manifest": manifest, "alg": "HMAC-SHA256 (toy)", "signature": tag}


@dataclass
class VerifyResult:
    ok: bool
    problems: list[str] = field(default_factory=list)


def verify_model(model_dir: str | Path, bundle: dict, key: bytes,
                 expected_signer: str | None = None) -> VerifyResult:
    """Verify the signature first, then every file. Never trust files whose manifest failed."""
    problems: list[str] = []
    manifest = bundle.get("manifest", {})
    expected_tag = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_tag, str(bundle.get("signature", ""))):
        return VerifyResult(False, ["signature invalid (wrong key, or the manifest was edited)"])
    if expected_signer is not None and manifest.get("signer") != expected_signer:
        problems.append(f"unexpected signer: {manifest.get('signer')!r} (wanted {expected_signer!r})")

    root = Path(model_dir)
    on_disk = {p.relative_to(root).as_posix(): p for p in root.rglob("*") if p.is_file()}
    listed = manifest.get("files", {})
    for rel, digest in listed.items():
        if rel not in on_disk:
            problems.append(f"missing file: {rel}")
        elif sha256_file(on_disk[rel]) != digest:
            problems.append(f"modified file: {rel}")
    for rel in sorted(set(on_disk) - set(listed)):
        problems.append(f"unexpected extra file: {rel}")
    return VerifyResult(not problems, problems)


def save_bundle(bundle: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def load_bundle(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
