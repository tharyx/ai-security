"""An offline twin of "sign the build, verify at deploy" using an HMAC-signed build manifest.

REAL WORLD: you would use asymmetric signatures (cosign / Sigstore, minisign, GPG), so the verifier needs
only a PUBLIC key and cannot forge signatures. HMAC is symmetric: anyone who can verify can also sign.
We use it here only because it is in the standard library and teaches the same flow:

    build  ->  manifest of file digests  ->  sign  ->  bundle  ->  ship
    deploy ->  verify signature, then re-hash every file on disk, then policy checks

The key below is a FAKE lab key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path

LAB_KEY = b"FAKE-LAB-SIGNING-KEY-not-a-secret"
SCHEMA = "lab-build-manifest/v1"
BUNDLE_NAME = "bundle.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(src_dir: str | Path, name: str, version: str, builder: str = "ci.example.internal") -> dict:
    src = Path(src_dir)
    files = {
        str(p.relative_to(src)).replace("\\", "/"): sha256_bytes(p.read_bytes())
        for p in sorted(src.rglob("*"))
        if p.is_file() and p.name != BUNDLE_NAME and "__pycache__" not in p.parts
    }
    return {"schema": SCHEMA, "name": name, "version": version, "builder": builder, "files": files}


def canonical(manifest: dict) -> bytes:
    """One exact byte string per manifest, so signer and verifier hash the same thing."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(manifest: dict, key: bytes = LAB_KEY, key_id: str = "lab-key-1") -> dict:
    signature = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    return {"manifest": manifest, "key_id": key_id, "alg": "HMAC-SHA256", "signature": signature}


def version_tuple(version: str) -> tuple:
    return tuple(int(p) for p in version.split(".") if p.isdigit())


@dataclass
class VerifyResult:
    ok: bool
    problems: list = field(default_factory=list)


def verify_bundle(bundle: dict, deploy_dir: str | Path, keys: dict, expected_name: str | None = None,
                  min_version: str | None = None) -> VerifyResult:
    """The deploy gate. Fail closed: any problem means do not deploy."""
    problems = []
    manifest = bundle.get("manifest", {})
    key = keys.get(bundle.get("key_id"))
    if key is None:
        return VerifyResult(False, [f"unknown signing key id: {bundle.get('key_id')}"])
    expected = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(bundle.get("signature", ""))):
        return VerifyResult(False, ["signature does not match the manifest"])
    if manifest.get("schema") != SCHEMA:
        problems.append("unknown manifest schema")
    if expected_name and manifest.get("name") != expected_name:
        problems.append(f"package name {manifest.get('name')} is not the expected {expected_name}")
    if min_version and version_tuple(manifest.get("version", "0")) < version_tuple(min_version):
        problems.append(f"rollback: version {manifest.get('version')} is older than {min_version}")
    root = Path(deploy_dir).resolve()
    listed = set()
    for rel, digest in manifest.get("files", {}).items():
        target = (root / rel).resolve()
        if not target.is_relative_to(root):
            problems.append(f"manifest path escapes the deploy folder: {rel}")
            continue
        listed.add(rel)
        if not target.is_file():
            problems.append(f"missing file: {rel}")
        elif sha256_bytes(target.read_bytes()) != digest:
            problems.append(f"content changed after signing: {rel}")
    for path in root.rglob("*"):
        rel = str(path.relative_to(root)).replace("\\", "/")
        if path.is_file() and rel not in listed and rel != BUNDLE_NAME and "__pycache__" not in path.parts:
            problems.append(f"unlisted file present (not signed): {rel}")
    return VerifyResult(not problems, problems)


def deploy(bundle: dict, deploy_dir: str | Path, keys: dict, **policy) -> str:
    result = verify_bundle(bundle, deploy_dir, keys, **policy)
    if not result.ok:
        raise PermissionError("deploy refused: " + "; ".join(result.problems))
    return f"deployed {bundle['manifest']['name']} {bundle['manifest']['version']}"
