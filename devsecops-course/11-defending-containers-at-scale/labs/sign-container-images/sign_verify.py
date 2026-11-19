"""Simulated image signing and verification (stdlib HMAC; NOT real cosign/Notation).

Models the workflow: sign the image DIGEST (not the tag), store the signature next to the
image, verify identity + digest before deploy, and detect tag re-pointing. Real keyless
cosign uses short-lived certificates from an identity provider and a transparency log; real
Notation uses X.509 certificates and trust policies. See real-tools in csse-course ch3.
Docker Content Trust (Notary v1) is RETIRED: do not build new workflows on it.
"""
from __future__ import annotations

import hashlib
import hmac
import json


def digest_of(manifest: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def sign(digest: str, signer: str, key: bytes) -> dict:
    mac = hmac.new(key, f"{signer}|{digest}".encode(), hashlib.sha256).hexdigest()
    return {"digest": digest, "signer": signer, "sig": mac}


def verify(registry: dict, ref: str, trusted: dict[str, bytes], allowed_signers: set[str]) -> tuple[bool, str]:
    """registry = {'tags': {ref: digest}, 'manifests': {digest: manifest}, 'sigs': {digest: [sig]}}.
    Verification resolves the tag to a digest, recomputes the digest from the manifest, and
    needs one valid signature from an allowed signer."""
    digest = registry["tags"].get(ref)
    if digest is None:
        return False, "unknown reference"
    if digest_of(registry["manifests"][digest]) != digest:
        return False, "manifest does not match its digest (tampered content)"
    for s in registry["sigs"].get(digest, []):
        if s["signer"] not in allowed_signers or s["signer"] not in trusted:
            continue
        expect = hmac.new(trusted[s["signer"]], f"{s['signer']}|{digest}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expect, s["sig"]) and s["digest"] == digest:
            return True, f"verified {digest[:19]}... signed by {s['signer']}"
    return False, "no valid signature from an allowed signer"
