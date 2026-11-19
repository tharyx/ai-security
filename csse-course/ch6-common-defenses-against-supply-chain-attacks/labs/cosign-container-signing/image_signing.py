"""Container image signing twin (HMAC with a FAKE shared key; real cosign/Notation use asymmetric keys or keyless certs).

What the lab teaches: sign the DIGEST not the tag, verify what the tag points to NOW, bind identity, sign attestations.
"""

from __future__ import annotations

import hashlib
import hmac
import json

FAKE_KEY = b"FAKE-demo-signing-key-not-a-secret"


def digest_of(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class Registry:
    """Tags are mutable pointers to digests; signatures are stored next to the digest (like cosign's .sig tag)."""

    def __init__(self):
        self.tags: dict[str, str] = {}
        self.blobs: dict[str, bytes] = {}
        self.signatures: dict[str, list] = {}

    def push(self, ref: str, content: bytes) -> str:
        d = digest_of(content)
        self.blobs[d] = content
        self.tags[ref] = d
        return d

    def resolve(self, ref: str) -> str:
        return self.tags[ref]


def _payload(image_ref: str, digest: str, claims: dict | None = None) -> bytes:
    body = {"critical": {"identity": {"docker-reference": image_ref}, "image": {"docker-manifest-digest": digest},
                         "type": "cosign container image signature"}, "optional": claims or {}}
    return json.dumps(body, sort_keys=True).encode()


def sign(reg: Registry, ref: str, key: bytes = FAKE_KEY, claims: dict | None = None) -> dict:
    """Resolve the tag ONCE and sign that digest."""
    d = reg.resolve(ref)
    repo = ref.rsplit(":", 1)[0]
    p = _payload(repo, d, claims)
    sig = {"payload": p.decode(), "signature": hmac.new(key, p, hashlib.sha256).hexdigest()}
    reg.signatures.setdefault(d, []).append(sig)
    return sig


def verify(reg: Registry, ref: str, key: bytes = FAKE_KEY, required_claims: dict | None = None) -> tuple[bool, str]:
    d = reg.resolve(ref)  # what the tag points to at verification time
    repo = ref.rsplit(":", 1)[0]
    for sig in reg.signatures.get(d, []):
        expected = hmac.new(key, sig["payload"].encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig["signature"]):
            continue
        body = json.loads(sig["payload"])
        if body["critical"]["image"]["docker-manifest-digest"] != d or body["critical"]["identity"]["docker-reference"] != repo:
            continue
        if required_claims and any(body["optional"].get(k) != v for k, v in required_claims.items()):
            continue
        return True, f"verified {d[:19]}..."
    return False, f"no valid signature for {d[:19]}..."


def attest(reg: Registry, ref: str, predicate_type: str, predicate: dict, key: bytes = FAKE_KEY) -> dict:
    d = reg.resolve(ref)
    stmt = json.dumps({"_type": "https://in-toto.io/Statement/v1", "subject": [{"digest": {"sha256": d.split(':')[1]}}],
                       "predicateType": predicate_type, "predicate": predicate}, sort_keys=True)
    att = {"statement": stmt, "signature": hmac.new(key, stmt.encode(), hashlib.sha256).hexdigest()}
    reg.signatures.setdefault(d + "#att", []).append(att)
    return att


def verify_attestation(reg: Registry, ref: str, predicate_type: str, key: bytes = FAKE_KEY):
    d = reg.resolve(ref)
    for att in reg.signatures.get(d + "#att", []):
        if hmac.compare_digest(hmac.new(key, att["statement"].encode(), hashlib.sha256).hexdigest(), att["signature"]):
            s = json.loads(att["statement"])
            if s["predicateType"] == predicate_type and s["subject"][0]["digest"]["sha256"] == d.split(":")[1]:
                return s["predicate"]
    return None


# Keyless identity check (concept): a short-lived certificate names WHO signed; you pin identity + issuer.
def verify_identity(cert: dict, expected_identity: str, expected_issuer: str) -> bool:
    return cert.get("san") == expected_identity and cert.get("issuer") == expected_issuer
