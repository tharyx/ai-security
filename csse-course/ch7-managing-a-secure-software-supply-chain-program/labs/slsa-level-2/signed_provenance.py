"""Simulated SLSA Build L2: signed provenance from a hosted builder, and a verifier.

HMAC twin. In real life the builder signs with Sigstore (a short-lived certificate tied
to an OIDC identity, recorded in a transparency log) or with an asymmetric key that
only the hosted platform can use. HMAC is symmetric, so here the verifier holds the
same secret as the builder: that is a teaching shortcut, not a design to copy.
Hedge: check the SLSA v1.0 spec and Sigstore docs for exact formats.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_statement(*, repo_uri, ref, commit, artifact_name, artifact_bytes, builder_id) -> dict:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": artifact_name, "digest": {"sha256": sha256_hex(artifact_bytes)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.invalid/simulated-build/v1",
                "externalParameters": {
                    "source": {"uri": f"git+{repo_uri}@{ref}", "digest": {"gitCommit": commit}}},
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {"builder": {"id": builder_id},
                           "metadata": {"invocationId": "run-1"}},
        },
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding: what is actually signed (hedge: check the DSSE spec)."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _sig(key: bytes, payload_type: str, payload: bytes) -> str:
    return base64.b64encode(hmac.new(key, pae(payload_type, payload), hashlib.sha256).digest()).decode()


class HostedBuilder:
    """The build platform. Users run builds on it but never see the signing key."""

    def __init__(self, builder_id: str, key: bytes):
        self.builder_id = builder_id
        self._key = key
        self.keyid = "key-" + sha256_hex(builder_id.encode())[:8]

    def build_and_sign(self, *, repo_uri, ref, commit, artifact_name, artifact_bytes) -> dict:
        stmt = make_statement(repo_uri=repo_uri, ref=ref, commit=commit,
                              artifact_name=artifact_name, artifact_bytes=artifact_bytes,
                              builder_id=self.builder_id)
        payload = json.dumps(stmt, sort_keys=True).encode()
        return {"payloadType": PAYLOAD_TYPE,
                "payload": base64.b64encode(payload).decode(),
                "signatures": [{"keyid": self.keyid, "sig": _sig(self._key, PAYLOAD_TYPE, payload)}]}


def self_attested(stmt: dict) -> dict:
    """What an L1-only pipeline gives you: a statement with no signature at all."""
    return {"payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(json.dumps(stmt, sort_keys=True).encode()).decode(),
            "signatures": []}


@dataclass
class TrustedBuilder:
    builder_id: str
    key: bytes


@dataclass
class Policy:
    trusted_builders: list[TrustedBuilder]
    expected_repo: str          # for example https://github.com/example/app
    allowed_refs_prefix: str = "refs/tags/"


@dataclass
class Verdict:
    ok: bool
    level: int
    reasons: list[str] = field(default_factory=list)


def verify(envelope: dict, artifact_bytes: bytes, policy: Policy) -> Verdict:
    """Return level 2 only if every check passes; otherwise explain what failed."""
    reasons: list[str] = []
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        stmt = json.loads(payload)
    except Exception:
        return Verdict(False, 0, ["payload is not valid base64 JSON"])

    if envelope.get("payloadType") != PAYLOAD_TYPE:
        reasons.append("unexpected payloadType")
    if stmt.get("_type") != STATEMENT_TYPE or stmt.get("predicateType") != PREDICATE_TYPE:
        reasons.append("not an in-toto v1 statement with a SLSA provenance v1 predicate")

    # Digest match: provenance must be about THIS artifact.
    digest_ok = any((s.get("digest") or {}).get("sha256") == sha256_hex(artifact_bytes)
                    for s in stmt.get("subject", []))
    if not digest_ok:
        reasons.append("subject digest does not match the artifact")

    pred = stmt.get("predicate") or {}
    builder_id = ((pred.get("runDetails") or {}).get("builder") or {}).get("id")
    src = ((pred.get("buildDefinition") or {}).get("externalParameters") or {}).get("source") or {}

    # Level 1 completeness (the same facts, minimal): needed to say "at least L1".
    complete = bool(builder_id and src.get("uri") and (src.get("digest") or {}).get("gitCommit"))
    if not complete:
        reasons.append("provenance is incomplete (builder or source missing)")

    # Signature and builder identity allowlist.
    sigs = envelope.get("signatures") or []
    trusted = {tb.builder_id: tb for tb in policy.trusted_builders}
    if not sigs:
        reasons.append("no signature: self-attested provenance is L1 at best")
    elif builder_id not in trusted:
        reasons.append(f"builder {builder_id!r} is not on the allowlist")
    else:
        tb = trusted[builder_id]
        good = any(hmac.compare_digest(s.get("sig", ""), _sig(tb.key, PAYLOAD_TYPE, payload))
                   for s in sigs)
        if not good:
            reasons.append("signature does not verify for the claimed builder")

    # Source repo: exact match on the repo, not a prefix (app-evil must not match app).
    uri = src.get("uri", "")
    repo_part, _, ref = uri.removeprefix("git+").partition("@")
    if repo_part != policy.expected_repo:
        reasons.append(f"source repo {repo_part!r} is not the expected repo")
    if not ref.startswith(policy.allowed_refs_prefix):
        reasons.append(f"ref {ref!r} is not a release ref")

    if not reasons:
        return Verdict(True, 2, [])
    level = 1 if complete and digest_ok and not any(
        r.startswith(("unexpected", "not an in-toto", "payload")) for r in reasons) else 0
    return Verdict(False, level, reasons)
