"""Provenance attestations for an MCP server build: an in-toto Statement with a SLSA provenance predicate,
wrapped in a DSSE envelope, signed with an HMAC twin, and checked by a deploy gate.

Shapes follow in-toto Statement v1 and SLSA provenance v1 as published at slsa.dev and in-toto.io.
Field names can change between versions (verify at the source). The signing here is the offline twin:
real pipelines sign with Sigstore/cosign or a KMS key (see the lab README for hedged commands).
The key and builder identity are FAKE.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
LAB_KEY = b"FAKE-LAB-ATTESTATION-KEY"
BUILD_TYPE = "https://ci.example.internal/mcp-build/v1"


class ProvenanceError(Exception):
    pass


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def make_statement(artifacts: dict, builder_id: str, repository: str, ref: str, commit: str,
                   workflow: str, materials: list, invocation_id: str) -> dict:
    """artifacts: {name: path}. materials: [{"uri":..., "digest": {"sha256"|"gitCommit": ...}}]."""
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha256_file(path)}} for name, path in sorted(artifacts.items())],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {"repository": repository, "ref": ref, "workflow": workflow},
                "resolvedDependencies": [{"uri": f"git+{repository}@{ref}", "digest": {"gitCommit": commit}}] + materials,
            },
            "runDetails": {"builder": {"id": builder_id}, "metadata": {"invocationId": invocation_id}},
        },
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: what is actually signed. It binds the payload TYPE to the bytes."""
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)


def sign_statement(statement: dict, key: bytes = LAB_KEY, keyid: str = "lab-attest-1") -> dict:
    payload = json.dumps(statement, sort_keys=True).encode()
    sig = hmac.new(key, pae(PAYLOAD_TYPE, payload), hashlib.sha256).digest()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}],
    }


def verify_envelope(envelope: dict, keys: dict) -> dict:
    """Return the statement if one signature is valid for a known key. Otherwise raise."""
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        payload_type = envelope["payloadType"]
        signatures = envelope["signatures"]
    except (KeyError, ValueError) as exc:
        raise ProvenanceError("malformed envelope") from exc
    for entry in signatures:
        key = keys.get(entry.get("keyid"))
        if key is None:
            continue
        expected = hmac.new(key, pae(payload_type, payload), hashlib.sha256).digest()
        try:
            given = base64.b64decode(entry["sig"], validate=True)
        except ValueError:
            continue
        if hmac.compare_digest(expected, given):
            if payload_type != PAYLOAD_TYPE:
                raise ProvenanceError("unexpected payloadType")
            return json.loads(payload)
    raise ProvenanceError("no valid signature from a trusted key")


@dataclass
class Policy:
    allowed_builders: set
    expected_repository: str
    allowed_refs: set = field(default_factory=lambda: {"refs/heads/main"})
    allowed_workflows: set = field(default_factory=set)


@dataclass
class GateResult:
    ok: bool
    reasons: list


def deploy_gate(envelope: dict, artifacts: dict, keys: dict, policy: Policy) -> GateResult:
    """Verify signature, then check WHAT was built, BY WHOM, FROM WHERE. Fail closed."""
    try:
        statement = verify_envelope(envelope, keys)
    except ProvenanceError as exc:
        return GateResult(False, [str(exc)])
    reasons = []
    if statement.get("_type") != STATEMENT_TYPE:
        reasons.append("unexpected statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        reasons.append("unexpected predicate type")
    subjects = {s["name"]: s["digest"].get("sha256") for s in statement.get("subject", [])}
    for name, path in artifacts.items():
        if name not in subjects:
            reasons.append(f"artifact {name} is not covered by the attestation")
        elif subjects[name] != sha256_file(path):
            reasons.append(f"artifact {name} does not match the attested digest")
    pred = statement.get("predicate", {})
    build_def, run = pred.get("buildDefinition", {}), pred.get("runDetails", {})
    builder = run.get("builder", {}).get("id")
    if builder not in policy.allowed_builders:
        reasons.append(f"builder {builder} is not trusted")
    params = build_def.get("externalParameters", {})
    if params.get("repository") != policy.expected_repository:
        reasons.append(f"built from {params.get('repository')}, expected {policy.expected_repository}")
    if params.get("ref") not in policy.allowed_refs:
        reasons.append(f"built from ref {params.get('ref')}, which is not allowed")
    if policy.allowed_workflows and params.get("workflow") not in policy.allowed_workflows:
        reasons.append(f"unexpected build workflow {params.get('workflow')}")
    for dep in build_def.get("resolvedDependencies", []):
        if not dep.get("digest"):
            reasons.append(f"material {dep.get('uri')} is not pinned by digest")
    return GateResult(not reasons, reasons)
