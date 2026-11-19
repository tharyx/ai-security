"""Kubernetes Secrets: base64 is not encryption (offline checks).

1. decode a Secret manifest to show how little protection base64 gives
2. flag Secret manifests committed to Git
3. audit an API-server EncryptionConfiguration (encryption at rest in etcd)
4. compare how pods consume secrets: environment variables vs mounted volumes
All keys and values in the fixtures are FAKE.
"""
from __future__ import annotations

import base64
import binascii

import yaml

ENCRYPTING = {"aescbc", "aesgcm", "secretbox", "kms"}


def decode_secret(doc: dict) -> dict[str, str]:
    """What anyone with `get secret` (or etcd read access without encryption) sees."""
    out = {}
    for k, v in (doc.get("data") or {}).items():
        try:
            out[k] = base64.b64decode(v, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError):
            out[k] = "<not valid base64 text>"
    out.update(doc.get("stringData") or {})
    return out


def secrets_in_git(docs: list[dict]) -> list[str]:
    """A Secret manifest in a repository leaks the value to everyone with read access and to its history."""
    return [f"Secret/{d['metadata'].get('namespace', 'default')}/{d['metadata']['name']}" for d in docs
            if d["kind"] == "Secret" and (d.get("data") or d.get("stringData"))]


def audit_encryption_config(text: str) -> list[tuple[str, str, str]]:
    """Returns (id, severity, message)."""
    cfg = yaml.safe_load(text)
    out: list[tuple[str, str, str]] = []
    if cfg.get("kind") != "EncryptionConfiguration":
        return [("ENC-000", "HIGH", "not an EncryptionConfiguration")]
    entries = [r for r in cfg.get("resources", []) if "secrets" in r.get("resources", [])]
    if not entries:
        return [("ENC-001", "CRITICAL", "secrets are not listed: stored in etcd as plain text")]
    providers = entries[0].get("providers", [])
    first = next(iter(providers[0]), "") if providers else ""
    if first == "identity":
        out.append(("ENC-002", "CRITICAL", "identity is the first provider: new secrets are written unencrypted"))
    elif first not in ENCRYPTING:
        out.append(("ENC-003", "HIGH", f"unknown first provider '{first}'"))
    elif first in ("aescbc", "aesgcm", "secretbox"):
        out.append(("ENC-004", "MEDIUM", f"{first} keeps the key in a file on the control-plane host; prefer a KMS provider (v2)"))
    if first == "aescbc":
        out.append(("ENC-005", "LOW", "aescbc is weaker than aesgcm/secretbox/KMS against padding-oracle style issues in some threat models (verify guidance)"))
    if first == "kms" and providers[0]["kms"].get("apiVersion", "v1") != "v2":
        out.append(("ENC-006", "MEDIUM", "KMS v1 is deprecated; use KMS v2"))
    keys = [k for p in providers for k in (p.get("aescbc") or p.get("aesgcm") or p.get("secretbox") or {}).get("keys", [])]
    if len({k["name"] for k in keys}) != len(keys):
        out.append(("ENC-007", "MEDIUM", "duplicate key names break rotation"))
    return out


def secret_consumption(pod: dict) -> dict[str, list[str]]:
    spec = pod["spec"]
    env, volumes = [], []
    for c in spec.get("containers", []):
        for e in c.get("env", []):
            ref = (e.get("valueFrom") or {}).get("secretKeyRef")
            if ref:
                env.append(f"{c['name']}:{e['name']} <- {ref['name']}/{ref['key']}")
        for ef in c.get("envFrom", []):
            if "secretRef" in ef:
                env.append(f"{c['name']}: ALL keys of {ef['secretRef']['name']}")
    for v in spec.get("volumes", []):
        if "secret" in v:
            volumes.append(f"{v['name']} <- {v['secret']['secretName']}")
    return {"env": env, "volumes": volumes}


def consumption_advice(pod: dict) -> list[str]:
    c = secret_consumption(pod)
    advice = []
    if c["env"]:
        advice.append("secrets in environment variables leak through crash dumps, `/proc/<pid>/environ`, child processes and logs; prefer a read-only volume mount (tmpfs) or an external secrets operator")
    if any("ALL keys" in e for e in c["env"]):
        advice.append("envFrom.secretRef exposes every key; reference only what is needed")
    for v in pod["spec"].get("volumes", []):
        if "secret" in v and v["secret"].get("defaultMode", 0o644) not in (0o400, 0o440, 256, 288):
            advice.append(f"volume {v['name']}: set defaultMode 0400")
    return advice
