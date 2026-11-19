"""Kubernetes service accounts: automount, token audience and bound tokens (offline).

Pods can receive a token that proves "I am system:serviceaccount:<ns>:<name>". Old clusters used a never-expiring
Secret-based token. Current clusters use **bound** tokens: signed JWTs with an audience, an expiry and a link to the
pod, so they die with the pod. Tokens in this lab are FAKE: three base64url parts, the signature is a placeholder.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass

DEFAULT_AUDIENCE = "https://kubernetes.default.svc"


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, sort_keys=True).encode()).rstrip(b"=").decode()


def _unb64(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def make_token(claims: dict) -> str:
    return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(claims)}.FAKE-SIGNATURE-NOT-VERIFIED"


def decode_claims(token: str) -> dict:
    """Reading claims needs no key: a JWT payload is only base64url. Never trust it without verifying the signature."""
    return _unb64(token.split(".")[1])


def bound_claims(ns: str, sa: str, pod: str, pod_uid: str, *, audience=DEFAULT_AUDIENCE, now=1_000_000, ttl=3600) -> dict:
    return {"aud": [audience], "iat": now, "exp": now + ttl, "iss": "https://kubernetes.default.svc.cluster.local",
            "sub": f"system:serviceaccount:{ns}:{sa}",
            "kubernetes.io": {"namespace": ns, "pod": {"name": pod, "uid": pod_uid}, "serviceaccount": {"name": sa, "uid": "sa-uid-1"}}}


def legacy_claims(ns: str, sa: str) -> dict:
    return {"iss": "kubernetes/serviceaccount", "sub": f"system:serviceaccount:{ns}:{sa}",
            "kubernetes.io/serviceaccount/secret.name": f"{sa}-token-abcde"}


def token_review(token: str, *, audience: str, now: int, live_pod_uids: set[str]) -> tuple[bool, str]:
    """What the API server (TokenReview) checks, minus the signature, which the lab does not model."""
    c = decode_claims(token)
    if "exp" not in c:
        return True, "ACCEPTED but legacy: no expiry, no audience, no pod binding (a stolen copy works forever)"
    if audience not in c.get("aud", []):
        return False, f"audience mismatch: token is for {c.get('aud')}, caller expects {audience}"
    if c["exp"] <= now:
        return False, "token expired"
    pod = (c.get("kubernetes.io") or {}).get("pod")
    if pod and pod["uid"] not in live_pod_uids:
        return False, "bound pod no longer exists"
    return True, "valid bound token"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str
    message: str


def analyse(docs: list[dict]) -> list[Finding]:
    sas = {(d["metadata"].get("namespace", "default"), d["metadata"]["name"]): d for d in docs if d["kind"] == "ServiceAccount"}
    out: list[Finding] = []
    for (ns, name), sa in sas.items():
        if any(s for s in sa.get("secrets", [])):
            out.append(Finding("SA-005", "HIGH", f"ServiceAccount/{ns}/{name}", "references a long-lived token Secret; use TokenRequest / projected tokens"))
    for d in docs:
        if d["kind"] != "Pod":
            continue
        ns, name, spec = d["metadata"].get("namespace", "default"), d["metadata"]["name"], d["spec"]
        where = f"Pod/{ns}/{name}"
        sa_name = spec.get("serviceAccountName", "default")
        sa = sas.get((ns, sa_name), {})
        automount = spec.get("automountServiceAccountToken", sa.get("automountServiceAccountToken", True))
        needs_api = (d["metadata"].get("annotations") or {}).get("needs-kubernetes-api") == "true"
        if sa_name == "default":
            out.append(Finding("SA-002", "MEDIUM", where, "uses the namespace's default ServiceAccount; give each workload its own"))
        if automount and not needs_api:
            out.append(Finding("SA-001", "HIGH", where, "API token is mounted but the workload is not marked as needing the Kubernetes API (set automountServiceAccountToken: false)"))
        for v in spec.get("volumes", []):
            for src in (v.get("projected") or {}).get("sources", []):
                tok = src.get("serviceAccountToken")
                if tok is None:
                    continue
                if not tok.get("audience"):
                    out.append(Finding("SA-003", "MEDIUM", where, "projected token has no audience, so it is valid for the API server; set a dedicated audience"))
                if tok.get("expirationSeconds", 3600) > 3600:
                    out.append(Finding("SA-004", "MEDIUM", where, f"token lifetime {tok['expirationSeconds']}s is long; shorter tokens limit theft impact"))
    return out
