"""Check configuration fixtures against the mitigations in the three case-study threat models:
AWS S3 (S3-T*), Kubernetes (K8S-T*) and vsftpd (FTP-T*). Threat ids match the lessons' tables.

Inputs are fixtures only (JSON for S3 and Kubernetes, key=value text for vsftpd). Nothing calls a cloud API
or a cluster. Setting names follow the providers' documentation as we understand it: verify at source.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    threat: str
    target: str
    ok: bool
    detail: str


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _is_anyone(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(v == "*" or v == ["*"] for v in principal.values())
    return False


# ------------------------------------------------------------------------------- AWS S3
def check_s3(bucket: dict) -> list[Finding]:
    name, out = bucket["name"], []
    bpa = bucket.get("public_access_block", {})
    flags = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    out.append(Finding("S3-T1", name, all(bpa.get(f) for f in flags), "Block Public Access: all four settings on"))
    stmts = _as_list(bucket.get("policy", {}).get("Statement", []))
    public = [s.get("Sid", "?") for s in stmts if s.get("Effect") == "Allow" and _is_anyone(s.get("Principal"))
              and not s.get("Condition")]
    out.append(Finding("S3-T2", name, not public, f"no unconditional Allow to Principal '*' (found: {public or 'none'})"))
    tls = any(s.get("Effect") == "Deny" and
              str(s.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport", "")).lower() == "false"
              for s in stmts)
    out.append(Finding("S3-T3", name, tls, "Deny when aws:SecureTransport is false (TLS only)"))
    out.append(Finding("S3-T4", name, bucket.get("object_ownership") == "BucketOwnerEnforced",
                       "Object Ownership = BucketOwnerEnforced (ACLs disabled)"))
    sse = bucket.get("encryption", {}).get("sse")
    out.append(Finding("S3-T5", name, sse == "aws:kms" or (sse == "AES256" and not bucket.get("sensitive")),
                       f"encryption at rest suited to the data (sse={sse}; sensitive data -> SSE-KMS)"))
    out.append(Finding("S3-T6", name, bucket.get("versioning") == "Enabled" and
                       (bucket.get("object_lock") or not bucket.get("critical")),
                       "versioning on; Object Lock for critical data (ransomware, accidental delete)"))
    out.append(Finding("S3-T7", name, bool(bucket.get("access_logging") or bucket.get("cloudtrail_data_events")),
                       "server access logs or CloudTrail data events"))
    deputies = [s.get("Sid", "?") for s in stmts if s.get("Effect") == "Allow"
                and isinstance(s.get("Principal"), dict) and "Service" in s["Principal"]
                and not any(k in json.dumps(s.get("Condition", {})) for k in ("aws:SourceAccount", "aws:SourceArn"))]
    out.append(Finding("S3-T8", name, not deputies,
                       f"service principals restricted by aws:SourceAccount/SourceArn (confused deputy) (found: {deputies or 'none'})"))
    wild = [s.get("Sid", "?") for s in stmts if s.get("Effect") == "Allow" and "s3:*" in _as_list(s.get("Action", []))]
    out.append(Finding("S3-T9", name, not wild, f"no s3:* in Allow statements (found: {wild or 'none'})"))
    return out


# ------------------------------------------------------------------------------- Kubernetes
SECRETISH = re.compile(r"(pass(word)?|secret|token|api[_-]?key)", re.I)


def _pod_spec(obj: dict) -> dict | None:
    if obj["kind"] == "Pod":
        return obj["spec"]
    if obj["kind"] in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
        return obj["spec"]["template"]["spec"]
    return None


def check_k8s(objects: list[dict]) -> list[Finding]:
    out = []
    for obj in objects:
        name = f"{obj['kind']}/{obj['metadata']['name']}"
        spec = _pod_spec(obj)
        if spec is not None:
            pod_sc = spec.get("securityContext", {})
            out.append(Finding("K8S-T1", name, not any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC")),
                               "no hostNetwork / hostPID / hostIPC"))
            out.append(Finding("K8S-T2", name, not any("hostPath" in v for v in spec.get("volumes", [])),
                               "no hostPath volumes"))
            out.append(Finding("K8S-T3", name, spec.get("automountServiceAccountToken") is False,
                               "automountServiceAccountToken: false unless the pod calls the API"))
            for c in spec.get("containers", []):
                cname, sc = f"{name}/{c['name']}", c.get("securityContext", {})
                caps = sc.get("capabilities", {}).get("drop", [])
                out.append(Finding("K8S-T4", cname, not sc.get("privileged") and sc.get("allowPrivilegeEscalation") is False
                                   and "ALL" in caps, "not privileged, allowPrivilegeEscalation false, drop ALL capabilities"))
                out.append(Finding("K8S-T5", cname, (sc.get("runAsNonRoot") or pod_sc.get("runAsNonRoot")) is True
                                   and sc.get("readOnlyRootFilesystem") is True, "runAsNonRoot and readOnlyRootFilesystem"))
                image = c.get("image", "")
                out.append(Finding("K8S-T6", cname, "@sha256:" in image or (":" in image.split("/")[-1]
                                   and not image.endswith(":latest")), f"image pinned (tag or digest, not latest): {image}"))
                out.append(Finding("K8S-T7", cname, bool(c.get("resources", {}).get("limits")),
                                   "CPU and memory limits set (resource exhaustion)"))
                literal = [e["name"] for e in c.get("env", []) if SECRETISH.search(e["name"]) and "value" in e]
                out.append(Finding("K8S-T8", cname, not literal,
                                   f"secrets come from secretKeyRef or a vault, not literal env values (found: {literal or 'none'})"))
        if obj["kind"] == "Namespace":
            label = obj["metadata"].get("labels", {}).get("pod-security.kubernetes.io/enforce")
            out.append(Finding("K8S-T9", name, label == "restricted", f"Pod Security Admission enforce=restricted (is {label})"))
        if obj["kind"] in ("ClusterRole", "Role"):
            wild = any("*" in r.get("verbs", []) or "*" in r.get("resources", []) for r in obj.get("rules", []))
            out.append(Finding("K8S-T10", name, not wild, "RBAC rules without '*' verbs or resources"))
        if obj["kind"] in ("ClusterRoleBinding", "RoleBinding"):
            anon = [s["name"] for s in obj.get("subjects", []) if s["name"] in ("system:anonymous", "system:unauthenticated")]
            out.append(Finding("K8S-T11", name, not anon, f"no bindings to anonymous users (found: {anon or 'none'})"))
    namespaces = {o["metadata"]["name"] for o in objects if o["kind"] == "Namespace"}
    for ns in sorted(namespaces):
        default_deny = any(o["kind"] == "NetworkPolicy" and o["metadata"].get("namespace") == ns
                           and o["spec"].get("podSelector") == {} and "Ingress" in o["spec"].get("policyTypes", [])
                           for o in objects)
        out.append(Finding("K8S-T12", f"Namespace/{ns}", default_deny, "default-deny NetworkPolicy present"))
    return out


# ------------------------------------------------------------------------------- vsftpd
def parse_vsftpd(text: str) -> dict[str, str]:
    conf = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
    return conf


def check_vsftpd(text: str, name: str = "vsftpd.conf") -> list[Finding]:
    c = parse_vsftpd(text)
    yes = lambda k: c.get(k, "").upper() == "YES"  # noqa: E731
    no = lambda k, default="NO": c.get(k, default).upper() == "NO"  # noqa: E731
    return [
        Finding("FTP-T1", name, no("anonymous_enable", "YES"), "anonymous_enable=NO (defaults differ between versions and distro packages: set it explicitly)"),
        Finding("FTP-T2", name, no("anon_upload_enable") and no("anon_mkdir_write_enable"), "no anonymous upload or mkdir"),
        Finding("FTP-T3", name, yes("chroot_local_user"), "chroot_local_user=YES (users jailed to their home)"),
        Finding("FTP-T4", name, yes("ssl_enable") and yes("force_local_logins_ssl") and yes("force_local_data_ssl"),
                "TLS on and forced for logins and data (otherwise passwords in clear text)"),
        Finding("FTP-T5", name, c.get("nopriv_user", "") not in ("", "root"), "nopriv_user is a dedicated unprivileged account"),
        Finding("FTP-T6", name, yes("xferlog_enable"), "transfer logging on (repudiation)"),
        Finding("FTP-T7", name, no("write_enable") or yes("chroot_local_user"), "write access only when users are jailed"),
    ]


def failed(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if not f.ok]


def gate(findings: list[Finding]) -> int:
    return 1 if failed(findings) else 0
