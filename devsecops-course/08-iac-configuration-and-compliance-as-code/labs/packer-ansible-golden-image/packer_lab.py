"""Packer HCL2 template validator, simulated build and promotion gate (teaching tool, offline).

* parse_hcl(): a small HCL2 SUBSET parser (blocks, attributes, one-line lists, object attributes).
  It is not a full HCL parser: no heredocs, no multi-line lists, no expressions beyond references.
* validate(): PKR-001..PKR-007 rules for golden image templates.
* simulate_build(): produces an image manifest with a content hash. No image is built. The hash
  covers the template, the base image reference and every playbook file, so any change to the
  inputs changes the image id (a stand-in for a real digest).
* promotion_gate(): decides whether an image may be promoted from "built" to "approved".

Real-tool twin: `packer validate`, `packer build`, the manifest post-processor, and your CI gate
(see real-tools/packer.md).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class Ref:
    """An unquoted expression such as var.base_image or env("X")."""
    text: str


@dataclass
class Block:
    type: str
    labels: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)
    children: list["Block"] = field(default_factory=list)

    def find(self, type_: str, label: str | None = None) -> list["Block"]:
        return [c for c in self.children if c.type == type_ and (label is None or (c.labels and c.labels[0] == label))]


# ------------------------------------------------------------------ parser
def strip_comment(line: str) -> str:
    out, in_str, i = [], False, 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and in_str:
            out.append(line[i:i + 2])
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        if not in_str and (ch == "#" or line[i:i + 2] == "//"):
            break
        out.append(ch)
        i += 1
    return "".join(out).strip()


def split_list(inner: str) -> list[str]:
    items, cur, in_str = [], [], False
    for ch in inner:
        if ch == '"':
            in_str = not in_str
        if ch == "," and not in_str:
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        items.append("".join(cur).strip())
    return items


def parse_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return bytes(raw[1:-1], "utf-8").decode("unicode_escape")
    if raw.startswith("[") and raw.endswith("]"):
        return [parse_value(x) for x in split_list(raw[1:-1])]
    if raw in {"true", "false"}:
        return raw == "true"
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return Ref(raw)


BLOCK_OPEN = re.compile(r'^([\w-]+)((?:\s+"[^"]*")*)\s*\{$')
OBJ_OPEN = re.compile(r"^([\w-]+)\s*=\s*\{$")
ATTR = re.compile(r"^([\w-]+)\s*=\s*(.+)$")


def parse_hcl(text: str) -> list[Block]:
    root = Block("__root__")
    stack: list[tuple[Block, str | None]] = [(root, None)]  # (block, object-attribute name or None)
    for number, raw in enumerate(text.splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        top, obj_name = stack[-1]
        if line == "}":
            if len(stack) == 1:
                raise ValueError(f"line {number}: unbalanced }}")
            done, name = stack.pop()
            if name is not None:  # an object attribute closed: store as dict on the parent
                stack[-1][0].attrs[name] = done.attrs
            continue
        m = OBJ_OPEN.match(line)
        if m:
            stack.append((Block("__object__"), m.group(1)))
            continue
        m = BLOCK_OPEN.match(line)
        if m:
            labels = re.findall(r'"([^"]*)"', m.group(2))
            blk = Block(m.group(1), labels)
            top.children.append(blk)
            stack.append((blk, None))
            continue
        m = ATTR.match(line)
        if m:
            top.attrs[m.group(1)] = parse_value(m.group(2))
            continue
        raise ValueError(f"line {number}: cannot parse: {line!r}")
    if len(stack) != 1:
        raise ValueError("unclosed block")
    return root.children


# ------------------------------------------------------------------ validator
@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str
    message: str


SECRET_NAME = re.compile(r"(password|passwd|secret|token|access_key|secret_key|api_key|private_key)", re.I)
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
AMI_ID = re.compile(r"^ami-[0-9a-f]{8,17}$")


def resolve(value: Any, variables: dict[str, Block]) -> Any:
    if isinstance(value, Ref):
        m = re.fullmatch(r"var\.(\w+)", value.text)
        if m and m.group(1) in variables:
            return variables[m.group(1)].attrs.get("default", value)
    return value


def validate(blocks: list[Block]) -> list[Finding]:
    out: list[Finding] = []
    variables = {b.labels[0]: b for b in blocks if b.type == "variable" and b.labels}
    sources = {f"source.{b.labels[0]}.{b.labels[1]}": b for b in blocks if b.type == "source" and len(b.labels) == 2}
    builds = [b for b in blocks if b.type == "build"]

    # PKR-006 plugins pinned
    packer_blocks = [b for b in blocks if b.type == "packer"]
    plugins: dict[str, Any] = {}
    for pb in packer_blocks:
        for rp in pb.find("required_plugins"):
            plugins.update(rp.attrs)
    if not plugins:
        out.append(Finding("PKR-006", "LOW", "packer{}", "no required_plugins block: plugin versions are not pinned"))
    for name, spec in plugins.items():
        version = spec.get("version") if isinstance(spec, dict) else None
        v = version if isinstance(version, str) else ""
        if not v or re.fullmatch(r">=\s*0(\.0)*", v.strip()):
            out.append(Finding("PKR-006", "MEDIUM", f"required_plugins.{name}", f"plugin version constraint {v or '(none)'} does not pin anything"))

    # PKR-002 secrets in variables
    for name, var in variables.items():
        if SECRET_NAME.search(name):
            default = var.attrs.get("default")
            if isinstance(default, str) and default:
                out.append(Finding("PKR-002", "CRITICAL", f"variable.{name}", "secret variable has a literal default: it lives in git forever"))
            if var.attrs.get("sensitive") is not True:
                out.append(Finding("PKR-002", "MEDIUM", f"variable.{name}", "secret variable is not marked sensitive = true (it can print in logs)"))

    # PKR-001 base image pinned, PKR-002 literal secrets in sources
    for ref, src in sources.items():
        stype = src.labels[0]
        if stype == "docker":
            image = resolve(src.attrs.get("image"), variables)
            if not (isinstance(image, str) and DIGEST.search(image)):
                out.append(Finding("PKR-001", "HIGH", ref, f"base image {image if isinstance(image, str) else '(unresolved)'} is not pinned by sha256 digest"))
        elif stype == "amazon-ebs":
            ami = resolve(src.attrs.get("source_ami"), variables)
            filt = src.find("source_ami_filter")
            if filt and filt[0].attrs.get("most_recent") is True and not ami:
                out.append(Finding("PKR-001", "HIGH", ref, "source_ami_filter with most_recent = true: tomorrow's build starts from a different base"))
            elif not (isinstance(ami, str) and AMI_ID.match(ami)):
                out.append(Finding("PKR-001", "HIGH", ref, "source_ami is not a literal AMI id"))
        else:
            out.append(Finding("PKR-001", "LOW", ref, f"unknown builder type {stype}: base pinning not checked"))
        for key, val in src.attrs.items():
            if SECRET_NAME.search(key) and isinstance(val, str) and val:
                out.append(Finding("PKR-002", "CRITICAL", f"{ref}.{key}", "literal credential in the template: use env() or a CI-injected variable"))

    if not builds:
        out.append(Finding("PKR-003", "HIGH", "build", "no build block"))
    for b in builds:
        where = f"build.{b.attrs.get('name', '(unnamed)')}"
        # PKR-007 dangling sources
        for s in b.attrs.get("sources", []):
            if isinstance(s, str) and s not in sources:
                out.append(Finding("PKR-007", "HIGH", where, f"build references {s} but no such source block exists"))
        provs = b.find("provisioner")
        ansible = [p for p in provs if p.labels and p.labels[0] == "ansible"]
        # PKR-003 ansible provisioner
        if not ansible:
            out.append(Finding("PKR-003", "HIGH", where, "no ansible provisioner: hardening is not code-reviewed configuration management"))
        for p in ansible:
            if not p.attrs.get("playbook_file"):
                out.append(Finding("PKR-003", "HIGH", where, "ansible provisioner without playbook_file"))
        # PKR-005 download and execute
        for p in provs:
            if p.labels and p.labels[0] in {"shell", "shell-local"}:
                cmds = " ".join(str(c) for c in (p.attrs.get("inline") or []))
                if re.search(r"(curl|wget)[^|]*\|\s*(ba|z)?sh", cmds):
                    out.append(Finding("PKR-005", "HIGH", where, "shell provisioner pipes a download into a shell"))
        # PKR-004 manifest
        pps = [pp for pp in b.find("post-processor") if pp.labels and pp.labels[0] == "manifest"]
        if not pps or not pps[0].attrs.get("output"):
            out.append(Finding("PKR-004", "MEDIUM", where, "no manifest post-processor with an output file: the pipeline cannot trace what was built"))
    return sorted(out, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.where))


# ------------------------------------------------------------------ simulated build
def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def simulate_build(template_path: str | Path, build_time: int = 1_700_000_000) -> dict:
    """Return a Packer-manifest-like dict. Reads the template and the playbooks it references."""
    path = Path(template_path)
    text = path.read_text(encoding="utf-8")
    blocks = parse_hcl(text)
    variables = {b.labels[0]: b for b in blocks if b.type == "variable"}
    sources = {f"source.{b.labels[0]}.{b.labels[1]}": b for b in blocks if b.type == "source"}
    entries = []
    for b in (x for x in blocks if x.type == "build"):
        playbooks = {}
        for p in b.find("provisioner", "ansible"):
            rel = p.attrs.get("playbook_file")
            if isinstance(rel, str):
                playbooks[rel] = sha256_hex((path.parent / rel).read_bytes())
        for s in b.attrs.get("sources", []):
            src = sources[s]
            base = resolve(src.attrs.get("image") or src.attrs.get("source_ami"), variables)
            base = base if isinstance(base, str) else "(unresolved)"
            inputs = {"template": sha256_hex(text.encode()), "base": base, "playbooks": playbooks}
            image_id = "sha256:" + sha256_hex(canonical(inputs))
            entries.append({
                "name": f"{b.attrs.get('name', 'build')}.{src.labels[0]}.{src.labels[1]}",
                "builder_type": src.labels[0],
                "build_time": build_time,
                "artifact_id": image_id,
                "packer_run_uuid": str(hashlib.md5(image_id.encode()).hexdigest()),
                "custom_data": {"base_image": base, "playbook_sha256": playbooks, "template_sha256": inputs["template"]},
            })
    return {"builds": entries, "last_run_uuid": entries[-1]["packer_run_uuid"] if entries else None}


def sign_manifest(manifest: dict, key: bytes) -> str:
    """HMAC attestation over the builds. Stand-in for a cosign signature or in-toto attestation."""
    return hmac.new(key, canonical(manifest["builds"]), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ promotion gate
@dataclass
class Gate:
    decision: str
    reasons: list[str]


def promotion_gate(manifest: dict, validator_findings: list[Finding], compliance_score: float, vuln_counts: dict,
                   attestation: str, key: bytes, min_score: float = 95.0) -> Gate:
    reasons: list[str] = []
    if any(f.severity in {"CRITICAL", "HIGH"} for f in validator_findings):
        reasons.append("template has CRITICAL/HIGH validator findings")
    if compliance_score < min_score:
        reasons.append(f"compliance score {compliance_score} is below {min_score}")
    if vuln_counts.get("critical", 0) > 0 or vuln_counts.get("high", 0) > 0:
        reasons.append("image scan has critical or high vulnerabilities")
    if not manifest.get("builds"):
        reasons.append("manifest has no builds")
    if not hmac.compare_digest(attestation, sign_manifest(manifest, key)):
        reasons.append("attestation does not match the manifest (tampered or unsigned)")
    for b in manifest.get("builds", []):
        if not DIGEST.search(b["custom_data"]["base_image"]) and not AMI_ID.match(b["custom_data"]["base_image"]):
            reasons.append(f"{b['name']}: base image is not pinned")
    return Gate("PROMOTE" if not reasons else "BLOCK", reasons)
