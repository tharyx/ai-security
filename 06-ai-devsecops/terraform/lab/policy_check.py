"""Policy-as-code for AI infrastructure: check a Terraform plan before it is applied.

Input is the JSON that Terraform prints for a saved plan:

    terraform plan -out tfplan
    terraform show -json tfplan > tfplan.json
    python policy_check.py tfplan.json --waivers waivers.json

Why the *plan* and not the .tf files? The plan has the final values after variables,
locals, modules and functions such as jsonencode() are resolved. A rule like "no IAM
policy with Action '*'" is easy to check on the plan and hard to check on raw HCL.

Two facts about plan JSON that every rule below has to handle:

1. Values that are only known after apply (ARNs, IDs) are LEFT OUT of ``change.after``
   and marked ``true`` in ``change.after_unknown``.
2. So "which bucket does this public-access-block belong to?" often cannot be answered
   from ``after``. We read the ``configuration`` section instead, where each expression
   lists the resources it ``references``.

Layers you can switch (to see what each one buys you):
    disabled=   turn individual rules off
    waivers=    approved, time-limited exceptions; expired waivers stop working
    fail_on=    the lowest severity that fails the pipeline

Limits (on purpose, to keep the lab small): root module only, AWS only, create/update only.
Real tools (Checkov, Trivy, OPA/conftest) cover far more. The ideas are the same.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterator

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PLAN_LEVEL = "<plan>"  # address used by rules about something MISSING from the plan
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
GITHUB_OIDC = "token.actions.githubusercontent.com"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    address: str
    message: str


@dataclass(frozen=True)
class Waiver:
    rule_id: str
    address: str  # glob, e.g. "aws_s3_bucket.*" or "<plan>"
    reason: str
    approved_by: str
    expires: date
    ticket: str = ""

    def covers(self, f: Finding) -> bool:
        return self.rule_id == f.rule_id and fnmatch.fnmatchcase(f.address, self.address)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)  # still open
    waived: list[tuple[Finding, Waiver]] = field(default_factory=list)
    expired_waivers: list[Waiver] = field(default_factory=list)

    def rule_ids(self) -> set[str]:
        return {f.rule_id for f in self.findings}

    def failed(self, fail_on: str = "HIGH") -> bool:
        return any(SEVERITY[f.severity] >= SEVERITY[fail_on] for f in self.findings)


# --------------------------------------------------------------------------- plan model

class Plan:
    """A small read-only view over ``terraform show -json`` output."""

    def __init__(self, data: dict) -> None:
        self.resources: dict[str, dict] = {}
        for rc in data.get("resource_changes", []):
            change = rc.get("change", {})
            if rc.get("mode") != "managed" or change.get("actions") == ["delete"]:
                continue  # a resource being destroyed cannot be misconfigured
            self.resources[rc["address"]] = {
                "type": rc["type"],
                "after": change.get("after") or {},
                "unknown": change.get("after_unknown") or {},
            }
        self.refs: dict[tuple[str, str], list[str]] = {}
        for res in data.get("configuration", {}).get("root_module", {}).get("resources", []):
            for attr, expr in res.get("expressions", {}).items():
                if isinstance(expr, dict) and "references" in expr:
                    self.refs[(res["address"], attr)] = expr["references"]

    def of_type(self, rtype: str) -> list[tuple[str, dict, dict]]:
        return [(a, r["after"], r["unknown"]) for a, r in self.resources.items() if r["type"] == rtype]

    def refers_to(self, address: str, attr: str, target: str) -> bool:
        return any(r == target or r.startswith(target + ".") for r in self.refs.get((address, attr), []))

    def companions(self, rtype: str, bucket_address: str, bucket_name: str, attr: str = "bucket") -> list[dict]:
        """Resources of ``rtype`` whose ``attr`` points at the bucket (by reference or by literal name)."""
        out = []
        for address, after, _ in self.of_type(rtype):
            if self.refers_to(address, attr, bucket_address) or (bucket_name and after.get(attr) == bucket_name):
                out.append(after)
        return out


def first(block: object) -> dict:
    """Nested blocks appear as lists of objects in plan JSON. Return the first one, or {}."""
    if isinstance(block, list) and block and isinstance(block[0], dict):
        return block[0]
    return block if isinstance(block, dict) else {}


def as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_policy(text: object) -> list[dict]:
    if not isinstance(text, str) or not text:
        return []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


# --------------------------------------------------------------------------- rules

Rule = Callable[[Plan], Iterator[tuple[str, str]]]
RULES: dict[str, tuple[str, str, Rule]] = {}


def rule(rule_id: str, severity: str, title: str) -> Callable[[Rule], Rule]:
    def register(fn: Rule) -> Rule:
        RULES[rule_id] = (severity, title, fn)
        return fn
    return register


def buckets(plan: Plan) -> list[tuple[str, str]]:
    return [(a, after.get("bucket", "")) for a, after, _ in plan.of_type("aws_s3_bucket")]


@rule("TF-AI-001", "HIGH", "S3 bucket without a full public access block")
def s3_public_access_block(plan: Plan):
    flags = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    for address, name in buckets(plan):
        blocks = plan.companions("aws_s3_bucket_public_access_block", address, name)
        if not any(all(b.get(f) is True for f in flags) for b in blocks):
            yield address, f"bucket '{name}' has no public access block with all four settings true"


@rule("TF-AI-002", "HIGH", "S3 bucket ACL grants public access")
def s3_public_acl(plan: Plan):
    for address, name in buckets(plan):
        for acl in plan.companions("aws_s3_bucket_acl", address, name):
            if acl.get("acl") in PUBLIC_ACLS:
                yield address, f"bucket '{name}' has canned ACL '{acl['acl']}'"


@rule("TF-AI-003", "HIGH", "S3 bucket not encrypted with a customer-managed KMS key")
def s3_cmek(plan: Plan):
    for address, name in buckets(plan):
        ok = False
        for rc_address, after, unknown in plan.of_type("aws_s3_bucket_server_side_encryption_configuration"):
            if not (plan.refers_to(rc_address, "bucket", address) or after.get("bucket") == name):
                continue
            default = first(first(after.get("rule")).get("apply_server_side_encryption_by_default"))
            key_unknown = first(first(unknown.get("rule")).get("apply_server_side_encryption_by_default"))
            has_key = bool(default.get("kms_master_key_id")) or key_unknown.get("kms_master_key_id") is True
            ok = ok or (default.get("sse_algorithm") in {"aws:kms", "aws:kms:dsse"} and has_key)
        if not ok:
            yield address, f"bucket '{name}' must use SSE-KMS with a customer-managed key (CMEK)"


@rule("TF-AI-004", "MEDIUM", "S3 bucket versioning not enabled")
def s3_versioning(plan: Plan):
    for address, name in buckets(plan):
        cfgs = plan.companions("aws_s3_bucket_versioning", address, name)
        if not any(first(c.get("versioning_configuration")).get("status") == "Enabled" for c in cfgs):
            yield address, f"bucket '{name}' cannot recover an overwritten or tampered object"


@rule("TF-AI-005", "MEDIUM", "S3 bucket access logging missing")
def s3_logging(plan: Plan):
    log_targets = set()
    for la, after, _ in plan.of_type("aws_s3_bucket_logging"):
        log_targets.update(r for r in plan.refs.get((la, "target_bucket"), []) if r.count(".") == 1)
        log_targets.add(after.get("target_bucket", ""))
    for address, name in buckets(plan):
        if address in log_targets or name in log_targets:
            continue  # the log bucket itself; logging it into itself would loop
        if not plan.companions("aws_s3_bucket_logging", address, name):
            yield address, f"bucket '{name}' has no server access logging"


@rule("TF-AI-010", "HIGH", "Notebook exposed: internet, root or no VPC")
def notebook_exposure(plan: Plan):
    for address, after, _ in plan.of_type("aws_sagemaker_notebook_instance"):
        problems = []
        if after.get("direct_internet_access", "Enabled") != "Disabled":
            problems.append("direct internet access")
        if after.get("root_access", "Enabled") != "Disabled":
            problems.append("root access")
        if not after.get("subnet_id"):
            problems.append("no private subnet")
        if problems:
            yield address, "notebook has " + ", ".join(problems)


@rule("TF-AI-011", "HIGH", "Model container not network-isolated / not in a VPC")
def model_network(plan: Plan):
    for address, after, _ in plan.of_type("aws_sagemaker_model"):
        if after.get("enable_network_isolation") is not True or not first(after.get("vpc_config")):
            yield address, "serving container can make outbound calls or runs outside your VPC"


@rule("TF-AI-012", "MEDIUM", "Model endpoint storage not encrypted with a customer key")
def endpoint_kms(plan: Plan):
    for address, after, unknown in plan.of_type("aws_sagemaker_endpoint_configuration"):
        if not after.get("kms_key_arn") and unknown.get("kms_key_arn") is not True:
            yield address, "endpoint configuration has no kms_key_arn"


@rule("TF-AI-013", "MEDIUM", "Model API has no private (interface) VPC endpoint")
def model_private_endpoint(plan: Plan):
    if not plan.of_type("aws_sagemaker_endpoint"):
        return
    for _, after, _ in plan.of_type("aws_vpc_endpoint"):
        if (str(after.get("service_name", "")).endswith(".sagemaker.runtime")
                and after.get("vpc_endpoint_type") == "Interface" and after.get("private_dns_enabled") is True):
            return
    yield PLAN_LEVEL, "callers will reach the model API over its public regional endpoint"


@rule("TF-AI-020", "CRITICAL", "Vector database reachable from the internet")
def vector_db_public(plan: Plan):
    for address, after, _ in plan.of_type("aws_opensearch_domain"):
        if not first(after.get("vpc_options")):
            yield address, "domain has a public endpoint (no vpc_options)"
        for stmt in parse_policy(after.get("access_policies")):
            principal = stmt.get("Principal")
            aws = principal.get("AWS") if isinstance(principal, dict) else principal
            if stmt.get("Effect") == "Allow" and "*" in as_list(aws) and not stmt.get("Condition"):
                yield address, "access policy allows Principal '*' with no condition"


@rule("TF-AI-021", "HIGH", "Vector database encryption or HTTPS disabled")
def vector_db_crypto(plan: Plan):
    for address, after, _ in plan.of_type("aws_opensearch_domain"):
        if first(after.get("encrypt_at_rest")).get("enabled") is not True:
            yield address, "encryption at rest is off (embeddings can be inverted to recover text)"
        if first(after.get("node_to_node_encryption")).get("enabled") is not True:
            yield address, "node-to-node encryption is off"
        if first(after.get("domain_endpoint_options")).get("enforce_https") is not True:
            yield address, "HTTPS is not enforced"


@rule("TF-AI-030", "CRITICAL", "Security group open to the internet")
def sg_open(plan: Plan):
    for address, after, _ in plan.of_type("aws_security_group"):
        for rule_ in as_list(after.get("ingress")):
            cidrs = set(as_list(rule_.get("cidr_blocks"))) | set(as_list(rule_.get("ipv6_cidr_blocks")))
            if cidrs & PUBLIC_CIDRS:
                yield address, (f"ingress {rule_.get('from_port')}-{rule_.get('to_port')} "
                                f"({rule_.get('description', 'no description')}) is open to the internet")
    for address, after, _ in plan.of_type("aws_vpc_security_group_ingress_rule"):
        if {after.get("cidr_ipv4"), after.get("cidr_ipv6")} & PUBLIC_CIDRS:
            yield address, f"ingress port {after.get('from_port')} is open to the internet"


@rule("TF-AI-040", "HIGH", "IAM policy with wildcard actions on all resources")
def iam_wildcards(plan: Plan):
    for rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        for address, after, _ in plan.of_type(rtype):
            for stmt in parse_policy(after.get("policy")):
                actions = as_list(stmt.get("Action"))
                wild = [a for a in actions if a == "*" or str(a).endswith(":*")]
                if stmt.get("Effect") == "Allow" and wild and "*" in as_list(stmt.get("Resource")):
                    yield address, f"allows {wild} on Resource '*'"
    for address, after, _ in plan.of_type("aws_iam_role_policy_attachment"):
        if str(after.get("policy_arn", "")).endswith("/AdministratorAccess"):
            yield address, "attaches AdministratorAccess"


@rule("TF-AI-041", "HIGH", "Long-lived IAM access key")
def iam_access_keys(plan: Plan):
    for address, _, _ in plan.of_type("aws_iam_access_key"):
        yield address, "static access keys leak and never expire; use roles / OIDC federation"


@rule("TF-AI-042", "HIGH", "GitHub OIDC trust policy does not restrict the subject")
def oidc_subject(plan: Plan):
    for address, after, _ in plan.of_type("aws_iam_role"):
        for stmt in parse_policy(after.get("assume_role_policy")):
            principal = stmt.get("Principal")
            federated = as_list(principal.get("Federated")) if isinstance(principal, dict) else []
            if not any(GITHUB_OIDC in str(f) for f in federated):
                continue
            subjects = []
            for operator in (stmt.get("Condition") or {}).values():
                subjects += as_list(operator.get(f"{GITHUB_OIDC}:sub"))
            if not subjects or any(s == "*" or str(s).startswith("repo:*") for s in subjects):
                yield address, "any GitHub repository could assume this role (no specific 'sub' condition)"


@rule("TF-AI-050", "MEDIUM", "KMS key rotation disabled")
def kms_rotation(plan: Plan):
    for address, after, _ in plan.of_type("aws_kms_key"):
        if after.get("enable_key_rotation") is not True:
            yield address, "enable_key_rotation is not true"


@rule("TF-AI-060", "MEDIUM", "No CloudTrail S3 data events for AI buckets")
def cloudtrail_data_events(plan: Plan):
    if not buckets(plan):
        return
    for _, after, _ in plan.of_type("aws_cloudtrail"):
        for selector in as_list(after.get("event_selector")):
            if any(d.get("type") == "AWS::S3::Object" for d in as_list(selector.get("data_resource"))):
                return
    yield PLAN_LEVEL, "nobody will be able to tell who read or replaced a model file"


# --------------------------------------------------------------------------- engine

def load_waivers(path: str | Path) -> list[Waiver]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Waiver(w["rule_id"], w["address"], w["reason"], w["approved_by"],
                   date.fromisoformat(w["expires"]), w.get("ticket", "")) for w in raw]


def check_plan(plan_json: dict, *, disabled: set[str] | frozenset[str] = frozenset(),
               waivers: list[Waiver] | None = None, today: date | None = None) -> Report:
    today = today or date.today()
    plan = Plan(plan_json)
    active = [w for w in (waivers or []) if w.expires >= today]
    report = Report(expired_waivers=[w for w in (waivers or []) if w.expires < today])
    for rule_id, (severity, _title, fn) in sorted(RULES.items()):
        if rule_id in disabled:
            continue
        for address, message in fn(plan):
            finding = Finding(rule_id, severity, address, message)
            waiver = next((w for w in active if w.covers(finding)), None)
            if waiver:
                report.waived.append((finding, waiver))
            else:
                report.findings.append(finding)
    return report


def load_plan(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Terraform plan JSON against AI-infrastructure policy.")
    parser.add_argument("plan", help="output of: terraform show -json tfplan")
    parser.add_argument("--waivers", help="JSON file of approved, time-limited exceptions")
    parser.add_argument("--disable", action="append", default=[], help="rule ID to skip (repeatable)")
    parser.add_argument("--fail-on", default="HIGH", choices=list(SEVERITY))
    args = parser.parse_args(argv)

    report = check_plan(load_plan(args.plan), disabled=set(args.disable),
                        waivers=load_waivers(args.waivers) if args.waivers else None)
    for f in report.findings:
        print(f"{f.severity:8} {f.rule_id}  {f.address}: {f.message}")
    for f, w in report.waived:
        print(f"WAIVED   {f.rule_id}  {f.address}: {w.reason} ({w.ticket}, expires {w.expires})")
    for w in report.expired_waivers:
        print(f"EXPIRED  waiver for {w.rule_id} on {w.address} expired {w.expires}; it no longer applies")
    verdict = "FAIL" if report.failed(args.fail_on) else "PASS"
    print(f"\n{verdict}: {len(report.findings)} open finding(s), {len(report.waived)} waived, fail-on={args.fail_on}")
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
