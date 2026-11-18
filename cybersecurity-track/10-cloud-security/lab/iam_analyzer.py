"""Static IAM policy analyzer (offline). Reads policy JSON dicts, never calls AWS.

Flags:
  WILDCARD_ACTION       Allow with "*" or "service:*"
  WILDCARD_RESOURCE     Allow on Resource "*" for write-capable actions
  ADMIN_EQUIVALENT      Allow "*" on "*" (full admin)
  PASSROLE_WILDCARD     iam:PassRole on every resource
  PASSROLE_ESCALATION   PassRole together with an action that runs code as the role
  PRIVESC_ACTION        IAM actions that let a caller raise its own privileges
  NOT_ACTION_ALLOW      Allow + NotAction (allows everything except a list)
  PUBLIC_PRINCIPAL      Principal "*" with no condition
  NO_MFA_CONDITION      sensitive Allow with no MFA condition and no MFA-deny guard
"""

from __future__ import annotations

from dataclasses import dataclass

# Actions that start compute or code which then runs with a role passed to it.
PASSROLE_PARTNERS = {
    "ec2:runinstances", "lambda:createfunction", "lambda:updatefunctionconfiguration",
    "cloudformation:createstack", "glue:createdevendpoint", "sagemaker:createnotebookinstance",
    "ecs:runtask", "datapipeline:createpipeline",
}
# Actions that change IAM itself and can be used to raise one's own privileges.
PRIVESC_ACTIONS = {
    "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachuserpolicy",
    "iam:attachrolepolicy", "iam:attachgrouppolicy", "iam:putuserpolicy", "iam:putrolepolicy",
    "iam:putgrouppolicy", "iam:updateassumerolepolicy", "iam:createaccesskey",
    "iam:createloginprofile", "iam:updateloginprofile", "iam:addusertogroup",
}
SENSITIVE_PREFIXES = ("iam:", "kms:schedulekeydeletion", "s3:delete", "ec2:terminate",
                      "cloudtrail:stop", "cloudtrail:delete", "organizations:", "rds:delete")
READ_PREFIXES = ("get", "list", "describe", "head", "lookup")


@dataclass
class PolicyFinding:
    rule: str
    severity: str
    policy: str
    statement: int
    detail: str


def _as_list(value) -> list:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _statements(policy: dict) -> list[dict]:
    stmts = policy.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else list(stmts)


def _mfa_condition(stmt: dict) -> bool:
    cond = stmt.get("Condition") or {}
    return any(
        "multifactorauth" in str(k).lower()
        for block in cond.values() if isinstance(block, dict) for k in block
    )


def _has_mfa_deny_guard(policy: dict) -> bool:
    """A Deny that fires when MFA is absent protects every Allow in the policy."""
    return any(s.get("Effect") == "Deny" and _mfa_condition(s) for s in _statements(policy))


def _is_sensitive(action: str) -> bool:
    a = action.lower()
    return a == "*" or a.startswith(SENSITIVE_PREFIXES)


def analyze_policy(policy: dict, name: str = "policy") -> list[PolicyFinding]:
    out: list[PolicyFinding] = []
    guarded = _has_mfa_deny_guard(policy)
    for i, stmt in enumerate(_statements(policy)):
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))
        lowered = {a.lower() for a in actions}
        star_resource = "*" in resources

        if "NotAction" in stmt:
            out.append(PolicyFinding("NOT_ACTION_ALLOW", "high", name, i,
                                     "Allow with NotAction grants everything except the listed actions"))
        if "Principal" in stmt and not stmt.get("Condition"):
            p = stmt["Principal"]
            if p == "*" or (isinstance(p, dict) and "*" in _as_list(p.get("AWS"))):
                out.append(PolicyFinding("PUBLIC_PRINCIPAL", "high", name, i,
                                         "Principal is * with no Condition: anyone can use this statement"))

        if "*" in actions and star_resource:
            out.append(PolicyFinding("ADMIN_EQUIVALENT", "critical", name, i,
                                     "Action * on Resource *: full administrator"))
        else:
            for a in actions:
                if a == "*":
                    out.append(PolicyFinding("WILDCARD_ACTION", "high", name, i, "Action is *"))
                elif a.endswith(":*"):
                    risky_service = a.split(":")[0].lower() in ("iam", "sts", "organizations", "kms")
                    out.append(PolicyFinding("WILDCARD_ACTION", "high" if risky_service else "medium",
                                             name, i, f"Service wildcard {a}"))
            if star_resource and any(not a.split(":")[-1].lower().startswith(READ_PREFIXES) for a in actions):
                out.append(PolicyFinding("WILDCARD_RESOURCE", "medium", name, i,
                                         "Write-capable actions allowed on Resource *"))

        if star_resource and "iam:passrole" in lowered:
            out.append(PolicyFinding("PASSROLE_WILDCARD", "high", name, i,
                                     "iam:PassRole on * lets the caller hand any role to a service"))
            partners = sorted(lowered & PASSROLE_PARTNERS)
            if partners:
                out.append(PolicyFinding("PASSROLE_ESCALATION", "critical", name, i,
                                         f"PassRole + {', '.join(partners)} on *: run code as a stronger role"))
        risky = sorted(lowered & PRIVESC_ACTIONS)
        if risky and star_resource:
            out.append(PolicyFinding("PRIVESC_ACTION", "high", name, i,
                                     f"IAM change actions on *: {', '.join(risky)}"))

        if (any(_is_sensitive(a) for a in actions) and not _mfa_condition(stmt)
                and not guarded and "Principal" not in stmt):
            out.append(PolicyFinding("NO_MFA_CONDITION", "medium", name, i,
                                     "Sensitive actions allowed with no aws:MultiFactorAuthPresent condition"))
    return out


def analyze_many(policies: dict[str, dict]) -> list[PolicyFinding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found = [f for name, p in policies.items() for f in analyze_policy(p, name)]
    return sorted(found, key=lambda f: (order[f.severity], f.policy, f.statement))
