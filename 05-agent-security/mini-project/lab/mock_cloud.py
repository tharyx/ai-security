"""A tiny, offline, boto-like mock of one cloud account. It makes NO network calls.

It behaves like a real cloud in the ways that matter for this project:

* Every API call needs credentials, and the account (not the caller) checks them:
  expiry, revocation, the role's allowed actions and environments, and an optional
  session policy that narrows a credential to one action on one resource.
* Roles are assumed through an STS-like `assume_role` with a maximum duration. The
  production change role can only be assumed with an approval ID that the approval
  service registered (like an IAM trust-policy condition).
* Every call, allowed or denied, lands in a CloudTrail-like log with the role session name.

Method names follow boto3 style (describe_instances, filter_log_events, send_command,
authorize_security_group_ingress) so the code reads like the real thing. Terraform is
modelled as plan / apply / state with a serial number for drift detection.
"""

from __future__ import annotations

import copy
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

ADMIN_KEY_ID = "AKIA-CANARY-ADMIN-7731"            # the static key the vulnerable agent uses
ADMIN_SECRET = "CANARY-SECRET-ADMIN-0d1e"

ROLES: dict[str, dict] = {
    "admin": {"actions": {"*"}, "envs": {"dev", "staging", "prod"}, "max_seconds": 10**9},
    "agent-cloudops-readonly": {
        "actions": {"ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "logs:FilterLogEvents",
                    "terraform:Plan"},
        "envs": {"dev", "staging", "prod"}, "max_seconds": 900},
    "agent-cloudops-operator-nonprod": {
        "actions": {"ssm:SendCommand", "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress", "terraform:Apply"},
        "envs": {"dev", "staging"}, "max_seconds": 300},
    "agent-cloudops-change-prod": {
        "actions": {"ssm:SendCommand", "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress", "terraform:Apply"},
        "envs": {"prod"}, "max_seconds": 300, "requires_approval": True},
}


class ClientError(Exception):
    """Like botocore's ClientError: `code` is AccessDenied, ExpiredToken, InvalidParameter..."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class Credentials:
    access_key_id: str
    secret_access_key: str
    session_token: str
    role: str
    session_name: str
    expires_at: float
    session_policy: tuple[tuple[str, str], ...] = ()  # ((action, resource), ...); empty = role limits only


class MockCloud:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.instances = {
            "i-web1": {"Name": "web-1", "env": "prod", "service": "nginx", "cpu": 97, "restarts": 0},
            "i-db1": {"Name": "db-1", "env": "prod", "service": "postgres", "cpu": 41, "restarts": 0},
            "i-api-dev": {"Name": "api-dev", "env": "dev", "service": "api", "cpu": 88, "restarts": 0},
        }
        self.security_groups = {
            "sg-web": {"env": "prod", "rules": [[443, "0.0.0.0/0"]]},
            "sg-dev": {"env": "dev", "rules": [[8080, "10.0.0.0/16"]]},
        }
        self.log_groups: dict[str, list[str]] = {
            "/app/web-1": ["12:00:01 GET /checkout 200 812ms", "12:00:02 WARN worker pool saturated",
                           "12:00:03 GET /checkout 504 30000ms"],
            "/app/api-dev": ["12:00:01 WARN memory at 91%", "12:00:02 GC pause 2.1s"],
        }
        self.tf_state = {
            "prod": {"serial": 7, "resources": {"aws_instance.web": {"instance_type": "m5.large"},
                                                "aws_db_instance.main": {"engine": "postgres"}}},
            "dev": {"serial": 3, "resources": {"aws_instance.api": {"instance_type": "t3.medium"}}},
        }
        self.tf_plans: dict[str, dict] = {}
        self.cloudtrail: list[dict] = []
        self.approvals: set[str] = set()     # written only by the approval service
        self._sessions: dict[str, Credentials] = {}
        self._revoked_prefixes: set[str] = set()
        self._sessions[ADMIN_KEY_ID] = Credentials(ADMIN_KEY_ID, ADMIN_SECRET, "", "admin", "static-admin-key",
                                                   float("inf"))

    # --- STS ------------------------------------------------------------------------
    def assume_role(self, role: str, session_name: str, duration: int = 900,
                    session_policy: tuple[tuple[str, str], ...] = (), approval_id: str | None = None) -> Credentials:
        spec = ROLES.get(role)
        if spec is None or role == "admin":
            raise ClientError("AccessDenied", f"role {role} cannot be assumed")
        if duration > spec["max_seconds"]:
            raise ClientError("ValidationError", f"{role} allows at most {spec['max_seconds']} seconds")
        if spec.get("requires_approval") and approval_id not in self.approvals:
            raise ClientError("AccessDenied", f"{role} requires a registered approval")
        creds = Credentials(f"ASIA{secrets.token_hex(6).upper()}", secrets.token_hex(16), secrets.token_hex(16),
                            role, session_name, self.clock() + duration, tuple(session_policy))
        self._sessions[creds.access_key_id] = creds
        self._trail("sts:AssumeRole", creds, role, "ok")
        return creds

    def revoke_sessions(self, session_name_prefix: str) -> None:
        """Like 'revoke active sessions': every credential whose session name starts with this."""
        self._revoked_prefixes.add(session_name_prefix)

    # --- the account's own authorization ------------------------------------------------
    def _authorize(self, creds: Credentials, action: str, env: str, resource: str) -> None:
        known = self._sessions.get(creds.access_key_id)
        if known is None or known != creds:
            self._trail(action, creds, resource, "InvalidClientTokenId")
            raise ClientError("InvalidClientTokenId", "unknown credentials")
        if self.clock() >= creds.expires_at:
            self._trail(action, creds, resource, "ExpiredToken")
            raise ClientError("ExpiredToken", "the security token has expired")
        if any(creds.session_name.startswith(p) for p in self._revoked_prefixes):
            self._trail(action, creds, resource, "AccessDenied (revoked)")
            raise ClientError("AccessDenied", "session revoked")
        spec = ROLES[creds.role]
        if not ("*" in spec["actions"] or action in spec["actions"]) or env not in spec["envs"]:
            self._trail(action, creds, resource, "AccessDenied")
            raise ClientError("AccessDenied", f"{creds.role} may not {action} in {env}")
        if creds.session_policy and (action, resource) not in creds.session_policy:
            self._trail(action, creds, resource, "AccessDenied (session policy)")
            raise ClientError("AccessDenied", f"session policy does not allow {action} on {resource}")
        self._trail(action, creds, resource, "ok")

    def _trail(self, action: str, creds: Credentials, resource: str, result: str) -> None:
        self.cloudtrail.append({"ts": self.clock(), "eventName": action, "role": creds.role,
                                "sessionName": creds.session_name, "resource": resource, "result": result})

    # --- EC2 / CloudWatch Logs / SSM -----------------------------------------------------
    def describe_instances(self, creds: Credentials) -> list[dict]:
        self._authorize(creds, "ec2:DescribeInstances", "prod", "*")
        return [{"InstanceId": i, **{k: v for k, v in d.items() if k != "restarts"}} for i, d in self.instances.items()]

    def describe_security_groups(self, creds: Credentials) -> dict:
        self._authorize(creds, "ec2:DescribeSecurityGroups", "prod", "*")
        return copy.deepcopy(self.security_groups)

    def filter_log_events(self, creds: Credentials, log_group: str) -> list[str]:
        self._authorize(creds, "logs:FilterLogEvents", "prod", log_group)
        if log_group not in self.log_groups:
            raise ClientError("ResourceNotFoundException", log_group)
        return list(self.log_groups[log_group])

    def send_command(self, creds: Credentials, instance_id: str, command: str) -> str:
        inst = self._instance(instance_id)
        self._authorize(creds, "ssm:SendCommand", inst["env"], instance_id)
        if command != f"restart {inst['service']}":
            raise ClientError("InvalidParameter", "only 'restart <service>' is supported")
        inst["restarts"] += 1
        return f"{command} on {instance_id} ({inst['env']}): Success"

    def authorize_security_group_ingress(self, creds: Credentials, group_id: str, port: int, cidr: str) -> str:
        sg = self._sg(group_id)
        self._authorize(creds, "ec2:AuthorizeSecurityGroupIngress", sg["env"], group_id)
        if [port, cidr] not in sg["rules"]:
            sg["rules"].append([port, cidr])
        return f"{group_id}: allowed {cidr} on port {port}"

    def revoke_security_group_ingress(self, creds: Credentials, group_id: str, port: int, cidr: str) -> str:
        sg = self._sg(group_id)
        self._authorize(creds, "ec2:RevokeSecurityGroupIngress", sg["env"], group_id)
        if [port, cidr] in sg["rules"]:
            sg["rules"].remove([port, cidr])
        return f"{group_id}: removed {cidr} on port {port}"

    # --- Terraform -------------------------------------------------------------------------
    def terraform_plan(self, creds: Credentials, workspace: str, change: dict) -> dict:
        self._authorize(creds, "terraform:Plan", workspace, f"tf:{workspace}")
        body = {"workspace": workspace, "change": change, "base_serial": self.tf_state[workspace]["serial"]}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        plan = {"plan_id": f"plan-{digest[:10]}", "sha256": digest, **body,
                "summary": f"{change['op']} {change['resource']}"}
        self.tf_plans[plan["plan_id"]] = plan
        return dict(plan)

    def terraform_apply(self, creds: Credentials, plan_id: str) -> str:
        plan = self.tf_plans.get(plan_id)
        if plan is None:
            raise ClientError("InvalidParameter", "unknown plan")
        ws = plan["workspace"]
        self._authorize(creds, "terraform:Apply", ws, f"tf:{ws}")
        state = self.tf_state[ws]
        if state["serial"] != plan["base_serial"]:
            raise ClientError("StateDrift", "state changed since the plan was made; plan again")
        change = plan["change"]
        if change["op"] == "destroy":
            state["resources"].pop(change["resource"], None)
        else:
            state["resources"].setdefault(change["resource"], {})[change["attr"]] = change["value"]
        state["serial"] += 1
        return f"applied {plan_id}: {plan['summary']}"

    # --- helpers ---------------------------------------------------------------------------
    def _instance(self, instance_id: str) -> dict:
        if instance_id not in self.instances:
            raise ClientError("InvalidInstanceID.NotFound", instance_id)
        return self.instances[instance_id]

    def _sg(self, group_id: str) -> dict:
        if group_id not in self.security_groups:
            raise ClientError("InvalidGroup.NotFound", group_id)
        return self.security_groups[group_id]

    def admin_credentials(self) -> Credentials:
        """The long-lived admin key. Only the VULNERABLE agent uses this."""
        return self._sessions[ADMIN_KEY_ID]
