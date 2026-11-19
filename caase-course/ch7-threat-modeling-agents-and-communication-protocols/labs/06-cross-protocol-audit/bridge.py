"""A cross-protocol orchestrator bridge (MCP, A2A-style, UCP-style) and an auditor for it (Chapter 7, lab 6).

The bridge accepts three inbound message shapes, translates each into one canonical Request, then runs the
same authorize/execute path against a tool backend (an MCP-style tool layer with a ledger).

    MCP        {"jsonrpc","method":"tools/call","params":{"name","arguments"},"client_id","nonce"}
    A2A-style  {"agent":{"name","org"},"skill","parts":[{"text": "<json arguments>"}],"nonce"}
    UCP-style  {"writer":{"name","org"},"key","value":{"tool","args"},"nonce"}    (course term: shared context)

Four confusion bugs can be switched OFF one at a time (the flags are the FIXES):
  keep_trust         the A2A/UCP adapters carry the sender org's trust level; vulnerable bridges stamp "internal"
  namespace_identity identity is protocol:org/name; vulnerable bridges map by display name only
  strict_schema      per-tool schema (types, no extra keys, limit in the bridge); vulnerable bridges forward
                     everything and coerce strings ("1e3") the backend happens to accept
  global_replay      one nonce store across protocols; vulnerable bridges keep one store per protocol
"""
from __future__ import annotations

import json

ORG_TRUST = {"acme": "internal", "acme-sandbox": "internal", "partner": "external"}
REFUND_LIMIT = 500


class Denied(Exception):
    pass


class Request:
    def __init__(self, protocol, identity, org, trust, tool, args, nonce):
        self.protocol, self.identity, self.org, self.trust = protocol, identity, org, trust
        self.tool, self.args, self.nonce = tool, args, nonce


class Backend:
    """MCP-style tool layer. Its own schema is lax, as many real servers are."""

    def __init__(self):
        self.ledger: list[dict] = []

    def execute(self, tool: str, args: dict) -> str:
        if tool == "lookup_order":
            self.ledger.append({"tool": tool, "order": args.get("order")})
            return f"order {args.get('order')}: shipped"
        if tool == "issue_refund":
            amount = int(float(args["amount"]))  # accepts "1e3" and 10.0
            if amount > REFUND_LIMIT and not args.get("override_limit"):
                raise Denied("over refund limit")
            self.ledger.append({"tool": tool, "order": args.get("order"), "amount": amount})
            return f"refunded {amount}"
        raise Denied("unknown tool")


class Bridge:
    def __init__(self, backend: Backend | None = None, *, keep_trust=False, namespace_identity=False,
                 strict_schema=False, global_replay=False):
        self.backend = backend or Backend()
        self.keep_trust, self.namespace_identity = keep_trust, namespace_identity
        self.strict_schema, self.global_replay = strict_schema, global_replay
        self._seen: dict[str, set] = {}

    # ---- adapters: protocol message -> canonical Request -------------------------------------
    def _identity(self, protocol: str, org: str, name: str) -> str:
        return f"{protocol}:{org}/{name}" if self.namespace_identity else name  # BUG 2 when False

    def from_mcp(self, msg: dict) -> Request:
        p = msg["params"]
        return Request("mcp", self._identity("mcp", "acme", msg["client_id"]), "acme", "internal",
                       p["name"], p.get("arguments", {}), msg["nonce"])

    def from_a2a(self, msg: dict) -> Request:
        org, name = msg["agent"]["org"], msg["agent"]["name"]
        trust = ORG_TRUST.get(org, "external") if self.keep_trust else "internal"  # BUG 1 when False
        args = json.loads(msg["parts"][0]["text"])
        return Request("a2a", self._identity("a2a", org, name), org, trust, msg["skill"], args, msg["nonce"])

    def from_ucp(self, entry: dict) -> Request:
        w = entry["writer"]
        trust = ORG_TRUST.get(w["org"], "external") if self.keep_trust else "internal"
        v = entry["value"]
        return Request("ucp", self._identity("ucp", w["org"], w["name"]), w["org"], trust, v["tool"], v["args"], entry["nonce"])

    # ---- policy -----------------------------------------------------------------------------
    def _allowed_refunders(self) -> set[str]:
        if self.namespace_identity:
            return {"mcp:acme/billing-agent", "a2a:acme/billing-agent", "ucp:acme/billing-agent"}
        return {"billing-agent"}

    def _validate(self, req: Request) -> None:
        if not self.strict_schema:
            return
        schemas = {"lookup_order": {"order": str}, "issue_refund": {"order": str, "amount": int}}
        sch = schemas.get(req.tool)
        if sch is None:
            raise Denied("unknown tool")
        if set(req.args) != set(sch):
            raise Denied(f"schema: keys must be exactly {sorted(sch)}")
        for k, t in sch.items():
            if not isinstance(req.args[k], t) or isinstance(req.args[k], bool):
                raise Denied(f"schema: {k} must be {t.__name__}")
        if req.tool == "issue_refund" and req.args["amount"] > REFUND_LIMIT:
            raise Denied("over refund limit")

    def handle(self, protocol: str, msg: dict) -> str:
        req = {"mcp": self.from_mcp, "a2a": self.from_a2a, "ucp": self.from_ucp}[protocol](msg)
        bucket = "all" if self.global_replay else protocol  # BUG 4 when per-protocol
        seen = self._seen.setdefault(bucket, set())
        if req.nonce in seen:
            raise Denied("replay")
        if req.trust != "internal":
            raise Denied("external callers may not use tools")
        if req.tool == "issue_refund" and req.identity not in self._allowed_refunders():
            raise Denied("identity not allowed to refund")
        self._validate(req)
        seen.add(req.nonce)
        return self.backend.execute(req.tool, req.args)


# ---------------------------------------------------------------------------------------------------
# Message builders used by tests, the auditor and the demo
def mcp_msg(client_id, tool, args, nonce):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "client_id": client_id, "nonce": nonce,
            "params": {"name": tool, "arguments": args}}


def a2a_msg(name, org, skill, args, nonce):
    return {"agent": {"name": name, "org": org}, "skill": skill, "nonce": nonce, "parts": [{"text": json.dumps(args)}]}


def ucp_msg(name, org, tool, args, nonce):
    return {"writer": {"name": name, "org": org}, "key": "ctx/request", "nonce": nonce, "value": {"tool": tool, "args": args}}


# ---------------------------------------------------------------------------------------------------
# The auditor: black-box probes against any bridge factory. Each probe returns a finding dict or None.
def _try(fn):
    try:
        return fn(), None
    except Denied as exc:
        return None, str(exc)


def probe_trust_does_not_carry(make):
    b = make()
    out, _ = _try(lambda: b.handle("a2a", a2a_msg("scout-agent", "partner", "lookup_order", {"order": "O-1"}, "t1")))
    if out:
        return {"id": "XP-1", "title": "Trust level lost across protocols", "evidence": "external A2A agent executed a tool",
                "fix": "carry org/trust from the protocol's own authentication into the canonical request"}


def probe_identity_mapping(make):
    b = make()
    out, _ = _try(lambda: b.handle("a2a", a2a_msg("billing-agent", "acme-sandbox", "issue_refund", {"order": "O-2", "amount": 10}, "i1")))
    if out:
        return {"id": "XP-2", "title": "Identity mapping error (display-name collision)",
                "evidence": "sandbox agent named billing-agent got the prod billing-agent's refund right",
                "fix": "namespace identities as protocol:org/name and key policy on the full identity"}


def probe_schema_mismatch(make):
    b = make()
    out, _ = _try(lambda: b.handle("mcp", mcp_msg("billing-agent", "issue_refund", {"order": "O-3", "amount": "1e3", "override_limit": True}, "s1")))
    if out:
        return {"id": "XP-3", "title": "Schema mismatch / pass-through",
                "evidence": "string amount '1e3' and an extra override_limit key reached the tool and passed the limit",
                "fix": "validate against a per-tool schema (types, additionalProperties false) before dispatch"}


def probe_cross_protocol_replay(make):
    b = make()
    first, _ = _try(lambda: b.handle("mcp", mcp_msg("billing-agent", "issue_refund", {"order": "O-4", "amount": 10}, "r1")))
    again, _ = _try(lambda: b.handle("ucp", ucp_msg("billing-agent", "acme", "issue_refund", {"order": "O-4", "amount": 10}, "r1")))
    if first and again:
        return {"id": "XP-4", "title": "Replay across protocols",
                "evidence": "the same nonce executed twice, once per protocol",
                "fix": "one replay store for all protocols (and sign messages with the protocol label)"}


def probe_benign(make):
    """Not a finding: the fixes must not break legitimate traffic. Returns a finding only if they do."""
    b = make()
    ok1, e1 = _try(lambda: b.handle("mcp", mcp_msg("billing-agent", "issue_refund", {"order": "O-5", "amount": 20}, "b1")))
    ok2, e2 = _try(lambda: b.handle("a2a", a2a_msg("billing-agent", "acme", "lookup_order", {"order": "O-5"}, "b2")))
    if not (ok1 and ok2):
        return {"id": "XP-0", "title": "Hardening broke benign traffic", "evidence": f"{e1} / {e2}", "fix": "-"}


PROBES = [probe_trust_does_not_carry, probe_identity_mapping, probe_schema_mismatch, probe_cross_protocol_replay, probe_benign]


def audit(make) -> list[dict]:
    return [f for p in PROBES if (f := p(make))]
