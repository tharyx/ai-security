"""GraphQL, SOAP and REST API best practices as code.

Each API style has a checklist of rules. A rule reads a small JSON config that
describes how an API is deployed (the kind of settings you find in Apollo/graphql-java,
a SOAP stack or a REST framework + gateway) and returns a finding when the setting is weak.

Two runtime helpers show that the limits are more than paperwork:
  * graphql_query_depth()/count_aliases(): measure a GraphQL-like query;
  * enforce_graphql_limits(): reject queries that break the configured limits.

Pure standard library. Rule ids are our own; map them to ASVS 5.0 ids in your checklist
(verify the current ASVS numbering at the source).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str


@dataclass
class Rule:
    rule_id: str
    severity: str
    title: str
    check: Callable[[dict], str | None]  # returns a problem description, or None when OK


def _get(cfg: dict, dotted: str, default=None):
    cur = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _need_true(key: str, why: str):
    return lambda c: None if _get(c, key) is True else why


def _need_false(key: str, why: str):
    return lambda c: None if _get(c, key) is False else why


def _max(key: str, limit: int, why: str):
    def f(c):
        v = _get(c, key)
        if v is None:
            return f"{why} (not set: unlimited)"
        return None if v <= limit else f"{why} (is {v}, want <= {limit})"
    return f


# ---------------------------------------------------------------- GraphQL
GRAPHQL_RULES = [
    Rule("GQL-01", "HIGH", "Introspection disabled in production",
         lambda c: None if not (c.get("environment") == "production" and _get(c, "introspection")) else
         "introspection is on in production: the whole schema (including admin mutations) is public"),
    Rule("GQL-02", "MEDIUM", "Field suggestions disabled",
         _need_false("field_suggestions", "'Did you mean ...?' suggestions leak schema even with introspection off")),
    Rule("GQL-03", "HIGH", "Query depth limit", _max("limits.max_depth", 10, "deep or circular queries can exhaust the server")),
    Rule("GQL-04", "HIGH", "Query cost/complexity limit", _max("limits.max_cost", 5000, "no cost limit: one query can fetch millions of nodes")),
    Rule("GQL-05", "HIGH", "Alias limit", _max("limits.max_aliases", 20, "aliases allow hundreds of login/OTP guesses in one request")),
    Rule("GQL-06", "MEDIUM", "Batching limit", _max("limits.max_batch", 5, "array batching multiplies every other limit")),
    Rule("GQL-07", "CRITICAL", "Authorization in every resolver",
         _need_true("authz.per_resolver", "authorization only at the HTTP layer: nested resolvers expose other users' objects (BOLA)")),
    Rule("GQL-08", "MEDIUM", "Persisted queries / operation allowlist",
         _need_true("persisted_queries", "arbitrary queries accepted from any client")),
    Rule("GQL-09", "MEDIUM", "Errors masked", _need_true("mask_errors", "stack traces and resolver errors reach the client")),
    Rule("GQL-10", "MEDIUM", "Execution timeout", _max("limits.timeout_ms", 10000, "no execution timeout")),
]

# ---------------------------------------------------------------- SOAP
SOAP_RULES = [
    Rule("SOAP-01", "CRITICAL", "DTD processing disabled",
         _need_false("xml.dtd_processing", "DTDs enabled: XXE file read/SSRF and billion-laughs entity expansion")),
    Rule("SOAP-02", "CRITICAL", "External entities disabled",
         _need_false("xml.external_entities", "external entities resolved: XXE")),
    Rule("SOAP-03", "HIGH", "Schema (XSD) validation on", _need_true("xml.schema_validation", "messages not validated against the XSD")),
    Rule("SOAP-04", "MEDIUM", "Message size limit", _max("xml.max_message_bytes", 1_048_576, "no message size limit")),
    Rule("SOAP-05", "MEDIUM", "WSDL not public in production",
         lambda c: None if not (c.get("environment") == "production" and _get(c, "wsdl_public")) else
         "WSDL published in production: full operation map for attackers"),
    Rule("SOAP-06", "HIGH", "WS-Security signature and timestamp required",
         lambda c: None if _get(c, "ws_security.require_signature") and _get(c, "ws_security.require_timestamp") else
         "unsigned or replayable messages accepted"),
    Rule("SOAP-07", "CRITICAL", "Process only the signed element (anti XML Signature Wrapping)",
         _need_true("ws_security.process_signed_element_only",
                    "the app may process an unsigned copy of the body (XML Signature Wrapping)")),
    Rule("SOAP-08", "MEDIUM", "SOAPAction must match the body operation",
         _need_true("soapaction_must_match_body", "SOAPAction header trusted for routing: operation spoofing")),
    Rule("SOAP-09", "HIGH", "TLS for transport", _need_true("transport.tls", "SOAP over plain HTTP")),
    Rule("SOAP-10", "MEDIUM", "Faults do not leak internals", _need_false("faults.include_stacktrace", "SOAP faults include stack traces")),
]

# ---------------------------------------------------------------- REST
REST_RULES = [
    Rule("REST-01", "HIGH", "HTTPS only (and HSTS)", _need_true("transport.https_only", "plain HTTP allowed")),
    Rule("REST-02", "CRITICAL", "Every non-public route authenticated",
         lambda c: (lambda bad: None if not bad else f"routes without authentication: {', '.join(bad)}")(
             [r["path"] for r in c.get("routes", []) if not r.get("public") and not r.get("auth")])),
    Rule("REST-03", "CRITICAL", "Object-level authorization on routes with ids",
         lambda c: (lambda bad: None if not bad else f"id routes without an owner check (BOLA): {', '.join(bad)}")(
             [r["path"] for r in c.get("routes", []) if "{" in r["path"] and not r.get("object_authz")])),
    Rule("REST-04", "HIGH", "Request schema validation", _need_true("validation.request_schema", "request bodies not validated against a schema")),
    Rule("REST-05", "HIGH", "Response field allowlist (no excessive data exposure)",
         _need_true("validation.response_allowlist", "whole objects serialized to the client (BOPLA / excessive data exposure)")),
    Rule("REST-06", "HIGH", "Rate limiting configured", lambda c: None if _get(c, "rate_limit.enabled") else "no rate limit"),
    Rule("REST-07", "MEDIUM", "Page size capped", _max("pagination.max_page_size", 100, "unbounded page size")),
    Rule("REST-08", "HIGH", "CORS allowlist, never '*' with credentials",
         lambda c: "CORS allows any origin" if "*" in _get(c, "cors.allowed_origins", []) or _get(c, "cors.reflect_origin") else None),
    Rule("REST-09", "MEDIUM", "Only needed HTTP methods",
         lambda c: (lambda bad: None if not bad else f"risky methods enabled: {', '.join(sorted(bad))}")(
             set(_get(c, "allowed_methods", [])) & {"TRACE", "CONNECT"})),
    Rule("REST-10", "MEDIUM", "Generic error bodies", _need_false("errors.verbose", "verbose errors (SQL, stack traces) in responses")),
    Rule("REST-11", "MEDIUM", "Strict Content-Type checking", _need_true("validation.enforce_content_type", "any Content-Type accepted")),
    Rule("REST-12", "MEDIUM", "API inventory: deprecated versions retired",
         lambda c: (lambda bad: None if not bad else f"old versions still live: {', '.join(bad)}")(
             [v["name"] for v in c.get("versions", []) if v.get("deprecated") and v.get("live")])),
]

RULESETS = {"graphql": GRAPHQL_RULES, "soap": SOAP_RULES, "rest": REST_RULES}


def check(style: str, cfg: dict) -> list[Finding]:
    out = []
    for r in RULESETS[style]:
        problem = r.check(cfg)
        if problem:
            out.append(Finding(r.rule_id, r.severity, f"{r.title}: {problem}"))
    return sorted(out, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule))


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def gate(findings: list[Finding], fail_on: str = "HIGH") -> int:
    worst = SEVERITY_ORDER[fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= worst for f in findings) else 0


# ---------------------------------------------------------------- runtime helpers
def graphql_query_depth(query: str) -> int:
    """Depth of nested selection sets, counted by braces (ignores strings)."""
    query = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
    depth = best = 0
    for ch in query:
        if ch == "{":
            depth += 1
            best = max(best, depth)
        elif ch == "}":
            depth -= 1
    return best - 1 if best else 0  # the outer operation braces are not a field level


def count_aliases(query: str) -> int:
    """Count `alias: field` pairs (a common brute-force amplifier)."""
    query = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
    query = re.sub(r"\([^)]*\)", "()", query)  # drop arguments (name: value pairs)
    return len(re.findall(r"\b[_A-Za-z]\w*\s*:\s*[_A-Za-z]\w*", query))


def enforce_graphql_limits(query: str, cfg: dict) -> tuple[bool, str]:
    limits = cfg.get("limits", {})
    d, a = graphql_query_depth(query), count_aliases(query)
    if limits.get("max_depth") is not None and d > limits["max_depth"]:
        return False, f"rejected: depth {d} > {limits['max_depth']}"
    if limits.get("max_aliases") is not None and a > limits["max_aliases"]:
        return False, f"rejected: {a} aliases > {limits['max_aliases']}"
    return True, f"accepted (depth {d}, aliases {a})"
