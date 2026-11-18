"""Threat model as code: analyze a YAML description of an AI system.

You describe the system once - trust zones, components, data flows and the controls
on each flow - and this analyzer finds the classic design mistakes automatically:

    AUTH-001  an actor reaches the system without authentication
    TB-001    untrusted (tainted) content can trigger a privileged action with no hard gate
    TB-002    a flow crosses a trust boundary with no hard control at all
    OUT-001   model output reaches a tool, service or browser without validation/encoding
    RAG-001   retrieval returns sensitive chunks without a permission filter
    DATA-001  sensitive data flows to a less-trusted zone without redaction or a contract
    SEC-001   a secret is placed in the model's prompt
    ID-001    the model calls a sensitive tool with a shared service identity (confused deputy)
    DOS-001   no rate limit or token budget (unbounded consumption)
    REP-001   a side-effecting tool call is not audit-logged
    TRI-001   the lethal trifecta: private data + untrusted content + an exfiltration channel

It also generates STRIDE-per-element threat *candidates* for a human to review.

Key idea taught by the code: **taint never washes out.** Once untrusted content flows
into a component, everything downstream is tainted. Soft controls (spotlighting,
injection detection) are recorded but do not remove taint. Only hard gates on the
dangerous action, or removing a leg of the trifecta, fix the design.

Usage (from the repository root):
    python 01-ai-security-fundamentals/lab/threat_model.py 01-ai-security-fundamentals/lab/designs/vulnerable_design.yaml
    python 01-ai-security-fundamentals/lab/threat_model.py <design.yaml> --requirements

The exit code is 1 when an open high or critical finding exists, so CI can block a merge.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------

TRUST = {"untrusted": 0, "semi": 1, "trusted": 2, "privileged": 3}
CLASSIFICATION = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

# Every control the analyzer understands, and what kind of control it is.
CONTROLS: dict[str, str] = {
    # hard: deterministic code or configuration, testable
    "authn": "hard", "authz": "hard", "acl_filter": "hard", "tenant_filter": "hard",
    "schema_validation": "hard", "tool_authz": "hard", "egress_allowlist": "hard",
    "url_allowlist": "hard", "output_encoding": "hard", "redaction": "hard", "tls": "hard",
    "rate_limit": "hard", "token_budget": "hard", "sandbox": "hard", "integrity_check": "hard",
    # process / detective: depends on people or happens after the fact
    "human_approval": "process", "dpa": "process", "audit_log": "detective",
    # soft: probabilistic, lowers the odds, never a boundary
    "spotlighting": "soft", "injection_detection": "soft", "content_filter": "soft",
    "system_prompt_rule": "soft",
}

ComponentType = Literal["actor", "external_source", "ui", "service", "model", "datastore",
                        "vector_store", "tool", "log"]
Capability = Literal["read_private", "write", "delete", "execute", "external_comms", "payment"]
SIDE_EFFECTS = {"write", "delete", "execute", "external_comms", "payment"}
HARD_GATES = {"tool_authz", "authz", "human_approval"}

# --------------------------------------------------------------------------------------
# Schema (pydantic validates the YAML so typos fail loudly instead of hiding risk)
# --------------------------------------------------------------------------------------


class Zone(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    trust: Literal["untrusted", "semi", "trusted", "privileged"]
    description: str = ""


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: ComponentType
    zone: str
    classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    capabilities: list[Capability] = []
    renders_markdown: bool = False
    multi_tenant: bool = False
    description: str = ""

    @property
    def side_effects(self) -> bool:
        return bool(SIDE_EFFECTS & set(self.capabilities))


class Flow(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    id: str
    source: str = Field(alias="from")
    target: str = Field(alias="to")
    data: str
    classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    controls: list[str] = []
    contains_secrets: bool = False
    identity: Literal["user", "service", "none"] = "none"

    @model_validator(mode="after")
    def _known_controls(self) -> "Flow":
        unknown = [c for c in self.controls if c not in CONTROLS]
        if unknown:
            raise ValueError(f"flow {self.id}: unknown control(s) {unknown}; known: {sorted(CONTROLS)}")
        return self


class AcceptedRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: str
    target: str
    reason: str
    owner: str
    expires: date


class Design(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    zones: list[Zone]
    components: list[Component]
    flows: list[Flow]
    accepted_risks: list[AcceptedRisk] = []

    @model_validator(mode="after")
    def _references_exist(self) -> "Design":
        zone_ids = {z.id for z in self.zones}
        comp_ids = {c.id for c in self.components}
        for c in self.components:
            if c.zone not in zone_ids:
                raise ValueError(f"component {c.id}: unknown zone {c.zone!r}")
        for f in self.flows:
            for end in (f.source, f.target):
                if end not in comp_ids:
                    raise ValueError(f"flow {f.id}: unknown component {end!r}")
        return self

    # helpers -----------------------------------------------------------------------
    def comp(self, cid: str) -> Component:
        return next(c for c in self.components if c.id == cid)

    def trust(self, cid: str) -> int:
        zone = self.comp(cid).zone
        return TRUST[next(z.trust for z in self.zones if z.id == zone)]


def load_design(path: str | Path) -> Design:
    with open(path, encoding="utf-8") as fh:
        return Design.model_validate(yaml.safe_load(fh))


# --------------------------------------------------------------------------------------
# Findings and risk scoring
# --------------------------------------------------------------------------------------

RULES: dict[str, str] = {
    "AUTH-001": "Unauthenticated entry point",
    "TB-001": "Untrusted content can trigger a privileged action",
    "TB-002": "Trust boundary crossed with no hard control",
    "OUT-001": "Model output used without validation",
    "RAG-001": "Retrieval without permission filter",
    "DATA-001": "Sensitive data to a less-trusted zone",
    "SEC-001": "Secret placed in the prompt",
    "ID-001": "Confused deputy: shared service identity",
    "DOS-001": "Unbounded consumption",
    "REP-001": "Side effect without audit trail",
    "TRI-001": "Lethal trifecta",
}


def severity(likelihood: int, impact: int) -> str:
    """Risk = likelihood x impact on a 1-5 scale (max 25)."""
    score = likelihood * impact
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


@dataclass
class Finding:
    rule: str
    target: str             # flow id or component id
    likelihood: int
    impact: int
    stride: str             # letters, e.g. "TE"
    owasp: str              # OWASP LLM Top 10 2025 ids
    message: str
    fix: str
    status: str = "open"    # open | accepted

    @property
    def title(self) -> str:
        return RULES[self.rule]

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def severity(self) -> str:
        return severity(self.likelihood, self.impact)


# --------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------


def taint_origins(design: Design) -> dict[str, set[str]]:
    """Which untrusted sources can influence each component (transitively).

    Sources: every component in an 'untrusted' zone, and every 'external_source'.
    Controls on a flow do NOT stop taint - there is no sanitizer for natural language.
    """
    origins: dict[str, set[str]] = defaultdict(set)
    for c in design.components:
        if design.trust(c.id) == TRUST["untrusted"] or c.type == "external_source":
            origins[c.id].add(c.id)
    changed = True
    while changed:
        changed = False
        for f in design.flows:
            new = origins[f.source] - origins[f.target]
            if new:
                origins[f.target] |= new
                changed = True
    return origins


def _has(flow: Flow, *controls: str) -> bool:
    return any(c in flow.controls for c in controls)


def analyze(design: Design, today: date | None = None) -> list[Finding]:
    today = today or date.today()
    tainted = taint_origins(design)
    findings: list[Finding] = []
    add = findings.append

    for f in design.flows:
        src, dst = design.comp(f.source), design.comp(f.target)

        if src.type == "actor" and not _has(f, "authn"):
            add(Finding("AUTH-001", f.id, 4, 4, "S", "-",
                        f"{src.id} reaches {dst.id} without authentication.",
                        "Require authn (SSO/OIDC) at the first hop; derive identity server-side."))

        if src.type in ("actor", "external_source") and not _has(f, "rate_limit"):
            add(Finding("DOS-001", f.id, 3, 3, "D", "LLM10",
                        f"No rate limit on the entry point {src.id} -> {dst.id}.",
                        "Add per-user, per-sender and per-tenant rate limits at the gateway."))

        privileged_target = dst.side_effects or design.trust(dst.id) == TRUST["privileged"]
        if tainted[src.id] and privileged_target and not _has(f, *HARD_GATES):
            impact = 5 if {"external_comms", "payment", "delete"} & set(dst.capabilities) else 4
            soft = [c for c in f.controls if CONTROLS[c] == "soft"]
            note = f" Soft controls present ({', '.join(soft)}) do not count." if soft else ""
            add(Finding("TB-001", f.id, 4, impact, "TE", "LLM01, LLM06",
                        f"Content from {sorted(tainted[src.id])} can drive {dst.id} with no hard gate.{note}",
                        "Add tool_authz (server-side policy with the user's permissions) and "
                        "human_approval for high-impact actions."))

        if src.type == "model" and dst.type != "model":
            need = "output_encoding" if dst.type == "ui" else "schema_validation"
            if not _has(f, need):
                add(Finding("OUT-001", f.id, 4, 4, "TE", "LLM05",
                            f"Output of {src.id} reaches {dst.id} without {need}.",
                            "Treat model output as untrusted input: validate against a strict "
                            "schema before tools; encode before rendering."))

        if src.type == "model" and dst.type == "tool" and f.identity == "service" \
                and CLASSIFICATION[dst.classification] >= CLASSIFICATION["confidential"]:
            add(Finding("ID-001", f.id, 3, 5, "E", "LLM06",
                        f"{dst.id} runs with a shared service identity, not the end user's.",
                        "Call tools on behalf of the user (delegated, scoped token) so the "
                        "backend enforces the user's own permissions."))

        sensitive = CLASSIFICATION[f.classification] >= CLASSIFICATION["confidential"]
        if src.type in ("vector_store", "datastore") and sensitive:
            missing = [c for c in ("acl_filter",) + (("tenant_filter",) if src.multi_tenant else ())
                       if c not in f.controls]
            if missing:
                add(Finding("RAG-001", f.id, 4, 5, "I", "LLM02, LLM08",
                            f"{src.id} -> {dst.id} returns {f.classification} chunks without "
                            f"{', '.join(missing)}. Similarity is not authorization.",
                            "Filter by tenant and ACL inside the query, using the server-side "
                            "identity, before ranking."))

        # "Less trusted" = below the source AND outside our own trusted zones
        # (a database feeding our own backend is normal; feeding a log platform is not).
        less_trusted = design.trust(dst.id) < min(design.trust(src.id), TRUST["trusted"])
        if sensitive and less_trusted and not _has(f, "redaction", "dpa"):
            add(Finding("DATA-001", f.id, 3, 4, "I", "LLM02",
                        f"{f.classification} data ({f.data}) flows from a more-trusted zone to "
                        f"{dst.id} without redaction or a data-processing agreement.",
                        "Redact or minimize before sending; for model providers, use a contract "
                        "with no training on your data and a short retention period."))

        if dst.type == "model" and f.contains_secrets:
            add(Finding("SEC-001", f.id, 4, 4, "I", "LLM07",
                        f"{f.id} puts a secret into the prompt of {dst.id}.",
                        "Keep secrets in server-side config; the prompt is not a vault."))

        if dst.type == "tool" and dst.side_effects and not _has(f, "audit_log"):
            add(Finding("REP-001", f.id, 3, 3, "R", "-",
                        f"Calls to {dst.id} ({', '.join(dst.capabilities)}) are not audit-logged.",
                        "Log who, on whose behalf, which tool, which arguments, which decision."))

    # Catch-all: every boundary needs at least one enforced rule. Flows already flagged
    # by a more specific rule are skipped to keep the report short.
    flagged = {f.target for f in findings if f.rule not in ("DOS-001", "REP-001")}
    for f in design.flows:
        crosses = design.comp(f.source).zone != design.comp(f.target).zone
        hard = [c for c in f.controls if CONTROLS[c] == "hard"]
        if crosses and not hard and f.id not in flagged:
            soft = [c for c in f.controls if CONTROLS[c] != "hard"]
            add(Finding("TB-002", f.id, 3, 3, "STI", "-",
                        f"{f.source} -> {f.target} crosses a trust boundary with no hard control"
                        + (f" (only {', '.join(soft)})." if soft else "."),
                        "Give every boundary an enforced rule: authenticate, authorize, validate, "
                        "encrypt (TLS), constrain or reject."))

    for m in (c for c in design.components if c.type == "model"):
        inbound = [f for f in design.flows if f.target == m.id]
        if not any(_has(f, "token_budget") for f in inbound):
            add(Finding("DOS-001", m.id, 3, 3, "D", "LLM10",
                        f"No token budget on any request to {m.id}.",
                        "Cap input and output tokens per request and per user per day."))
        tri = trifecta(design, m.id, tainted)
        if tri["private"] and tri["untrusted"] and tri["channels"]:
            ungated = [c for c in tri["channels"] if not c.endswith("(approval)")]
            likelihood = 5 if ungated else 3
            add(Finding("TRI-001", m.id, likelihood, 5, "I", "LLM01, LLM02, LLM06",
                        f"{m.id} has private data {tri['private']}, untrusted content from "
                        f"{tri['untrusted']} and exfiltration channels {tri['channels']}.",
                        "Remove one leg: no external channel for this model, or no private data, "
                        "or no untrusted content. Gating a channel only lowers likelihood."))

    for f in findings:  # apply risk acceptances that are still valid
        for a in design.accepted_risks:
            if a.rule == f.rule and a.target == f.target and a.expires >= today:
                f.status = "accepted"
    return findings


def trifecta(design: Design, model_id: str, tainted: dict[str, set[str]] | None = None) -> dict:
    """Return the three legs of the lethal trifecta for one model component."""
    tainted = tainted if tainted is not None else taint_origins(design)
    inbound = [f for f in design.flows if f.target == model_id]
    outbound = [f for f in design.flows if f.source == model_id]
    private = sorted(f.id for f in inbound
                     if CLASSIFICATION[f.classification] >= CLASSIFICATION["confidential"])
    channels = []
    for f in outbound:
        dst = design.comp(f.target)
        if dst.type == "tool" and "external_comms" in dst.capabilities \
                and not _has(f, "egress_allowlist"):
            channels.append(f"{dst.id}(approval)" if _has(f, "human_approval") else dst.id)
        if dst.type == "ui" and dst.renders_markdown and not _has(f, "url_allowlist"):
            channels.append(f"{dst.id}:markdown-images")
    return {"private": private, "untrusted": sorted(tainted[model_id]), "channels": channels}


# --------------------------------------------------------------------------------------
# STRIDE-per-element candidate generation
# --------------------------------------------------------------------------------------

STRIDE_NAMES = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Information disclosure", "D": "Denial of service",
                "E": "Elevation of privilege"}

# Which STRIDE categories apply to which element type (Microsoft STRIDE-per-element, adapted).
ELEMENT_STRIDE = {
    "actor": "SR", "external_source": "ST",
    "ui": "STRIDE", "service": "STRIDE", "model": "STRIDE", "tool": "STRIDE",
    "datastore": "TID", "vector_store": "TID", "log": "TRID",
}

# AI-flavoured wording. Generic wording is used for anything not listed.
TEMPLATES = {
    ("model", "S"): "A fake model endpoint (wrong base URL or key) returns attacker-chosen output.",
    ("model", "T"): "Prompt injection or poisoned context changes what {id} says or does.",
    ("model", "R"): "No record of prompt, context, model version and output for {id}.",
    ("model", "I"): "{id} reveals its system prompt, other users' context or training data.",
    ("model", "D"): "Huge, looping or many-shot prompts exhaust tokens, quota and budget of {id}.",
    ("model", "E"): "Output of {id} triggers actions beyond the end user's own permissions.",
    ("vector_store", "T"): "Poisoned or keyword-stuffed chunks are written into {id}.",
    ("vector_store", "I"): "{id} returns chunks across tenants or ACLs; embeddings can be inverted.",
    ("vector_store", "D"): "Bulk ingestion or expensive queries degrade {id}.",
    ("tool", "S"): "A look-alike or swapped tool definition is registered instead of {id}.",
    ("tool", "T"): "Model-chosen arguments to {id} carry injection (SQL, path, URL, shell).",
    ("tool", "E"): "{id} runs with more privilege than the user (shared token, broad scope).",
    ("external_source", "T"): "{id} carries hidden instructions (indirect prompt injection).",
    ("log", "I"): "{id} stores prompts, outputs or secrets readable by too many people.",
}

MITIGATES = {
    "S": {"authn", "tls", "integrity_check"},
    "T": {"schema_validation", "tool_authz", "tls", "integrity_check", "authz"},
    "R": {"audit_log"},
    "I": {"acl_filter", "tenant_filter", "redaction", "tls", "output_encoding",
          "egress_allowlist", "url_allowlist", "dpa"},
    "D": {"rate_limit", "token_budget"},
    "E": {"tool_authz", "authz", "human_approval", "sandbox"},
}


@dataclass
class StrideThreat:
    element: str
    category: str
    text: str
    controls: list[str] = field(default_factory=list)  # mapped controls on touching flows


def stride_candidates(design: Design) -> list[StrideThreat]:
    out = []
    for c in design.components:
        touching = {ctl for f in design.flows if c.id in (f.source, f.target) for ctl in f.controls}
        for cat in ELEMENT_STRIDE[c.type]:
            text = TEMPLATES.get((c.type, cat),
                                 f"{STRIDE_NAMES[cat]} against {{id}} ({c.type}).").format(id=c.id)
            out.append(StrideThreat(c.id, cat, text, sorted(touching & MITIGATES[cat])))
    for f in design.flows:
        for cat in "TID":
            out.append(StrideThreat(f.id, cat, f"{STRIDE_NAMES[cat]} on flow {f.id} ({f.data}).",
                                    sorted(set(f.controls) & MITIGATES[cat])))
    return out


# --------------------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------------------

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def report(design: Design, today: date | None = None) -> str:
    findings = sorted(analyze(design, today), key=lambda f: (ORDER[f.severity], f.rule, f.target))
    lines = [f"Threat model: {design.name}", "=" * 78]
    for f in findings:
        tag = "" if f.status == "open" else " [ACCEPTED]"
        lines.append(f"[{f.severity.upper():8}] {f.rule:8} {f.target:20} score {f.score:2}  "
                     f"STRIDE {f.stride:3} OWASP {f.owasp}{tag}")
        lines.append(f"           {f.message}")
        lines.append(f"           fix: {f.fix}")
    open_ = [f for f in findings if f.status == "open"]
    counts = {s: sum(f.severity == s for f in open_) for s in ORDER}
    lines.append("-" * 78)
    lines.append(f"open findings: {len(open_)}  " + "  ".join(f"{k}={v}" for k, v in counts.items())
                 + f"  accepted: {len(findings) - len(open_)}")
    stride = stride_candidates(design)
    uncovered = sum(not t.controls for t in stride)
    lines.append(f"STRIDE candidates for human review: {len(stride)} "
                 f"({uncovered} with no mapped control - start there)")
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Requirements: every rule traces to one testable requirement (lesson 04)
# --------------------------------------------------------------------------------------

REQUIREMENTS: dict[str, tuple[str, str, str]] = {
    # rule: (requirement id, requirement text, how to verify it)
    "AUTH-001": ("REQ-ID-01", "Every human entry point MUST authenticate the user (SSO) before any AI call.",
                 "test: an unauthenticated request gets 401 and no model call is made"),
    "ID-001": ("REQ-ID-02", "Tools MUST run with the end user's delegated, scoped identity, never a shared "
               "service account.", "test: a user without CRM access gets 403 through the tool"),
    "TB-001": ("REQ-TOOL-01", "Side-effecting tools MUST be authorized by server-side policy with the user's "
               "permissions; high-impact actions MUST need human approval of the exact arguments.",
               "test: an injected tool call from untrusted content executes nothing"),
    "TB-002": ("REQ-BND-01", "Every trust-boundary crossing MUST have at least one enforced control.",
               "CI: this analyzer reports no TB-002"),
    "OUT-001": ("REQ-OUT-01", "Model output MUST pass a strict schema before tool use and be encoded "
                "before rendering.", "test: extra fields are rejected; <script> renders as text"),
    "RAG-001": ("REQ-RAG-01", "Retrieval MUST filter by tenant and ACL from the verified session, inside "
                "the query, before ranking.", "test: cross-tenant canary queries return 0 foreign chunks"),
    "DATA-001": ("REQ-DATA-01", "Confidential data MUST be redacted, or covered by a data-processing "
                 "agreement, before it leaves trusted zones.", "test: canary PII never appears in logs"),
    "SEC-001": ("REQ-SEC-01", "Secrets MUST NOT be placed in prompts.",
                "test: scanning every rendered prompt finds no secret or canary"),
    "DOS-001": ("REQ-COST-01", "Every entry point MUST be rate limited and every model call MUST have a "
                "token budget.", "test: 1,000 oversized requests are mostly rejected; spend is capped"),
    "REP-001": ("REQ-LOG-01", "Every side-effecting tool call MUST be audit-logged: user, tool, "
                "arguments, decision.", "test: each executed call has exactly one audit record"),
    "TRI-001": ("REQ-ARCH-01", "A model context MUST NOT combine private data, untrusted content and an "
                "external channel.", "CI: this analyzer reports no TRI-001"),
}


def requirements(design: Design, today: date | None = None) -> list[tuple[str, str, str, list[str]]]:
    """Open findings grouped into requirements: (req id, text, verification, finding targets)."""
    targets: dict[str, list[str]] = defaultdict(list)
    for f in analyze(design, today):
        if f.status == "open":
            targets[f.rule].append(f.target)
    out = []
    for rule, tgts in targets.items():
        req_id, text, verify = REQUIREMENTS[rule]
        out.append((req_id, text, verify, sorted(set(tgts))))
    return sorted(out)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print("usage: python threat_model.py <design.yaml> [--requirements]")
        return 2
    design = load_design(args[0])
    if "--requirements" in argv:
        reqs = requirements(design)
        print(f"Security requirements derived from open findings: {design.name}")
        for req_id, text, verify, tgts in reqs:
            print(f"{req_id:12} {text}\n{'':12} verify: {verify}\n{'':12} applies to: {', '.join(tgts)}")
        print(f"{len(reqs)} requirement(s)")
    else:
        print(report(design))
    # Exit code 1 = open high/critical risk: use it as a CI gate.
    return 1 if any(f.status == "open" and f.severity in ("critical", "high")
                    for f in analyze(design)) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
