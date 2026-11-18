"""Architecture-as-code reviewer for enterprise AI platforms.

An AI platform deployment is described in YAML (components, identities, keys, logging,
data flows). This reviewer checks it against the multi-cloud control matrix in
``control_matrix.yaml`` and reports gaps with a severity and a cloud-specific fix.

Run it from the repository root:

    python 09-enterprise-architecture/lab/reviewer.py 09-enterprise-architecture/lab/architectures/vulnerable_aws.yaml

The exit code is 1 when the review gate fails (any open critical or high finding), so
the same script can block a pull request in CI.

Design choices worth noticing (they are the lesson, not just the code):

* **Fail closed on unknown keys.** A typo such as ``public_network_acess: false`` would
  otherwise be ignored and the reviewer would think the setting is missing or fine.
  The pydantic models use ``extra="forbid"``, so a typo is a hard error.
* **Insecure defaults.** If a setting is not written down, the reviewer assumes the
  common cloud default, which is usually the *less* secure option (public access on,
  provider-managed keys, open egress). Security must be explicit.
* **Graph checks, not only attribute checks.** ``gateway_chokepoint`` walks the data
  flows to find any path from the internet to a model, RAG service, agent or tool that
  skips the AI gateway. A single "debug" route is enough to fail the review.
* **Time-bound exceptions.** A failed control can be risk-accepted with an approver and
  an expiry date. Expired exceptions stop counting. Critical findings cannot be accepted.
"""

from __future__ import annotations

import csv
import io
import sys
from collections import deque
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

HERE = Path(__file__).resolve().parent
MATRIX_PATH = HERE / "control_matrix.yaml"
ARCH_DIR = HERE / "architectures"
CLOUDS = ("aws", "azure", "gcp")
SEVERITIES = ("critical", "high", "medium", "low")
GATE_BLOCKING = {"critical", "high"}
INTERNET = "internet"


# =========================================================================== models
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Guardrails(Strict):
    input: list[str] = []
    output: list[str] = []


class Limits(Strict):
    max_steps: int | None = None
    max_cost_usd: float | None = None


class DataUse(Strict):
    training_opt_out: bool = False
    retention_reviewed: bool = False


ComponentType = Literal[
    "frontend", "ai_gateway", "model_endpoint", "rag_service", "vector_store",
    "object_store", "mcp_gateway", "tool", "agent_runtime", "log_store",
]


class Component(Strict):
    id: str
    type: ComponentType
    zone: Literal["public", "app", "model", "data", "tools", "security"] = "app"
    service: str = ""
    identity: str | None = None
    # Insecure defaults on purpose: unspecified means "the cloud default".
    public_network_access: bool = True
    private_endpoint: bool = False
    encryption_key: str | None = None  # None = provider-managed key
    user_auth: Literal["oidc", "saml", "api_key", "none"] = "none"
    rate_limits: bool = False
    token_budget: bool = False
    guardrails: Guardrails = Guardrails()
    retrieval_authz: Literal["server_side", "prompt_only", "none"] = "none"
    tenant_isolation: Literal["per_tenant_index", "server_side_filter", "none"] = "none"
    tool_registry: Literal["allowlist", "open"] = "open"
    approval_required_for: list[Literal["read", "write"]] = []
    limits: Limits = Limits()
    kill_switch: bool = False
    egress: Literal["deny_by_default", "allow_all"] = "allow_all"
    data_use: DataUse = DataUse()
    side_effects: Literal["read", "write"] = "read"
    immutable: bool = False
    retention_days: int = 30
    exports_to_siem: bool = False
    # Gateway settings. Unspecified routing = any model name is passed through.
    model_routing: Literal["allowlist", "open"] = "open"
    cache_scope: Literal["per_tenant", "global", "none"] = "none"
    # How an agent or tool gateway authenticates to downstream services.
    downstream_auth: Literal["token_exchange", "own_identity", "passthrough"] = "passthrough"


class Identity(Strict):
    id: str
    kind: Literal["workload", "agent", "mcp_server", "ci", "human"] = "workload"
    credential: Literal["short_lived", "static_key"] = "static_key"
    permissions: list[str] = []
    owner: str | None = None  # accountable human or team for this identity


class Key(Strict):
    id: str
    managed_by: Literal["customer", "provider"] = "provider"
    rotation: bool = False


class Secrets(Strict):
    store: str | None = None
    inline: list[str] = []  # secrets found in config, env vars, images or prompts


class Logging(Strict):
    control_plane_audit: bool = False
    model_invocation_logs: bool = False
    prompt_redaction: bool = False
    sink: str | None = None


class Flow(Strict):
    source: str = Field(alias="from")
    to: str
    note: str = ""


class RiskException(Strict):
    control: str
    reason: str
    approver: str
    expires: date


class Assessment(Strict):
    """How the running platform is re-assessed after go-live (continuous assessment)."""
    redteam_schedule: Literal["daily", "weekly", "monthly", "none"] = "none"
    redteam_on_change: bool = False  # model, prompt or tool change re-runs the attack suite
    drift_detection: bool = False    # declared design is compared with the observed system


class Architecture(Strict):
    name: str
    cloud: Literal["aws", "azure", "gcp"]
    environment: Literal["dev", "test", "prod"] = "prod"
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    multi_tenant: bool = False
    components: list[Component]
    identities: list[Identity] = []
    keys: list[Key] = []
    secrets: Secrets = Secrets()
    logging: Logging = Logging()
    flows: list[Flow] = []
    exceptions: list[RiskException] = []
    assessment: Assessment = Assessment()

    @model_validator(mode="after")
    def _references_must_resolve(self) -> "Architecture":
        """Dangling references are errors: a flow to a missing component hides a gap."""
        comp_ids = [c.id for c in self.components]
        if len(comp_ids) != len(set(comp_ids)):
            raise ValueError("component ids must be unique")
        ident_ids = {i.id for i in self.identities}
        key_ids = {k.id for k in self.keys}
        for c in self.components:
            if c.identity and c.identity not in ident_ids:
                raise ValueError(f"component {c.id!r} uses unknown identity {c.identity!r}")
            if c.encryption_key and c.encryption_key not in key_ids:
                raise ValueError(f"component {c.id!r} uses unknown key {c.encryption_key!r}")
        known = set(comp_ids) | {INTERNET}
        for f in self.flows:
            for end in (f.source, f.to):
                if end not in known:
                    raise ValueError(f"flow {f.source}->{f.to} references unknown node {end!r}")
        if self.logging.sink and self.logging.sink not in comp_ids:
            raise ValueError(f"logging sink {self.logging.sink!r} is not a component")
        return self

    # helpers used by the checks
    def of_type(self, *types: str) -> list[Component]:
        return [c for c in self.components if c.type in types]

    def component(self, cid: str) -> Component | None:
        return next((c for c in self.components if c.id == cid), None)

    def key(self, kid: str | None) -> Key | None:
        return next((k for k in self.keys if k.id == kid), None)


class CloudMapping(Strict):
    services: str
    evidence: str


class Control(Strict):
    id: str
    family: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    responsibility: Literal["customer", "shared", "provider"]
    check: str
    owasp_llm: list[str] = []  # OWASP Top 10 for LLM Applications, 2026 numbering
    owasp_asi: list[str] = []  # OWASP Top 10 for Agentic Applications 2026
    owasp_mcp: list[str] = []  # OWASP MCP Top 10 (beta)
    cis_v8: list[int] = []
    outcome: str
    clouds: dict[str, CloudMapping]


# ======================================================================== loading
def parse_matrix(data: dict) -> list[Control]:
    return [Control.model_validate(c) for c in data["controls"]]


def load_matrix(path: Path | str = MATRIX_PATH) -> list[Control]:
    return parse_matrix(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def load_architecture(path: Path | str) -> Architecture:
    return Architecture.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def parse_architecture(data: dict) -> Architecture:
    return Architecture.model_validate(data)


# ========================================================================= checks
@dataclass
class CheckResult:
    status: Literal["pass", "fail", "n/a"]
    detail: str = ""


CHECKS: dict[str, Callable[[Architecture], CheckResult]] = {}


def check(fn: Callable[[Architecture], CheckResult]) -> Callable[[Architecture], CheckResult]:
    CHECKS[fn.__name__] = fn
    return fn


def _result(problems: list[str], ok_detail: str = "") -> CheckResult:
    return CheckResult("fail", "; ".join(problems)) if problems else CheckResult("pass", ok_detail)


RUNTIME_TYPES = ("ai_gateway", "rag_service", "mcp_gateway", "agent_runtime")
DATA_STORE_TYPES = ("vector_store", "object_store", "log_store")


@check
def short_lived_credentials(a: Architecture) -> CheckResult:
    if not a.identities:
        return CheckResult("fail", "no identities declared: who does each component run as?")
    bad = [i.id for i in a.identities if i.credential != "short_lived"]
    return _result([f"static credentials: {', '.join(bad)}"] if bad else [])


BROAD_ROLES = {"owner", "admin", "administrator", "editor", "contributor",
               "roles/owner", "roles/editor", "administratoraccess"}


def is_broad(permission: str) -> bool:
    """'bedrock:*' or 'Owner' is broad. A wildcard in the *resource* part
    ('CreateChangeSet on ops-assistant-*') is a naming pattern, not a broad action."""
    action = permission.split(" on ")[0].strip()
    return "*" in action or action.lower() in BROAD_ROLES


@check
def least_privilege(a: Architecture) -> CheckResult:
    problems = []
    for i in a.identities:
        wild = [p for p in i.permissions if is_broad(p)]
        if wild:
            problems.append(f"{i.id} has broad permissions {wild}")
    return _result(problems)


@check
def identity_per_component(a: Architecture) -> CheckResult:
    runtimes = a.of_type(*RUNTIME_TYPES)
    if not runtimes:
        return CheckResult("n/a", "no runtime components")
    problems = [f"{c.id} has no identity" for c in runtimes if not c.identity]
    users: dict[str, list[str]] = {}
    for c in a.components:
        if c.identity:
            users.setdefault(c.identity, []).append(c.id)
    problems += [f"identity {i} shared by {', '.join(cs)}" for i, cs in users.items() if len(cs) > 1]
    return _result(problems)


@check
def user_authentication(a: Architecture) -> CheckResult:
    gateways = a.of_type("ai_gateway")
    if not gateways:
        return CheckResult("fail", "no AI gateway: nowhere to authenticate users")
    bad = [f"{g.id} user_auth={g.user_auth}" for g in gateways if g.user_auth not in ("oidc", "saml")]
    return _result(bad)


@check
def identity_ownership(a: Architecture) -> CheckResult:
    """Non-human identities (workloads, agents, MCP servers, CI) need an accountable owner."""
    nhis = [i for i in a.identities if i.kind != "human"]
    if not nhis:
        return CheckResult("n/a", "no non-human identities declared")
    orphans = [i.id for i in nhis if not (i.owner and i.owner.strip())]
    return _result([f"no owner: {', '.join(orphans)}"] if orphans else [])


@check
def no_token_passthrough(a: Architecture) -> CheckResult:
    """Agents and tool gateways must not forward the user's token (confused deputy, MCP01)."""
    actors = a.of_type("agent_runtime", "mcp_gateway")
    if not actors:
        return CheckResult("n/a", "no agents or tool gateways")
    return _result([f"{c.id} forwards the user's token (downstream_auth=passthrough)"
                    for c in actors if c.downstream_auth == "passthrough"])


@check
def private_model_endpoint(a: Architecture) -> CheckResult:
    models = a.of_type("model_endpoint")
    if not models:
        return CheckResult("n/a", "no model endpoint")
    problems = []
    for m in models:
        if m.public_network_access:
            problems.append(f"{m.id} public network access is on")
        if not m.private_endpoint:
            problems.append(f"{m.id} has no private endpoint")
    return _result(problems)


@check
def private_data_stores(a: Architecture) -> CheckResult:
    stores = a.of_type(*DATA_STORE_TYPES)
    if not stores:
        return CheckResult("n/a", "no data stores")
    problems = [f"{s.id} is publicly reachable" for s in stores if s.public_network_access]
    problems += [f"{s.id} has no private endpoint" for s in stores
                 if s.type != "log_store" and not s.private_endpoint]
    return _result(problems)


@check
def egress_control(a: Architecture) -> CheckResult:
    actors = a.of_type("agent_runtime", "mcp_gateway", "tool")
    if not actors:
        return CheckResult("n/a", "no agents or tools")
    return _result([f"{c.id} egress={c.egress}" for c in actors if c.egress != "deny_by_default"])


def reachable_avoiding(a: Architecture, start: str, avoid_types: Iterable[str]) -> set[str]:
    """Nodes reachable from ``start`` along data flows without passing an ``avoid_types`` node."""
    avoid = set(avoid_types)
    graph: dict[str, list[str]] = {}
    for f in a.flows:
        graph.setdefault(f.source, []).append(f.to)
    seen, queue = {start}, deque([start])
    while queue:
        node = queue.popleft()
        for nxt in graph.get(node, []):
            comp = a.component(nxt)
            if nxt in seen or (comp and comp.type in avoid):
                continue
            seen.add(nxt)
            queue.append(nxt)
    seen.discard(start)
    return seen


@check
def gateway_chokepoint(a: Architecture) -> CheckResult:
    if not a.of_type("ai_gateway"):
        return CheckResult("fail", "no AI gateway in the architecture")
    protected = {"model_endpoint", "rag_service", "vector_store", "agent_runtime", "mcp_gateway", "tool"}
    leaks = sorted(n for n in reachable_avoiding(a, INTERNET, {"ai_gateway"})
                   if (c := a.component(n)) and c.type in protected)
    if leaks:
        return CheckResult("fail", f"reachable from the internet without the AI gateway: {', '.join(leaks)}")
    return CheckResult("pass")


def _confidential(a: Architecture) -> bool:
    return a.data_classification in ("confidential", "restricted")


@check
def customer_managed_keys(a: Architecture) -> CheckResult:
    if not _confidential(a):
        return CheckResult("n/a", f"data classification is {a.data_classification}")
    problems = []
    for s in a.of_type(*DATA_STORE_TYPES):
        k = a.key(s.encryption_key)
        if k is None or k.managed_by != "customer":
            problems.append(f"{s.id} uses a provider-managed key")
    return _result(problems)


@check
def key_rotation(a: Architecture) -> CheckResult:
    cmks = [k for k in a.keys if k.managed_by == "customer"]
    if not cmks:
        return CheckResult("n/a", "no customer-managed keys")
    return _result([f"{k.id} rotation off" for k in cmks if not k.rotation])


@check
def tenant_isolation(a: Architecture) -> CheckResult:
    if not a.multi_tenant:
        return CheckResult("n/a", "single tenant")
    problems = [f"{r.id} retrieval_authz={r.retrieval_authz}" for r in a.of_type("rag_service")
                if r.retrieval_authz != "server_side"]
    problems += [f"{v.id} tenant_isolation={v.tenant_isolation}" for v in a.of_type("vector_store")
                 if v.tenant_isolation == "none"]
    return _result(problems)


@check
def provider_data_terms(a: Architecture) -> CheckResult:
    models = a.of_type("model_endpoint")
    if not models:
        return CheckResult("n/a", "no model endpoint")
    problems = []
    for m in models:
        if not m.data_use.training_opt_out:
            problems.append(f"{m.id}: training use not confirmed off")
        if not m.data_use.retention_reviewed:
            problems.append(f"{m.id}: prompt retention not reviewed")
    return _result(problems)


@check
def input_guardrails(a: Architecture) -> CheckResult:
    gws = a.of_type("ai_gateway")
    if not gws:
        return CheckResult("fail", "no AI gateway to host guardrails")
    return _result([f"{g.id} has no prompt_attack input filter" for g in gws
                    if "prompt_attack" not in g.guardrails.input])


@check
def output_guardrails(a: Architecture) -> CheckResult:
    gws = a.of_type("ai_gateway")
    if not gws:
        return CheckResult("fail", "no AI gateway to host guardrails")
    need = {"pii", "secrets"}
    return _result([f"{g.id} output filters missing {sorted(need - set(g.guardrails.output))}"
                    for g in gws if not need <= set(g.guardrails.output)])


@check
def model_routing(a: Architecture) -> CheckResult:
    gws = a.of_type("ai_gateway")
    if not gws:
        return CheckResult("fail", "no AI gateway to route models")
    return _result([f"{g.id} model_routing={g.model_routing} (any model name is passed through)"
                    for g in gws if g.model_routing != "allowlist"])


@check
def cache_isolation(a: Architecture) -> CheckResult:
    gws = a.of_type("ai_gateway")
    if not gws:
        return CheckResult("fail", "no AI gateway")
    if all(g.cache_scope == "none" for g in gws):
        return CheckResult("n/a", "no response cache")
    return _result([f"{g.id} cache_scope=global (answers can cross tenants)"
                    for g in gws if g.cache_scope == "global"])


@check
def tool_gateway(a: Architecture) -> CheckResult:
    tools, agents = a.of_type("tool"), a.of_type("agent_runtime")
    if not tools and not agents:
        return CheckResult("n/a", "no tools or agents")
    problems = [f"{g.id} registry={g.tool_registry}" for g in a.of_type("mcp_gateway")
                if g.tool_registry != "allowlist"]
    if tools and not a.of_type("mcp_gateway"):
        problems.append("tools exist but there is no MCP/tool gateway")
    for ag in agents:
        direct = sorted(n for n in reachable_avoiding(a, ag.id, {"mcp_gateway"})
                        if (c := a.component(n)) and c.type == "tool")
        if direct:
            problems.append(f"{ag.id} reaches tools without the gateway: {', '.join(direct)}")
    return _result(problems)


@check
def human_approval(a: Architecture) -> CheckResult:
    agents = a.of_type("agent_runtime")
    if not agents:
        return CheckResult("n/a", "no agents")
    writes = [t for t in a.of_type("tool") if t.side_effects == "write"]
    if not writes:
        return CheckResult("n/a", "no write tools")
    return _result([f"{ag.id} runs write tools without approval" for ag in agents
                    if "write" not in ag.approval_required_for])


@check
def agent_limits(a: Architecture) -> CheckResult:
    agents = a.of_type("agent_runtime")
    if not agents:
        return CheckResult("n/a", "no agents")
    problems = []
    for ag in agents:
        if ag.limits.max_steps is None:
            problems.append(f"{ag.id} has no max_steps")
        if ag.limits.max_cost_usd is None:
            problems.append(f"{ag.id} has no max_cost_usd")
        if not ag.kill_switch:
            problems.append(f"{ag.id} has no kill switch")
    return _result(problems)


@check
def audit_logging(a: Architecture) -> CheckResult:
    lg, problems = a.logging, []
    if not lg.control_plane_audit:
        problems.append("control-plane audit off")
    if not lg.model_invocation_logs:
        problems.append("model invocation logs off")
    sink = a.component(lg.sink) if lg.sink else None
    if sink is None:
        problems.append("no central log sink")
    elif not sink.exports_to_siem:
        problems.append(f"{sink.id} is not exported to the SIEM")
    return _result(problems)


@check
def log_protection(a: Architecture) -> CheckResult:
    problems = [] if a.logging.prompt_redaction else ["prompts are logged without redaction"]
    stores = a.of_type("log_store")
    if not stores:
        problems.append("no log store")
    for s in stores:
        if not s.immutable:
            problems.append(f"{s.id} is not immutable")
        if s.retention_days < 365:
            problems.append(f"{s.id} retention {s.retention_days}d < 365d")
    return _result(problems)


@check
def abuse_limits(a: Architecture) -> CheckResult:
    gws = a.of_type("ai_gateway")
    if not gws:
        return CheckResult("fail", "no AI gateway to enforce limits")
    problems = []
    for g in gws:
        if not g.rate_limits:
            problems.append(f"{g.id} has no rate limits")
        if not g.token_budget:
            problems.append(f"{g.id} has no token budget")
    return _result(problems)


@check
def continuous_assessment(a: Architecture) -> CheckResult:
    s, problems = a.assessment, []
    if s.redteam_schedule == "none":
        problems.append("no scheduled red-team run")
    if not s.redteam_on_change:
        problems.append("model/prompt/tool changes do not re-run the attack suite")
    if not s.drift_detection:
        problems.append("no drift detection between design and running system")
    return _result(problems)


@check
def secrets_management(a: Architecture) -> CheckResult:
    problems = [f"inline secret: {s}" for s in a.secrets.inline]
    if not a.secrets.store:
        problems.append("no secrets manager declared")
    return _result(problems)


# ========================================================================= review
@dataclass
class Finding:
    control_id: str
    family: str
    title: str
    severity: str
    status: Literal["PASS", "FAIL", "ACCEPTED", "N/A"]
    detail: str
    remediation: str


@dataclass
class Report:
    architecture: str
    cloud: str
    findings: list[Finding] = field(default_factory=list)

    def by_status(self, status: str) -> list[Finding]:
        return [f for f in self.findings if f.status == status]

    def status_of(self, control_id: str) -> str:
        return next(f.status for f in self.findings if f.control_id == control_id)

    @property
    def open_findings(self) -> list[Finding]:
        return self.by_status("FAIL")

    @property
    def gate_passed(self) -> bool:
        return not any(f.severity in GATE_BLOCKING for f in self.open_findings)

    def counts(self) -> dict[str, int]:
        return {s: sum(1 for f in self.open_findings if f.severity == s) for s in SEVERITIES}


def _apply_exception(a: Architecture, ctrl: Control, finding: Finding, today: date) -> Finding:
    exc = next((e for e in a.exceptions if e.control == ctrl.id), None)
    if exc is None:
        return finding
    if ctrl.severity == "critical":
        finding.detail += f" | exception by {exc.approver} rejected: critical findings cannot be risk-accepted"
    elif exc.expires < today:
        finding.detail += f" | exception by {exc.approver} EXPIRED on {exc.expires.isoformat()}"
    else:
        finding.status = "ACCEPTED"
        finding.detail += f" | accepted by {exc.approver} until {exc.expires.isoformat()}: {exc.reason}"
    return finding


def review(
    arch: Architecture,
    matrix: list[Control] | None = None,
    *,
    today: date | None = None,
    families: Iterable[str] | None = None,
) -> Report:
    """Run every control in the matrix (optionally only some families) against ``arch``."""
    matrix = matrix if matrix is not None else load_matrix()
    today = today or date.today()
    wanted = set(families) if families else None
    report = Report(arch.name, arch.cloud)
    for ctrl in matrix:
        if wanted and ctrl.family not in wanted:
            continue
        res = CHECKS[ctrl.check](arch)
        status = {"pass": "PASS", "fail": "FAIL", "n/a": "N/A"}[res.status]
        fix = f"On {arch.cloud}: {ctrl.clouds[arch.cloud].services}"
        finding = Finding(ctrl.id, ctrl.family, ctrl.title, ctrl.severity, status, res.detail, fix)
        if status == "FAIL":
            finding = _apply_exception(arch, ctrl, finding, today)
        report.findings.append(finding)
    return report


def format_report(report: Report) -> str:
    lines = [f"Architecture review: {report.architecture} ({report.cloud})", "-" * 78]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for f in sorted(report.findings, key=lambda f: (f.status == "PASS", f.status == "N/A", order[f.severity])):
        lines.append(f"{f.status:8} {f.severity:8} {f.control_id:8} {f.title}")
        if f.status in ("FAIL", "ACCEPTED"):
            lines.append(f"{'':26}why: {f.detail}")
        if f.status == "FAIL":
            lines.append(f"{'':26}fix: {f.remediation}")
    c = report.counts()
    lines.append("-" * 78)
    lines.append(f"open: {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low"
                 f" | accepted: {len(report.by_status('ACCEPTED'))}")
    lines.append(f"GATE: {'PASS' if report.gate_passed else 'FAIL (open critical/high findings)'}")
    return "\n".join(lines)


def export_csv(matrix: list[Control]) -> str:
    """Flatten the matrix for spreadsheets and GRC tools."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "family", "severity", "responsibility", "title", "aws", "azure", "gcp"])
    for c in matrix:
        w.writerow([c.id, c.family, c.severity, c.responsibility, c.title,
                    *(c.clouds[cl].services for cl in CLOUDS)])
    return buf.getvalue()


def main(argv: list[str]) -> int:
    usage = ("usage: python reviewer.py <architecture.yaml> [--today YYYY-MM-DD]\n"
             "       python reviewer.py --csv")
    if len(argv) == 2 and argv[1] == "--csv":
        print(export_csv(load_matrix()), end="")
        return 0
    if len(argv) == 4 and argv[2] == "--today":
        today = date.fromisoformat(argv[3])
    elif len(argv) == 2:
        today = None
    else:
        print(usage)
        return 2
    try:
        arch = load_architecture(argv[1])
    except ValidationError as exc:  # fail closed: a file we cannot fully read is not "passing"
        print(f"INVALID architecture file {argv[1]}:")
        for err in exc.errors():
            print(f"  {'.'.join(str(p) for p in err['loc'])}: {err['msg']}")
        print("GATE: FAIL (fix the file first)")
        return 2
    report = review(arch, today=today)
    print(format_report(report))
    return 0 if report.gate_passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
