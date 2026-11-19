"""pytm-lite: a small, dependency-free imitation of OWASP pytm for learning.

What it copies from pytm (in shape, not in exact API; verify the real API in the pytm README):
  * elements: Actor, Server, Process, Datastore, Dataflow, Boundary, Data
  * elements register themselves into the current TM (``with TM("name") as tm:``)
  * a JSON threat library (id, target types, condition, severity, mitigation)
  * ``tm.process()`` applies the rules and returns findings
  * ``tm.dfd()`` writes Graphviz DOT, ``tm.seq()`` writes a PlantUML sequence diagram
  * ``tm.report(template)`` fills a report template that uses pytm's ``{findings:repeat:...}`` idea

What is different on purpose:
  * conditions use a tiny SAFE expression language instead of Python ``eval``
    (pytm evaluates conditions as Python; fine for its own library, risky for untrusted libraries);
  * every threat carries a ``requirement`` id, so the model produces security requirements too;
  * ``load_model()`` reads a declarative JSON model ("threat model AS code", Threagile style).
"""
from __future__ import annotations

import json
import re
import string
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_LIBRARY = HERE / "fixtures" / "threatlib.json"
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

_CURRENT: list["TM"] = []


# ---------------------------------------------------------------- elements
class Element:
    kind = "Element"
    defaults: dict = {}

    def __init__(self, name: str, inBoundary: "Boundary | None" = None, description: str = "", **attrs):
        self.name = name
        self.inBoundary = inBoundary
        self.description = description
        for k, v in self.defaults.items():
            setattr(self, k, v)
        for k, v in attrs.items():
            if k not in self.defaults:
                raise AttributeError(f"{self.kind} has no attribute {k!r} (typo in the model?)")
            setattr(self, k, v)
        if _CURRENT:
            _CURRENT[-1].add(self)

    def __repr__(self) -> str:
        return f"{self.kind}({self.name!r})"


class Boundary(Element):
    kind = "Boundary"
    defaults = {"trusted": True}


class Actor(Element):
    kind = "Actor"
    defaults = {"isAdmin": False}


class Process(Element):
    kind = "Process"
    defaults = {
        "authenticatesSource": False,
        "hasAccessControl": False,
        "sanitizesInput": False,
        "encodesOutput": False,
        "rendersHTML": False,
        "handlesResourceConsumption": False,
        "logsSecurityEvents": False,
    }


class Server(Process):
    kind = "Server"


class Datastore(Element):
    kind = "Datastore"
    defaults = {"isEncrypted": False, "storesPII": False, "hasAccessControl": False, "isBackedUp": False}


@dataclass
class Data:
    name: str
    classification: str = "PUBLIC"  # PUBLIC, RESTRICTED, SECRET
    isPII: bool = False
    isCredentials: bool = False


class Dataflow(Element):
    kind = "Dataflow"
    defaults = {"protocol": "", "isEncrypted": False, "authenticatesDestination": False, "data": ()}

    def __init__(self, source: Element, sink: Element, name: str, **attrs):
        self.source, self.sink = source, sink
        super().__init__(name, **attrs)

    @property
    def crossesBoundary(self) -> bool:
        return self.source.inBoundary is not self.sink.inBoundary

    @property
    def carriesPII(self) -> bool:
        return any(d.isPII for d in self.data)

    @property
    def carriesCredentials(self) -> bool:
        return any(d.isCredentials for d in self.data)


# ---------------------------------------------------------------- safe conditions
CLAUSE = re.compile(r"^(?P<path>target(?:\.\w+)+)\s+(?P<op>is not|is|==|!=)\s+(?P<lit>.+)$")


def _literal(text: str):
    text = text.strip()
    table = {"True": True, "False": False, "None": None}
    if text in table:
        return table[text]
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    raise ValueError(f"unsupported literal {text!r}")


def _resolve(target, path: str):
    obj = target
    for part in path.split(".")[1:]:
        obj = getattr(obj, part)
    return obj


def evaluate(condition: str, target) -> bool:
    """Evaluate ``clause and clause ...``. Each clause is ``target.a.b <op> <literal>``.

    No eval(): a malicious threat library can only compare attributes, never run code.
    """
    for clause in condition.split(" and "):
        m = CLAUSE.match(clause.strip())
        if not m:
            raise ValueError(f"bad clause {clause!r}")
        try:
            left = _resolve(target, m["path"])
        except AttributeError:
            return False
        right, op = _literal(m["lit"]), m["op"]
        ok = {"is": left is right, "is not": left is not right, "==": left == right, "!=": left != right}[op]
        if not ok:
            return False
    return True


@dataclass(frozen=True)
class Threat:
    sid: str
    targets: tuple[str, ...]
    condition: str
    stride: str
    severity: str
    description: str
    mitigation: str
    requirement: str
    references: str = ""

    def applies(self, element: Element) -> bool:
        kinds = {type(element).__name__} | {c.__name__ for c in type(element).__mro__}
        return bool(kinds & set(self.targets)) and evaluate(self.condition, element)


def load_library(path: Path = DEFAULT_LIBRARY) -> list[Threat]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Threat(sid=t["SID"], targets=tuple(t["target"]), condition=t["condition"], stride=t["stride"],
                   severity=t["severity"], description=t["description"], mitigation=t["mitigation"],
                   requirement=t["requirement"], references=t.get("references", "")) for t in raw]


@dataclass
class Finding:
    sid: str
    target: str
    target_kind: str
    stride: str
    severity: str
    description: str
    mitigation: str
    requirement: str
    references: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.sid, self.target)


# ---------------------------------------------------------------- report formatter
class ReportFormatter(string.Formatter):
    """pytm-style template formatter.

    ``{findings:repeat:- {{item.sid}} {{item.target}}\n}`` repeats the inner text for each item.
    ``{findings_high:if:text}`` prints the text only when the list is not empty.
    ``{findings_high:ifnot:text}`` prints the text only when the list is empty.
    """

    def format_field(self, value, spec):
        if spec.startswith("repeat:"):
            inner = spec[len("repeat:"):]
            return "".join(inner.format(item=item) for item in value)
        if spec.startswith("if:"):
            return spec[3:] if value else ""
        if spec.startswith("ifnot:"):
            return spec[6:] if not value else ""
        return super().format_field(value, spec)


# ---------------------------------------------------------------- the model
class TM:
    def __init__(self, name: str, description: str = ""):
        self.name, self.description = name, description
        self.elements: list[Element] = []
        self.findings: list[Finding] = []

    def __enter__(self):
        _CURRENT.append(self)
        return self

    def __exit__(self, *exc):
        _CURRENT.pop()

    def add(self, element: Element) -> None:
        self.elements.append(element)

    def of(self, kind: type) -> list:
        return [e for e in self.elements if isinstance(e, kind)]

    @property
    def flows(self) -> list[Dataflow]:
        return self.of(Dataflow)

    def receives_untrusted_input(self, element: Element) -> bool:
        return any(f.sink is element and (isinstance(f.source, Actor) or
                                          (f.source.inBoundary is not None and not f.source.inBoundary.trusted))
                   for f in self.flows)

    def check(self) -> list[str]:
        """Model sanity checks (pytm also refuses some broken models)."""
        problems = []
        names = [e.name for e in self.elements]
        for n in sorted({n for n in names if names.count(n) > 1}):
            problems.append(f"duplicate element name: {n}")
        for f in self.flows:
            for end in (f.source, f.sink):
                if end not in self.elements:
                    problems.append(f"flow {f.name!r} uses an element that is not in the model: {end.name}")
        connected = {id(f.source) for f in self.flows} | {id(f.sink) for f in self.flows}
        for e in self.elements:
            if isinstance(e, (Process, Datastore, Actor)) and id(e) not in connected:
                problems.append(f"element with no data flow: {e.name}")
        return problems

    def process(self, library: list[Threat] | None = None) -> list[Finding]:
        library = library if library is not None else load_library()
        out = []
        for e in self.elements:
            if isinstance(e, Process):
                e.receivesUntrustedInput = self.receives_untrusted_input(e)
            for t in library:
                if t.applies(e):
                    out.append(Finding(t.sid, e.name, e.kind, t.stride, t.severity, t.description,
                                       t.mitigation, t.requirement, t.references))
        out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.sid, f.target))
        self.findings = out
        return out

    def requirements(self) -> dict[str, list[str]]:
        """Security requirements derived from the findings: requirement id -> targets."""
        req: dict[str, list[str]] = {}
        for f in self.findings:
            req.setdefault(f.requirement, []).append(f.target)
        return dict(sorted(req.items()))

    # ------------------------------------------------ diagrams as code
    def dfd(self) -> str:
        """Graphviz DOT: one cluster per boundary. Render with `dot -Tpng` (not needed for tests)."""
        shape = {"Actor": "box", "Datastore": "cylinder"}
        lines = [f'digraph "{self.name}" {{', "  rankdir=LR;", '  node [fontname="Arial"];']
        boundaries = self.of(Boundary)
        for i, b in enumerate(boundaries):
            style = "dashed" if b.trusted else "bold"
            lines.append(f'  subgraph cluster_{i} {{ label="{b.name}"; style={style}; color=firebrick;')
            for e in self.elements:
                if e.inBoundary is b and not isinstance(e, (Dataflow, Boundary)):
                    lines.append(f'    {_nid(e)} [label="{e.name}", shape={shape.get(e.kind, "ellipse")}];')
            lines.append("  }")
        for e in self.elements:
            if e.inBoundary is None and not isinstance(e, (Dataflow, Boundary)):
                lines.append(f'  {_nid(e)} [label="{e.name}", shape={shape.get(e.kind, "ellipse")}];')
        for f in self.flows:
            lock = " (enc)" if f.isEncrypted else ""
            lines.append(f'  {_nid(f.source)} -> {_nid(f.sink)} [label="{f.name}{lock}"];')
        lines.append("}")
        return "\n".join(lines)

    def seq(self) -> str:
        """PlantUML sequence diagram from the data flows, in model order."""
        word = {"Actor": "actor", "Datastore": "database"}
        lines = ["@startuml"]
        seen = []
        for f in self.flows:
            for e in (f.source, f.sink):
                if e not in seen:
                    seen.append(e)
        for e in seen:
            lines.append(f'{word.get(e.kind, "entity")} "{e.name}" as {_nid(e)}')
        for f in self.flows:
            lines.append(f"{_nid(f.source)} -> {_nid(f.sink)}: {f.name}")
        lines.append("@enduml")
        return "\n".join(lines)

    # ------------------------------------------------ reports
    def report(self, template: str) -> str:
        if not self.findings:
            self.process()
        high = [f for f in self.findings if f.severity == "High"]
        reqs = [{"id": k, "targets": ", ".join(v)} for k, v in self.requirements().items()]
        ctx = dict(tm=self, findings=self.findings, findings_high=high, findings_count=len(self.findings),
                   high_count=len(high), elements=[e for e in self.elements if not isinstance(e, (Dataflow, Boundary))],
                   dataflows=self.flows, requirements=[_Obj(r) for r in reqs])
        return ReportFormatter().format(template, **ctx)


def _nid(e: Element) -> str:
    return re.sub(r"\W", "_", e.name)


class _Obj:
    def __init__(self, d: dict):
        self.__dict__.update(d)


# ---------------------------------------------------------------- gate
def gate(findings: list[Finding], accepted: set[tuple[str, str]] = frozenset(), fail_on: str = "High") -> int:
    """Return 1 when a finding at ``fail_on`` severity (or worse) is not in the accepted set."""
    limit = SEVERITY_ORDER[fail_on]
    open_ = [f for f in findings if SEVERITY_ORDER[f.severity] <= limit and f.key not in accepted]
    return 1 if open_ else 0


# ---------------------------------------------------------------- declarative model ("as code")
KINDS = {"Actor": Actor, "Server": Server, "Process": Process, "Datastore": Datastore}


def load_model(path: Path) -> TM:
    """Build a TM from a declarative JSON model (the Threagile idea, in JSON)."""
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    with TM(spec["name"], spec.get("description", "")) as tm:
        bounds = {b["name"]: Boundary(b["name"], trusted=b.get("trusted", True)) for b in spec.get("boundaries", [])}
        data = {d["name"]: Data(**d) for d in spec.get("data", [])}
        elems = {}
        for e in spec["elements"]:
            attrs = {k: v for k, v in e.items() if k not in ("name", "kind", "boundary")}
            elems[e["name"]] = KINDS[e["kind"]](e["name"], inBoundary=bounds.get(e.get("boundary")), **attrs)
        for f in spec.get("dataflows", []):
            attrs = {k: v for k, v in f.items() if k not in ("name", "from", "to", "data")}
            Dataflow(elems[f["from"]], elems[f["to"]], f["name"], data=tuple(data[d] for d in f.get("data", [])),
                     **attrs)
    return tm
