"""AI SOC pipeline: normalise -> detect (naive vs tuned) -> risk score with decay -> correlate.

Three raw sources, three formats (like real life):
  llm_app.jsonl        LLM gateway: ISO time, nested prompt/completion/guardrail objects
  agent_runtime.jsonl  agent runtime: epoch seconds, OpenTelemetry-ish tool-call spans
  mcp_gateway.jsonl    MCP gateway: @timestamp with millis, tool description hashes + pins

The normaliser maps all three to one ``Event`` schema. Detection rules read only that
schema, so the same rule works whichever product produced the log (the DBA analogy: one
view over three differently-designed tables).

Standard library only. Nothing here changes anything: detection is read-only. The SOAR
engine that acts lives in soar.py.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Callable
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


# ===================================================================== 1. normalise
@dataclass
class Event:
    id: str
    ts: datetime
    source: str            # llm_app | agent_runtime | mcp_gateway
    kind: str              # llm_request | tool_call | mcp_list | mcp_call
    tenant: str = ""
    user: str = ""
    session: str = ""
    trace: str = ""
    agent: str = ""
    prompt_sha: str = ""
    prompt_chars: int = 0
    preview: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    guard_in: str = ""
    guard_ctx: str = ""
    guard_out: str = ""
    categories: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    docs: tuple[str, ...] = ()
    sys_prompt_ver: str = ""
    tool: str = ""
    dest: str = ""
    decision: str = ""
    taint: str = ""
    bytes_out: int = 0
    rows: int = 0
    desc_sha: str = ""
    pinned_sha: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        return d


def _iso(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s).astimezone(timezone.utc).replace(microsecond=0)


def norm_llm(r: dict, n: int) -> Event:
    g, p, c = r["guardrail"], r["prompt"], r["completion"]
    return Event(f"llm:{n}", _iso(r["ts"]), "llm_app", "llm_request", r["tenant"], r["user"], r["session"],
                 r["trace_id"], r["app"], p["sha256"], p["chars"], p["preview"], p["tokens"], c["tokens"],
                 r["latency_ms"], g["input"], g["context"], g["output"], tuple(g["categories"]),
                 tuple(c["flags"]), tuple(r["retrieval"]["docs"]), r["sys_prompt_ver"])


def norm_agent(r: dict, n: int) -> Event:
    url = urlparse(r["target"])
    return Event(f"agt:{n}", datetime.fromtimestamp(r["time_unix"], timezone.utc), "agent_runtime", "tool_call",
                 r["tenant_id"], r["on_behalf_of"], r["session_id"], r["trace_id"], r["agent"],
                 tool=r["tool"], dest=url.hostname or url.netloc or r["target"], decision=r["decision"],
                 taint=r["taint"], bytes_out=r["bytes_out"], rows=r["rows_returned"])


def norm_mcp(r: dict, n: int) -> Event:
    kind = "mcp_list" if r["method"] == "tools/list" else "mcp_call"
    return Event(f"mcp:{n}", _iso(r["@timestamp"]), "mcp_gateway", kind, r["tenant"], r["user"], "",
                 r["trace_id"], r["client"], tool=f"{r['server']}/{r['tool']}", decision=r["status"],
                 rows=r["rows"], desc_sha=r["desc_sha256"], pinned_sha=r["pinned_sha256"])


PARSERS = {"llm_app.jsonl": norm_llm, "agent_runtime.jsonl": norm_agent, "mcp_gateway.jsonl": norm_mcp}


def load_events(folder: Path = FIX) -> list[Event]:
    out: list[Event] = []
    for name, fn in PARSERS.items():
        for n, line in enumerate((folder / name).read_text(encoding="utf-8").splitlines()):
            if line.strip():
                out.append(fn(json.loads(line), n))
    return sorted(out, key=lambda e: (e.ts, e.id))


def load_json(name: str, folder: Path = FIX) -> dict:
    return json.loads((folder / name).read_text(encoding="utf-8"))


# ===================================================================== 2. detect
# ATLAS technique NAMES are cited; IDs change between ATLAS releases: verify at atlas.mitre.org.
# OWASP names follow the 2026 LLM list used in this repo (see the 2023<->2026 mapping page).
ATLAS_ID_HINTS = {
    "LLM Prompt Injection (indirect)": "AML.T0051.001", "LLM Meta Prompt Extraction": "AML.T0056",
    "Cost Harvesting": "AML.T0034", "Denial of AI Service": "AML.T0029", "RAG Poisoning": "AML.T0070",
    "AI Supply Chain Compromise": "AML.T0010", "LLM Jailbreak": "AML.T0054",
    "Exfiltration via AI Agent Tool Invocation": "verify",
}
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    rule: str
    severity: str
    ts: datetime                    # when the rule could first fire (last needed event)
    first_ts: datetime              # earliest evidence event
    entities: list[str]             # correlation keys: user:, trace:, doc:, dest:, mcp:
    evidence: list[str]             # event ids (facts, not interpretation)
    summary: str
    affected: list[str] = field(default_factory=list)  # victims, not correlation keys
    context: dict = field(default_factory=dict)
    atlas: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()


def _alert(rule: str, sev: str, evs: list[Event], entities: list[str], summary: str,
           atlas=(), owasp=(), **ctx) -> Alert:
    return Alert(rule, sev, max(e.ts for e in evs), min(e.ts for e in evs), sorted(set(entities)),
                 [e.id for e in evs], summary, sorted(set(ctx.pop("affected", []))),
                 {k: v for k, v in ctx.items() if v}, tuple(atlas), tuple(owasp))


def _allowed(dest: str, allow: list[str]) -> bool:
    return any(dest == a or dest.endswith("." + a) for a in allow)


def _by_trace(events: list[Event]) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.trace:
            out[e.trace].append(e)
    return out


# ---------------------------------------------------------------- naive rules
def naive_guard_block(events, wl):
    """Every guardrail input block is an alert. Noisy, and blind to INDIRECT injection."""
    return [_alert("naive_guard_block", "medium", [e], [f"user:{e.user}"], f"guardrail blocked input from {e.user}",
                   ["LLM Jailbreak"], ["Prompt Injection"], user=e.user)
            for e in events if e.kind == "llm_request" and e.guard_in == "block"]


def naive_external_tool_call(events, wl):
    """Any tool call that leaves corp.example. Fires on the approved partner API too."""
    return [_alert("naive_external_tool_call", "high", [e], [f"user:{e.user}", f"trace:{e.trace}", f"dest:{e.dest}"],
                   f"{e.agent} called {e.tool} -> {e.dest}", ["Exfiltration via AI Agent Tool Invocation"],
                   ["Excessive Agency"], user=e.user, agent=e.agent, dest=e.dest)
            for e in events if e.kind == "tool_call" and "." in e.dest and not _allowed(e.dest, ["corp.example"])]


def naive_big_prompt(events, wl):
    """Per-request threshold. Misses many medium requests; flags one big honest one."""
    return [_alert("naive_big_prompt", "medium", [e], [f"user:{e.user}"], f"{e.tokens_in} prompt tokens",
                   ["Cost Harvesting"], ["Unbounded Consumption"], user=e.user)
            for e in events if e.kind == "llm_request" and e.tokens_in > 10_000]


LEAK_WORDS = re.compile(r"system prompt|your instructions", re.IGNORECASE)


def naive_leak_keyword(events, wl):
    """Keyword match on the prompt preview. Attackers paraphrase; honest users use the words."""
    return [_alert("naive_leak_keyword", "high", [e], [f"user:{e.user}"], f"prompt mentions system prompt",
                   ["LLM Meta Prompt Extraction"], ["Hidden Context Exposure"], user=e.user)
            for e in events if e.kind == "llm_request" and LEAK_WORDS.search(e.preview)]


def naive_context_flag(events, wl):
    """One alert per flagged retrieval. Right idea, but 1 alert per user per doc = alert storm."""
    return [_alert("naive_context_flag", "medium", [e], [f"doc:{d}" for d in e.docs], f"instruction text in {e.docs}",
                   ["RAG Poisoning"], ["Vector and Embedding Weaknesses"], affected=[e.user], doc=e.docs[0])
            for e in events if e.kind == "llm_request" and e.guard_ctx == "flag"]


def naive_mcp_desc_changed(events, wl):
    """Description differs from the last one SEEN. Fires on approved updates too."""
    last: dict[str, str] = {}
    out = []
    for e in events:
        if e.kind != "mcp_list":
            continue
        if e.tool in last and last[e.tool] != e.desc_sha:
            out.append(_alert("naive_mcp_desc_changed", "high", [e], [f"mcp:{e.tool}"], f"{e.tool} description changed",
                              ["AI Supply Chain Compromise"], ["Supply Chain"], mcp=e.tool))
        last[e.tool] = e.desc_sha
    return out


# ---------------------------------------------------------------- tuned rules
def exfil_untrusted_egress(events, wl):
    """Tool call to a host NOT on the egress allow-list. Critical if the same trace carried
    injected content (context guard flag) or the runtime marked the call as tainted."""
    traces = _by_trace(events)
    out = []
    for e in events:
        if e.kind != "tool_call" or not e.dest or "." not in e.dest or _allowed(e.dest, wl["egress_allowlist"]):
            continue
        same = traces.get(e.trace, [e])
        injected = [x for x in same if x.kind == "llm_request" and x.guard_ctx == "flag"]
        tainted = e.taint != "none" or bool(injected)
        docs = [d for x in injected for d in x.docs]
        evs = injected + [e]
        out.append(_alert("exfil_untrusted_egress", "critical" if tainted else "high", evs,
                          [f"user:{e.user}", f"trace:{e.trace}", f"dest:{e.dest}"] + [f"doc:{d}" for d in docs],
                          f"{e.agent} sent {e.bytes_out} bytes to {e.dest} (tainted={tainted})",
                          ["LLM Prompt Injection (indirect)", "Exfiltration via AI Agent Tool Invocation"],
                          ["Prompt Injection", "Excessive Agency"], user=e.user, agent=e.agent, dest=e.dest,
                          doc=docs[0] if docs else "", intel=wl.get("known_bad_domains", {}).get(e.dest, "")))
    return out


def user_baselines(events: list[Event], before: datetime | None = None) -> dict[str, float]:
    """Median prompt+completion tokens per request, per user (behaviour baseline)."""
    per: dict[str, list[int]] = defaultdict(list)
    for e in events:
        if e.kind == "llm_request" and (before is None or e.ts < before):
            per[e.user].append(e.tokens_in + e.tokens_out)
    return {u: float(median(v)) for u, v in per.items()}


def token_burst(events, wl, window=timedelta(minutes=10), floor=100_000, factor=10):
    """Rolling 10-minute token sum per user above max(floor, factor x 10-minute baseline).
    The baseline assumes about one request per 10 minutes at the user's median size."""
    reqs = [e for e in events if e.kind == "llm_request"]
    per: dict[str, list[Event]] = defaultdict(list)
    for e in reqs:
        per[e.user].append(e)
    out = []
    for user, evs in per.items():
        start = 0
        for i, e in enumerate(evs):
            while evs[start].ts < e.ts - window:
                start += 1
            win = evs[start:i + 1]
            total = sum(x.tokens_in + x.tokens_out for x in win)
            base = user_baselines(events, before=win[0].ts).get(user, 0.0)
            limit = max(floor, factor * base)
            if total > limit:
                out.append(_alert("token_burst", "high", win, [f"user:{user}"] + sorted({f"session:{x.session}" for x in win}),
                                  f"{total} tokens in 10 min ({len(win)} requests; limit {int(limit)})",
                                  ["Cost Harvesting", "Denial of AI Service"], ["Unbounded Consumption"], user=user))
                break  # one alert per user per run; real rules use suppression windows
    return out


def canary_leak(events, wl):
    """The canary planted in the system prompt appeared in output: proof, not a guess."""
    return [_alert("canary_leak", "high", [e], [f"user:{e.user}", f"session:{e.session}"],
                   f"canary from system prompt {e.sys_prompt_ver} in a response to {e.user}",
                   ["LLM Meta Prompt Extraction"], ["Hidden Context Exposure"], user=e.user,
                   prompt_version=e.sys_prompt_ver)
            for e in events if e.kind == "llm_request" and "canary_hit" in e.flags]


def shared_poisoned_doc(events, wl, min_users=3, window=timedelta(hours=2)):
    """Same document flagged for injected instructions for >= 3 distinct users in 2 hours."""
    per: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "llm_request" and e.guard_ctx == "flag":
            for d in e.docs:
                per[d].append(e)
    out = []
    for doc, evs in per.items():
        start = 0
        for j, e in enumerate(evs):  # fire at the FIRST moment the threshold is reached
            while e.ts - evs[start].ts > window:
                start += 1
            win = evs[start:j + 1]
            users = {x.user for x in win}
            if len(users) >= min_users:
                out.append(_alert("shared_poisoned_doc", "high", win, [f"doc:{doc}"],
                                  f"{doc} flagged for {len(users)} users", ["RAG Poisoning"],
                                  ["Vector and Embedding Weaknesses", "Data and Model Poisoning"],
                                  affected=sorted(users), doc=doc))
                break
    return out


def mcp_pin_mismatch(events, wl):
    """Observed tool description hash differs from the APPROVED pin (approved updates re-pin)."""
    out, seen = [], set()
    for e in events:
        if e.kind in ("mcp_list", "mcp_call") and e.pinned_sha and e.desc_sha != e.pinned_sha and e.tool not in seen:
            seen.add(e.tool)
            out.append(_alert("mcp_pin_mismatch", "critical", [e], [f"mcp:{e.tool}"],
                              f"{e.tool} description {e.desc_sha} != pinned {e.pinned_sha}",
                              ["AI Supply Chain Compromise"], ["Supply Chain"], mcp=e.tool, agent=e.agent))
    return out


def bulk_tool_read(events, wl, max_rows=1000):
    return [_alert("bulk_tool_read", "high", [e], [f"mcp:{e.tool}", f"trace:{e.trace}", f"user:{e.user}"],
                   f"{e.agent} read {e.rows} rows from {e.tool} for {e.user}",
                   ["Exfiltration via AI Agent Tool Invocation"], ["Excessive Agency"],
                   user=e.user, agent=e.agent, mcp=e.tool)
            for e in events if e.kind == "mcp_call" and e.rows > max_rows]


def repeated_guard_blocks(events, wl, n=3, window=timedelta(minutes=30)):
    """3+ input blocks for one user in 30 min, except watch-listed red-team accounts."""
    per: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "llm_request" and e.guard_in == "block" and e.user not in wl.get("redteam_accounts", {}):
            per[e.user].append(e)
    out = []
    for user, evs in per.items():
        for i in range(len(evs)):
            win = [x for x in evs[i:] if x.ts - evs[i].ts <= window]
            if len(win) >= n:
                out.append(_alert("repeated_guard_blocks", "medium", win, [f"user:{user}"],
                                  f"{len(win)} blocked prompts in 30 min", ["LLM Jailbreak"], ["Prompt Injection"], user=user))
                break
    return out


Rule = Callable[[list[Event], dict], list[Alert]]
RULESETS: dict[str, list[Rule]] = {
    "naive": [naive_guard_block, naive_external_tool_call, naive_big_prompt, naive_leak_keyword,
              naive_context_flag, naive_mcp_desc_changed],
    "tuned": [exfil_untrusted_egress, token_burst, canary_leak, shared_poisoned_doc, mcp_pin_mismatch,
              bulk_tool_read, repeated_guard_blocks],
}


def run_rules(events: list[Event], ruleset: str = "tuned", wl: dict | None = None) -> list[Alert]:
    wl = wl if wl is not None else load_json("watchlists.json")
    return sorted((a for r in RULESETS[ruleset] for a in r(events, wl)), key=lambda a: (a.ts, a.rule))


def evaluate(alerts: list[Alert], truth: dict) -> dict:
    """Alert-level precision and incident-level recall against the ground truth."""
    incidents = truth["incidents"]

    def match(a: Alert) -> str | None:
        keys = set(a.entities)
        return next((t["id"] for t in incidents if keys & set(t["keys"])), None)

    tp = [a for a in alerts if match(a)]
    fp = [a for a in alerts if not match(a)]
    hit = Counter(match(a) for a in tp)
    fn = [t["id"] for t in incidents if t["id"] not in hit]
    return {"alerts": len(alerts), "tp": len(tp), "fp": len(fp), "fn": fn,
            "precision": round(len(tp) / len(alerts), 2) if alerts else 0.0,
            "recall": round((len(incidents) - len(fn)) / len(incidents), 2),
            "alerts_per_true_incident": dict(sorted(hit.items())),
            "fp_rules": sorted(Counter(a.rule for a in fp).items())}


# ===================================================================== 2b. behaviour / drift
def hourly_profile(events: list[Event]) -> list[dict]:
    """Per-hour aggregates: the 'drift' view an analyst eyeballs on a dashboard."""
    per: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.kind == "llm_request":
            per[e.ts.strftime("%H:00")].append(e)
    rows = []
    for hour, evs in sorted(per.items()):
        rows.append({"hour": hour, "requests": len(evs), "tokens": sum(e.tokens_in + e.tokens_out for e in evs),
                     "p50_latency_ms": int(median(e.latency_ms for e in evs)),
                     "guard_flag_rate": round(sum(1 for e in evs if "flag" in (e.guard_ctx, e.guard_out)
                                                  or e.guard_in == "block") / len(evs), 3)})
    base_tokens = median(r["tokens"] for r in rows[:2]) if len(rows) >= 2 else rows[0]["tokens"]
    for r in rows:
        r["drift"] = "ANOMALY" if r["tokens"] > 3 * base_tokens else "ok"
    return rows


# ===================================================================== 3. risk scoring with decay
SEV_POINTS = {"low": 10, "medium": 25, "high": 50, "critical": 80}


@dataclass
class RiskBook:
    half_life_min: float = 30.0
    entries: dict[str, list[tuple[datetime, float, str]]] = field(default_factory=lambda: defaultdict(list))

    def add(self, entity: str, ts: datetime, points: float, reason: str) -> None:
        self.entries[entity].append((ts, points, reason))

    def score(self, entity: str, at: datetime) -> float:
        total = 0.0
        for ts, pts, _ in self.entries.get(entity, []):
            if ts <= at:
                age = (at - ts).total_seconds() / 60
                total += pts * 0.5 ** (age / self.half_life_min)
        return round(total, 1)

    def peak(self, entity: str) -> tuple[float, datetime]:
        """Highest score this entity reached (checked at each of its own entry times)."""
        times = [t for t, _, _ in self.entries.get(entity, [])]
        return max(((self.score(entity, t), t) for t in times), default=(0.0, datetime.min.replace(tzinfo=timezone.utc)))

    def top(self, at: datetime, n: int = 8) -> list[tuple[str, float]]:
        scored = [(e, self.score(e, at)) for e in self.entries]
        return sorted((x for x in scored if x[1] > 0), key=lambda x: -x[1])[:n]


def band(score: float) -> str:
    return "CONTAIN" if score >= 80 else "INVESTIGATE" if score >= 40 else "MONITOR"


def build_risk(events: list[Event], alerts: list[Alert], wl: dict, half_life_min: float = 30.0) -> RiskBook:
    """Alerts add severity points to their entities (victims get half); weak signals add a little.
    Points decay with a half-life, so one odd event fades but a pattern accumulates."""
    book = RiskBook(half_life_min)
    for a in alerts:
        pts = SEV_POINTS[a.severity]
        for ent in a.entities:
            book.add(ent, a.ts, pts, a.rule)
        for u in a.affected:
            book.add(f"user:{u}", a.ts, pts / 2, a.rule + " (affected)")
    red = wl.get("redteam_accounts", {})
    for e in events:
        if e.kind != "llm_request" or e.user in red:
            continue
        if e.guard_in == "block":
            book.add(f"user:{e.user}", e.ts, 15, "signal: guard block")
        if e.guard_ctx == "flag":
            book.add(f"user:{e.user}", e.ts, 10, "signal: context flag")
    return book


# ===================================================================== 4. correlate into incidents
CORRELATION_PREFIXES = ("user:", "trace:", "session:", "doc:", "dest:", "mcp:")


@dataclass
class Incident:
    id: str
    alerts: list[Alert]

    @property
    def rules(self) -> list[str]:
        return sorted({a.rule for a in self.alerts})

    @property
    def severity(self) -> str:
        return max((a.severity for a in self.alerts), key=SEV_RANK.__getitem__)

    @property
    def first_seen(self) -> datetime:
        return min(a.first_ts for a in self.alerts)

    @property
    def detected_at(self) -> datetime:
        return min(a.ts for a in self.alerts)

    @property
    def entities(self) -> list[str]:
        return sorted({k for a in self.alerts for k in a.entities})

    @property
    def evidence(self) -> list[str]:
        return sorted({x for a in self.alerts for x in a.evidence})

    @property
    def tags(self) -> dict[str, list[str]]:
        return {"atlas": sorted({t for a in self.alerts for t in a.atlas}),
                "owasp": sorted({t for a in self.alerts for t in a.owasp})}

    def context(self) -> dict:
        """Flat values the SOAR templates can use: {{user}}, {{agent}}, {{dest}}, {{doc}}, {{mcp}} ..."""
        ctx: dict = {"incident": self.id, "severity": self.severity}
        for a in sorted(self.alerts, key=lambda a: -SEV_RANK[a.severity]):
            for k, v in a.context.items():
                ctx.setdefault(k, v)
        ctx["traces"] = sorted(k[6:] for k in self.entities if k.startswith("trace:"))
        ctx["docs"] = sorted(k[4:] for k in self.entities if k.startswith("doc:"))
        affected = sorted({u for a in self.alerts for u in a.affected})
        ctx["affected"] = affected
        ctx["affected_count"] = len(affected)
        return ctx


def correlate(alerts: list[Alert], window: timedelta = timedelta(hours=2)) -> list[Incident]:
    """Union-find: two alerts join if they share a correlation key and are within the window."""
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(alerts):
        for j in range(i + 1, len(alerts)):
            b = alerts[j]
            if set(a.entities) & set(b.entities) and abs(a.ts - b.ts) <= window:
                parent[find(j)] = find(i)
    groups: dict[int, list[Alert]] = defaultdict(list)
    for i, a in enumerate(alerts):
        groups[find(i)].append(a)
    ordered = sorted(groups.values(), key=lambda g: min(a.ts for a in g))
    return [Incident(f"INC-{n:03d}", g) for n, g in enumerate(ordered, 1)]
