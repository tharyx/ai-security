"""Continuous AI security assessment: drift, posture trend, exceptions and cadence.

A design review proves the platform was secure on the day of the review. Continuous
assessment answers the harder question: "is it still secure today?" This module gives
four small, testable building blocks:

* ``diff_architecture``  declared design vs observed system -> drift items, each linked
  to the control it may break (the "declared vs observed" check behind control OPS-02);
* ``summarize`` / ``regressions`` / ``posture_score``  a trend over scheduled review runs;
* ``exception_alerts``  risk acceptances that expired or will expire soon;
* ``overdue``  assessments (red-team run, architecture review, access review) that are late;
* ``attack_surface_minutes``  how long a weakness stayed exploitable before containment.

It works on plain dicts (the YAML architecture files) and on report-like objects that
have ``.findings`` with ``control_id``, ``severity`` and ``status``. It does not import
its sibling lab files; ``assess.py`` wires it to ``reviewer.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

INTERNET = "internet"

# Which control a changed setting can break. Unknown settings are still reported.
SETTING_TO_CONTROL = {
    "user_auth": "IAM-04", "identity": "IAM-03", "downstream_auth": "IAM-06",
    "public_network_access": "NET-01/NET-02", "private_endpoint": "NET-01/NET-02",
    "egress": "NET-03", "encryption_key": "DATA-01", "retrieval_authz": "DATA-03",
    "tenant_isolation": "DATA-03", "data_use": "DATA-04",
    "guardrails.input": "GR-01", "guardrails.output": "GR-02",
    "model_routing": "GW-01", "cache_scope": "GW-02", "tool_registry": "TOOL-01",
    "approval_required_for": "AGT-01", "limits": "AGT-02", "kill_switch": "AGT-02",
    "exports_to_siem": "LOG-01", "immutable": "LOG-02", "retention_days": "LOG-02",
    "rate_limits": "OPS-01", "token_budget": "OPS-01",
}
IGNORED_SETTINGS = {"service"}  # descriptive text, not a security setting


@dataclass(frozen=True)
class Drift:
    kind: str     # added_component | removed_component | changed_setting | added_flow |
                  # removed_flow | added_identity | removed_identity | changed_identity | new_exception
    target: str
    detail: str
    control: str = ""


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and k == "guardrails":
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def diff_architecture(declared: dict, observed: dict) -> list[Drift]:
    """Compare the approved design with what is really deployed."""
    drifts: list[Drift] = []
    dc = {c["id"]: c for c in declared.get("components", [])}
    oc = {c["id"]: c for c in observed.get("components", [])}
    for cid in sorted(oc.keys() - dc.keys()):
        drifts.append(Drift("added_component", cid, f"not in the approved design (type {oc[cid].get('type')}): "
                            "shadow AI until reviewed", "NET-04"))
    for cid in sorted(dc.keys() - oc.keys()):
        drifts.append(Drift("removed_component", cid, "in the design but not deployed: update the design or the inventory"))
    for cid in sorted(dc.keys() & oc.keys()):
        a, b = _flatten(dc[cid]), _flatten(oc[cid])
        for key in sorted((a.keys() | b.keys()) - IGNORED_SETTINGS):
            if a.get(key) != b.get(key):
                drifts.append(Drift("changed_setting", f"{cid}.{key}", f"{a.get(key)!r} -> {b.get(key)!r}",
                                    SETTING_TO_CONTROL.get(key, "")))
    dflows = {(f["from"], f["to"]) for f in declared.get("flows", [])}
    oflows = {(f["from"], f["to"]) for f in observed.get("flows", [])}
    for src, dst in sorted(oflows - dflows):
        drifts.append(Drift("added_flow", f"{src}->{dst}", "new data flow",
                            "NET-04" if src == INTERNET else ""))
    for src, dst in sorted(dflows - oflows):
        drifts.append(Drift("removed_flow", f"{src}->{dst}", "flow in the design is gone"))
    di = {i["id"]: i for i in declared.get("identities", [])}
    oi = {i["id"]: i for i in observed.get("identities", [])}
    for iid in sorted(oi.keys() - di.keys()):
        owner = oi[iid].get("owner")
        drifts.append(Drift("added_identity", iid, f"new identity, owner={owner!r}", "IAM-05" if not owner else "IAM-02"))
    for iid in sorted(di.keys() - oi.keys()):
        drifts.append(Drift("removed_identity", iid, "identity removed: check that its credentials were revoked"))
    for iid in sorted(di.keys() & oi.keys()):
        for key in ("credential", "permissions", "owner"):
            if di[iid].get(key) != oi[iid].get(key):
                drifts.append(Drift("changed_identity", f"{iid}.{key}", f"{di[iid].get(key)!r} -> {oi[iid].get(key)!r}",
                                    {"credential": "IAM-01", "permissions": "IAM-02", "owner": "IAM-05"}[key]))
    known = {(e["control"], str(e["expires"])) for e in declared.get("exceptions", [])}
    for e in observed.get("exceptions", []):
        if (e["control"], str(e["expires"])) not in known:
            drifts.append(Drift("new_exception", e["control"], f"approved by {e['approver']} until {e['expires']}",
                                e["control"]))
    return drifts


# ------------------------------------------------------------------ posture trend
WEIGHTS = {"critical": 25, "high": 10, "medium": 3, "low": 1}


@dataclass
class PostureRun:
    when: date
    design: str
    failed: dict[str, str] = field(default_factory=dict)   # control id -> severity (open findings)
    accepted: set[str] = field(default_factory=set)

    @property
    def score(self) -> int:
        return posture_score(self)


def summarize(when: date, report) -> PostureRun:
    run = PostureRun(when, report.architecture)
    for f in report.findings:
        if f.status == "FAIL":
            run.failed[f.control_id] = f.severity
        elif f.status == "ACCEPTED":
            run.accepted.add(f.control_id)
    return run


def posture_score(run: PostureRun) -> int:
    """100 = no open findings. Each open finding costs points by severity (floor 0)."""
    return max(0, 100 - sum(WEIGHTS[s] for s in run.failed.values()))


def regressions(previous: PostureRun, current: PostureRun) -> list[str]:
    """Controls that fail now but did not fail in the previous run: page someone."""
    return sorted(set(current.failed) - set(previous.failed))


# --------------------------------------------------------------------- exceptions
def exception_alerts(exceptions: list[dict], today: date, warn_days: int = 30) -> list[tuple[str, str, int]]:
    """(control, 'expired' | 'expiring', days_left) for every exception that needs action."""
    out = []
    for e in exceptions:
        expires = e["expires"] if isinstance(e["expires"], date) else date.fromisoformat(str(e["expires"]))
        days = (expires - today).days
        if days < 0:
            out.append((e["control"], "expired", days))
        elif days <= warn_days:
            out.append((e["control"], "expiring", days))
    return out


# ------------------------------------------------------------------------ cadence
DEFAULT_CADENCE_DAYS = {
    "redteam_suite": 7,          # automated attack suite (also on every model/prompt/tool change)
    "architecture_review": 30,   # reviewer against the observed system (drift)
    "access_review": 90,         # owners re-certify non-human identities
    "manual_red_team": 180,      # people, goal-based (also after major changes)
}


def overdue(last_run: dict[str, date], today: date, cadence: dict[str, int] | None = None) -> list[str]:
    """Assessments that never ran or are older than their cadence."""
    cadence = cadence or DEFAULT_CADENCE_DAYS
    return sorted(name for name, days in cadence.items()
                  if name not in last_run or (today - last_run[name]).days > days)


def attack_surface_minutes(exploitable_at: datetime, contained_at: datetime) -> int:
    """Minutes a weakness was exploitable before controls contained it (shorter is better)."""
    if contained_at < exploitable_at:
        raise ValueError("containment cannot happen before the weakness existed")
    return int((contained_at - exploitable_at).total_seconds() // 60)
