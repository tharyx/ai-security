"""AI vulnerability management: advisory intake, context-based priority, SLA tracking.

An AI system has more kinds of "vulnerability" than a normal service:

    dependency  a CVE or advisory in a package, inference server, vector DB, GPU driver
    model       a provider advisory, a jailbreak the base model is known to fall for,
                an unsafe file format, a model that must be upgraded or retired
    prompt      a system prompt or template that leaks hidden context or tool schemas
    config      a guardrail switched off, a tool permission too wide, a missing limit

This module keeps them all in one register, linked to an inventory (SBOM + AI-BOM), so a
new advisory turns into findings for exactly the affected services, with a due date.

Priority is NOT just the advisory's severity. It goes up for internet-facing services with
tools or sensitive data, and for known-exploited issues; it goes down for internal,
tool-less services with only public data. SLA days below are an EXAMPLE policy: agree your
own with risk owners.

    python vuln_register.py fixtures/inventory.json fixtures/advisories.json --now 2026-11-18
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

LEVELS = ["low", "medium", "high", "critical"]
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}   # example policy, not a standard


def parse_version(v: str) -> tuple[int, ...]:
    out = []
    for part in v.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


@dataclass
class Asset:
    id: str
    owner: str
    internet_facing: bool
    has_tools: bool
    data_class: str                              # public | internal | confidential | restricted
    components: dict[str, str]                   # name -> version (packages, models, prompt templates)


@dataclass
class Advisory:
    id: str
    source: str                                  # CVE | GHSA | vendor | model-provider | red-team | internal
    kind: str                                    # dependency | model | prompt | config
    component: str
    introduced: str                              # first affected version (OSV-style range)
    fixed: str | None                            # first fixed version, or None if no fix yet
    severity: str                                # low | medium | high | critical
    known_exploited: bool = False
    summary: str = ""

    def affects(self, version: str) -> bool:
        v = parse_version(version)
        if v < parse_version(self.introduced):
            return False
        return self.fixed is None or v < parse_version(self.fixed)


@dataclass
class Finding:
    advisory: Advisory
    asset: Asset
    version: str
    priority: str
    opened: date
    status: str = "open"                         # open | fixed | accepted
    exception_until: date | None = None          # risk acceptance must expire
    notes: list[str] = field(default_factory=list)

    @property
    def due(self) -> date:
        return self.opened + timedelta(days=SLA_DAYS[self.priority])

    def overdue(self, today: date) -> bool:
        if self.status == "fixed":
            return False
        if self.status == "accepted" and self.exception_until and today <= self.exception_until:
            return False
        return today > self.due


def contextual_priority(adv: Advisory, asset: Asset) -> tuple[str, list[str]]:
    """Start from the advisory severity, then adjust for exposure and consequence."""
    level = LEVELS.index(adv.severity)
    reasons = [f"base {adv.severity}"]
    if adv.known_exploited:
        level += 1
        reasons.append("+1 known exploited")
    if asset.internet_facing and (asset.has_tools or asset.data_class in ("confidential", "restricted")):
        level += 1
        reasons.append("+1 internet-facing with tools or sensitive data")
    if not asset.internet_facing and not asset.has_tools and asset.data_class == "public":
        level -= 1
        reasons.append("-1 internal, no tools, public data")
    return LEVELS[max(0, min(level, len(LEVELS) - 1))], reasons


def intake(advisories: list[Advisory], assets: list[Asset], today: date,
           existing: list[Finding] | None = None) -> list[Finding]:
    """Match advisories to inventory components. Re-running intake does not duplicate findings."""
    findings = list(existing or [])
    seen = {(f.advisory.id, f.asset.id) for f in findings}
    for adv in advisories:
        for asset in assets:
            version = asset.components.get(adv.component)
            if version is None or not adv.affects(version) or (adv.id, asset.id) in seen:
                continue
            priority, reasons = contextual_priority(adv, asset)
            findings.append(Finding(adv, asset, version, priority, today, notes=reasons))
            seen.add((adv.id, asset.id))
    return findings


def accept_risk(finding: Finding, until: date, compensating: str) -> None:
    """A risk acceptance needs compensating controls and an end date, never 'forever'."""
    if not compensating.strip():
        raise ValueError("risk acceptance needs a compensating control")
    finding.status, finding.exception_until = "accepted", until
    finding.notes.append(f"accepted until {until.isoformat()}: {compensating}")


def load(inventory_path: str | Path, advisories_path: str | Path) -> tuple[list[Asset], list[Advisory]]:
    inv = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    adv = json.loads(Path(advisories_path).read_text(encoding="utf-8"))
    return [Asset(**a) for a in inv["assets"]], [Advisory(**a) for a in adv["advisories"]]


def report(findings: list[Finding], today: date) -> str:
    lines = [f"{'advisory':14} {'kind':10} {'asset':16} {'version':9} {'sev':8} {'priority':9} {'due':10} state"]
    lines.append("-" * 96)
    order = sorted(findings, key=lambda f: (-LEVELS.index(f.priority), f.due, f.asset.id))
    for f in order:
        state = "OVERDUE" if f.overdue(today) else f.status
        lines.append(f"{f.advisory.id:14} {f.advisory.kind:10} {f.asset.id:16} {f.version:9} "
                     f"{f.advisory.severity:8} {f.priority:9} {f.due.isoformat():10} {state}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI vulnerability register")
    parser.add_argument("inventory")
    parser.add_argument("advisories")
    parser.add_argument("--now", default=date.today().isoformat())
    args = parser.parse_args(argv)
    today = date.fromisoformat(args.now)
    assets, advisories = load(args.inventory, args.advisories)
    findings = intake(advisories, assets, today)
    print(report(findings, today))
    return 0


if __name__ == "__main__":
    sys.exit(main())
