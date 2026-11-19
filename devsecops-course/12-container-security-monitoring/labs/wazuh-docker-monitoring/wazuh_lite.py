"""Wazuh-style decoder + rule engine for Docker-listener events (simplified, not Wazuh).

The Wazuh docker-listener wodle turns Docker daemon events into JSON that the JSON decoder
splits into fields like docker.Action. Rules match fields with regexes, chain with if_sid,
and a rule with frequency/timeframe/if_matched_sid correlates repeats. Levels run 0-15
(0 = no alert; 12+ is usually 'page someone'). Verify details in the Wazuh docs.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass, field


def flatten(d: dict, prefix: str = "") -> dict[str, str]:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = str(v)
    return out


@dataclass
class Rule:
    id: int
    level: int
    desc: str
    if_sid: int | None = None
    fields: list[tuple[str, str, bool]] = field(default_factory=list)  # (name, regex, negate)
    frequency: int = 0
    timeframe: int = 0
    if_matched_sid: int | None = None
    same_field: str | None = None
    groups: list[str] = field(default_factory=list)


def load_rules(xml_text: str) -> list[Rule]:
    xml_text = re.sub(r"<!--.*?-->", "", xml_text, flags=re.S)
    root = ET.fromstring(xml_text)
    rules = []
    for el in root.iter("rule"):
        r = Rule(int(el.get("id")), int(el.get("level")), (el.findtext("description") or "").strip())
        if el.get("frequency"):
            r.frequency, r.timeframe = int(el.get("frequency")), int(el.get("timeframe", "0"))
        if el.findtext("if_sid"):
            r.if_sid = int(el.findtext("if_sid"))
        if el.findtext("if_matched_sid"):
            r.if_matched_sid = int(el.findtext("if_matched_sid"))
        r.same_field = el.findtext("same_field")
        for f in el.findall("field"):
            r.fields.append((f.get("name"), f.text.strip(), f.get("negate") == "yes"))
        r.groups = [g for g in (el.findtext("group") or "").split(",") if g]
        rules.append(r)
    return rules


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = {r.id: r for r in rules}
        self.history: dict[tuple[int, str], deque] = defaultdict(deque)

    def _fields_match(self, r: Rule, flat: dict) -> bool:
        for name, rx, neg in r.fields:
            hit = name in flat and re.search(rx, flat[name]) is not None
            if hit == neg:
                return False
        return True

    def _matches(self, r: Rule, flat: dict, matched: set[int]) -> bool:
        if r.if_sid is not None and r.if_sid not in matched:
            return False
        return self._fields_match(r, flat)

    def process(self, event: dict) -> list[dict]:
        """Return alerts (rules with level > 0 that fired) for one event."""
        flat = flatten(event)
        if event.get("integration") != "docker":
            return []
        matched: set[int] = set()
        for rid in sorted(self.rules):  # parents have lower ids in this file
            r = self.rules[rid]
            if r.if_matched_sid is not None:
                continue
            if self._matches(r, flat, matched):
                matched.add(rid)
        alerts = [self._alert(self.rules[i], flat, event) for i in sorted(matched) if self.rules[i].level > 0]
        # correlation rules
        for r in self.rules.values():
            if r.if_matched_sid is None or r.if_matched_sid not in matched:
                continue
            key = (r.id, flat.get(r.same_field, "") if r.same_field else "")
            q = self.history[key]
            q.append(event["ts"])
            while q and event["ts"] - q[0] > r.timeframe:
                q.popleft()
            if len(q) >= r.frequency:
                alerts.append(self._alert(r, flat, event))
                q.clear()
        # keep only the most specific alert per rule chain: highest level first
        return sorted(alerts, key=lambda a: -a["level"])

    @staticmethod
    def _alert(r: Rule, flat: dict, event: dict) -> dict:
        return {"rule": r.id, "level": r.level, "description": r.desc, "ts": event["ts"],
                "groups": r.groups, "target": flat.get("docker.Actor.ID", "")}


def run(rules: list[Rule], events: list[dict], min_level: int = 3) -> list[dict]:
    eng = Engine(rules)
    out = []
    for ev in events:
        out += [a for a in eng.process(ev) if a["level"] >= min_level]
    return out
