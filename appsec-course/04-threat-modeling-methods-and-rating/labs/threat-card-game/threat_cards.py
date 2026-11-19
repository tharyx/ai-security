"""A tiny threat card game, in the spirit of Elevation of Privilege / OWASP Cornucopia.

The cards below are ORIGINAL lab wording (not copied from any published deck). Each card
has a STRIDE suit. Players take turns: play a card against an element of the DFD, say how
the threat applies, and propose a mitigation. Scoring:

* +1 if the card's suit is valid for that element type (STRIDE per element),
* +1 more if the target is a data flow that crosses a trust boundary,
* +1 more if a mitigation is proposed (the threat goes into the backlog),
* 0 points and a reason if the play is invalid.

The real value is the backlog of threats the game produces, not the score.
Standard library only.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

CARDS = [
    ("S1", "S", "A caller can claim to be another user because the identity is taken from a request field."),
    ("S2", "S", "A service accepts calls from anything on the network without proving who is calling."),
    ("S3", "S", "A stolen long-lived token works from any device for months."),
    ("T1", "T", "Data can be changed in transit because the channel is not integrity protected."),
    ("T2", "T", "The client sends a value (price, role, owner id) that the server trusts."),
    ("T3", "T", "A stored record can be edited by a component that should only read it."),
    ("R1", "R", "A sensitive action leaves no record of who did it."),
    ("R2", "R", "Logs can be edited or deleted by the same admin whose actions they record."),
    ("R3", "R", "Log entries carry no reliable time or request id, so events cannot be linked."),
    ("I1", "I", "Error messages reveal internal names, stack traces or queries."),
    ("I2", "I", "A store or backup holds sensitive data without encryption or access control."),
    ("I3", "I", "Different responses reveal whether a user, file or record exists."),
    ("D1", "D", "One request can consume unbounded CPU, memory or rows."),
    ("D2", "D", "There is no limit on how often a caller can repeat an expensive action."),
    ("D3", "D", "A single failing dependency stops the whole flow."),
    ("E1", "E", "A normal user can reach an admin function by calling its URL directly."),
    ("E2", "E", "A component runs with far more privilege than its task needs."),
    ("E3", "E", "Input is interpreted as code or a query, letting the caller run their own logic."),
]
PER_ELEMENT = {"external": "SR", "process": "STRIDE", "datastore": "TID", "flow": "TID"}

DEFAULT_DFD = {
    "elements": {"customer": "external", "web": "process", "api": "process", "db": "datastore", "audit_log": "datastore"},
    "logs": {"audit_log"},
    "flows": {"F1": ("customer", "web", True), "F2": ("web", "api", True), "F3": ("api", "db", True),
              "F4": ("api", "audit_log", False)},  # (src, dst, crosses_boundary)
}


@dataclass
class Play:
    player: str
    card: str
    target: str
    how: str
    mitigation: str
    points: int = 0
    reason: str = ""


def deal(players: list[str], seed: int, hand_size: int = 3) -> dict[str, list[str]]:
    deck = [c[0] for c in CARDS]
    random.Random(seed).shuffle(deck)
    hands = {p: [] for p in players}
    for i in range(hand_size * len(players)):
        hands[players[i % len(players)]].append(deck[i])
    return hands


def target_type(target: str, dfd: dict) -> str | None:
    if target in dfd["elements"]:
        return dfd["elements"][target]
    if target in dfd["flows"]:
        return "flow"
    return None


def judge(play: Play, dfd: dict = DEFAULT_DFD) -> Play:
    suit = next((c[1] for c in CARDS if c[0] == play.card), None)
    ttype = target_type(play.target, dfd)
    if suit is None:
        play.reason = "unknown card"
    elif ttype is None:
        play.reason = "unknown target"
    elif not play.how.strip():
        play.reason = "say how the threat applies"
    else:
        allowed = PER_ELEMENT[ttype] + ("R" if play.target in dfd.get("logs", set()) else "")
        if suit not in allowed:
            play.reason = f"{suit} is unusual for a {ttype}; argue it or pick another target"
        else:
            play.points = 1
            if ttype == "flow" and dfd["flows"][play.target][2]:
                play.points += 1
            if play.mitigation.strip():
                play.points += 1
    return play


def score(plays: list[Play]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for p in plays:
        totals[p.player] = totals.get(p.player, 0) + p.points
    return dict(sorted(totals.items(), key=lambda kv: -kv[1]))


def backlog(plays: list[Play]) -> list[str]:
    """Valid plays become threat-model entries; plays without a mitigation are marked TODO."""
    out = []
    for p in plays:
        if p.points:
            out.append(f"[{p.card}] {p.target}: {p.how} -> {p.mitigation or 'TODO: mitigation'}")
    return out
