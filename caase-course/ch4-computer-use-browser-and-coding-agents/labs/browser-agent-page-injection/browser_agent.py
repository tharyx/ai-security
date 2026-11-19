"""A mock DOM-parsing browser agent and its defenses (all simulated; no network, no browser).

The page "perception" is produced two ways:
  * naive   : every text node + alt/title/aria-label (what a careless DOM dump does)
  * visible : only text a person could actually see; invisible overlays removed from the action surface
The planner is deliberately gullible: it obeys `AGENT:` lines from any text it sees
and clicks "Allow" on dialogs. Nothing is fetched; "navigate" only records a URL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

FAKE_PASSWORD = "FAKE-SAVED-PASSWORD-1234"
VOID = {"img", "br", "hr", "input", "meta", "link"}


def _style(attrs: dict) -> dict:
    out = {}
    for part in (attrs.get("style") or "").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def _px(v: str) -> float:
    m = re.match(r"-?\d+(\.\d+)?", v or "")
    return float(m.group(0)) if m else 0.0


def is_hidden(attrs: dict) -> bool:
    s = _style(attrs)
    if "hidden" in attrs or attrs.get("aria-hidden") == "true":
        return True
    if s.get("display") == "none" or s.get("visibility") == "hidden":
        return True
    if s.get("opacity") in ("0", "0.0") or _px(s.get("font-size", "1")) == 0 and "font-size" in s:
        return True
    if _px(s.get("left", "0")) <= -1000 or _px(s.get("top", "0")) <= -1000 or _px(s.get("text-indent", "0")) <= -1000:
        return True
    if s.get("color") in ("#fff", "#ffffff", "white"):          # white text on the (assumed) white page
        return True
    if "width" in s and _px(s["width"]) == 0 or "height" in s and _px(s["height"]) == 0:
        return True
    return False


def is_overlay(attrs: dict) -> bool:
    """A positioned element drawn above the page that is either invisible or covers the viewport."""
    s = _style(attrs)
    if s.get("position") not in ("fixed", "absolute"):
        return False
    z = _px(s.get("z-index", "0"))
    covers = s.get("width") == "100%" and s.get("height") == "100%"
    invisible = s.get("opacity") in ("0", "0.0")
    return z >= 1000 and (covers or invisible)


@dataclass
class Perception:
    text: list[str] = field(default_factory=list)
    buttons: list[dict] = field(default_factory=list)   # {"label", "action", "overlay"}
    flags: list[str] = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self, mode: str):
        super().__init__()
        self.mode = mode
        self.p = Perception()
        self.stack: list[tuple[str, bool, bool]] = []   # (tag, hidden, overlay)
        self.cur_button: dict | None = None
        self.skip = 0

    @property
    def hidden(self):
        return any(h for _, h, _ in self.stack)

    @property
    def overlay(self):
        return any(o for _, _, o in self.stack)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self.skip += 1
        hid, ov = is_hidden(a), is_overlay(a)
        if self.mode == "naive":
            for k in ("alt", "title", "aria-label"):
                if a.get(k):
                    self.p.text.append(a[k])
        else:
            if ov:
                self.p.flags.append("overlay element")
            if hid:
                self.p.flags.append(f"hidden <{tag}>")
        if tag == "button":
            self.cur_button = {"label": "", "action": a.get("data-action", "click"), "overlay": ov or self.overlay, "hidden": hid or self.hidden}
        if tag not in VOID:
            self.stack.append((tag, hid, ov))

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        if tag == "button" and self.cur_button is not None:
            b, self.cur_button = self.cur_button, None
            if self.mode == "naive" or not (b["overlay"] or b["hidden"]):
                self.p.buttons.append(b)
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.skip or not data.strip():
            return
        if self.cur_button is not None:
            self.cur_button["label"] += data.strip()
        if self.mode == "visible" and (self.hidden or self.overlay):
            return
        self.p.text.append(data.strip())


def perceive(html: str, mode: str = "naive") -> Perception:
    parser = _Parser(mode)
    parser.feed(html)
    return parser.p


# ------------------------------------------------------------------ the agent

DIRECTIVE_RE = re.compile(r"AGENT:\s*(navigate|click|fill)\s+(.+)", re.IGNORECASE)


def gullible_planner(p: Perception) -> list[dict]:
    actions = []
    for chunk in p.text:
        m = DIRECTIVE_RE.search(chunk)
        if m:
            verb, rest = m.group(1).lower(), m.group(2).strip()
            if verb == "navigate":
                actions.append({"type": "navigate", "url": rest})
            elif verb == "click":
                actions.append({"type": "click", "label": rest, "action": "click"})
            else:
                actions.append({"type": "fill", "field": "password", "value": "<autofill>"})
    for b in p.buttons:                                    # "dismiss any dialog" habit
        if b["label"].lower() in ("allow", "accept", "ok", "play video"):
            actions.append({"type": "click", "label": b["label"], "action": b["action"]})
    return actions


@dataclass
class World:
    navigations: list[str] = field(default_factory=list)
    clicks: list[str] = field(default_factory=list)
    credentials_sent: list[str] = field(default_factory=list)
    grants: list[str] = field(default_factory=list)


@dataclass
class Defenses:
    visible_only: bool = False
    domain_allowlist: tuple[str, ...] | None = None
    no_autofill: bool = False
    approval_actions: tuple[str, ...] = ()
    approve: object = None            # callable(action)->bool; None = deny
    log: list[str] = field(default_factory=list)


def _host_ok(url: str, allow: tuple[str, ...]) -> bool:
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in allow)


def act(action: dict, world: World, d: Defenses) -> str:
    kind = action["type"]
    if kind == "navigate":
        if d.domain_allowlist is not None and not _host_ok(action["url"], d.domain_allowlist):
            d.log.append(f"BLOCK navigate {action['url']}")
            return "blocked"
        world.navigations.append(action["url"])
        return "done"
    if kind == "fill":
        if d.no_autofill:
            d.log.append("BLOCK credential autofill")
            return "blocked"
        world.credentials_sent.append(FAKE_PASSWORD)
        return "done"
    if kind == "click":
        gate = action["action"]
        if gate in d.approval_actions or action["label"].lower() in d.approval_actions:
            if d.approve is None or not d.approve(action):
                d.log.append(f"DENY (approval) click {action['label']} [{gate}]")
                return "blocked"
        world.clicks.append(action["label"])
        if gate == "grant-permissions":
            world.grants.append("permissions")
        return "done"
    return "error"


def run(html: str, d: Defenses) -> World:
    world = World()
    p = perceive(html, "visible" if d.visible_only else "naive")
    for a in gullible_planner(p):
        act(a, world, d)
    return world
