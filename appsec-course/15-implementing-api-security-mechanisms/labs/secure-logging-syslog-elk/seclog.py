"""Secure logging for APIs: redaction, log-injection defense, RFC 5424 syslog, and an ELK-like pipeline.

1. `redact()` removes secrets and masks PII in structured events before they are written.
2. `naive_log_line()` (VULNERABLE) vs `safe_log_line()`: CRLF injection forges log lines;
   `${...}` lookups (the Log4Shell pattern) are neutralized.
3. `format_rfc5424()` / `parse_rfc5424()`: syslog with STRUCTURED-DATA (RFC 5424; RFC 3164 is legacy BSD).
4. `Pipeline` (Logstash/Elastic-Agent-like) parses syslog lines into JSON documents with ECS-style
   field names; `MiniIndex` stores them and answers a small KQL-like query language
   (`field:value AND field:val* OR ...`); `detect_bruteforce()` is a simple detection rule.

Pure standard library. Token-like values are built at runtime and labelled FAKE.
"""
from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

SENSITIVE_KEYS = re.compile(r"pass(word)?|secret|token|api[_-]?key|authorization|cookie|session|private", re.I)
JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*")
BEARER_RE = re.compile(r"(?i)bearer\s+[\w.~+/=-]+")
EMAIL_RE = re.compile(r"\b([\w.+-])([\w.+-]*)@([\w-]+\.[\w.-]+)\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def _mask_cards(s: str) -> str:
    def repl(m):
        digits = re.sub(r"\D", "", m.group(0))
        return f"****{digits[-4:]}" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else m.group(0)
    return CARD_RE.sub(repl, s)


def redact_text(s: str) -> str:
    s = BEARER_RE.sub("Bearer [REDACTED]", s)
    s = JWT_RE.sub("[REDACTED-JWT]", s)
    s = EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(3)}", s)
    return _mask_cards(s)


def redact(event):
    if isinstance(event, dict):
        return {k: ("[REDACTED]" if SENSITIVE_KEYS.search(k) else redact(v)) for k, v in event.items()}
    if isinstance(event, list):
        return [redact(v) for v in event]
    if isinstance(event, str):
        return redact_text(event)
    return event


# ------------------------------------------------------------------ log injection
def naive_log_line(ts: str, user: str, msg: str) -> str:
    """VULNERABLE: user-controlled text goes straight into a line-oriented log."""
    return f"{ts} user={user} {msg}"


def neutralize(value: str) -> str:
    value = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
    value = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)
    return value.replace("${", "$\\{")  # lookup syntax (Log4Shell-style) is never interpreted


def safe_log_line(ts: str, user: str, msg: str) -> str:
    return json.dumps({"@timestamp": ts, "user.name": neutralize(user), "message": neutralize(msg)})


# ------------------------------------------------------------------ RFC 5424
FACILITY = {"kern": 0, "user": 1, "auth": 4, "authpriv": 10, "local0": 16, "local4": 20}
SEVERITY = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}


def _sd_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_rfc5424(facility: str, severity: str, ts: datetime, host: str, app: str, procid: str, msgid: str,
                   sd: dict[str, dict[str, str]] | None, msg: str) -> str:
    pri = FACILITY[facility] * 8 + SEVERITY[severity]
    stamp = ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if sd:
        sd_txt = "".join(f"[{sid} " + " ".join(f'{k}="{_sd_escape(str(v))}"' for k, v in params.items()) + "]"
                         for sid, params in sd.items())
    else:
        sd_txt = "-"
    return f"<{pri}>1 {stamp} {host} {app} {procid} {msgid} {sd_txt} {neutralize(msg)}"


SYSLOG_RE = re.compile(r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<proc>\S+) (?P<msgid>\S+) "
                       r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)$")
SD_ELEM_RE = re.compile(r"\[(\S+)((?: \S+?=\"(?:[^\"\\]|\\.)*\")*)\]")
SD_PARAM_RE = re.compile(r"(\S+?)=\"((?:[^\"\\]|\\.)*)\"")


def parse_rfc5424(line: str) -> dict:
    m = SYSLOG_RE.match(line)
    if not m:
        raise ValueError("not RFC 5424")
    pri = int(m["pri"])
    sd = {}
    if m["sd"] != "-":
        for sid, params in SD_ELEM_RE.findall(m["sd"]):
            sd[sid] = {k: re.sub(r"\\(.)", r"\1", v) for k, v in SD_PARAM_RE.findall(params)}
    return {"facility": pri // 8, "severity": pri % 8, "timestamp": m["ts"], "host": m["host"], "app": m["app"],
            "procid": m["proc"], "msgid": m["msgid"], "sd": sd, "msg": m["msg"]}


# ------------------------------------------------------------------ ELK-like pipeline and index
@dataclass
class MiniIndex:
    docs: list[dict] = field(default_factory=list)

    def index(self, doc: dict) -> None:
        self.docs.append(doc)

    @staticmethod
    def _match_term(doc: dict, term: str) -> bool:
        neg = term.startswith("NOT ")
        term = term[4:] if neg else term
        k, _, v = term.partition(":")
        val = str(doc.get(k.strip(), ""))
        hit = fnmatch.fnmatchcase(val, v.strip().strip('"'))
        return hit != neg

    def query(self, q: str) -> list[dict]:
        """KQL-like subset: terms `field:value` (wildcards *), AND, OR, NOT; AND binds tighter than OR."""
        ors = [part.strip() for part in re.split(r"\s+OR\s+", q)]
        out = []
        for d in self.docs:
            if any(all(self._match_term(d, t.strip()) for t in re.split(r"\s+AND\s+", grp)) for grp in ors):
                out.append(d)
        return out

    def count_by(self, field_name: str, docs: list[dict] | None = None) -> Counter:
        return Counter(d.get(field_name) for d in (docs if docs is not None else self.docs))


class Pipeline:
    """input (syslog lines) -> filter (parse, map to ECS-like fields, redact) -> output (index)."""

    def __init__(self, index: MiniIndex):
        self.index, self.dead_letter = index, []

    def process(self, line: str) -> None:
        try:
            p = parse_rfc5424(line)
        except ValueError:
            self.dead_letter.append(line)  # never silently drop: unparsed lines go to a dead-letter queue
            return
        audit = p["sd"].get("audit@32473", {})
        doc = {"@timestamp": p["timestamp"], "host.name": p["host"], "service.name": p["app"],
               "log.level": {v: k for k, v in SEVERITY.items()}[p["severity"]], "message": p["msg"],
               "event.action": audit.get("action"), "event.outcome": audit.get("outcome"),
               "user.name": audit.get("user"), "source.ip": audit.get("src"), "http.request.id": audit.get("req")}
        self.index.index(redact({k: v for k, v in doc.items() if v is not None}))


def detect_bruteforce(index: MiniIndex, threshold: int = 5, window_s: int = 60) -> list[dict]:
    fails = index.query("event.action:login AND event.outcome:failure")
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for d in fails:
        by_ip[d["source.ip"]].append(datetime.fromisoformat(d["@timestamp"].replace("Z", "+00:00")))
    alerts = []
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            j = i
            while j < len(times) and times[j] - times[i] <= timedelta(seconds=window_s):
                j += 1
            if j - i >= threshold:
                alerts.append({"rule": "api-login-bruteforce", "source.ip": ip, "count": j - i,
                               "first": times[i].isoformat()})
                break
    return alerts


def fake_jwt() -> str:
    """FAKE, unsigned-looking JWT built at runtime for redaction tests."""
    import base64
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{b({'alg': 'HS256', 'typ': 'JWT'})}.{b({'sub': 'FAKE-user'})}.FAKE-signature"
