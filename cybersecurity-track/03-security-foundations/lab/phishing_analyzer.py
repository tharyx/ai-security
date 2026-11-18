"""Phishing email header analyzer for synthetic .eml text.

Checks: SPF/DKIM/DMARC results, From vs Reply-To mismatch, From vs Return-Path
mismatch, lookalike (typosquat) domains, and link text that hides a different domain.
Offline only. It reads the Authentication-Results header written by YOUR mail
gateway; it does not do DNS lookups.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import parseaddr

TRUSTED_DOMAINS = {"northwind.example", "corp.example"}

# characters that look like other characters (very small table for the lab)
CONFUSABLES = {"1": "l", "0": "o", "rn": "m", "vv": "w"}

RISK_WEIGHTS = {
    "spf_fail": 25, "dkim_fail": 15, "dmarc_fail": 30,
    "reply_to_mismatch": 25, "return_path_mismatch": 10,
    "lookalike_domain": 35, "link_mismatch": 30,
}


@dataclass
class Finding:
    code: str
    detail: str

    @property
    def weight(self) -> int:
        return RISK_WEIGHTS.get(self.code, 5)


@dataclass
class Report:
    subject: str
    from_domain: str
    auth: dict[str, str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.weight for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.score >= 50:
            return "PHISHING-LIKELY"
        if self.score >= 20:
            return "SUSPICIOUS"
        return "CLEAN"


def domain_of(address_header: str) -> str:
    addr = parseaddr(address_header)[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def parse_auth_results(header_value: str) -> dict[str, str]:
    """Pull spf/dkim/dmarc results out of an Authentication-Results header."""
    out = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for mech in out:
        m = re.search(rf"\b{mech}=(\w+)", header_value or "", re.IGNORECASE)
        if m:
            out[mech] = m.group(1).lower()
    return out


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize(domain: str) -> str:
    for fake, real in CONFUSABLES.items():
        domain = domain.replace(fake, real)
    return domain


def lookalike_of(domain: str, trusted: set[str] = TRUSTED_DOMAINS) -> str | None:
    """Return the trusted domain this one imitates, or None. Exact matches are not lookalikes."""
    if not domain or domain in trusted:
        return None
    for good in trusted:
        if normalize(domain) == good:
            return good
        # compare the first label only (northwind vs northwlnd) and require the same TLD
        d_label, g_label = domain.split(".")[0], good.split(".")[0]
        if domain.split(".")[-1] == good.split(".")[-1] and d_label != g_label:
            if edit_distance(d_label, g_label) <= 2 and len(g_label) >= 6:
                return good
            if g_label in d_label:        # northwind-secure
                return good
    return None


def link_mismatches(body: str) -> list[tuple[str, str]]:
    """Find <a href=X>text</a> where the visible text names a different domain than X."""
    result = []
    for href, text in re.findall(r'<a\s+href="([^"]+)"[^>]*>(.*?)</a>', body, re.I | re.S):
        h = re.search(r"https?://([^/\s]+)", href)
        t = re.search(r"https?://([^/\s<]+)", text)
        if h and t and h.group(1).lower() != t.group(1).lower():
            result.append((t.group(1).lower(), h.group(1).lower()))
    return result


def analyze(eml_text: str) -> Report:
    msg = message_from_string(eml_text)
    from_domain = domain_of(msg.get("From", ""))
    auth = parse_auth_results(" ".join(msg.get_all("Authentication-Results", [])))
    rep = Report(msg.get("Subject", ""), from_domain, auth)

    if auth["spf"] != "pass":
        rep.findings.append(Finding("spf_fail", f"SPF result is '{auth['spf']}'"))
    if auth["dkim"] != "pass":
        rep.findings.append(Finding("dkim_fail", f"DKIM result is '{auth['dkim']}'"))
    if auth["dmarc"] != "pass":
        rep.findings.append(Finding("dmarc_fail", f"DMARC result is '{auth['dmarc']}'"))

    reply_domain = domain_of(msg.get("Reply-To", ""))
    if reply_domain and reply_domain != from_domain:
        rep.findings.append(Finding(
            "reply_to_mismatch", f"Reply-To domain {reply_domain} differs from From {from_domain}"))

    rp_domain = domain_of(msg.get("Return-Path", ""))
    if rp_domain and rp_domain != from_domain and not rp_domain.endswith("." + from_domain):
        rep.findings.append(Finding(
            "return_path_mismatch", f"Return-Path domain {rp_domain} differs from From {from_domain}"))

    imitated = lookalike_of(from_domain)
    if imitated:
        rep.findings.append(Finding(
            "lookalike_domain", f"{from_domain} looks like trusted domain {imitated}"))

    body = msg.get_payload() if not msg.is_multipart() else ""
    for shown, real in link_mismatches(body if isinstance(body, str) else ""):
        rep.findings.append(Finding("link_mismatch", f"link text shows {shown} but goes to {real}"))
    return rep


def format_report(rep: Report) -> str:
    lines = [f"Subject : {rep.subject}",
             f"From    : {rep.from_domain}",
             f"Auth    : spf={rep.auth['spf']} dkim={rep.auth['dkim']} dmarc={rep.auth['dmarc']}",
             f"Score   : {rep.score}  -> {rep.verdict}"]
    lines += [f"  - [{f.code}] {f.detail}" for f in rep.findings]
    return "\n".join(lines)
