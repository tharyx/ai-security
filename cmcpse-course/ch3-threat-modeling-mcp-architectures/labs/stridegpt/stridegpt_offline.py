"""An offline twin of the STRIDE GPT idea, plus a validator that compares AI output with manual STRIDE.

STRIDE GPT (open source, github.com/mrwadams/stride-gpt) asks an LLM to produce a STRIDE threat model
from an application description. This file teaches the same workflow without an API key:

    build_prompt()      the kind of prompt such a tool sends (app description in, JSON threats out)
    generate()          a TEMPLATE-based generator (deterministic). If you pass an LLM object it is tried
                        first; non-JSON answers (MockLLM never returns JSON) fall back to the templates.
    validate()          compare the AI threats with the manual findings from the stride-mcp-architecture lab:
                        STRIDE coverage, MCP-specific MISSES, UNSUPPORTED claims about components that
                        do not exist, and DUPLICATES.

The templates are intentionally generic. They miss several MCP-specific threats (tool poisoning, rug pull,
shadowing, cross-server leakage, config command lines) and one template invents a "web form". That is the
lesson: an AI draft is a starting point, a human must validate it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from aisec_lab import load_lab_module

HERE = Path(__file__).resolve().parent
sm = load_lab_module(str(HERE.parent / "stride-mcp-architecture" / "_"), "stride_mcp")

STRIDE_NAMES = sm.STRIDE_NAMES

# feature -> keywords that switch it on in an app description
FEATURES: dict[str, tuple[str, ...]] = {
    "stdio": ("stdio",),
    "local_http": ("127.0.0.1", "localhost", "loopback"),
    "remote": ("remote",),
    "oauth": ("oauth",),
    "registry": ("registry",),
    "llm": ("llm", "model"),
    "database": ("database", "sql", " db "),
    "secrets": ("token", "api key", "credential", "secret"),
    "filesystem": ("file",),
}

# feature -> list of (stride letter, scenario, impact)
TEMPLATES: dict[str, list[tuple[str, str, str]]] = {
    "stdio": [
        ("E", "A compromised stdio server process runs with the full privileges of the user and reads files outside its purpose.", "Local data theft and persistence."),
        ("T", "A crafted tool argument is passed to a shell by the stdio server (command injection).", "Arbitrary command execution on the workstation."),
    ],
    "local_http": [
        ("S", "A malicious web page reaches the server on 127.0.0.1 through DNS rebinding and calls its tools.", "Unauthorised tool calls from the browser."),
    ],
    "remote": [
        ("S", "An attacker impersonates the remote MCP server with a look-alike endpoint.", "Credentials and data go to the attacker."),
        ("I", "Traffic to the remote server is intercepted when TLS is not enforced.", "Disclosure of tool arguments and results."),
    ],
    "oauth": [
        ("E", "The access token carries more scopes than the tools need (scope creep).", "A stolen token can do far more than intended."),
        ("S", "A stolen access token is replayed against the server.", "The attacker acts as the user."),
    ],
    "registry": [
        ("S", "A typosquatted server in the public registry is installed by mistake.", "Malicious code runs as an MCP server."),
        ("T", "A trusted package is updated with a backdoor (supply chain).", "Silent compromise of every user of the package."),
    ],
    "llm": [
        ("T", "Instructions hidden in a tool result steer the model (indirect prompt injection).", "Unintended tool calls and data leaks."),
        ("I", "Sensitive tool results are sent to the hosted LLM provider.", "Data leaves the organisation boundary."),
    ],
    "database": [
        ("I", "A tool returns more rows and columns than the task needs.", "Over-sharing of customer data."),
        ("T", "SQL injection through the web form that feeds the database tool.", "Data modification or theft."),   # invented: no web form
    ],
    "secrets": [
        ("I", "Secrets appear in logs or error messages of the server.", "Credential exposure."),
    ],
    "filesystem": [
        ("T", "Path traversal in a file tool reads or writes outside the project folder.", "Exposure of SSH keys and other files."),
    ],
    "always": [
        ("R", "Tool calls are not logged, so actions cannot be traced to a user.", "No forensic trail after an incident."),
        ("D", "Repeated tool calls exhaust quotas or the context window.", "Service degradation and cost."),
    ],
}

# Words that suggest the AI invented a component. Compared with the architecture text.
SUSPICIOUS_COMPONENTS = ("web form", "kubernetes", "kafka", "graphql", "s3 bucket", "saml", "ldap", "mobile app", "blockchain")

# manual library id -> stems that show the AI covered that threat
COVERAGE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "MT-S01": ("impersonat", "look-alike"), "MT-S02": ("typosquat", "registry"),
    "MT-S03": ("dns rebinding", "127.0.0.1"), "MT-S04": ("replay", "stolen"),
    "MT-T01": ("poison", "description"), "MT-T02": ("rug pull", "definition changes"),
    "MT-T03": ("indirect prompt injection", "tool result"), "MT-T04": ("command injection", "path traversal"),
    "MT-T05": ("mcp.json", "launch command", "config"), "MT-T06": ("tls", "intercept"),
    "MT-T07": ("backdoor", "supply chain"), "MT-R01": ("not logged", "logging"),
    "MT-I01": ("secrets appear", "in logs"), "MT-I02": ("plaintext", "token store"),
    "MT-I03": ("more rows", "over-shar"), "MT-I04": ("another server", "cross-server"),
    "MT-D01": ("exhaust", "repeated tool calls"), "MT-E01": ("full privileges",), "MT-E02": ("scope",),
    "MT-E03": ("passthrough", "confused deputy"), "MT-E04": ("without approval", "excessive agency"),
    "MT-E05": ("collision", "shadow"),
}


def build_prompt(description: str, app_type: str = "MCP-enabled AI application", internet_facing: bool = True,
                 sensitive: str = "Medium") -> str:
    """The kind of prompt a STRIDE-GPT-like tool sends. Shown so you can read and improve it."""
    return (
        "Act as a cyber security expert. Produce a STRIDE threat model for the application below.\n"
        f"APPLICATION TYPE: {app_type}\nINTERNET FACING: {internet_facing}\nDATA SENSITIVITY: {sensitive}\n"
        f"DESCRIPTION: {description}\n"
        "Return JSON only: {\"threat_model\": [{\"Threat Type\": \"Spoofing|Tampering|Repudiation|Information "
        "disclosure|Denial of service|Elevation of privilege\", \"Scenario\": \"...\", \"Potential Impact\": \"...\"}]}\n"
        "Consider MCP specifics: tool descriptions, tool results, transports (stdio and HTTP), OAuth tokens, registries."
    )


def detect_features(description: str) -> list[str]:
    text = f" {description.lower()} "
    return [f for f, words in FEATURES.items() if any(w in text for w in words)]


def template_threats(description: str) -> list[dict]:
    out = []
    for feat in detect_features(description) + ["always"]:
        for letter, scenario, impact in TEMPLATES[feat]:
            out.append({"Threat Type": STRIDE_NAMES[letter], "Scenario": scenario, "Potential Impact": impact})
    return out


def parse_llm_json(text: str) -> list[dict] | None:
    """Extract {"threat_model": [...]} from a model answer (it may be wrapped in a code fence). None if invalid."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
        items = data["threat_model"]
        ok = all({"Threat Type", "Scenario", "Potential Impact"} <= set(i) for i in items)
        return items if ok and items else None
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def generate(description: str, llm=None) -> dict:
    """Return {"source": "llm"|"template", "threats": [...]}. The LLM answer is used only if it is valid JSON."""
    if llm is not None:
        answer = llm.complete([{"role": "system", "content": "You are a security expert."},
                               {"role": "user", "content": build_prompt(description)}])
        parsed = parse_llm_json(answer)
        if parsed:
            return {"source": "llm", "threats": parsed}
    return {"source": "template", "threats": template_threats(description)}


def stride_letter(name: str) -> str:
    for k, v in STRIDE_NAMES.items():
        if v.lower() == name.lower() or k == name:
            return k
    return "?"


def validate(ai_threats: list[dict], findings: list, arch_text: str) -> dict:
    """Compare an AI threat list with manual findings (list of stride_mcp.Finding). Returns a report dict."""
    ai_text = [(t["Scenario"] + " " + t["Potential Impact"]).lower() for t in ai_threats]
    ai_letters = {stride_letter(t["Threat Type"]) for t in ai_threats}
    manual_letters = {f.stride for f in findings}
    manual = {f.library_id: f.title for f in findings}
    covered = sorted(lid for lid in manual
                     if any(any(k in text for k in COVERAGE_KEYWORDS.get(lid, ())) for text in ai_text))
    missed = sorted(set(manual) - set(covered))
    arch_low = arch_text.lower()
    unsupported = [t["Scenario"] for t in ai_threats
                   if any(c in t["Scenario"].lower() and c not in arch_low for c in SUSPICIOUS_COMPONENTS)]
    seen, dups = set(), []
    for t in ai_threats:
        key = t["Scenario"].lower()
        if key in seen:
            dups.append(t["Scenario"])
        seen.add(key)
    return {
        "ai_count": len(ai_threats), "manual_unique_threats": len(manual),
        "stride_missing_from_ai": sorted(manual_letters - ai_letters),
        "covered": covered, "missed": missed, "missed_titles": [manual[m] for m in missed],
        "recall": round(len(covered) / len(manual), 2) if manual else 1.0,
        "unsupported": unsupported, "duplicates": dups,
        "ai_threats_without_manual_match": [
            t["Scenario"] for t, text in zip(ai_threats, ai_text)
            if not any(any(k in text for k in COVERAGE_KEYWORDS.get(lid, ())) for lid in manual)],
    }


def render_report(report: dict) -> str:
    lines = ["# Validation of AI-generated threats against the manual STRIDE results", "",
             f"* AI threats: {report['ai_count']}; unique manual threat types: {report['manual_unique_threats']}",
             f"* Recall of manual threat types: {report['recall']:.0%} ({len(report['covered'])} covered)",
             f"* STRIDE letters missing from the AI output: {', '.join(report['stride_missing_from_ai']) or 'none'}",
             "", "## Missed by the AI (add these by hand)", ""]
    lines += [f"* {lid}: {t}" for lid, t in zip(report["missed"], report["missed_titles"])] or ["* none"]
    lines += ["", "## Unsupported (mentions parts the architecture does not have)", ""]
    lines += [f"* {s}" for s in report["unsupported"]] or ["* none"]
    lines += ["", "## Duplicates", ""] + ([f"* {s}" for s in report["duplicates"]] or ["* none"])
    return "\n".join(lines) + "\n"


def main() -> int:
    arch = sm.load_arch()
    findings = sm.find_threats(arch)
    result = generate(arch["description"])
    print(render_report(validate(result["threats"], findings, json.dumps(arch))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
