"""Parse a Trivy JSON report (fixture) and apply a CI severity gate.

Field names follow Trivy's JSON schema (SchemaVersion 2): Results[].Vulnerabilities[],
Secrets[], Misconfigurations[]. Verify against your Trivy version. CVE ids in the
fixture are fictional (CVE-2099-xxxx).
"""
from __future__ import annotations

SEV = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def rank(s: str) -> int:
    return SEV.index(s.upper()) if s.upper() in SEV else 0


def vulns(report: dict) -> list[dict]:
    out = []
    for r in report.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            out.append({
                "id": v["VulnerabilityID"], "pkg": v["PkgName"], "installed": v["InstalledVersion"],
                "fixed": v.get("FixedVersion") or "", "severity": v["Severity"], "target": r["Target"],
                "class": r.get("Class", ""), "title": v.get("Title", ""),
            })
    return out


def secrets(report: dict) -> list[dict]:
    return [dict(s, target=r["Target"]) for r in report.get("Results", []) for s in r.get("Secrets") or []]


def misconfigs(report: dict) -> list[dict]:
    return [dict(m, target=r["Target"]) for r in report.get("Results", [])
            for m in r.get("Misconfigurations") or [] if m.get("Status") == "FAIL"]


def parse_ignore(text: str) -> set[str]:
    """.trivyignore: one id per line, '#' starts a comment."""
    ids = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ids.add(line)
    return ids


def summary(report: dict) -> dict[str, int]:
    counts = {s: 0 for s in reversed(SEV)}
    for v in vulns(report):
        counts[v["severity"]] += 1
    return counts


def gate(report: dict, fail_on: str = "HIGH", ignore_unfixed: bool = False,
         ignore_ids: set[str] | None = None, fail_on_secrets: bool = True) -> tuple[bool, list[str]]:
    """Return (passes, reasons). Mirrors `trivy --severity HIGH,CRITICAL --exit-code 1
    [--ignore-unfixed] [--ignorefile ...]` plus a secret check."""
    ignore_ids = ignore_ids or set()
    reasons = []
    for v in vulns(report):
        if rank(v["severity"]) < rank(fail_on) or v["id"] in ignore_ids:
            continue
        if ignore_unfixed and not v["fixed"]:
            continue
        reasons.append(f'{v["severity"]} {v["id"]} {v["pkg"]} {v["installed"]} -> fix {v["fixed"] or "none"}')
    if fail_on_secrets:
        reasons += [f'SECRET {s["RuleID"]} in {s["target"]}:{s["StartLine"]}' for s in secrets(report)]
    return (not reasons, reasons)
