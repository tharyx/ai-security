"""A tiny offline model of DefectDojo's data model: Product > Engagement > Test > Finding.

It copies the IDEAS (importers per scanner, severity normalisation, hash-code
deduplication, reimport that closes fixed findings), not the real code or database.
Real DefectDojo has far more (product types, endpoints, SLA configuration, JIRA push...).
Hedge: field names and dedup algorithms are as the author remembers them; verify in the
DefectDojo docs ("Deduplication", "Parsers", API v2 import-scan / reimport-scan).
"""
from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass, field

SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"]


@dataclass
class Finding:
    title: str
    severity: str
    description: str = ""
    cve: str | None = None
    cwe: int | None = None
    component_name: str | None = None
    component_version: str | None = None
    file_path: str | None = None
    line: int | None = None
    unique_id_from_tool: str | None = None
    fix_available: str | None = None
    # state
    active: bool = True
    duplicate: bool = False
    duplicate_of: int | None = None
    false_p: bool = False
    risk_accepted: bool = False
    is_mitigated: bool = False
    found_by: str = ""
    hash_code: str = ""
    id: int = 0
    test_id: int = 0


@dataclass
class Test:
    id: int
    engagement_id: int
    test_type: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Engagement:
    id: int
    product_id: int
    name: str
    tests: list[Test] = field(default_factory=list)


@dataclass
class Product:
    id: int
    name: str
    engagements: list[Engagement] = field(default_factory=list)


# Which fields feed the hash code, per scanner (DefectDojo keeps a setting like this; hedge).
HASH_FIELDS = {
    "SARIF": ["title", "cwe", "file_path", "line"],
    "Trivy Scan": ["title", "component_name", "component_version"],
}


def compute_hash(f: Finding, test_type: str) -> str:
    fields = HASH_FIELDS.get(test_type, ["title", "severity", "file_path"])
    raw = "|".join(str(getattr(f, name)) for name in fields)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def normalise_severity(value: str) -> str:
    v = (value or "").strip().lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
            "low": "Low", "info": "Info", "informational": "Info", "unknown": "Info"}.get(v, "Info")


def parse_sarif(data: dict) -> list[Finding]:
    out = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            sec = (rule.get("properties") or {}).get("security-severity")
            if sec is not None:
                score = float(sec)
                sev = ("Critical" if score >= 9 else "High" if score >= 7
                       else "Medium" if score >= 4 else "Low" if score > 0 else "Info")
            else:
                sev = {"error": "High", "warning": "Medium", "note": "Low"}.get(res.get("level", ""), "Info")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            tags = (rule.get("properties") or {}).get("tags", [])
            cwe = next((int(t.split("-")[1]) for t in tags if t.upper().startswith("CWE-")), None)
            out.append(Finding(
                title=rule.get("name") or res.get("ruleId", "unknown"), severity=sev,
                description=(res.get("message") or {}).get("text", ""), cwe=cwe,
                file_path=(loc.get("artifactLocation") or {}).get("uri"),
                line=(loc.get("region") or {}).get("startLine"),
                unique_id_from_tool=res.get("ruleId")))
    return out


def parse_trivy(data: dict) -> list[Finding]:
    out = []
    for result in data.get("Results", []):
        for vul in result.get("Vulnerabilities") or []:
            out.append(Finding(
                title=f"{vul['VulnerabilityID']} in {vul['PkgName']}",
                severity=normalise_severity(vul.get("Severity", "")),
                description=vul.get("Title") or vul.get("Description", ""),
                cve=vul["VulnerabilityID"] if vul["VulnerabilityID"].startswith("CVE-") else None,
                component_name=vul["PkgName"], component_version=vul.get("InstalledVersion"),
                file_path=result.get("Target"), fix_available=vul.get("FixedVersion"),
                unique_id_from_tool=vul["VulnerabilityID"] + ":" + vul["PkgName"]))
    return out


PARSERS = {"SARIF": parse_sarif, "Trivy Scan": parse_trivy}


class Dojo:
    def __init__(self, dedupe_scope: str = "product"):
        assert dedupe_scope in ("engagement", "product")
        self.scope = dedupe_scope
        self.products: dict[int, Product] = {}
        self._ids = itertools.count(1)
        self.findings: dict[int, Finding] = {}
        self.tests: dict[int, Test] = {}
        self.engagements: dict[int, Engagement] = {}

    # -- structure
    def add_product(self, name: str) -> Product:
        p = Product(next(self._ids), name)
        self.products[p.id] = p
        return p

    def add_engagement(self, product: Product, name: str) -> Engagement:
        e = Engagement(next(self._ids), product.id, name)
        product.engagements.append(e)
        self.engagements[e.id] = e
        return e

    def add_test(self, engagement: Engagement, test_type: str) -> Test:
        t = Test(next(self._ids), engagement.id, test_type)
        engagement.tests.append(t)
        self.tests[t.id] = t
        return t

    # -- scope helpers
    def _peers(self, test: Test) -> list[Finding]:
        eng = self.engagements[test.engagement_id]
        if self.scope == "engagement":
            tests = eng.tests
        else:
            tests = [t for e in self.products[eng.product_id].engagements for t in e.tests]
        return [f for t in tests for f in t.findings if not f.duplicate]

    # -- import
    def import_scan(self, test: Test, scan_type: str, data: dict) -> dict:
        """Like POST /api/v2/import-scan/: add findings, mark duplicates, never close anything."""
        created = dups = 0
        for f in PARSERS[scan_type](data):
            f.found_by = scan_type
            f.hash_code = compute_hash(f, scan_type)
            f.id, f.test_id = next(self._ids), test.id
            original = next((p for p in self._peers(test)
                             if (p.hash_code == f.hash_code or
                                 (f.unique_id_from_tool and p.unique_id_from_tool == f.unique_id_from_tool
                                  and p.found_by == f.found_by))), None)
            if original:
                f.duplicate, f.active, f.duplicate_of = True, False, original.id
                dups += 1
            else:
                created += 1
            test.findings.append(f)
            self.findings[f.id] = f
        return {"created": created, "duplicates": dups}

    def reimport_scan(self, test: Test, scan_type: str, data: dict) -> dict:
        """Like POST /api/v2/reimport-scan/: new -> create, still there -> keep, gone -> mitigated."""
        incoming = PARSERS[scan_type](data)
        for f in incoming:
            f.hash_code = compute_hash(f, scan_type)
        seen = {f.hash_code for f in incoming}
        current = {f.hash_code: f for f in test.findings if not f.duplicate}
        closed = reopened = 0
        for h, f in current.items():
            if h not in seen and f.active:
                f.active, f.is_mitigated = False, True
                closed += 1
            elif h in seen and f.is_mitigated:
                f.active, f.is_mitigated = True, False
                reopened += 1
        new = [f for f in incoming if f.hash_code not in current]
        for f in new:
            f.found_by = scan_type
            f.id, f.test_id = next(self._ids), test.id
            test.findings.append(f)
            self.findings[f.id] = f
        return {"created": len(new), "closed": closed, "reopened": reopened}

    # -- views
    def open_findings(self, product: Product) -> list[Finding]:
        return [f for e in product.engagements for t in e.tests for f in t.findings
                if f.active and not f.duplicate and not f.false_p and not f.risk_accepted]

    def counts_by_severity(self, product: Product) -> dict[str, int]:
        counts = {s: 0 for s in reversed(SEVERITIES)}
        for f in self.open_findings(product):
            counts[f.severity] += 1
        return counts
