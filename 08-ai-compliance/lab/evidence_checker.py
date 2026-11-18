"""Evidence-gap checker: controls <-> evidence files -> missing, stale or untrustworthy evidence.

Input:
    fixtures/controls.yaml          one control set, mapped to several frameworks, with the
                                    evidence each control needs and how fresh it must be
    fixtures/evidence_*/index.yaml  the evidence index: which file proves which control,
                                    when it was collected, by what, and its SHA-256

Statuses for each required evidence item:
    OK            present, fresh, file exists, hash matches
    MISSING       no evidence of this type for this control
    STALE         older than max_age_days on the as-of date
    FILE_MISSING  the index points to a file that is not there
    TAMPERED      the file's hash no longer matches the index
    MANUAL_ONLY   the control needs automated evidence (from a pipeline) but only a person's
                  upload exists (e.g. a screenshot)

Switchable layers (to prove what each one catches):
    check_freshness, check_integrity, require_automation

Hashes are computed on content with Windows line endings normalized (CRLF -> LF), so a
git checkout on another OS does not look like tampering.

Add a new evidence file:  python 08-ai-compliance/lab/evidence_checker.py --hash <file>
"""

from __future__ import annotations

import argparse
import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

AUTOMATED_COLLECTORS = {"pipeline", "scheduler", "cloud-config-export"}
FRAMEWORKS = ["eu_ai_act", "iso_42001", "nist_ai_rmf", "soc2", "iso_27001"]


def normalized_digest(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def sha256_normalized(path: str | Path) -> str:
    return normalized_digest(Path(path).read_bytes())


@dataclass
class EvidenceResult:
    control: str
    evidence_type: str
    status: str
    detail: str
    evidence_id: str = "-"


def load(path: str | Path) -> dict | list:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def check_evidence(controls: list[dict], index: list[dict], evidence_dir: str | Path, as_of: date, *,
                   check_freshness: bool = True, check_integrity: bool = True,
                   require_automation: bool = True) -> list[EvidenceResult]:
    evidence_dir = Path(evidence_dir)
    by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for ev in index:
        by_key[(ev["control"], ev["type"])].append(ev)

    results: list[EvidenceResult] = []
    for ctl in controls:
        for req in ctl.get("evidence", []):
            candidates = sorted(by_key.get((ctl["id"], req["type"]), []),
                                key=lambda e: e["collected"], reverse=True)
            if not candidates:
                results.append(EvidenceResult(ctl["id"], req["type"], "MISSING", "no evidence in the index"))
                continue
            ev = candidates[0]  # judge the newest item
            results.append(_judge(ctl, req, ev, evidence_dir, as_of, check_freshness, check_integrity,
                                  require_automation))
    return results


def _judge(ctl, req, ev, evidence_dir, as_of, check_freshness, check_integrity, require_automation):
    r = lambda status, detail: EvidenceResult(ctl["id"], req["type"], status, detail, ev["id"])  # noqa: E731
    path = evidence_dir / ev["file"]
    if check_integrity:
        if not path.is_file():
            return r("FILE_MISSING", f"{ev['file']} not found")
        if sha256_normalized(path) != ev.get("sha256"):
            return r("TAMPERED", f"{ev['file']} hash does not match the index")
    age = (as_of - ev["collected"]).days
    if check_freshness and age > req["max_age_days"]:
        return r("STALE", f"collected {ev['collected']} ({age} days > {req['max_age_days']})")
    if require_automation and req.get("automated") and ev.get("collected_by") not in AUTOMATED_COLLECTORS:
        return r("MANUAL_ONLY", f"needs automated evidence, got upload by '{ev.get('collected_by')}'")
    return r("OK", f"{ev['file']} ({age} days old)")


def control_status(results: list[EvidenceResult]) -> dict[str, str]:
    """A control is OK only if every required evidence item is OK."""
    out: dict[str, str] = {}
    for res in results:
        if res.status != "OK":
            out[res.control] = "GAP"
        else:
            out.setdefault(res.control, "OK")
    return out


def framework_coverage(controls: list[dict], results: list[EvidenceResult]) -> dict[str, dict]:
    """For each framework: how many mapped requirements are backed by controls with good evidence.

    One control can satisfy requirements in several frameworks ("test once, comply many").
    A requirement is covered only if at least one mapped control is OK. A requirement that no
    control maps to is an unmapped gap - this is how you find what a framework adds.
    """
    status = control_status(results)
    cov: dict[str, dict] = {}
    for fw in FRAMEWORKS:
        reqs: dict[str, list[str]] = defaultdict(list)
        for ctl in controls:
            for ref in ctl.get("maps_to", {}).get(fw, []):
                reqs[ref].append(ctl["id"])
        covered = sorted(ref for ref, ctls in reqs.items() if any(status.get(c) == "OK" for c in ctls))
        gaps = sorted(set(reqs) - set(covered))
        cov[fw] = {"requirements": len(reqs), "covered": len(covered), "gaps": gaps}
    return cov


def main() -> None:
    """python 08-ai-compliance/lab/evidence_checker.py 08-ai-compliance/lab/fixtures/evidence_vulnerable"""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("evidence_dir", nargs="?", help="folder with index.yaml and the evidence files")
    p.add_argument("--controls", default=str(Path(__file__).with_name("fixtures") / "controls.yaml"))
    p.add_argument("--as-of", default="2026-11-15", help="audit date (YYYY-MM-DD)")
    p.add_argument("--no-freshness", action="store_true", help="ignore evidence age")
    p.add_argument("--no-integrity", action="store_true", help="do not check files exist or hashes match")
    p.add_argument("--no-automation", action="store_true", help="accept manual uploads everywhere")
    p.add_argument("--hash", metavar="FILE", help="print the normalized SHA-256 of FILE for the index")
    args = p.parse_args()
    if args.hash:
        print(sha256_normalized(args.hash))
        return
    if not args.evidence_dir:
        p.print_help()
        return
    controls = load(args.controls)
    index = load(Path(args.evidence_dir) / "index.yaml")
    results = check_evidence(controls, index, args.evidence_dir, date.fromisoformat(args.as_of),
                             check_freshness=not args.no_freshness, check_integrity=not args.no_integrity,
                             require_automation=not args.no_automation)
    for r in results:
        print(f"{r.control:11} {r.evidence_type:26} {r.status:12} {r.evidence_id:7} {r.detail}")
    print("controls:", control_status(results))


if __name__ == "__main__":
    main()
