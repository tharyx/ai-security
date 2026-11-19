"""Simulated SLSA Build L1: generate provenance, then check the L1 requirements.

The statement follows the in-toto Statement v1 layout with a SLSA provenance v1
predicate. Field names here are from the public spec as the author remembers it:
verify against https://slsa.dev/spec/v1.0/provenance before relying on them.
Nothing runs a real build; the "pipeline" is a function.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

import yaml

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://example.invalid/simulated-build/v1"  # a made-up build type


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def simulate_pipeline(*, repo_uri: str, ref: str, commit: str, entry_point: str,
                      artifact_name: str, artifact_bytes: bytes, builder_id: str,
                      invocation_id: str = "run-1",
                      started: str = "2026-01-01T10:00:00Z",
                      finished: str = "2026-01-01T10:03:00Z") -> dict:
    """Return the provenance statement a build step would emit for one artifact."""
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": artifact_name, "digest": {"sha256": sha256_hex(artifact_bytes)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "source": {"uri": f"git+{repo_uri}@{ref}", "digest": {"gitCommit": commit}},
                    "entryPoint": entry_point,
                },
                "internalParameters": {},
                "resolvedDependencies": [
                    {"uri": f"git+{repo_uri}@{ref}", "digest": {"gitCommit": commit}}
                ],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": invocation_id, "startedOn": started,
                             "finishedOn": finished},
                "byproducts": [],
            },
        },
    }


@dataclass
class Check:
    requirement: str
    ok: bool
    detail: str = ""


@dataclass
class L1Result:
    checks: list[Check] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks)

    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]


def check_l1(statement: dict, artifact_bytes: bytes | None = None,
             artifact_name: str | None = None) -> L1Result:
    """Check what SLSA Build L1 asks for: provenance exists, is complete, matches the artifact.

    L1 does NOT ask for signatures or a hardened builder, so this is a completeness
    check, not a trust check. Anyone could have written this file (see slsa-level-2).
    """
    r = L1Result()

    def add(req, ok, detail=""):
        r.checks.append(Check(req, bool(ok), detail))

    if not isinstance(statement, dict):
        add("provenance exists and is a JSON object", False, "not an object")
        return r
    add("provenance exists and is a JSON object", True)
    add("statement type is in-toto Statement v1", statement.get("_type") == STATEMENT_TYPE,
        str(statement.get("_type")))
    add("predicate type is SLSA provenance v1", statement.get("predicateType") == PREDICATE_TYPE,
        str(statement.get("predicateType")))

    subjects = statement.get("subject") or []
    digests_ok = bool(subjects) and all(
        re.fullmatch(r"[0-9a-f]{64}", (s.get("digest") or {}).get("sha256", "")) for s in subjects)
    add("subject lists the artifact with a sha256 digest", digests_ok)

    if artifact_bytes is not None:
        actual = sha256_hex(artifact_bytes)
        match = [s for s in subjects if (s.get("digest") or {}).get("sha256") == actual
                 and (artifact_name is None or s.get("name") == artifact_name)]
        add("subject digest matches the artifact bytes", bool(match),
            f"artifact sha256={actual[:12]}...")

    pred = statement.get("predicate") or {}
    bd = pred.get("buildDefinition") or {}
    rd = pred.get("runDetails") or {}
    add("buildType is present", bool(bd.get("buildType")))
    ext = bd.get("externalParameters") or {}
    add("externalParameters are present (what the user controlled)", bool(ext))
    src = ext.get("source") or {}
    add("source repository and commit are recorded",
        bool(src.get("uri")) and bool((src.get("digest") or {}).get("gitCommit")))
    add("builder id is present", bool((rd.get("builder") or {}).get("id")))
    add("invocation id is present", bool((rd.get("metadata") or {}).get("invocationId")))
    return r


def write_provenance(path: str, statement: dict) -> None:
    """Provenance must be available to consumers: one JSON line, like *.intoto.jsonl."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(statement, sort_keys=True) + "\n")


def read_provenance(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.loads(fh.readline())


# --- CI YAML fixtures --------------------------------------------------------

_SHA = re.compile(r"@[0-9a-f]{40}$")


def analyze_pipeline_yaml(text: str) -> dict:
    """Spot how a pipeline file produces provenance. Heuristic, hedged: real pipelines vary."""
    doc = yaml.safe_load(text)
    out = {"platform": "unknown", "produces_provenance": False, "mechanism": None,
           "unpinned_actions": []}
    if isinstance(doc, dict) and "jobs" in doc:
        out["platform"] = "github-actions"
        for job in doc["jobs"].values():
            uses = job.get("uses")
            if uses and "slsa-github-generator" in uses:
                out.update(produces_provenance=True, mechanism="slsa-github-generator reusable workflow")
            elif uses and not _SHA.search(uses):
                out["unpinned_actions"].append(uses)
            for step in job.get("steps", []) or []:
                u = step.get("uses", "")
                if "attest-build-provenance" in u:
                    out.update(produces_provenance=True, mechanism="actions/attest-build-provenance")
                if u and not _SHA.search(u):
                    out["unpinned_actions"].append(u)
    elif isinstance(doc, dict):
        out["platform"] = "gitlab-ci"
        variables = doc.get("variables") or {}
        if str(variables.get("RUNNER_GENERATE_ARTIFACTS_METADATA", "")).lower() == "true":
            out.update(produces_provenance=True, mechanism="GitLab Runner artifacts metadata")
    return out
