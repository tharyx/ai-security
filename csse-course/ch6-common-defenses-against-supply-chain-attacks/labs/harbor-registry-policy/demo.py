"""Demo: a policy-enforcing registry."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry as r  # noqa: E402

reg = r.Registry(today=date(2026, 11, 19))
reg.create_project(r.Project("prod", public=False, immutable_patterns=("v",), prevent_vulnerable=True, severity_threshold="HIGH", require_signature=True))
reg.create_robot(r.Robot("ci-push", "prod", {"push"}, date(2027, 1, 1)))
reg.create_robot(r.Robot("k8s-pull", "prod", {"pull"}, date(2027, 1, 1)))


def attempt(label, fn):
    try:
        fn()
        print(f"OK    {label}")
    except r.PolicyError as e:
        print(f"DENY  {label}: {e}")


a = r.Artifact("prod/api", "v1.0", "sha256:aaa", [("EXAMPLE-2026-0002", "LOW")], signed=True)
attempt("push prod/api:v1.0", lambda: reg.push("ci-push", a))
attempt("push again (immutable tag)", lambda: reg.push("ci-push", r.Artifact("prod/api", "v1.0", "sha256:bbb", [], True)))
attempt("pull with push-only robot", lambda: reg.pull("ci-push", "prod/api", "v1.0"))
attempt("anonymous pull", lambda: reg.pull(None, "prod/api", "v1.0"))
attempt("pull signed LOW-only image", lambda: reg.pull("k8s-pull", "prod/api", "v1.0"))
reg.push("ci-push", r.Artifact("prod/api", "dev-1", "sha256:ccc", [("EXAMPLE-2026-0003", "CRITICAL")], signed=True))
attempt("pull image with a CRITICAL vuln", lambda: reg.pull("k8s-pull", "prod/api", "dev-1"))
reg.projects["prod"].cve_allowlist["EXAMPLE-2026-0003"] = date(2026, 12, 1)
attempt("pull after time-boxed CVE allowlist", lambda: reg.pull("k8s-pull", "prod/api", "dev-1"))
