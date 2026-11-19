import json
import pathlib
import tempfile

import slsa_provenance as sp

artifact = b"fake wheel bytes"
stmt = sp.simulate_pipeline(
    repo_uri="https://github.com/example/app", ref="refs/tags/v1.0.0",
    commit="a" * 40, entry_point=".github/workflows/release.yml",
    artifact_name="app-1.0.0.whl", artifact_bytes=artifact,
    builder_id="https://example.invalid/builders/simulated-runner")
print(json.dumps(stmt, indent=2)[:500], "...\n")

for label, s, data in [("good", stmt, artifact), ("artifact swapped", stmt, b"evil bytes")]:
    res = sp.check_l1(s, data, "app-1.0.0.whl")
    print(f"{label:17}: passed={res.passed}", [c.requirement for c in res.failures()])

broken = json.loads(json.dumps(stmt))
del broken["predicate"]["runDetails"]["builder"]
print("no builder id    :", [c.requirement for c in sp.check_l1(broken, artifact).failures()])

with tempfile.TemporaryDirectory() as d:
    p = pathlib.Path(d) / "app.intoto.jsonl"
    sp.write_provenance(str(p), stmt)
    print("round trip equal :", sp.read_provenance(str(p)) == stmt)

fx = pathlib.Path(__file__).parent / "fixtures"
for name in ["github-actions-slsa.yml", "gitlab-ci-provenance.yml", "unpinned-no-provenance.yml"]:
    print(name, "->", sp.analyze_pipeline_yaml((fx / name).read_text()))
