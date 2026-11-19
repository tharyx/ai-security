"""Demo: audit a vulnerable and a hardened cross-protocol bridge."""
from aisec_lab import load_lab_module

br = load_lab_module(__file__, "bridge")

for label, make in (("VULNERABLE bridge", lambda: br.Bridge()),
                    ("HARDENED bridge", lambda: br.Bridge(keep_trust=True, namespace_identity=True, strict_schema=True, global_replay=True))):
    findings = br.audit(make)
    print(f"== {label}: {len(findings)} finding(s) ==")
    for f in findings:
        print(f"  {f['id']} {f['title']}\n      evidence: {f['evidence']}\n      fix: {f['fix']}")
