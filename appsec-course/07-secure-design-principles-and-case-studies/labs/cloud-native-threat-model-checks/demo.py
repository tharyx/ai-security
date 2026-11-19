import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cn_checks as cn  # noqa: E402

FIX = HERE / "fixtures"
cases = [
    ("AWS S3", lambda v: cn.check_s3(cn.load_json(FIX / f"s3_{v}.json"))),
    ("Kubernetes", lambda v: cn.check_k8s(cn.load_json(FIX / f"k8s_{v}.json"))),
    ("vsftpd", lambda v: cn.check_vsftpd((FIX / f"vsftpd_{v}.conf").read_text(encoding="utf-8"))),
]
for title, run in cases:
    for variant in ("insecure", "hardened"):
        findings = run(variant)
        bad = cn.failed(findings)
        print(f"== {title} ({variant}): {len(findings) - len(bad)}/{len(findings)} mitigations in place, "
              f"gate exit code {cn.gate(findings)} ==")
        for f in bad:
            print(f"  FAIL {f.threat:8} {f.target:34} {f.detail}")
    print()
