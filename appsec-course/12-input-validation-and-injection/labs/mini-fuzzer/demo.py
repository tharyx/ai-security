import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzzer as f  # noqa: E402

print("== Brute forcing paths (ffuf-style: -u /api/v1/FUZZ -w wordlist -fc 404) ==")
for word, status, size in f.fuzz_keyword("/api/v1/FUZZ", f.WORDLIST):
    print(f"  {word:<16} [Status: {status}, Size: {size}]")

for secure in (False, True):
    print(f"\n== Fuzzing POST /api/v1/orders body fields ({'SECURE' if secure else 'VULNERABLE'}) ==")
    findings = f.fuzz(secure)
    if not findings:
        print("  no findings")
    for issue, cases in sorted(findings.items()):
        print(f"  {issue}: {len(cases)} input(s), e.g. {cases[0]}")
