import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_sim as c  # noqa: E402

pub = c.sha256(c.GOOD_SCRIPT)
cases = [
    ("1 clean script, no checks", c.GOOD_SCRIPT, {}),
    ("2 tampered, no checks", c.TAMPERED_SCRIPT, {}),
    ("3 tampered + checksum verify", c.TAMPERED_SCRIPT, {"published_sha256": pub}),
    ("4 tampered + minimal env only", c.TAMPERED_SCRIPT, {"needed_vars": {"CODECOV_TOKEN"}}),
    ("5 tampered + egress allowlist", c.TAMPERED_SCRIPT, {"allowed_hosts": {c.GOOD_HOST}}),
]
for label, script, kw in cases:
    sink = c.Sink()
    r = c.ci_job(script, c.CI_ENV, sink, **kw)
    print(f"{label:32} executed={r.executed!s:5} leaked_vars={sorted(sink.received[0]) if sink.received else []}")
