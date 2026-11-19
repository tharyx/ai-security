import json
import pathlib
import tempfile
from datetime import date

import vetting as v

fx = pathlib.Path(__file__).parent / "fixtures"
intel = json.loads((fx / "intel.json").read_text())
today = date(2026, 11, 19)

requests = [
    ("acme-http", "3.2.1", "open_source"), ("yamlish", "0.9.0", "open_source"),
    ("reqeusts", "2.0.0", "open_source"), ("oldcrypto", "1.1.0", "open_source"),
    ("parsekit", "2.3.1", "open_source"), ("tiny-utils", "1.0.0", "open_source"),
    ("agpl-chart", "5.0.0", "open_source"), ("exploited-lib", "4.0.0", "open_source"),
    ("vendorsdk", "8.1", "commercial"), ("internal-billing", "1.7", "proprietary"),
]
with tempfile.TemporaryDirectory() as d:
    log = v.AuditLog(str(pathlib.Path(d) / "audit.jsonl"))
    for name, ver, ctype in requests:
        req = dict(name=name, version=ver, component_type=ctype, requester="demo",
                   justification="demo", use="runtime")
        dec = v.vet(req, intel, today)
        log.record(dec, today)
        print(f"{name:17} {ver:6} {dec.outcome:11} score={dec.score}")
        for f in dec.findings:
            if f.status != "pass":
                print(f"    {f.status:9} {f.check}: {f.detail}")
    print("audit chain valid:", log.verify_chain())
