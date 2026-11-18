"""Networking lab demo: subnet quiz, firewall log analysis, DNS log analysis.

    .venv/Scripts/python cybersecurity-track/02-networking/lab/demo.py
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dns_analyzer as dns        # noqa: E402
import firewall_analyzer as fw    # noqa: E402
import sample_data as sd          # noqa: E402
import subnet_trainer as st       # noqa: E402


def main() -> None:
    print("=== 1. Subnet trainer (seed 42) ===")
    rng = random.Random(42)
    for i, kind in enumerate(st.KINDS, 1):
        q = st.generate_question(rng, kind)
        print(f"Q{i}. {q.prompt}\n    answer: {q.answer}")
    print()
    info = st.subnet_info("198.51.100.77/26")
    print("198.51.100.77/26 ->", {k: info[k] for k in ("network", "broadcast", "netmask", "usable_hosts")})
    print("wrong answer check:", st.check_answer(st.Question("broadcast", "?", "198.51.100.127"), "198.51.100.255"))
    print()

    print("=== 2. Firewall log ===")
    events = fw.parse_firewall_log(sd.FIREWALL_LOG)
    print(f"{len(events)} events parsed")
    for a in fw.analyze(events):
        print(f"{a.severity:<7} {a.rule:<13} {a.subject:<14} {a.detail}")
    print()

    print("=== 3. DNS log ===")
    queries = dns.parse_dns_log(sd.DNS_LOG)
    print(f"{len(queries)} queries parsed")
    for a in dns.analyze(queries):
        print(f"{a.severity:<7} {a.rule:<19} {a.subject:<13} {a.detail}")


if __name__ == "__main__":
    main()
