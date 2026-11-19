"""Assess three docker run commands. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/demo.py
"""
import run_assess as ra

COMMANDS = {
    "sloppy dev": "docker run -d --privileged -v /var/run/docker.sock:/var/run/docker.sock --network host -e DB_PASSWORD=FAKE-hunter2 nginx:latest",
    "typical": "docker run -d -p 8080:80 --name web nginx:1.27",
    "hardened": ("docker run -d --read-only --tmpfs /tmp --user 10001:10001 --cap-drop ALL --cap-add NET_BIND_SERVICE "
                 "--security-opt no-new-privileges --memory 256m --pids-limit 100 -p 127.0.0.1:8080:8080 "
                 "nginx@sha256:" + "a" * 64),
}
for name, cmd in COMMANDS.items():
    findings = ra.assess(ra.parse_run(cmd))
    print(f"== {name}: {ra.verdict(findings)} (score {ra.risk_score(findings)}) ==")
    for f in findings:
        print(f"  [{f.severity:8}] {f.rule_id} {f.message}")
