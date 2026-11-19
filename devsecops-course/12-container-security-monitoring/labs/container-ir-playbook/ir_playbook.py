"""Simulated container IR response script: runs a runbook against a FAKE docker.

The FakeDocker answers from an incident fixture and records every command, so tests can
assert ORDER (the whole point of container IR). Real commands are listed in the runbook;
run them by hand or adapt this into your SOAR tool. Link: cybersecurity-track/05 SOC.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


class PlaybookError(Exception):
    pass


class FakeDocker:
    def __init__(self, incident: dict):
        self.inc = incident
        self.log: list[str] = []
        self.paused = False
        self.networks = list(incident["networks"])
        self.running = True
        self.exists = True

    def run(self, cmd: str) -> str:
        self.log.append(cmd)
        inc = self.inc
        if cmd.startswith("docker inspect"):
            return json.dumps(dict(inc["inspect"], Networks=list(self.networks), Paused=self.paused), indent=1)
        if cmd.startswith("docker top"):
            return inc["top"]
        if cmd.startswith("docker logs"):
            return inc["logs"]
        if cmd.startswith("docker diff"):
            return inc["diff"]
        if cmd.startswith("docker commit"):
            return "sha256:" + hashlib.sha256(inc["diff"].encode()).hexdigest()
        if cmd.startswith("docker export"):
            return f"(rootfs tar of {inc['cid']}: simulated)"
        if cmd.startswith("docker pause"):
            self.paused = True
            return inc["cid"]
        if cmd.startswith("docker network disconnect"):
            self.networks.remove(cmd.split()[3])
            return ""
        if cmd.startswith("ss -tnp"):
            return inc["host_connections"]
        if cmd.startswith("docker stop"):
            self.running = False
            return inc["cid"]
        if cmd.startswith("docker rm"):
            self.exists = False
            return inc["cid"]
        if cmd.startswith("docker run"):
            return "new-container-id"
        raise PlaybookError(f"unknown command {cmd}")


def run_playbook(runbook: dict, incident: dict, docker: FakeDocker, evidence_dir: Path) -> dict:
    """Execute phases in order. Returns a manifest {file: sha256} plus the executed commands."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    done_steps: set[str] = set()
    manifest: dict[str, str] = {}
    ctx = {"cid": incident["cid"], "name": incident["name"], "case": incident["case"].lower(), "clean_image": incident["clean_image"]}
    for ph in runbook["phases"]:
        for st in ph["steps"]:
            if st.get("destructive") and not {"commit", "export", "inspect"} <= done_steps:
                raise PlaybookError(f"refusing {st['id']}: evidence not preserved and snapshotted yet")
            if st.get("destructive") and docker.networks:
                raise PlaybookError(f"refusing {st['id']}: container still attached to {docker.networks}")
            if st.get("requires_clean_image") and incident["clean_image_digest"] == incident["image_digest"]:
                raise PlaybookError("refusing to redeploy the compromised image digest")
            cmds = [st["cmd"].format(network=n, **ctx) for n in list(docker.networks)] if st.get("per_network") else [st["cmd"].format(**ctx)]
            for cmd in cmds:
                out = docker.run(cmd)
                if st.get("evidence"):
                    p = evidence_dir / st["evidence"]
                    p.write_text(out, encoding="utf-8")
                    manifest[st["evidence"]] = hashlib.sha256(p.read_bytes()).hexdigest()
            done_steps.add(st["id"])
    (evidence_dir / "MANIFEST.sha256").write_text("".join(f"{h}  {f}\n" for f, h in sorted(manifest.items())), encoding="utf-8")
    return {"manifest": manifest, "commands": list(docker.log)}


def load_runbook(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))
