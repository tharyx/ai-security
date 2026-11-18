"""Scorecard: a denylist-only code runner vs a process sandbox with hard limits.

From the repository root:
    python 05-agent-security/sandboxing/lab/demo.py
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
from pathlib import Path

import attacks
from secure_runner import KillSwitch, SubprocessSandbox
from vulnerable_runner import NaiveRunner


def grade(res, target: Path) -> str:
    out = res.stdout
    if attacks.ENV_CANARY in out or attacks.DOTENV_CANARY in out:
        return "SECRET LEAKED"
    if target.exists():
        return "WROTE OUTSIDE"
    if "42" in out and "b'42" in out:
        return "PROCESS SPAWNED"
    if res.status == "hung":
        return "HUNG (no limit)"
    if len(out) > 1_000_000:
        return f"{len(out) // 1_000_000} MB OUTPUT"
    return res.status


def main() -> None:
    project = Path(tempfile.mkdtemp(prefix="agent-project-"))  # the agent's own folder
    (project / ".env").write_text(f"ACME_API_KEY={attacks.DOTENV_CANARY}\n", encoding="utf-8")
    host_env = {**os.environ, "ACME_API_KEY": attacks.ENV_CANARY}  # the agent host's environment
    target = project / "PWNED.txt"

    print(f"{'case':24} {'vulnerable':18} {'secure':16} secure-side evidence")
    print("-" * 100)
    try:
        for name, code in {**attacks.SNIPPETS, "benign": attacks.BENIGN}.items():
            code = code.replace("{target}", str(target))
            vr = NaiveRunner(str(project), host_env, lab_fuse=3.0).run(code)
            v = grade(vr, target)
            target.unlink(missing_ok=True)
            sr = SubprocessSandbox(host_env=host_env, timeout=1.5).run(code)
            s = grade(sr, target)
            target.unlink(missing_ok=True)
            note = sr.events[0] if sr.events else f"{sr.stdout.strip()[:40]!r} in {sr.seconds:.1f}s"
            note = note if len(note) <= 62 else note[:59] + "..."
            print(f"{name:24} {v:18} {s:16} {note}")

        # Soft layers OFF: the hard layers must still protect the secrets.
        print("\nSecure sandbox with BOTH soft layers off (denylist=False, fs_guard=False):")
        hard_only = SubprocessSandbox(host_env=host_env, denylist=False, fs_guard=False, block_network=False)
        for name in ("read_env_obvious", "read_env_bypass", "read_project_dotenv"):
            r = hard_only.run(attacks.SNIPPETS[name])
            shown = r.events[0] if r.events else repr(r.stdout.strip())
            print(f"  {name:22} -> {grade(r, target):14} {shown[:70]}")

        # Kill switch: stop a running snippet and refuse new ones.
        switch = KillSwitch()
        box = SubprocessSandbox(host_env=host_env, timeout=30, kill_switch=switch)
        threading.Timer(0.5, switch.trip, args=("operator pressed stop",)).start()
        r1 = box.run(attacks.SNIPPETS["infinite_loop"])
        r2 = box.run(attacks.BENIGN)
        print(f"\nKill switch: running snippet -> {r1.status} after {r1.seconds:.1f}s; next run -> {r2.status}")

        r = SubprocessSandbox(host_env=host_env).run(attacks.WRITE_OWN_FILE)
        print(f"Ephemeral work dir: snippet created {r.files}; dir still exists afterwards: "
              f"{Path(r.workdir).exists()}")
    finally:
        shutil.rmtree(project, ignore_errors=True)


if __name__ == "__main__":
    main()
