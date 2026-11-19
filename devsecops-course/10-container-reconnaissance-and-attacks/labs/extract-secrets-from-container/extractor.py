"""Where secrets hide in a container and how an investigator (or attacker with a foothold) finds them.

Four places: (1) environment variables, (2) files mounted or copied into the container, (3) image history
(`docker history --no-trunc`), (4) /proc/1/environ of the main process. All data is a runtime-built canary.
"""
from __future__ import annotations

import math
import re

PRIVATE_KEY_HEAD = "-----" + "BEGIN "
SECRET_NAME = re.compile(r"(?i)(pass(word|wd)?|secret|token|api_?key|credential|private)")


def canary_token() -> str:
    return "cn-" + "token-" + "9d41" + "e7b2" + "a60c"


def canary_tls_key() -> str:
    return (f"{PRIVATE_KEY_HEAD}FAKE CANARY KEY-----\nQ0FOQVJZLU5PVC1BLVJFQUwtS0VZLU1BVEVSSUFM\n"
            f"-----END FAKE CANARY KEY-----")


def canary_cert() -> str:
    return f"{PRIVATE_KEY_HEAD}FAKE CANARY CERTIFICATE-----\nQ0FOQVJZLUNFUlQ=\n-----END FAKE CANARY CERTIFICATE-----"


def build_fixture() -> dict:
    tok = canary_token()
    return {
        "name": "shop-api",
        "env": ["PATH=/usr/bin", f"API_TOKEN={tok}", "DB_PASSWORD=canary-db-pw-1", "DB_PASSWORD_FILE=/run/secrets/db", "LOG_LEVEL=debug"],
        "files": {
            "/etc/ssl/private/server.key": canary_tls_key(),
            "/etc/ssl/certs/server.crt": canary_cert(),
            "/run/secrets/db": "canary-db-pw-1\n",
            "/app/config.yml": f"db:\n  host: shop-db\n  password: canary-db-pw-1\nservice_token: {tok}\n",
            "/app/readme.txt": "nothing to see here\n",
        },
        "history": [
            "/bin/sh -c #(nop) ADD file:abc in /",
            f"/bin/sh -c echo 'API_TOKEN={tok}' > /app/.env",
            "/bin/sh -c pip install -r requirements.txt",
            "/bin/sh -c curl -u deploy:canary-registry-pw https://repo.example.invalid/pkg.tgz -o /tmp/pkg.tgz",
        ],
        "proc1_environ": f"API_TOKEN={tok}\0HOME=/root\0",
    }


def entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def redact(value: str) -> str:
    return value[:3] + "*" * max(3, len(value) - 3) if len(value) > 3 else "***"


def scan_env(env: list[str]) -> list[dict]:
    out = []
    for e in env:
        k, _, v = e.partition("=")
        if SECRET_NAME.search(k) and v:
            kind = "reference to a secret file (good)" if k.endswith("_FILE") else "secret in environment"
            out.append({"source": "env", "where": k, "kind": kind, "preview": v if k.endswith("_FILE") else redact(v),
                        "is_leak": not k.endswith("_FILE")})
    return out


def scan_files(files: dict[str, str]) -> list[dict]:
    out = []
    for path, content in files.items():
        if PRIVATE_KEY_HEAD in content and "KEY-----" in content.splitlines()[0]:
            out.append({"source": "file", "where": path, "kind": "TLS/private key", "preview": content.splitlines()[0][:20] + "...", "is_leak": True})
        elif PRIVATE_KEY_HEAD in content:
            out.append({"source": "file", "where": path, "kind": "certificate (public, low risk)", "preview": "...", "is_leak": False})
        for line in content.splitlines():
            m = re.match(r"\s*([\w\-]*(?:pass\w*|secret|token|key)[\w\-]*)\s*[:=]\s*(\S+)", line, re.I)
            if m and path.endswith((".yml", ".yaml", ".env", ".conf", ".ini", ".json")):
                out.append({"source": "file", "where": f"{path}:{m.group(1)}", "kind": "credential in config", "preview": redact(m.group(2)), "is_leak": True})
    return out


def scan_history(history: list[str]) -> list[dict]:
    out = []
    for step in history:
        if re.search(r"(?i)(token|pass(word)?|secret)\w*=\S+", step) or re.search(r"-u \w+:\S+", step):
            out.append({"source": "image history", "where": step[:48], "kind": "secret baked into a build step", "preview": "(see step)", "is_leak": True})
    return out


def scan_proc_environ(raw: str) -> list[dict]:
    return [dict(d, source="/proc/1/environ") for d in scan_env([p for p in raw.split("\0") if p])]


def investigate(fx: dict) -> list[dict]:
    return scan_env(fx["env"]) + scan_files(fx["files"]) + scan_history(fx["history"]) + scan_proc_environ(fx["proc1_environ"])


ADVICE = {
    "env": "Use Docker/Compose secrets or a secret manager; env is visible in `docker inspect`, /proc and crash dumps.",
    "file": "Mount keys read-only from a secret store; never COPY them into the image.",
    "image history": "Use BuildKit secret mounts (RUN --mount=type=secret); rotate anything that reached a layer.",
    "/proc/1/environ": "Same exposure as env: anyone with the same UID (or root) can read it.",
}
