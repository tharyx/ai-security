"""A MOCK container management UI (modelled on what tools like Portainer do) to show why an exposed admin UI is a
high-value target, how far its blast radius reaches, and how to harden it. It is an in-process object: no web
server, no real Portainer API, no network. Portainer's actual behaviour and defaults change: verify at source.

Core fact: a management UI is usually connected to the Docker socket (or an agent) as ROOT. Whoever logs in to the UI
can do what the socket can do.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Environment:
    """What the UI manages (the 'blast radius')."""
    containers: list[dict] = field(default_factory=lambda: [
        {"name": "shop-web", "env": {"MODE": "prod"}},
        {"name": "shop-api", "env": {"DB_PASSWORD": "canary-ui-pw", "API_TOKEN": "canary-ui-token"}},
        {"name": "shop-db", "env": {"POSTGRES_PASSWORD": "canary-pg-pw"}},
        {"name": "ci-runner", "env": {"RUNNER_TOKEN": "canary-runner-token"}},
    ])
    volumes: list[str] = field(default_factory=lambda: ["pgdata", "uploads"])
    stacks: list[str] = field(default_factory=lambda: ["shop", "ci"])
    agents: int = 3


class ManagementUI:
    def __init__(self, env: Environment, *, exposed: bool, admin_set: bool, admin_password: str | None = "admin",
                 mfa: bool = False, tls: bool = False, rbac: bool = False, socket_mode: str = "rw"):
        self.env, self.exposed, self.admin_set = env, exposed, admin_set
        self.admin_password, self.mfa, self.tls, self.rbac, self.socket_mode = admin_password, mfa, tls, rbac, socket_mode
        self.failed_logins = 0

    # --- attacker-facing behaviour ---
    def first_run_takeover(self, new_password: str) -> bool:
        """An UNinitialised instance lets the first visitor create the admin account (some products time this out; verify)."""
        if self.exposed and not self.admin_set:
            self.admin_set, self.admin_password = True, new_password
            return True
        return False

    def login(self, user: str, password: str, otp: str | None = None) -> bool:
        if not self.admin_set:
            return False
        ok = user == "admin" and password == self.admin_password
        if ok and self.mfa and otp != "000000-canary":
            ok = False
        self.failed_logins += 0 if ok else 1
        return ok

    def blast_radius(self) -> dict:
        """What an attacker with a UI session gets."""
        secrets = [(c["name"], k) for c in self.env.containers for k in c["env"] if any(w in k.upper() for w in ("PASS", "TOKEN", "SECRET"))]
        host_root = self.socket_mode == "rw"
        return {
            "containers_controllable": len(self.env.containers),
            "volumes_readable": list(self.env.volumes),
            "secrets_visible_in_env": secrets,
            "can_start_privileged_container": host_root and not self.rbac,
            "host_root_equivalent": host_root and not self.rbac,
            "other_hosts_via_agents": self.env.agents,
        }

    def exposure_findings(self) -> list[tuple[str, str]]:
        f = []
        if self.exposed and not self.admin_set:
            f.append(("CRITICAL", "UI reachable and no admin account created yet: first visitor becomes admin"))
        if self.admin_password in ("admin", "password", "portainer", "changeme", "12345678"):
            f.append(("CRITICAL", "default/weak admin password"))
        if self.exposed and not self.tls:
            f.append(("HIGH", "UI exposed over plain HTTP: credentials and sessions can be sniffed"))
        if self.exposed and not self.mfa:
            f.append(("HIGH", "internet/LAN-exposed UI without MFA or SSO"))
        if not self.rbac:
            f.append(("MEDIUM", "no role separation: every UI user is effectively an admin"))
        if self.socket_mode == "rw":
            f.append(("MEDIUM", "UI holds the Docker socket read-write: compromise of the UI == root on the host"))
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        return sorted(f, key=lambda t: order.index(t[0]))


HARDENING = [
    "Do not expose the UI to the internet: put it behind a VPN or an identity-aware proxy; bind to 127.0.0.1 or a management network.",
    "Create the admin account immediately at install time (script it) and use a long random password from a secret store.",
    "Terminate TLS with a valid certificate; disable plain HTTP.",
    "Enable SSO/OIDC and MFA; use role-based access with least-privilege teams.",
    "Use an agent or a socket proxy with an allow-list instead of the raw docker.sock where possible.",
    "Keep the UI image updated and pinned by digest; monitor its audit logs and the Docker events it triggers.",
    "Never put secrets in container env vars that the UI will display: use file-based secrets.",
]


def vulnerable() -> ManagementUI:
    return ManagementUI(Environment(), exposed=True, admin_set=False)


def default_creds() -> ManagementUI:
    return ManagementUI(Environment(), exposed=True, admin_set=True, admin_password="admin")


def hardened() -> ManagementUI:
    return ManagementUI(Environment(), exposed=False, admin_set=True, admin_password="long-random-canary-pw-7f3a9c",
                        mfa=True, tls=True, rbac=True, socket_mode="proxy")
