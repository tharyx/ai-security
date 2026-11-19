"""Container Attack Matrix: tactics and techniques, plus the map from EVERY CCSE 3 topic to a lab.

The matrix below is a teaching summary in the style of Microsoft's Threat Matrix for Kubernetes and the MITRE ATT&CK
Containers matrix (both change over time: verify names and techniques at source: attack.mitre.org and the Microsoft
Security blog). Tactic order follows the attack life cycle.

`CCSE3_TOPICS` is the course rule 'every topic/subtopic has an exercise in this module' turned into data: a test checks
that each topic points at a lab folder that really exists.
"""
from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
LABS = HERE.parent                                    # 10-.../labs
CSSE_LABS = HERE.parents[3] / "csse-course" / "ch3-attacking-container-supply-chain" / "labs"

TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Discovery", "Lateral Movement", "Impact"]

TECHNIQUES: dict[str, list[str]] = {
    "Initial Access": ["Exposed Docker API / management UI", "Vulnerable application in a container", "Malicious or backdoored image (supply chain)", "Open or weak registry"],
    "Execution": ["Exec into container", "New container from attacker image", "Application exploit (RCE)"],
    "Persistence": ["Backdoored image tag in a registry", "Container with restart policy", "Writable host mount"],
    "Privilege Escalation": ["Privileged container", "Docker socket / host mount", "Dangerous capability", "SetUID binary", "Kernel exploit", "docker group membership"],
    "Defense Evasion": ["Delete logs or events", "Masquerade as a legitimate image name (typosquat)", "Disable seccomp/AppArmor"],
    "Credential Access": ["Secrets in env, files or image layers", "Cloud metadata service (SSRF)", "Management UI session"],
    "Discovery": ["docker ps / inspect / info", "Network and port scan from inside", "Registry catalog enumeration"],
    "Lateral Movement": ["Flat default bridge network", "Shared host network or PID namespace", "Management agents across hosts"],
    "Impact": ["Resource hijacking (mining)", "Denial of service without limits", "Data destruction through mounts", "Tag overwrite / image poisoning"],
}

# finding ids used by the other labs in this chapter -> tactic
FINDING_TO_TACTIC = {
    "ESC-PRIV": "Privilege Escalation", "ESC-SOCK": "Privilege Escalation", "ESC-HOSTMOUNT": "Privilege Escalation", "ESC-SETUID": "Privilege Escalation",
    "ESC-HOSTPID": "Lateral Movement", "ESC-HOSTNET": "Lateral Movement", "ESC-HOSTIPC": "Lateral Movement",
    "V-SOCK": "Privilege Escalation", "V-PRIV": "Privilege Escalation", "V-IMDS": "Credential Access", "V-ENV": "Credential Access",
    "EVT-PRIV": "Privilege Escalation", "EVT-EXEC": "Execution", "EVT-PULL": "Initial Access", "EVT-OOM": "Impact", "EVT-TAG": "Persistence",
    "UNAUTH-API": "Initial Access", "REGISTRY-OPEN": "Initial Access", "SECRETS-IN-LAYER": "Credential Access", "NO-LIMITS": "Impact", "FLAT-NET": "Lateral Movement",
    "KERNEL-CVE": "Privilege Escalation", "RECON-INVENTORY": "Discovery", "SSRF-IMDS": "Credential Access",
}

# every CCSE 3 topic, verbatim -> (kind, lab folder, tactic(s))
CCSE3_TOPICS: list[tuple[str, str, str, list[str]]] = [
    ("Container Attack Matrix", "local", "container-attack-matrix", ["Initial Access", "Impact"]),
    ("Image-based attacks", "local", "image-based-attacks", ["Initial Access", "Credential Access"]),
    ("Malicious Images", "csse", "malicious-image", ["Initial Access", "Execution"]),
    ("Extracting passwords, tokens, TLS certs, etc.", "local", "extract-secrets-from-container", ["Credential Access"]),
    ("Exploiting vulnerable components", "local", "image-based-attacks", ["Initial Access", "Execution"]),
    ("Registry-based attacks", "local", "registry-attacks", ["Initial Access", "Persistence"]),
    ("Insecure Docker registries", "csse", "attack-docker-registry", ["Initial Access"]),
    ("Open Docker registries", "local", "registry-attacks", ["Discovery", "Impact"]),
    ("Lack of authorization (RBAC)", "local", "registry-attacks", ["Persistence", "Impact"]),
    ("Container-based attacks", "local", "container-escapes", ["Privilege Escalation"]),
    ("Manipulating the privileged mode containers", "local", "container-escapes", ["Privilege Escalation"]),
    ("Attacking mounted Docker volumes", "local", "container-escapes", ["Privilege Escalation", "Persistence"]),
    ("Abusing SetUID/SetGID binaries", "local", "container-escapes", ["Privilege Escalation"]),
    ("Exploiting shared namespaces", "local", "container-escapes", ["Lateral Movement"]),
    ("Attacking Linux capabilities", "local", "container-escapes", ["Privilege Escalation"]),
    ("Docker host (Daemon) / kernel attacks", "local", "daemon-and-kernel-attacks", ["Privilege Escalation"]),
    ("Exploiting unauthenticated Docker API", "local", "remote-docker-api-scan", ["Initial Access"]),
    ("Insecure Docker endpoint", "local", "daemon-and-kernel-attacks", ["Initial Access"]),
    ("Lack of network segregation", "local", "daemon-and-kernel-attacks", ["Lateral Movement"]),
    ("Denial of service attacks", "local", "daemon-and-kernel-attacks", ["Impact"]),
    ("Kernel exploits", "local", "daemon-and-kernel-attacks", ["Privilege Escalation"]),
    ("Privilege escalation methods in Docker", "local", "privilege-escalation-and-misconfig", ["Privilege Escalation"]),
    ("Security misconfigurations", "local", "privilege-escalation-and-misconfig", ["Privilege Escalation", "Defense Evasion"]),
    ("Attacking management tools (Portainer)", "local", "portainer-attack", ["Initial Access", "Credential Access"]),
    ("Exploiting OWASP Top 10 issues in containerized apps", "local", "owasp-top10-in-containers", ["Initial Access", "Credential Access"]),
]

# the seven CCSE 3 hands-on exercises -> lab
CCSE3_EXERCISES = [
    ("Backdooring Docker Image", "csse", "backdoor-docker-image"),
    ("Inspecting Docker Daemon Activity", "local", "inspect-daemon-activity"),
    ("Malicious Container Image", "csse", "malicious-image"),
    ("Exploiting Containerized Apps", "csse", "exploit-containerized-app"),
    ("Unsecured Docker Daemon", "csse", "unsecured-docker-daemon"),
    ("Docker Exploitation using deepce", "local", "deepce-exploitation"),
    ("Attacking Misconfigured Docker Registry", "csse", "attack-docker-registry"),
]


def lab_path(kind: str, name: str) -> Path:
    return (LABS if kind == "local" else CSSE_LABS) / name


def missing_labs() -> list[str]:
    rows = [(t, k, n) for t, k, n, _ in CCSE3_TOPICS] + CCSE3_EXERCISES
    return [f"{t} -> {n}" for t, k, n in rows if not lab_path(k, n).is_dir()]


def coverage(finding_ids: list[str]) -> dict[str, list[str]]:
    """Group findings by tactic, showing which part of the life cycle an environment is exposed in."""
    out: dict[str, list[str]] = {t: [] for t in TACTICS}
    for f in finding_ids:
        t = FINDING_TO_TACTIC.get(f)
        if t:
            out[t].append(f)
    return out


def kill_chain(finding_ids: list[str]) -> str:
    cov = coverage(finding_ids)
    hit = [t for t in TACTICS if cov[t]]
    gaps = [t for t in TACTICS if not cov[t]]
    return f"tactics exposed: {', '.join(hit) or 'none'}; no finding for: {', '.join(gaps) or 'none'}"
