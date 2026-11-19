# Lesson 04: Management Tools (Portainer), OWASP Top 10 in Containers and Daemon Activity

> **Chapter:** 10 · Container Reconnaissance and Attacks · **Time:** ~4 hours
> **You will:** explain why management UIs are high-value targets, harden one, map the OWASP Top 10 onto containerized apps, demonstrate SSRF to the cloud metadata service and its defences, and read Docker events as evidence.

| | |
|---|---|
| **Prerequisites** | [Lessons 02](02-container-attack-matrix-image-and-registry-attacks.md) and [03](03-container-host-daemon-and-kernel-attacks.md) |
| **Labs** | [portainer-attack](labs/portainer-attack/README.md) · [owasp-top10-in-containers](labs/owasp-top10-in-containers/README.md) · [inspect-daemon-activity](labs/inspect-daemon-activity/README.md) |
| **Syllabus lines** | Attacking management tools (Portainer) · Exploiting OWASP Top 10 issues in containerized apps · (exercise) Inspecting Docker Daemon Activity |
| **Reuse** | Web testing: [csse ch2 dynamic-analysis lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md) and [cybersecurity-track 09 pentesting](../../cybersecurity-track/09-pentesting-fundamentals/README.md). Cloud metadata background: [csse ch5](../../csse-course/ch5-attacking-cloud-supply-chain/README.md) (IMDS v1 vs v2 SVG). |

## 1. Why it matters

Two things sit **on top** of the daemon: tools that manage it and apps that run in it. Both inherit the daemon's power. A weak dashboard is a root shell with a login page; a web flaw in a container reaches the cloud account if the container can talk to the metadata service.

## 2. Attacking management tools (Portainer)

Management UIs (Portainer is the best-known; Rancher, Docker Desktop dashboards and cloud consoles are similar) show containers, images, volumes and networks, and let users **start, stop, create and exec**. To do that they hold the **Docker socket** (or an agent on each host). So:

> **Whoever logs in to the UI can do what the socket can do: root on the host.**

Common weaknesses (verify against the current product; defaults and fixes change):

| Weakness | Why it is bad |
|---|---|
| **Exposed to the network or internet** | Scanners find login pages quickly |
| **No admin created yet** | On a fresh install the first visitor can set the admin password (products have time limits and warnings; verify) |
| **Default or weak credentials** | Guessed within minutes |
| **No MFA or SSO** | One password protects root on many hosts |
| **No role separation** | Every user is an admin |
| **Plain HTTP** | Sessions and passwords sniffable |
| **Outdated version** | Known vulnerabilities in the UI itself |
| **Secrets visible in container env** | The UI displays them to every user |

**Blast radius** is the key idea: containers controllable, volumes readable, secrets visible, other hosts reachable through agents, host root through the socket. The [portainer-attack lab](labs/portainer-attack/README.md) is a **mock UI object** (no web server, no real Portainer) with three states: fresh and exposed, default credentials, hardened. It prints the blast radius of each.

**Hardening:** do not expose it publicly (VPN or identity-aware proxy); create the admin account at install time with a long random password from a secret store; TLS; SSO and MFA; role-based access with least privilege; agents or a socket proxy instead of the raw socket where possible; keep it updated and pinned by digest; log and alert on its actions; keep secrets out of env vars. If you do not need a UI, do not run one.

## 3. OWASP Top 10 in containerized apps

The OWASP Top 10 describes web application risks. Running the app in a container does not remove them; it changes **what an attacker gets** when one succeeds. The lab holds the full 10-row table (2021 edition; a newer edition may exist, verify at owasp.org). Highlights:

| Category | Container angle |
|---|---|
| A01 Broken access control | Admin UI/API on a published port; path traversal reads mounted host files |
| A02 Cryptographic failures | TLS keys in the image, secrets in env, plain HTTP between containers |
| A03 Injection | Command injection in a root container with `docker.sock` = host compromise |
| A05 Security misconfiguration | Privileged mode, debug on, default credentials |
| A06 Vulnerable components | Old base images, unpatched libraries in layers |
| A07 Authentication failures | Default `admin/admin` on tools and registries |
| A08 Integrity failures | Unsigned images by mutable tag; unverified CI artifacts |
| A09 Logging failures | No daemon events, container logs lost on `rm` |
| A10 SSRF | App fetches attacker URLs and reaches the metadata service |

To practise the web side of these, use the [csse ch2 dynamic-analysis lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md) and the [pentesting fundamentals](../../cybersecurity-track/09-pentesting-fundamentals/README.md) module. For authorised hands-on practice use deliberately vulnerable apps in a lab VM (OWASP Juice Shop, DVWA, WebGoat; verify current names and images).

### 3.1 SSRF to the cloud metadata service from a container

**Server-Side Request Forgery (SSRF)** means the attacker makes the server send a request on their behalf: "fetch this URL" features (link previews, webhooks, image import, PDF renderers). On a cloud VM there is a special internal address, `169.254.169.254`, the **instance metadata service (IMDS)**. It can return the **temporary credentials of the VM's role**. A container on that VM often reaches it too. So an SSRF in a container app can become **cloud account access**.

How the defences differ (concepts; verify provider details):

| Defence | Effect |
|---|---|
| Validate and allow-list URLs; resolve the host and **block link-local, private and loopback addresses after canonicalisation** | Stops the request in the app. A **naive string blocklist** (`if "169.254.169.254" in url`) is bypassed by other spellings of the same address (decimal, hex, IPv6-mapped, DNS names pointing at it, redirects) |
| **IMDSv2** (session token via a PUT request) | A plain GET from an SSRF bug has no token, so it fails; this is the strongest single control on AWS |
| **Hop limit 1** on IMDSv2 | The token response cannot cross the extra network hop to a container, so containers cannot obtain a token |
| Least-privilege instance role | Even a leak gives little |
| Network policy / firewall on the node | Blocks the metadata address from pods and containers |
| Workload identity (IRSA, Pod Identity, Workload Identity) | Per-pod credentials instead of the node's role |

The [owasp-top10-in-containers lab](labs/owasp-top10-in-containers/README.md) simulates all of it **in-process with fake objects and canary credentials**: a vulnerable fetch feature, a fake metadata service (v1 and v2 behaviour), and a matrix showing which defence stops which request. Nothing leaves your machine.

## 4. Inspecting Docker daemon activity

Everything an attacker does through the API leaves **events**: image pulls, container create/start/exec/die/oom, network and volume changes, daemon reloads. `docker events --format '{{json .}}'` streams them; `docker logs` shows what the app said; the daemon log shows the daemon's view. The [inspect-daemon-activity lab](labs/inspect-daemon-activity/README.md) turns a JSON events fixture into a timeline and alerts (privileged create, socket mount, pull from an unapproved registry, exec, OOM, crash loops, daemon reload). The monitoring tools that do this at scale (Falco, Tracee, auditd, Wazuh) are chapter 12.

## 5. Defend (summary)

- Management tools: private network, SSO and MFA, RBAC, TLS, socket proxy or agent, updates.
- OWASP: secure SDLC (chapters 3 to 7) plus container hardening (chapter 11); least privilege for the container so one bug stays small.
- SSRF: URL validation after canonicalisation, IMDSv2 with hop limit 1, least-privilege roles, node network policy.
- Detection: ship events and logs off-host; alert on privileged creates, socket mounts and unknown registries.

## 6. Hands-on

[portainer-attack](labs/portainer-attack/README.md), [owasp-top10-in-containers](labs/owasp-top10-in-containers/README.md), [inspect-daemon-activity](labs/inspect-daemon-activity/README.md).

## 7. Scenario

A security scan finds a dashboard on `http://203.0.113.20:9000` that shows a login page for a container management tool. List what you check in the first ten minutes, what you tell the owner to do immediately, and how you would prove the blast radius without touching production data.

## 8. References

- OWASP Top 10, OWASP Docker Security Cheat Sheet, OWASP SSRF Prevention Cheat Sheet.
- Portainer documentation (security and deployment guides): verify at docs.portainer.io.
- AWS documentation on IMDSv2 and hop limits; equivalent provider documents (verify at source).
- Repo: csse [ch5 cloud](../../csse-course/ch5-attacking-cloud-supply-chain/README.md), [cybersecurity-track 09](../../cybersecurity-track/09-pentesting-fundamentals/README.md).
