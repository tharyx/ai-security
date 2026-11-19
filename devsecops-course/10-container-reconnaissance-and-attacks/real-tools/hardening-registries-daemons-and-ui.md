# Real tool guide: hardening registries, the Docker daemon and management UIs (chapter 10)

> **Hedged guide.** Not run by the repo author for this guide. Verify every setting against the current documentation of your Docker, Harbor and Portainer versions. Tests in this repo never need these tools.

## Docker daemon (`/etc/docker/daemon.json`)

Compare with `daemon-good.json` in [daemon-and-kernel-attacks](../labs/daemon-and-kernel-attacks/README.md):

```json
{
  "hosts": ["unix:///var/run/docker.sock"],
  "userns-remap": "default",
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false
}
```

- Remote access: prefer `docker context create remote --docker "host=ssh://user@host"`. If TCP is unavoidable, use `tlsverify`, `tlscacert`, `tlscert`, `tlskey` on port **2376** and a private bind address (see the CA and certificate steps in Docker's "Protect the Docker daemon socket" page).
- Note: `userns-remap` changes volume ownership and some features: test first. **Rootless Docker** is the other route (`dockerd-rootless-setuptool.sh install`; verify prerequisites such as `newuidmap`).
- Audit with `docker-bench-security` and read `docker info` for Security Options and Rootless.
- Socket permissions: `ls -l /var/run/docker.sock` should show `root:docker` with mode `660`. Review `getent group docker`.

## Run flags worth making the default

`--cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 200 --memory 256m --cpus 0.5 --user 10001:10001 -p 127.0.0.1:HOST:CONTAINER`. Enforce in Kubernetes with Pod Security Admission "restricted" or policy engines (Kyverno, OPA Gatekeeper).

## Registry (Harbor and registry:2)

| Control | Harbor (CNCF graduated, verify) | Plain `registry:2` |
|---|---|---|
| Authentication | Local, LDAP/OIDC | htpasswd or token service |
| RBAC | Projects with roles; robot accounts with scopes | None built in: put a proxy or use a token service |
| Immutable tags | Tag immutability rules | Not built in |
| Scan on push | Built-in scanner integration (Trivy) | Not built in |
| Signing | cosign and Notation support | Store signatures as OCI artifacts |
| TLS | Yes | Configure certificates |
| Audit | Audit logs | Access logs |

Practise the attack side with [registry-attacks](../labs/registry-attacks/README.md) and the [csse registry lab](../../../csse-course/ch3-attacking-container-supply-chain/labs/attack-docker-registry/README.md), then check each Harbor setting above.

## Management UI (Portainer-style)

1. Install it on a private network or `127.0.0.1`; reach it through a VPN or an identity-aware proxy.
2. Create the admin user immediately at install time (use the product's documented option to pre-set the password from a file or secret; verify).
3. Enable TLS with a real certificate; disable plain HTTP.
4. Configure SSO (OIDC) and MFA if the edition supports it; otherwise place MFA in the proxy.
5. Use teams and roles; avoid giving every user admin.
6. Prefer an **agent** or a **socket proxy** with an allow-list over the raw socket.
7. Update regularly; pin by digest; watch its audit log.

Check your result against the hardening list in [portainer-attack](../labs/portainer-attack/README.md).

## Cloud metadata (SSRF defence)

- AWS: require IMDSv2 (`HttpTokens=required`) and set `HttpPutResponseHopLimit=1` for instances that run containers which should not reach IMDS. Other clouds have equivalents: verify at source.
- Kubernetes: prefer workload identity (IRSA, Pod Identity, Workload Identity) and a network policy or firewall rule blocking `169.254.169.254` from pods.
- Application: validate URLs after canonicalisation, as in [owasp-top10-in-containers](../labs/owasp-top10-in-containers/README.md).

## Runtime detection (preview of chapter 12)

Falco (CNCF graduated), Tracee (Aqua, eBPF), auditd rules on the Docker socket and `/var/lib/docker`, Wazuh's Docker listener. Alert on: privileged container creation, socket mounts, new registries, exec into production containers.
