# Real tool guide: container recon and assessment tools (chapter 10)

> **Hedged guide.** Written from project documentation, not run by the repo author for this guide. Tool names, flags, licences and maintenance status change: **check each project's page before you rely on it.** Tests in this repo never need any of these tools.

## Rules of engagement

- Use these tools **only** on systems you own or have written permission to test. Use a disposable lab VM.
- Do not scan networks you do not own for exposed Docker APIs. The labs use localhost mocks for that reason.
- Treat results as data. Never run a downloaded script before reading it.

## Native tools (always available)

| Goal | Commands |
|---|---|
| Inventory | `docker ps -a --format '{{json .}}'`, `docker inspect $(docker ps -aq)`, `docker info`, `docker network ls`, `docker volume ls`, `docker system df` |
| Image facts | `docker images --digests`, `docker image inspect IMG`, `docker history --no-trunc IMG` |
| Activity | `docker events --since 1h --format '{{json .}}'`, `docker logs --since 1h NAME`, `journalctl -u docker` |
| Snapshots | `docker diff NAME`, `docker commit NAME evidence:1`, `docker export NAME -o fs.tar`, `docker save evidence:1 -o img.tar` |
| Host view | `ss -ltnp`, `ps -ef`, `lsns`, `ls -l /proc/<pid>/ns`, `stat -fc %T /sys/fs/cgroup` |
| Capability masks | in a container `grep Cap /proc/self/status`; decode with `capsh --decode=<hex>` (libcap) |

Feed the JSON into [recon-builtin-tools](../labs/recon-builtin-tools/README.md) to practise ranking.

## Third-party tools

| Tool | Use | Typical command (verify) | Note |
|---|---|---|---|
| **Dive** | Layer explorer, efficiency score | `dive IMAGE`; CI mode `CI=true dive IMAGE` | Practise with [recon-third-party-image-inspection](../labs/recon-third-party-image-inspection/README.md) |
| **Trivy** | Vulnerabilities, misconfigurations, secrets, SBOM | `trivy image IMAGE`; `trivy image --scanners secret IMAGE`; `trivy config .` | See [csse trivy guide](../../../csse-course/ch3-attacking-container-supply-chain/real-tools/trivy.md) |
| **Grype** and **Syft** | SBOM then vulnerability match | `syft IMAGE -o json > sbom.json`; `grype sbom:sbom.json` | |
| **amicontained** | From inside a container: runtime, namespaces, capabilities, seccomp | run the binary in the container | Small tool; check that it is maintained |
| **deepce** | Docker enumeration and escape checks | shell script run inside a container | Check maintenance; read the script first. Practise with [deepce-exploitation](../labs/deepce-exploitation/README.md) |
| **CDK** | Container penetration toolkit | binary run inside a container | For authorised red-team labs only |
| **docker-bench-security** | CIS Docker Benchmark checks on a host | `./docker-bench-security.sh` | Check the benchmark version it implements |
| **Dockle** | Image linter (CIS-style) | `dockle IMAGE` | Complements Hadolint |
| **Hadolint** | Dockerfile linter | `hadolint Dockerfile` | |
| **nmap** | Port scan (your own hosts) | `nmap -p 2375,2376 127.0.0.1` | Never against hosts you do not own |
| **crane / skopeo** | Inspect registry content without pulling | `crane catalog REGISTRY`, `crane ls REPO`, `skopeo inspect docker://IMG` | On your own registries only |

## A lab setup you can trust

1. A VM with a snapshot you can revert to.
2. Docker or Podman installed, API on the Unix socket only.
3. A local `registry:2` on `127.0.0.1:5000` and a few intentionally weak containers you create yourself (a privileged one, one with a socket mount).
4. Run the labs' fixtures first, then repeat each analysis on your own weak containers with the real tools and compare results.

## Mapping tools to CCSE 2 exercises

| Exercise | Tools |
|---|---|
| Using Built-in Docker Tools for Reconnaissance | `docker ps/inspect/info/network/volume` |
| Use Third-party Tools for Image Inspection | Dive, Trivy, Grype, Syft |
| Scanning the Remote Host for Unauthenticated Docker API Access | `curl` and `nmap` on a host you own; the lab's localhost scanner |
| Identify a Container and Extract Sensitive Information | `docker inspect`, `exec`, `cp`, `history`, Trivy secret scan |
| Create and Restore a Snapshot of the Container for Further Analysis | `commit`, `export`, `save`, `diff`, `run` |
