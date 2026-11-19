# Lab: Identify a container and extract sensitive information

**Course exercise:** "Identify a Container and Extract Sensitive Information". Lessons: [02 image-based attacks: extracting secrets](../../02-container-attack-matrix-image-and-registry-attacks.md#4-extracting-passwords-tokens-tls-certs-etc).

**Time:** 60 minutes. **Safety:** All secrets are runtime-built canaries ([extractor.py](extractor.py) builds the token and the fake TLS key from pieces). Nothing real is read.

## What it models

Four places secrets hide in a container: **environment**, **files** (TLS key, config), **image history**, and **/proc/1/environ**. Each finding shows the location, the kind, a redacted preview and whether it is a leak. A `*_FILE` variable (a reference to a secret file) is correctly classed as fine.

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/extract-secrets-from-container/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/extract-secrets-from-container -v
```

1. Run the demo and count the places the same token appears.
2. Add your own fixture secret in a new place (for example a `.git/config`).
3. Check the previews: no full secret is printed.
4. Apply the advice per source and re-run.

## Expected output (real run)

```text
source          where                                       kind                                preview
env             API_TOKEN                                   secret in environment               cn-******************
env             DB_PASSWORD                                 secret in environment               can***********
env             DB_PASSWORD_FILE                            reference to a secret file (good)   /run/secrets/db
file            /etc/ssl/private/server.key                 TLS/private key                     -----BEGIN FAKE CANA...
file            /etc/ssl/certs/server.crt                   certificate (public, low risk)      ...
file            /app/config.yml:password                    credential in config                can***********
file            /app/config.yml:service_token               credential in config                cn-******************
image history   /bin/sh -c echo 'API_TOKEN=cn-token-9d41e7  secret baked into a build step      (see step)
image history   /bin/sh -c curl -u deploy:canary-registry-  secret baked into a build step      (see step)
/proc/1/environ API_TOKEN                                   secret in environment               cn-******************

8 leaks, 2 fine. Same token in 4 places: rotate it everywhere.
  fix [env]: Use Docker/Compose secrets or a secret manager; env is visible in `docker inspect`, /proc and crash dumps.
  fix [file]: Mount keys read-only from a secret store; never COPY them into the image.
  fix [image history]: Use BuildKit secret mounts (RUN --mount=type=secret); rotate anything that reached a layer.
  fix [/proc/1/environ]: Same exposure as env: anyone with the same UID (or root) can read it.
```

## Think about it

Identify first, then extract: `docker ps` and `inspect` identify the container, then `exec`, `cp` and `history` reach the data. Who needs docker access to do this? (Anyone with the socket: it is root-equivalent.)

## Run the real tool

`docker inspect -f '{{.Config.Env}}' NAME`, `docker exec NAME env`, `docker cp NAME:/path .`, `docker history --no-trunc IMAGE`, `trivy image --scanners secret IMAGE`.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/extract-secrets-from-container`.
