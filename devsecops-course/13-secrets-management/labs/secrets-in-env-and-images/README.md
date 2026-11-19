# Lab: Secrets leaked through environment variables and images (and the fix)

**Course topics:** [CDE 8] "Environment Variables and Configuration files" and "Docker, immutable systems, and their security challenges". Lessons: [lesson 03](../../03-env-vars-config-files-and-immutable-systems.md).

**Time:** 45 minutes. **Safety:** JSON, YAML and text fixtures only: an image config, `docker inspect` output, an image history, a compose file and a log. Secrets are fake canaries (`CANARY-...`). Evidence in findings is always redacted. Nothing runs Docker.

## What it does

[leak_finder.py](leak_finder.py) looks for secrets in every place a container can leak them:

| Source | Scanner | Who can read it |
|---|---|---|
| Image config `Env` | `scan_image_config` | Anyone who can pull the image |
| `docker inspect` (`Config.Env`, bind mounts of `.env` and key files) | `scan_docker_inspect` | Anyone with Docker access (root-equivalent) |
| Image history | `scan_history` | Anyone who can pull the image: `ENV`, build `ARG`s, `COPY .env`, `echo password > file`, URLs with credentials, and "deleted later but still in the layer" |
| `/proc/<pid>/environ` | `scan_proc_environ` | Same user or root on the host, compromised code in the container |
| Application logs | `scan_log` | Everyone with log access |
| Compose file | `scan_compose` | Git history and laptops |

**Fix with runtime injection**: `runtime_injection` and `rewrite_compose` replace `NAME=value` by `NAME_FILE=/run/secrets/name`, move values to Compose `secrets:`, and the app reads them with `read_secret` (file first, env fallback for development only). The tests assert that the fixed documents scan clean and contain no canary values.

## Steps

```text
.venv/Scripts/python devsecops-course/13-secrets-management/labs/secrets-in-env-and-images/demo.py
.venv/Scripts/python -m pytest devsecops-course/13-secrets-management/labs/secrets-in-env-and-images -v
```

1. Run the demo. For each finding, name who could read it and how.
2. Look at `image_history.json`: why is `rm /app/.env` a MEDIUM finding and not a fix?
3. Add a new secret to `docker_inspect.json` (for example `SLACK_WEBHOOK_SECRET`) and re-run. Does a name like `SESSION_ID` cause a false positive? Why not?
4. Make a value look like a reference (`/run/secrets/x`, `${X}`) and see that it is not flagged. What could an attacker do to hide a secret from this scanner? (Encode it; use a name that does not match. That is why you also need entropy-based and verified scanners such as TruffleHog.)
5. Write the BuildKit secret mount that would replace the `ARG NPM_TOKEN` line (see lesson 03).

## Expected output (real run, abridged)

```text
== Image config (what anyone who pulls the image can read) ==
  [HIGH  ] image-config   config.Env[3]                secret-in-env: DB_PASSWORD=CA***
  [HIGH  ] image-config   config.Env[4]                secret-in-env: API_TOKEN=CA***
  [HIGH  ] image-config   config.Env[5]                url-credentials: DATABASE_URL=po***

== docker inspect (what anyone with docker access can read) ==
  [HIGH  ] docker-inspect api.Config.Env[2]            secret-in-env: REDIS_PASSWORD=CA***
  [HIGH  ] docker-inspect api.Config.Env[3]            secret-in-env: STRIPE_SECRET=CA***
  [MEDIUM] docker-inspect api.Mounts                   secret-file-bind-mount: /srv/shop/.env -> /app/.env (readable on the host by whoever can reach the file)
  [MEDIUM] docker-inspect api.Mounts                   secret-file-bind-mount: /srv/shop/tls/server.pem -> /etc/tls/server.pem (readable on the host by whoever can reach the file)

== Image history (docker history --no-trunc) ==
  [HIGH  ] image-history  history[3]                   secret-in-ENV-layer: ENV DB_PASSWORD=CA***
  [HIGH  ] image-history  history[4]                   build-arg-secret: ARG NPM_TOKEN=CA*** (build args persist in history)
  [HIGH  ] image-history  history[5]                   secret-file-copied: COPY of /app/.env into the image
  [HIGH  ] image-history  history[6]                   url-credentials: ci-bot:CA***@...
  [HIGH  ] image-history  history[7]                   secret-written-to-file: smtp_password=CA***
  [MEDIUM] image-history  history[8]                   deleted-but-still-in-layer: /app/.env was added in history[5]; removing it later does not remove it from that layer

== Log file ==
  [HIGH  ] log            line 2                       secret-in-log: DB_PASSWORD=CA***
  [HIGH  ] log            line 3                       bearer-token-in-log: Bearer CA***
  [HIGH  ] log            line 4                       url-credentials-in-log: orders:CA***@...

== /proc/<pid>/environ of the running container ==
  [HIGH  ] proc-environ   /proc/1/environ[3]           secret-in-env: DB_PASSWORD=CA***
  [HIGH  ] proc-environ   /proc/1/environ[4]           secret-in-env: API_TOKEN=CA***
  [HIGH  ] proc-environ   /proc/1/environ[5]           url-credentials: DATABASE_URL=po***

== Compose file before ==
  [HIGH  ] compose        services.api.environment[0]  secret-in-env: DB_PASSWORD=CA***
  [HIGH  ] compose        services.api.environment[1]  secret-in-env: API_TOKEN=CA***
  [HIGH  ] compose        services.worker.environment[0] secret-in-env: SMTP_PASSWORD=CA***
  [HIGH  ] compose        services.worker.environment[1] url-credentials: QUEUE_URL=am***
...
```

## Run the real tools

Trivy (secret and config scanners), TruffleHog, gitleaks, Dockle, `docker history --no-trunc`, `docker inspect`: see [CSSE ch6 Trivy secrets lab](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/README.md) and [TruffleHog lab](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md). Rotate every secret that ever leaked.
