# Harbor (hedged)

> Harbor is a CNCF graduated open-source registry. Verify install and configuration steps in the Harbor documentation for your version. A real install needs a database, Redis and storage, so check your laptop's disk and memory before trying it; it is optional.

## What to configure (concepts match the offline twin)

| Feature | Setting (names approximate) | Twin |
|---|---|---|
| **Projects** | public or private; storage quota | `Project(public=...)` |
| **Robot accounts** | scoped to a project and permissions (push, pull), with expiry; use them in CI instead of personal accounts | `Robot(...)` |
| **Tag immutability** | immutability rules by tag pattern | `immutable_patterns` |
| **Vulnerability scanning** | built-in scanner adapter (Trivy by default); scan on push | `Artifact.vulns` |
| **Prevent vulnerable images from running** | block pulls at or above a severity; CVE allowlist with expiry | `prevent_vulnerable`, `cve_allowlist` |
| **Content signature** | require signed images (cosign or Notation, check the docs) | `require_signature` |
| **Replication and proxy cache** | mirror upstream registries, enforce a single approved source | n/a |
| **Retention** | delete old tags by policy | n/a |

## Commands (shape)

```text
helm repo add harbor https://helm.goharbor.io
helm install harbor harbor/harbor -n harbor --create-namespace -f harbor-values.yaml   # configure TLS, persistence, admin secret via values (do not commit real secrets)
docker login harbor.example -u 'robot$<name>'          # secret from the Harbor UI/API
docker tag app:1.0 harbor.example/prod/app:1.0 && docker push harbor.example/prod/app:1.0
```

## Security notes

- Change default admin credentials; do not expose the admin UI to the internet.
- Use TLS and a trusted certificate; configure OIDC login where possible.
- Review robot account scopes and expirations regularly.
- Keep Harbor patched; registries are high-value targets.

Lab: [harbor-registry-policy](../labs/harbor-registry-policy/README.md)
