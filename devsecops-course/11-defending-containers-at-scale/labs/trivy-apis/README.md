# Lab: Trivy server/client and a local mock API

**Course exercise:** "Scanning docker images using Trivy and its APIs" [CDE 7]. Lesson: [02 section 5](../../02-secure-images-linting-and-scanning.md#5-sca-of-images-and-choosing-a-scanner).

**Time:** 40 minutes. **Safety:** the mock server binds to **127.0.0.1** only, on a random port, and lives for the length of the test. No Trivy, no Docker, no internet.

## The concept

Trivy can run in **client/server mode**: a long-lived `trivy server` keeps the vulnerability database in one place, and thin CI clients send what they found in an image (packages and layers) and get results back. Benefits: one DB download instead of one per job, faster CI, central token control. DBA analogy: one shared reference database instead of every app copying the reference tables.

[trivy_mock_api.py](trivy_mock_api.py) is a **mock**: it answers a Twirp-style `POST /twirp/trivy.scanner.v1.Scanner/Scan` with a canned report, requires a `Trivy-Token` header, and offers `/healthz`. Route and header names are modelled on the real design: verify in the Trivy docs for your version.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/trivy-apis/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/trivy-apis -v
```

1. Call without a token: 401. With a wrong one: 401. What would happen to a server exposed with no token at all?
2. Scan the known image and feed the result to the gate from [trivy-vuln-scan](../trivy-vuln-scan/README.md) (shared parser, loaded by path).
3. Ask for an unknown target: 404. A real server scans what the client sends; the mock only looks up fixtures.

## Expected output (real run)

```text
server on 127.0.0.1 (port chosen at runtime)
no token     -> 401
unknown img  -> 404
valid scan   -> 200 {'CRITICAL': 2, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 1, 'UNKNOWN': 0}
CI gate (CRITICAL): FAIL 3 reasons
```

## Run the real tool (hedged)

```text
trivy server --listen 127.0.0.1:4954 --token "$TRIVY_TOKEN"
trivy image --server http://127.0.0.1:4954 --token "$TRIVY_TOKEN" registry.example.invalid/shop/api:1.4.0
```

Put the server behind TLS and an allow-list; the token is a shared secret, not user authentication. See [real-tools](../../real-tools/README.md).
