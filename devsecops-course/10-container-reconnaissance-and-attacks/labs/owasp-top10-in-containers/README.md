# Lab: Exploiting OWASP Top 10 issues in containerized apps (with SSRF to cloud metadata)

**Course exercise:** "Exploiting OWASP Top 10 issues in containerized apps". Lessons: [04 OWASP Top 10 in containers](../../04-management-tools-and-owasp-top10.md#3-owasp-top-10-in-containerized-apps).

**Time:** 60 minutes. **Safety:** All in-process on fake objects: a fake metadata service at 169.254.169.254, a vulnerable fetch feature and canary credentials. No real request leaves your machine.

## What it models

Part 1: the OWASP Top 10 (2021 edition) with the **container angle** of each category and the lab where you practise it. Part 2: **SSRF to the cloud metadata service** from a container app: no filter, a naive string blocklist (bypassed by the decimal IP form of the same address), a strict address filter plus allow-list, and **IMDSv2 with hop limit 1**. The web-app side of the Top 10 is practised in [csse ch2 dynamic-analysis](../../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md) and the [pentesting fundamentals](../../../../cybersecurity-track/09-pentesting-fundamentals/README.md).

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/owasp-top10-in-containers/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/owasp-top10-in-containers -v
```

1. Run the demo and read the 12-row matrix.
2. Find the one defence that works even with no filter in the app. (IMDSv2.)
3. Add octal or IPv6-mapped spellings to `canonical_host()` and write a test.
4. Why does hop limit 1 stop containers? (The extra network hop of the container's bridge drops the token response.)

## Expected output (real run)

```text
A01 Broken Access Control: Container exposes an admin UI/API on a published port; path traversal ...
A02 Cryptographic Failures: TLS keys baked into the image; secrets in env vars; plain HTTP between...
A03 Injection: Command injection in an app running as root with docker.sock mounted b...
... (10 rows in total)

SSRF to the metadata service from a container app:
  IMDSv1, no filter / direct                           200  LEAK (credentials returned)
  IMDSv1, no filter / decimal IP trick                 200  LEAK (credentials returned)
  IMDSv1, no filter / legit                            200  fetched normally
  IMDSv1, naive blocklist / direct                     403  stopped (filter)
  IMDSv1, naive blocklist / decimal IP trick           200  LEAK (credentials returned)
  IMDSv1, naive blocklist / legit                      200  fetched normally
  IMDSv1, strict filter / direct                       403  stopped (filter)
  IMDSv1, strict filter / decimal IP trick             403  stopped (filter)
  IMDSv1, strict filter / legit                        200  fetched normally
  IMDSv2 (token + hop limit 1), no filter / direct     401  stopped (token needed)
  IMDSv2 (token + hop limit 1), no filter / decimal IP trick 401  stopped (token needed)
  IMDSv2 (token + hop limit 1), no filter / legit      200  fetched normally

What 'LEAK' looks like (canary values): {'AccessKeyId': 'CANARY-ACCESS-KEY-ID', 'SecretAccessKey': 'canary-secret-value', 'Token': 'canary-session-token'}
```

## Think about it

SSRF is a container problem because a container on a cloud VM often inherits the VM's network path and instance role. Defence in depth: validate URLs, block link-local addresses, IMDSv2, hop limit 1, least-privilege roles, network policy.

## Run the real tool

AWS IMDSv2 settings (`HttpTokens=required`, `HttpPutResponseHopLimit=1`) and equivalents on other clouds: verify at source. Practise only in your own cloud account.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`9` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/owasp-top10-in-containers`.
