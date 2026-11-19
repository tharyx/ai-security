# Lab: How the Codecov attack happened

**Course exercise:** "How the Codecov attack happened". Lessons: [06 section 1](../../06-real-world-case-studies.md#1-stealing-environment-variables-from-build-servers-the-codecov-pattern), [04 section 1](../../04-attacks-on-build-and-cicd-systems.md#1-why-cicd-is-the-prize). Related: [CAISP ch4 poisoned-pipeline](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/poisoned-pipeline/README.md), [06 cicd](../../../../06-ai-devsecops/cicd/README.md).

**Time:** 30 minutes. **Safety:** the "uploader script" is a list of toy operations, the "attacker server" is an in-memory sink, secrets are FAKE strings, hosts are `.example`. Nothing is downloaded or run in a shell.

## The story in one paragraph (hedged; verify at the vendor's disclosure)

From January to April 2021 an attacker modified Codecov's Bash Uploader script on its servers, using credentials that were extracted from a Docker image creation process. Customers' CI jobs fetched and ran the script, which also sent environment variables (tokens, keys) to an attacker-controlled host. It was found in April 2021, when a customer noticed that the script's hash did not match the one published on GitHub.

## What the lab simulates

| Step | In the lab |
|---|---|
| Normal job | runs `GOOD_SCRIPT` (collect coverage, upload to the vendor host) |
| Attack | `TAMPERED_SCRIPT` = same script plus one line, `send_env` to `collector.attacker.example` |
| Defense 1 | verify a sha256 published **through another channel** before running the script |
| Defense 2 | give the job only the variables it needs (minimal CI environment) |
| Defense 3 | egress allowlist: the job may only talk to the vendor host |

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/codecov-attack/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/codecov-attack
```

## Expected output (real run)

```text
1 clean script, no checks        executed=True  leaked_vars=[]
2 tampered, no checks            executed=True  leaked_vars=['AWS_SECRET_ACCESS_KEY', 'CODECOV_TOKEN', 'GITHUB_REF', 'NPM_TOKEN']
3 tampered + checksum verify     executed=False leaked_vars=[]
4 tampered + minimal env only    executed=True  leaked_vars=['CODECOV_TOKEN']
5 tampered + egress allowlist    executed=True  leaked_vars=[]
```

## Break it yourself

1. Publish the checksum from the same server as the script (the test `test_checksum_from_same_server_is_weak`). Why does verification then fail to help? (An attacker who controls the server also controls the hash.) What fixes it? (A signature checked against a key you obtained separately, or a pinned version/digest in your own repo.)
2. Even in case 4 the attacker got `CODECOV_TOKEN`. What would you do after an incident like this? (Rotate every secret the job could see, review logs for use, and re-issue.)
3. Replace `curl | bash` in your own pipeline with "download, verify, then run". Where would you store the expected hash? (In your repo, reviewed like code.)

## Real tools

Pin tools by version and digest, use the vendor's signed releases (many now publish checksums and signatures; verify), prefer short-lived OIDC credentials over stored secrets, and scan pipelines: see [lesson 07](../../07-best-practices-for-securing-the-application-supply-chain.md) and [real-tools/gitlab.md](../../real-tools/gitlab.md).
