# Lesson 02: Secrets Scanning, Custom Secret Checks, and Why Pre-Commit Is Not a Gate

**Syllabus items covered:** "Secrets scanning to prevent secret exposure in the code.", "Writing custom checks to catch secrets leakage in an organization." ([CDP 5]); "Why pre-commit hooks are not a good fit in DevSecOps." ([CDE 3]).

**Time:** 2 hours plus labs. **Safety:** every secret in the lab is FAKE and built at runtime from pieces. Never paste a real key into a scanner or a test.

> **DBA analogy.** A hard-coded database password in a script is a credential left on a sticky note. Worse, git is like a transaction log you cannot truncate: once a secret is committed, it stays in the history even after you delete it from the file.

## 1. Why secrets in code are a big problem

- Git history is permanent and cloned everywhere (laptops, CI caches, forks).
- Attackers scan public repositories automatically; leaked cloud keys are abused within minutes.
- CI logs, container image layers, config files and chat messages leak secrets too.
- Many breaches start with one leaked token (see [CSE ch2 Codecov case](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/codecov-attack/README.md)).

**Prevention beats detection:** do not put secrets in code at all. Use a secrets manager and short-lived credentials ([chapter 13](../13-secrets-management/README.md)). Scanning is the safety net for the mistakes that still happen.

## 2. How secret scanners work

![Secrets live on in git history](../../images/dso-ch05-secrets-history.svg)

| Technique | Idea | Strength | Weakness |
|---|---|---|---|
| **Provider regex** | Known token formats (prefixes, lengths) | Precise, few false positives | Only known formats |
| **Generic assignment** | `password = "..."`, `api_key: "..."` | Finds custom secrets | Placeholders and test data |
| **Entropy** | Random-looking strings | Finds unknown formats | Hashes, UUIDs, build ids look random |
| **Keyword + context** | Near words like `secret`, `token` | Reduces noise | Misses unlabeled values |
| **File name signatures** | `id_rsa`, `.pem`, `.env`, `credentials` | Cheap, catches whole files | Name only; gitrob's idea |
| **Verification** | Call the provider API to see if the key is live (TruffleHog) | Very few false positives | Needs network and sends the secret to the provider |
| **Checksums** | Some tokens carry a check digit | Offline and safe | Only for formats that have one |
| **History scan** | Scan every commit on every branch | Finds deleted secrets | Slower; needs repo access |

The lab [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) implements regex, entropy, file-name signatures, an offline checksum "verification", and a **git history scan of a temporary repository**.

**Tools (verify at source).** **TruffleHog** (verification, many sources), **gitleaks** (fast, TOML rules), **detect-secrets** (Yelp, baseline workflow), GitHub secret scanning and **push protection** (blocks the push). **gitrob** (file-name based reconnaissance of repositories) is **unmaintained**; the course names it, but use TruffleHog, gitleaks or detect-secrets today. CSE reference labs: [CSE ch6 trufflehog](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md), [trivy-secrets-scan](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/README.md), [false-positive-analysis](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/false-positive-analysis/README.md), and the [CMCPSE ch5 secret scanner](../../cmcpse-course/ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md).

## 3. Writing custom checks for secret leakage in your organisation

Generic scanners know public formats. Your organisation has **internal** token formats, internal hostnames and conventions. Custom checks catch those:

1. **Internal token pattern.** If your platform issues `ORG_live_<20 chars><4 check chars>`, write one regex plus a checksum function. The lab does this with a fake `acme_live_` token: a bad checksum drops the finding to LOW (probably test data).
2. **Internal URLs with credentials.** `https://user:pass@internal-host/`.
3. **File name rules** for your own config files (`secrets.yaml`, `vault-token`, `.kube/config`).
4. **Allow-lists with a reason.** A path such as `tests/fixtures/` or a pragma comment on a line, never a global disable.
5. **Test the rules** with known-good and known-bad samples and measure the false-positive rate.
6. **Report with redaction.** Never print the secret in CI logs: show a prefix and the length.

## 4. Responding to a leaked secret (the order matters)

1. **Revoke and rotate** the secret immediately. Assume it is compromised.
2. **Check logs** for use of the old secret.
3. **Fix the code path** (read it from the secrets manager or environment).
4. **Add scanning** to CI on the merge-request range and on a schedule over history.
5. **Only then** consider rewriting history (`git filter-repo`, BFG). It does not help if the repo was cloned or pushed, and it breaks everyone's checkouts.

## 5. Why pre-commit hooks are not a good fit in DevSecOps

A **pre-commit hook** runs on the developer's machine before a commit. Frameworks such as **pre-commit** make it easy to add secret scanners and linters. It is a good **convenience**. It is a poor **control**.

| Problem | Detail |
|---|---|
| **Client side only** | The hook lives in `.git/hooks` on each laptop. It is not part of the repository's protected workflow. |
| **Skippable** | `git commit --no-verify`, `SKIP=hook-id git commit`, or simply never running `pre-commit install`. A new clone has no hook until someone installs it. |
| **Slow hooks get disabled** | If a full SAST scan takes a minute per commit, developers bypass it. |
| **Inconsistent versions** | Rules and tool versions drift between laptops. |
| **Not auditable** | No central record that the check ran or passed. |
| **Environment problems** | Windows, IDE commits, Git GUIs and bots may not run hooks; hooks need Python or other runtimes locally. |
| **Hooks are an attack surface** | A repository can ship hooks or hook config that run code on the developer machine; see [CSE ch2 exploiting-pre-commit-hooks](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/exploiting-pre-commit-hooks/README.md). |
| **Late for history** | A hook sees staged changes, not the whole branch, not old history. |

**What to do instead.**

1. **Enforce in CI** on every merge request, with protected branches so the job **must pass** to merge. Scan the **whole commit range** (`base..HEAD`) and periodically the full history.
2. **Keep a fast pre-commit hook as an optional convenience** (secrets and formatting), using the same rule set and version as CI, so developers find problems before the pipeline does.
3. Add **server-side** protection where the platform offers it (GitHub push protection, GitLab secret push protection; verify).
4. Treat the hook as **feedback**, CI as the **gate**.

Contrast with CSE: the sibling course teaches how to *set up* hooks in [pre-commit-hooks](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/pre-commit-hooks/README.md) and [sca-sast-pre-commit](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit/README.md) and how they are attacked. This DevSecOps chapter explains why they are not the enforcement point.

## 6. Common mistakes

- Relying on a hook and not scanning in CI.
- Scanning only the latest checkout, not history or other branches.
- Printing the secret in the scanner output.
- Marking a real secret as a false positive because "it is only a test key".
- Deleting the secret from the file and calling it fixed without rotating it.
- A global allow-list that hides a whole directory forever.

## 7. Checklist

- [ ] I can explain why a deleted secret is still exposed.
- [ ] I can name four detection techniques and the weakness of each.
- [ ] I can write a custom rule for an internal token format, with a checksum.
- [ ] I can list six reasons pre-commit hooks are not a gate, and what to do instead.
- [ ] I know gitrob is unmaintained and which tools replace it.
- [ ] I can state the correct order of response to a leaked secret.

## References

- TruffleHog, gitleaks, detect-secrets, pre-commit documentation (verify current versions); GitHub secret scanning and push protection docs.
- OWASP Secrets Management Cheat Sheet; CWE-798 (hard-coded credentials), CWE-532 (information exposure through logs).
- Repo: [chapter 13 secrets management](../13-secrets-management/README.md), [CMCPSE ch4 secrets-vault lab](../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/README.md).
