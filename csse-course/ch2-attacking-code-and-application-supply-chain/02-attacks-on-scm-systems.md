# Lesson 02: Attacks on SCM Systems

> **Chapter:** 2 · Attacking Code and Application Supply Chain · **Time:** ~5 hours
> **You will:** explain seven classes of attack on git hosting and clients (shell breakouts, leaks, hooks, repojacking, code execution through git, unencrypted traffic, weak authentication), plus commit spoofing, and name the control for each.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-introduction-to-the-code-supply-chain.md) |
| **Labs** | [pre-commit-hooks](labs/pre-commit-hooks/README.md) · [exploiting-pre-commit-hooks](labs/exploiting-pre-commit-hooks/README.md) · [git-commit-spoofing](labs/git-commit-spoofing/README.md) · [git-commit-signing](labs/git-commit-signing/README.md) |
| **Syllabus lines** | Attacks on SCM systems · Breaking out of restricted Git shells · Git servers leaking confidential information · Exploiting pre-commit hooks · Repo Jacking · Executing Arbitrary Code With Git Commands · Risks of unencrypted Git traffic · Insufficient Authentication In Git Servers |

> **Safety.** Examples are conceptual or run as simulations in temporary directories. Specific CVEs are named only where well known; **verify versions and details at the source**.

## Why this matters

- Source control holds the code, the history (with every secret ever committed) and the keys to the pipeline.
- Git is a tool that **runs programs** for you (hooks, filters, helpers). Opening an untrusted repository can be as risky as running its code.
- Hosting platforms are internet-facing, and their default settings and account hygiene decide who can write to your repo.

## 1. Breaking out of restricted Git shells

A common setup for a self-hosted git server: users connect over SSH as one account (`git`), and that account's login shell is **`git-shell`**, a restricted shell that only allows git commands such as `git-receive-pack` and `git-upload-pack`, plus any scripts the admin places in a `git-shell-commands` directory. The idea: people can push and pull but cannot get a normal shell.

**How restrictions fail (conceptual).**

| Weakness | Idea |
|---|---|
| Interactive mode left on | `git-shell-commands/` has a `help` or `list` command, or an interactive script. Any script there is a new attack surface. |
| Helper scripts with unsafe argument handling | a "create repo" script that builds a shell command from user input (command injection) |
| SSH options not restricted | keys without `no-pty`, `no-port-forwarding`, `no-agent-forwarding` allow tunnels and pivots even without a shell |
| Writable repo internals | if the user can write into the bare repo's `hooks/` or `config` through some path, server-side code execution follows |
| Allowed program with an escape | a pager, editor or diff tool launched by an allowed command can spawn a shell (the classic restricted-shell escape) |
| Old software | historic bugs in git or the shell wrapper; keep patched (verify advisories) |

**Defend.** Use hosted platforms or a maintained server (Gitea, GitLab) instead of hand-rolled `git-shell` setups where possible; keep `git-shell-commands` empty or tiny and audited; use `restrict` (or the individual `no-*`) options on SSH keys; separate OS users and file permissions per repo; patch regularly; log SSH sessions.

## 2. Git servers leaking confidential information

| Leak | How it happens |
|---|---|
| **Secrets in history** | A key was committed once and "deleted" in a later commit. It lives in history, in every clone and every fork. |
| **Exposed `.git` directory** | A website deployed from a repo leaves `/.git/` readable on the web server. Anyone can download history and source. |
| **Public by mistake** | A private repo or a fork switched to public; a repo created public by default; a mirror pushed to a public remote. |
| **Anonymous access on self-hosted servers** | Public projects, open registration, user and repo listing through the API. |
| **Remote URLs with tokens** | `https://user:TOKEN@host/repo.git` ends up in `.git/config`, CI logs or shell history. |
| **Dangling and fork-reachable commits** | Deleted branches or forced pushes may still be reachable by SHA, on the server or through forks (hosting-specific; verify the platform's behavior and their documentation). |
| **CI logs and artifacts** | Build logs print environment variables or config. |

**Defend.** Secret scanning on push (platform feature plus gitleaks or TruffleHog), pre-commit secret detection, never put secrets in git (use a vault or CI secret store), block `/.git/` at the web server and build deployments from artifacts, restrict repo visibility by org policy, scrub history with `git filter-repo` or BFG **and rotate the secret** (rewriting history never un-leaks it), short-lived credentials.

**Lab link.** The [GitLab privilege-escalation lab](labs/gitlab-privilege-escalation/README.md) shows how variables and roles decide who can read secrets on a CI platform.

## 3. Exploiting pre-commit hooks

Git hooks are scripts in `.git/hooks/`. Frameworks like **pre-commit** manage them from a config file in the repo (`.pre-commit-config.yaml`) and run hook code **on every commit**. That config can:

- define `repo: local` hooks with any `entry` command (arbitrary code stored in the repo);
- reference a remote hook repo at a `rev`, whose code is cloned and run (a branch name as `rev` means the code can change under you);
- run on the developer's laptop, with their SSH keys, cloud credentials and tokens in reach.

**Attack scenario.** An attacker sends a "helpful" pull request that adds a hook, or publishes a repo whose README says "run `pre-commit install`". The next commit runs their code. Or an attacker compromises a hook repository that many projects use and moves its tag.

Note what is **not** the problem: plain `git clone` does not copy `.git/hooks` (the lab tests this with real git). The risk is the config you then install and run.

**Defend.**

1. Do not install or run hooks from a repo you do not trust. Read the config and local hook scripts first.
2. Pin `rev` to a version tag, better a full commit SHA, and allowlist hook repos.
3. Require review (CODEOWNERS) on `.pre-commit-config.yaml`, `.githooks/` and CI files.
4. Use throwaway containers for unfamiliar repos.
5. Remember that hooks are client-side: `git commit --no-verify` skips them. Re-run the checks in CI.

**Labs:** [pre-commit-hooks](labs/pre-commit-hooks/README.md) (working hooks, real commit blocked) then [exploiting-pre-commit-hooks](labs/exploiting-pre-commit-hooks/README.md) (a canary-only malicious hook, audit, safe runner).

## 4. Repo Jacking

On GitHub, a repository URL contains the owner name (`github.com/OWNER/REPO`). If an owner **renames** their account or **deletes** it, the old name becomes available. An attacker registers the freed name, recreates the repository, and everything that still points to `OWNER/REPO` now fetches the attacker's code.

**What points at repo names:** Go module paths, `go get` and GitHub Actions (`uses: owner/repo@v1`), install scripts with `raw.githubusercontent.com/...` or release URLs, Dockerfiles that `git clone`, docs and badges, package metadata (`repository` fields), and submodules.

**Facts to hedge.** GitHub added protections (for example retiring the names of popular repositories when an account is renamed), but research has repeatedly found many references to abandoned names, and some cases remain open. Behavior changes: **verify the current rules at GitHub's documentation.**

**Defend.** Pin dependencies to **commit SHAs or immutable digests**, not only owner/name; use a package proxy that caches known-good versions; periodically check that your referenced owners still exist and still own those repos; when **you** rename an account or org, keep the old name reserved (create a placeholder or use the rename-redirect carefully); prefer registries with namespace verification.

## 5. Executing Arbitrary Code With Git Commands

Several git features run programs, and some can be influenced by **repository content or config**. The ones to know (the [lab's `gitconfig_audit`](labs/exploiting-pre-commit-hooks/README.md) flags them):

| Setting or feature | What it runs |
|---|---|
| `core.fsmonitor` | a program git calls to learn which files changed. If it is set in a repository's own config, `git status` in that directory can run it. |
| `core.sshCommand` | a command used in place of `ssh` for fetch and push |
| `core.hooksPath` | the directory git reads hooks from; pointed at a path inside the working tree it makes committed scripts act as hooks |
| `alias.x = !command` | a shell command |
| `diff.external`, `core.pager`, `core.editor` | external programs launched during normal commands |
| filter drivers (`filter.<name>.smudge/clean/process`) | programs run on checkout or `git add` (Git LFS uses this legitimately) |
| submodules and transports | historic bugs (for example a 2024 recursive-clone issue on case-insensitive filesystems, CVE-2024-32002; verify) and the old `ext::` transport, now restricted by default |
| the `safe.directory` check | added after a 2022 issue where running git in a directory owned by another user could load that directory's config; keep git updated |

**Important nuance (hedged).** A normal `git clone` copies the repository's **content**, not the server's `.git/config` or hooks. So these settings reach you when you (a) copy or unpack a directory that already contains a `.git` folder from an untrusted source (zip, tarball, shared drive, CI cache), (b) run tools that set config for you, (c) run a script from the repo that sets it, or (d) have a git bug. IDEs, shell prompts and file managers that run `git status` in untrusted folders are the common victims. **Verify exact behavior for your git version.**

**Defend.** Keep git patched; treat `.git/` directories from outside as hostile; open unknown repos only in a sandbox; do not set `safe.directory = '*'`; use tools that open untrusted folders in a restricted mode (editors with workspace trust); audit config with a script or review it before use.

## 6. Risks of unencrypted Git traffic

Plain `git://` and `http://` give **no confidentiality and no authentication of the server**. A person on the path can read the traffic and can **change** it: serve different code for a clone or fetch. Git's hash chain does not rescue you because you have no trusted hash to compare with. Even over `http://` with a login, credentials can be captured.

GitHub removed the unauthenticated `git://` protocol on 15 March 2022 (verify). Self-hosted and older servers may still offer it, and `svn://` has similar issues.

**Defend.** Use `ssh://` or `https://` only; set `protocol.allow` and `url.<base>.insteadOf` to rewrite `http://` and `git://` to `https://`; verify host keys (do not blindly accept new host keys in automation); **sign commits and tags** so content is checked no matter how it traveled; mirror internally; block cleartext ports at the network edge (see [networking basics](../../cybersecurity-track/02-networking/README.md)).

## 7. Insufficient Authentication In Git Servers

| Weakness | Result |
|---|---|
| Anonymous or guest **write** (for example an HTTP backend with `receive-pack` enabled for anyone) | anyone can push |
| Open registration on a self-hosted server | an attacker creates an account, then browses internal projects or fork-and-PRs |
| Shared SSH account with many keys and no key lifecycle | departed users keep access; no attribution |
| No MFA or SSO; weak or reused passwords | account takeover |
| Long-lived personal access tokens with wide scope; tokens in CI variables | one leak = full repo access |
| Deploy keys with **write** access | a stolen CI key can push code |
| No branch protection, force pushes allowed | history rewriting, direct pushes to the release branch |
| Admin interface exposed to the internet, default credentials | server takeover |

**Defend.** SSO plus MFA, short-lived tokens (fine-grained, expiring), read-only deploy keys, branch protection and required reviews, disable open sign-up on self-hosted servers, audit logs and alerts for new keys and token use, regular access reviews, network restrictions for admin.

## 8. Commit spoofing: identity is free text

`git commit --author="Alice <alice@example.com>"` works for anyone. Git does not check it. A malicious commit can look like it came from a trusted maintainer, and an attacker can also impersonate bots. On some hosting platforms, the commit author shown in the UI is matched to an account **only by email**, so an unverified email looks like a real person.

**Defend.** Require **signed commits** and show verification status; keep an `allowed_signers` file (SSH signing) or registered keys; configure branch protection to reject unsigned commits; review the **committer** and signature, not just the author. Signing proves a key signed the content; it does not prove the code is safe (a stolen key signs malicious code too).

**Labs:** [git-commit-spoofing](labs/git-commit-spoofing/README.md) then [git-commit-signing](labs/git-commit-signing/README.md).

## Hands-on

1. Run both pre-commit labs and read the `gitconfig_audit` output.
2. Run the spoofing and signing labs; in the spoofing demo find which status letter means "valid signature, wrong signer".
3. On a throwaway repo, scan history for secrets with a scanner of your choice (see [real-tools](real-tools/README.md)).

## Real-world scenarios

1. **A website serves `/.git/config` and `/.git/HEAD`.** What does an attacker do? (Reconstruct the repo and read secrets from history.) Fix: remove `.git` from deployments, deny dot-directories, rotate every secret found.
2. **A contributor's PR adds a "lint" hook that downloads a binary.** Review finds a `repo: local` hook with `curl`. Fix: reject; require pinned, allowlisted hook repos.
3. **An open-source maintainer renames their GitHub account.** Your build downloads `github.com/oldname/tool/releases/...`. Fix: pin by digest, mirror, and check ownership of referenced names.

## Common mistakes

- Deleting a secret in a new commit and calling it fixed.
- Trusting the author name in `git log`.
- Auto-running `pre-commit install` from a README.
- Using a tag as a pin for something you must trust (tags move; SHAs do not).
- Running `git status` helpers on folders you downloaded.

## Interview preparation

<details><summary><b>Q1. A secret was committed and then removed. Is it safe?</b></summary>
No. It remains in history and in every clone and fork. Rotate it first, then optionally rewrite history with git filter-repo or BFG and force-push; tell collaborators to re-clone. Add secret scanning to prevent a repeat.
</details>

<details><summary><b>Q2. How can a pre-commit configuration be an attack?</b></summary>
It can define local hooks with arbitrary commands, or hook repos at moving revisions, and the framework runs that code on every commit with the developer's privileges. Review the config, pin revs to SHAs, allowlist repos, and use sandboxes for unknown repos.
</details>

<details><summary><b>Q3. What is repojacking and how do you reduce the risk?</b></summary>
When an owner renames or deletes an account, an attacker registers the old name and recreates the repository, so references to owner/repo now fetch attacker code. Pin to commit SHAs or digests, mirror dependencies, and audit references to external owners.
</details>

<details><summary><b>Q4. Why does signing help against spoofing, and what does it not do?</b></summary>
A signature binds the commit contents and the signer's key, checked against trusted keys, so a forged author fails verification. It does not prove the code is benign, and a stolen key can sign anything.
</details>

## Checklist (definition of done)

- [ ] I ran the four labs and can explain each result.
- [ ] I can list five git settings that execute programs.
- [ ] I know why clone does not copy hooks and when config still reaches you.
- [ ] I can state three fixes for weak git server authentication.

## References

- Git docs: <https://git-scm.com/docs> (`githooks`, `git-config`, `git-shell`, `gitformat-signature`)
- pre-commit: <https://pre-commit.com/>
- GitHub Docs on renaming accounts and repository redirects, and on secret scanning: <https://docs.github.com/>
- Git security advisories and release notes: <https://github.com/git/git/security/advisories>
- OWASP Top 10 CI/CD Security Risks: <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
