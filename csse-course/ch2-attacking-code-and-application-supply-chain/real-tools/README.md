# Real-tool guides (chapter 2)

> **Status: hedged outlines, not executed by the repo author.** Versions, flags and licenses change. Verify every command at the tool's own documentation. The tested offline twins in [labs/](../labs/) teach the same ideas, and **no test in this chapter needs Docker, a network or an account**.

| Guide | Real tool | Offline twin |
|---|---|---|
| [gitlab.md](gitlab.md) | GitLab CE/EE (self-hosted or SaaS) with GitLab CI | [gitlab-privilege-escalation](../labs/gitlab-privilege-escalation/README.md) |
| [pre-commit.md](pre-commit.md) | the `pre-commit` framework | [pre-commit-hooks](../labs/pre-commit-hooks/README.md), [exploiting-pre-commit-hooks](../labs/exploiting-pre-commit-hooks/README.md), [sca-sast-pre-commit](../labs/sca-sast-pre-commit/README.md) |
| [semgrep-and-bandit.md](semgrep-and-bandit.md) | Semgrep, Bandit | [sast](../labs/sast/README.md) |
| [zap.md](zap.md) | OWASP ZAP | [dynamic-analysis](../labs/dynamic-analysis/README.md) |
| [osv-scanner-and-syft.md](osv-scanner-and-syft.md) | OSV-Scanner, Syft, Grype, Trivy | [sca](../labs/sca/README.md), [dependency-confusion](../labs/dependency-confusion/README.md) |

Rules for all of them: use a **throwaway VM or container**, scan only things you own or may test, never put real secrets in test repos, and bind lab services to localhost.
