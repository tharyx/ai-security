# Jenkins: running and hardening the secure pipeline (real tool, hedged)

> **Status: hedged outline, not tested by the repo author.** Verify at <https://www.jenkins.io/doc/>. Repo tests never need Jenkins or Java.

**Offline twin (tested):** [ci-pipeline-multi-platform](../labs/ci-pipeline-multi-platform/README.md) validates [fixtures/Jenkinsfile](../labs/ci-pipeline-multi-platform/fixtures/Jenkinsfile) with a regex-based check, not a Jenkins parser. Basics: [chapter 1 guide](../../01-devops-devsecops-and-maturity/real-tools/jenkins.md).

## Run the fixture

1. Use a throwaway Jenkins on your own machine or the course lab. Bind it to `localhost`; do not expose it to a network.
2. Install the plugins you need (Pipeline, Git, Docker Pipeline, Credentials Binding). Fewer plugins means fewer advisories.
3. Create a *Multibranch Pipeline* job pointing at a test repository that contains the `Jenkinsfile`.
4. Add a credential with ID `staging-kubeconfig` (a dummy file is enough for a dry run). The Jenkinsfile only binds it inside the Deploy stage.
5. The Docker agents need a Docker host reachable by the agent. **Do not mount `docker.sock` into job containers** as a shortcut.

## Hardening checklist

| Item | Why |
|---|---|
| `agent none` at the top and an agent per stage | No stage inherits more than it needs |
| Controller runs no builds | The controller holds credentials and job config |
| Ephemeral agents (containers or cloud VMs) | No leftovers between jobs |
| Credentials only in the stage that needs them | Smaller exposure and cleaner logs |
| Role-based authorisation, SSO, no anonymous access | Default-deny |
| Update core and plugins regularly; read the security advisories | Plugins are the main attack surface |
| Pin Docker image tags in `agent { docker { image '...' } }` | Reproducible, safer toolchain |
| Protect the Jenkinsfile: required review via the SCM | Whoever edits it controls the build |
| Script security / sandbox for shared libraries | Groovy runs with high privilege |
| Back up and monitor the controller | It is a production system |

## Notes

- Jenkins LTS and plugin versions move; **check the current LTS line and Java requirements** in the documentation.
- The fixture's regex-based validator understands `stage('...') { ... }` blocks and `withCredentials`/`credentials(` usage. A real Jenkins linter exists inside Jenkins itself (declarative pipeline linter): use it for syntax.
