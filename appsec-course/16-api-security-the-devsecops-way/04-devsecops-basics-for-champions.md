# Lesson 04: DevSecOps Basics for Security Champions (summary and links)

**Syllabus items covered:** all of [CSC 5] "DevSecOps Basics": building blocks, CAMS, benefits, the toolchain, challenges, secure SDLC, CI/CD, Docker commands and data, GitLab CI/CD, and integrating SCA/SAST/DAST.

**Time:** 45 minutes for this summary; the linked devsecops lessons and labs take 1–2 days if you have not done them.

> **Already taught in depth.** The repo's [devsecops-course](../../devsecops-course/README.md) covers every topic here with lessons and labs. This lesson is a **short summary** so the chapter stands on its own, with a link for each item. Do the linked labs instead of repeating them.

## 1. DevOps building blocks: people, process and technology

- **People:** shared ownership between development, operations and security; blameless culture; small autonomous teams.
- **Process:** small batches, trunk-based development, automated testing, continuous feedback, incident reviews.
- **Technology:** version control, CI/CD, infrastructure as code, containers, monitoring.

Full lesson: [devsecops ch01 section 3](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#3-the-building-blocks-people-process-technology).

## 2. DevOps principles: CAMS

**C**ulture (collaboration, shared goals), **A**utomation (build, test, deploy, infrastructure), **M**easurement (lead time, deploy frequency, change failure rate, time to restore: the DORA metrics), **S**haring (knowledge, tools, post-incident learning). DevSecOps adds security to each: security culture and champions, security automation, security metrics, shared threat models. Full lesson: [devsecops ch01 section 4](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#4-cams-the-four-principles).

## 3. Benefits of DevOps

Speed (faster releases), reliability (automated tests, smaller changes), availability (quick recovery, redundancy), scalability (automation and IaC), automation (fewer manual errors), cost (less waste, earlier bug fixes) and visibility (dashboards, traceability). For security: patches ship in hours, not quarters. Full lesson: [devsecops ch01 section 5](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#5-benefits-of-devops).

## 4. Overview of the DevSecOps critical toolchain

Full lesson: [devsecops ch01 lesson 03 section 2](../../devsecops-course/01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#2-the-devsecops-critical-toolchain).

### 4.1 Repository management tools

GitLab, GitHub, Bitbucket, Azure Repos. Security: branch protection, signed commits, CODEOWNERS, secret scanning, MFA for all users.

### 4.2 Continuous integration and continuous deployment tools

GitLab CI, GitHub Actions, Jenkins, Azure Pipelines, CircleCI; Argo CD and Flux for GitOps deployment. Security: protected variables, OIDC to clouds, pinned actions/images, isolated runners.

### 4.3 Artifact management tools

Artifactory, Nexus, GitLab/GitHub package and container registries, Harbor. Store build outputs **immutably**, with digests, signatures (cosign) and SBOMs; proxy and scan third-party packages (blocks dependency confusion). See [csse ch6 Harbor lab](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/harbor-registry-policy/README.md).

### 4.4 Infrastructure as Code (IaC) tools

Terraform (BSL) / **OpenTofu** (open-source fork), Pulumi, CloudFormation, Bicep for provisioning; Ansible, Chef, Puppet for configuration. Scanners: Checkov, KICS, Trivy (tfsec merged into Trivy). [Lesson 05](05-iac-and-ansible-for-champions.md) covers IaC for this course.

### 4.5 Distributed and scalable infrastructure

Containers (Docker, Podman), orchestration (Kubernetes), cloud load balancers and auto-scaling, service meshes (Istio, Linkerd), serverless. Security: least-privilege workloads, network policies, mTLS, runtime monitoring. See [devsecops ch09](../../devsecops-course/09-container-fundamentals/README.md) to [ch12](../../devsecops-course/12-container-security-monitoring/README.md).

### 4.6 Monitoring and logging tools

Prometheus and Grafana, ELK/OpenSearch, Loki, OpenTelemetry, cloud monitoring, SIEM (Sentinel, Splunk). [Chapter 15 lesson 04](../15-implementing-api-security-mechanisms/04-logging-and-monitoring.md) covers them for APIs.

### 4.7 Communication and sharing tools

Slack, Microsoft Teams, Mattermost, Jira, Confluence, wikis, ChatOps bots that post scan results and deployment events. Security: no secrets in chat, access control on channels, alerts routed to owners. See [devsecops ch01 section 2.4](../../devsecops-course/01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#24-communication-and-sharing-tools).

## 5. Common challenges faced when using the DevOps principles

Culture change and silos; legacy systems that cannot be automated; tool sprawl; skills gaps; security seen as a blocker; speed pressure; too many scanner false positives; compliance evidence; secrets everywhere. Answers: champions, paved roads, small steps (DSOMM levels), tuned gates, metrics. Full lesson: [devsecops ch01 section 6](../../devsecops-course/01-devops-devsecops-and-maturity/01-devops-foundations.md#6-common-challenges-and-what-to-do).

## 6. Secure SDLC

### 6.1 Overview of secure SDLC and CI/CD

A secure SDLC adds a security activity to each phase, and CI/CD runs the automatable ones on every change. Full lessons: [devsecops ch01 section 4](../../devsecops-course/01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#4-overview-of-secure-sdlc-and-cicd), [ch02 lesson 02](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/02-secure-sdlc-and-security-gates.md).

### 6.2 Review of security activities in secure SDLC

| Phase | Activity | This course |
|---|---|---|
| Requirements | Security requirements, abuse cases, ASVS level | [ch05](../05-agile-threat-modeling-as-code/README.md), [lesson 01](01-owasp-asvs-for-apis.md) |
| Design | Threat modeling, secure design principles | [ch03](../03-risk-management-and-threat-modeling-overview/README.md)–[ch07](../07-secure-design-principles-and-case-studies/README.md) |
| Implementation | Secure coding, code review, SAST, secrets scanning | [ch02](../02-secure-code-review-and-asvs/README.md) |
| Testing | DAST, security tests, pentest | [lesson 02](02-automated-vulnerability-discovery.md) |
| Deploy | Hardening, IaC scanning, signed artifacts | [lesson 05](05-iac-and-ansible-for-champions.md), [lesson 03](03-api-security-at-scale-and-cicd.md) |
| Maintain | Monitoring, vulnerability management, incident response | [ch15](../15-implementing-api-security-mechanisms/README.md) |

Full lesson: [devsecops ch01 section 5](../../devsecops-course/01-devops-devsecops-and-maturity/03-devsecops-toolchain-sdlc-and-dsomm.md#5-review-of-security-activities-in-the-secure-sdlc).

### 6.3 Continuous integration and continuous deployment

CI: merge small changes often, build and test each one. CD: continuous **delivery** keeps every build releasable; continuous **deployment** releases every passing build automatically. See [lesson 03 section 3](03-api-security-at-scale-and-cicd.md#3-continuous-integration-vs-continuous-delivery-vs-continuous-deployment) and the [simple-cicd-pipeline lab](labs/simple-cicd-pipeline/README.md).

## 7. Working with Docker commands

`docker pull/run/ps/logs/exec/stop/rm`, `docker build -t name .`, `docker image ls`, `docker inspect`. Security habits: run as non-root (`--user`), drop capabilities (`--cap-drop ALL`), read-only root filesystem (`--read-only`), no `--privileged`, no Docker socket mounts, pin images by digest. Lab: [devsecops ch09 docker-command](../../devsecops-course/09-container-fundamentals/labs/docker-command/README.md); lesson: [ch09 lesson 03](../../devsecops-course/09-container-fundamentals/03-images-dockerfile-and-registries.md#7-running-a-container).

## 8. Managing data in Docker

Containers are ephemeral; data lives in **volumes** (managed by Docker), **bind mounts** (host paths) or **tmpfs** (memory). Security: never bind-mount sensitive host paths (`/`, `/var/run/docker.sock`); mount read-only where possible; secrets via Docker/Kubernetes secrets or a secret manager, not image layers or environment variables baked into images; back up and encrypt volumes. Lab: [devsecops ch09 manage-data](../../devsecops-course/09-container-fundamentals/labs/manage-data/README.md); lesson: [ch09 section 6](../../devsecops-course/09-container-fundamentals/03-images-dockerfile-and-registries.md#6-data-volumes-bind-mounts-tmpfs).

## 9. Working with GitLab CI/CD

A `.gitlab-ci.yml` defines `stages` and `jobs` (`script`, `image`, `needs`, `artifacts`, `rules`, `environment`, `when: manual`); runners execute them; CI/CD variables can be **protected** and **masked**; environments can require approvals. Labs: [simple-cicd-pipeline](labs/simple-cicd-pipeline/README.md) (offline), [csse ch1 gitlab-ci-stages](../../csse-course/ch1-introduction-to-supply-chain-security/labs/gitlab-ci-stages/README.md), [devsecops ch02 ci-pipeline-multi-platform](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/ci-pipeline-multi-platform/README.md); guide: [devsecops ch02 GitLab real-tools](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/real-tools/gitlab-ci.md).

## 10. Integrating SCA, SAST and DAST in the CI/CD pipeline

Summary in [lesson 03 section 5](03-api-security-at-scale-and-cicd.md#5-embedding-sca-sast-and-dast-into-the-pipeline); lab: [sca-sast-dast-gates](labs/sca-sast-dast-gates/README.md). Deep dives: SCA in [devsecops ch04](../../devsecops-course/04-software-component-analysis/README.md), SAST in [ch05](../../devsecops-course/05-static-analysis-and-secrets/README.md), DAST in [ch06](../../devsecops-course/06-dynamic-analysis/README.md); the complete gated pipeline in [devsecops ch02 complete-cicd-pipeline](../../devsecops-course/02-tools-pipelines-and-secure-sdlc/labs/complete-cicd-pipeline/README.md).

## 11. Scenario: the champion's first pipeline change

A champion in the payments team wants to add security scans. Instead of five blocking scanners at once, she adds secrets scanning (blocking) and SCA (warning only) in week 1, tunes SAST rules with the team in week 3 and makes three high-confidence rules blocking, and adds a nightly ZAP API scan against staging in week 5. Developers see few false positives, and the team keeps the gates on. That is CAMS in practice: culture first, automation in small steps, measurement (findings fixed per sprint), sharing (a wiki page other teams copy).

## 12. Checklist

- [ ] I can explain people/process/technology and CAMS with a security example each.
- [ ] I can list the seven toolchain categories and a tool for each.
- [ ] I can map security activities to SDLC phases.
- [ ] I have done the devsecops ch09 Docker labs and one GitLab lab.
- [ ] I can describe how SCA, SAST and DAST fit into a GitLab pipeline.

## References

- Repo: [devsecops-course](../../devsecops-course/README.md) chapters 01, 02, 04, 05, 06, 09; [csse-course](../../csse-course/README.md) chapters 1 and 2.
- DORA "Accelerate State of DevOps" reports; OWASP DevSecOps Guideline; OWASP DSOMM.
