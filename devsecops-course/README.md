# DevSecOps: One Complete Course (three syllabi merged)

This folder merges **three DevSecOps-related syllabi** into **one course** with no repetition and nothing dropped:

| Tag | Source course |
|---|---|
| **[CDP n]** | DevSecOps Professional: CI/CD, secure SDLC, SCA, SAST, DAST, IaC, compliance as code, vulnerability management |
| **[CDE n]** | DevSecOps Expert: DSOMM L2→L4, threat modeling as code, advanced SAST/DAST, RASP/IAST, Packer, secrets, advanced vulnerability management |
| **[CCSE n]** | Container Security: containers, reconnaissance, attacks, defense at scale, monitoring |

Each chapter README starts with a **coverage table** that lists every original syllabus line, with its tag. Topics that appear in more than one course are taught once and listed once per source, so you can prove that nothing was missed. The full line-by-line checklist is in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

## The merged course (study in this order)

| # | Chapter | Merges | Key labs |
|---|---|---|---|
| 01 | [DevOps, DevSecOps and maturity](01-devops-devsecops-and-maturity/) | CDP 1, CDE 1 | DSOMM self-assessment, pipeline design with blue/green |
| 02 | [Tools, pipelines and secure SDLC](02-tools-pipelines-and-secure-sdlc/) | CDP 2, CDP 3 | One pipeline in GitLab/GitHub/Jenkins/CircleCI/Travis, full CI/CD, automated findings, BDD security |
| 03 | [Security requirements and threat modeling](03-security-requirements-and-threat-modeling/) | CDE 2 | Requirements as code, threat modeling as code, BDD threats |
| 04 | [Software component analysis (SCA)](04-software-component-analysis/) | CDP 4 | RetireJS/npm, Safety/pip, Dependency-Check (Java) |
| 05 | [Static analysis (SAST) and secrets](05-static-analysis-and-secrets/) | CDP 5, CDE 3 | Custom Bandit checks, SpotBugs, secrets scanning, Brakeman/Bandit, regex vs AST vs graph rules |
| 06 | [Dynamic analysis (DAST)](06-dynamic-analysis/) | CDP 6, CDE 4 | ZAP schedules, local DAST, TLS checks, OpenAPI scans, ZAP authentication + Zest, QA-driven deep scans |
| 07 | [Runtime analysis (RASP / IAST)](07-runtime-analysis-rasp-iast/) | CDE 5 | Build a tiny IAST agent, RASP blocking |
| 08 | [IaC, configuration and compliance as code](08-iac-configuration-and-compliance-as-code/) | CDP 7, CDP 8, CDE 6 | Ansible + Docker, golden images, PCI DSS hardening, Packer + Ansible, InSpec profiles, OpenSCAP |
| 09 | [Container fundamentals](09-container-fundamentals/) | CCSE 1 | Docker commands, networking, data, Dockerfiles, registry, Compose, Docker SDK |
| 10 | [Container reconnaissance and attacks](10-container-reconnaissance-and-attacks/) | CCSE 2, CCSE 3 | Recon, remote API scan (localhost only), secrets, snapshots, image/registry attacks, escape-path analysis, Portainer, deepce |
| 11 | [Defending containers at scale](11-defending-containers-at-scale/) | CCSE 4, CDE 7 | Hadolint, Trivy (+ API, + GitLab CI), CIS compliance, seccomp/AppArmor policies, userns/socket, Dive/Dockle |
| 12 | [Container security monitoring](12-container-security-monitoring/) | CCSE 5 | auditd, Falco rules, Tracee, Wazuh, container IR |
| 13 | [Secrets management](13-secrets-management/) | CDE 8 | Vault/Consul-style API, secrets in env and images |
| 14 | [Vulnerability management](14-vulnerability-management/) | CDP 9, CDE 9 | DefectDojo, custom VM tools and metrics, FP/FN analysis |

## Where the syllabi are out of date (Nov 2026)

| Syllabus says | Current reality |
|---|---|
| Docker **Content Trust** | **Retired.** The Notary v1 service shuts down on 8 Dec 2026. Use **cosign** or **Notation**. |
| **Travis CI** | Still exists but is rarely used for open source now. Focus on GitLab CI, GitHub Actions and Jenkins. |
| **ThreatSpec**, **BDD-Security**, **gitrob** | Little or no maintenance in years. The ideas are taught, alongside current tools (pytm/Threagile/Threat Dragon; pytest-bdd/behave + ZAP; TruffleHog/gitleaks). |
| **FindBugs** | Replaced by **SpotBugs** (+ find-sec-bugs). |
| **OWASP ZAP** | Now "**ZAP by Checkmarx**"; Zest scripts are still supported. |
| **Ansible Tower** | Now **Ansible Automation Platform**; AWX is the open-source upstream. |
| **Packer / Vault** | HashiCorp moved them to the **BSL licence** (2023). **OpenBao** is the open-source fork of Vault. |
| **InSpec** | InSpec 6+ needs a licence key. **CINC Auditor** is the free, compatible community build. |
| **Docker Swarm** | Still works and is supported by Mirantis, but Kubernetes is the default choice for new work. |
| **DSOMM "4 axes"** | Current DSOMM versions describe more dimensions and levels. Check dsomm.owasp.org. |
| PCI DSS | The current version is **v4.0.1**. |

## How the labs run

| Lab type | Where | Needs |
|---|---|---|
| `labs/…` | Your laptop, offline | `python -m pytest devsecops-course`: no Docker, Java, Ruby, Node, Vault or cloud needed |
| `real-tools/` guides and "Run the real tool" sections | Your course lab, or your laptop with Docker | The named tool. Commands are hedged: check `--help` |

## How this connects to the rest of the repo

Much container and supply-chain material already lives in [csse-course](../csse-course/) and [06-ai-devsecops](../06-ai-devsecops/). The chapters here link to it instead of repeating it. For SOC/SIEM-side monitoring and vulnerability management basics, see the [cybersecurity track](../cybersecurity-track/).
