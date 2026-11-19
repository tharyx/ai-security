# Lesson 03: The DevSecOps toolchain, the secure SDLC and the maturity model

> **Chapter:** 1 · DevOps, DevSecOps and Maturity · **Time:** ~3.5 hours
> **You will:** name the five toolchain categories and what to secure in each, walk through the SDLC and secure SDLC, and explain how an organisation moves from DSOMM level 2 to level 4, including best practices, challenges and the honest limits of security automation.

| | |
|---|---|
| **Prerequisites** | [Lessons 01 and 02](01-devops-foundations.md) |
| **Labs** | [dsomm-assessment](labs/dsomm-assessment/README.md) |
| **Syllabus lines** | Critical toolchain (5 categories) · SDLC · Secure SDLC and CI/CD · Security activities · CI/CD · DSOMM L2 to L4 · L3 and L4 best practices · Limits of automation · L3/L4 challenges |
| **Continues in** | [Chapter 2: the full L1 to L4 path and the tools](../02-tools-pipelines-and-secure-sdlc/03-dsomm-path-and-embedding-security.md) |

## 1. Why it matters

Tools do not make a DevSecOps programme. A company can own ten scanners and still be at maturity level 1 because nobody reads the results. The **maturity model** gives a shared language for "where are we, what is next, and what does it cost", and the **toolchain map** tells you what you need to protect, because every tool in the chain is also a target.

## 2. The DevSecOps critical toolchain

Five categories. For each one: what it is, examples, and what an attacker wants from it.

### 2.1 Repository management tools

Where code (and often pipeline definitions, IaC and policies) lives. **Examples:** GitLab, GitHub, Bitbucket, Gitea.

| Secure it by | Because |
|---|---|
| Branch protection, required reviews, signed commits | A malicious commit is the cheapest supply chain attack |
| Least-privilege roles, no shared accounts, MFA/SSO | Stolen developer tokens are a top entry point |
| Secret scanning (push protection) | Credentials committed once stay in history |
| CODEOWNERS for pipeline and IaC files | Whoever edits the pipeline controls the build |

### 2.2 Continuous Integration and Continuous Deployment tools

Run builds, tests and deployments. **Examples:** GitLab CI, GitHub Actions, Jenkins, CircleCI, Argo CD. ([Chapter 2](../02-tools-pipelines-and-secure-sdlc/01-tools-of-the-trade.md) compares them.)

| Secure it by | Because |
|---|---|
| Ephemeral, isolated runners; no Docker socket in untrusted jobs | A compromised job can take the runner |
| Pin actions, plugins and images | Third-party steps run with your secrets |
| Scoped, short-lived credentials (OIDC) | Long-lived deploy keys leak |
| Protected branches and environments for deploy jobs | Anyone could otherwise deploy |

### 2.3 Infrastructure as Code (IaC) tools

Define servers, networks and configuration in files. **Examples:** Terraform/OpenTofu, Ansible, Packer, CloudFormation, Helm. ([Chapter 8](../08-iac-configuration-and-compliance-as-code/README.md) goes deep.)

| Secure it by | Because |
|---|---|
| Scanning IaC (Checkov, tfsec-style rules, policy as code) | A public storage bucket is one line of YAML |
| State files and vaults protected | State often contains secrets |
| Peer review and the same pipeline as application code | IaC is code |

### 2.4 Communication and sharing tools

Chat, ticketing, wikis, artifact and package registries, dashboards. **Examples:** Slack/Teams, Jira, Confluence, an internal package registry.

| Secure it by | Because |
|---|---|
| Never paste secrets in chat or tickets; use a secret manager | Chat history is searchable by everyone |
| Treat webhooks and bots as privileged integrations | A bot token can post, read and sometimes approve |
| Ticket automation for findings with owner and due date | Findings die in PDFs |
| Registry access control and immutable tags | Overwriting a tag replaces what you deploy |

### 2.5 Security as Code (SaC) tools

Everything that checks security automatically and is itself defined as code: SAST, SCA, DAST, secret scanners, image scanners, compliance checkers, policy engines. **Examples:** Semgrep, Trivy, ZAP, gitleaks, InSpec, OPA. Rules, thresholds and waivers live in a repository, are reviewed like code and are versioned.

| Secure it by | Because |
|---|---|
| Pin scanner versions; review rule changes | A weakened rule is a silent backdoor |
| Waivers with an owner and an expiry date | Accepted risks must not live forever |
| Run scanners with minimal rights | They parse untrusted code |

**One picture of all five** in a real pipeline is in the [demo lesson](04-enterprise-devsecops-pipeline-demo.md).

## 3. SDLC: the plain software development life cycle

Whatever the method (waterfall, agile, DevOps), software goes through the same activities:

1. **Requirements:** what should it do?
2. **Design:** how will it be built?
3. **Implementation:** write the code.
4. **Testing:** does it work?
5. **Deployment:** put it in production.
6. **Maintenance:** operate, fix, improve.

DevOps compresses this into a loop that repeats daily, instead of a line that runs once a year.

## 4. Overview of secure SDLC and CI/CD

A **secure SDLC** adds a security activity and a gate to each phase, so security problems are found when they are cheapest to fix.

| Phase | Security activity | Example gate in CI/CD |
|---|---|---|
| Requirements | Security requirements, abuse cases | Requirements as acceptance tests ([ch03](../03-security-requirements-and-threat-modeling/README.md)) |
| Design | Threat modelling | Threats tracked; high ones have mitigations |
| Implementation | Static analysis, secrets scan, dependency scan, secure defaults | SAST, SCA, secrets scan fail the merge request |
| Testing | Dynamic analysis, security tests | DAST baseline on staging |
| Deployment | Hardening, image scan, signing | Image scan, signature check, IaC scan |
| Maintenance | Monitoring, compliance, patching | Runtime alerts, compliance scans, SLA on findings |

The full chapter-2 view with an SVG: [Chapter 2 lesson 02](../02-tools-pipelines-and-secure-sdlc/02-secure-sdlc-and-security-gates.md).

**Where CI/CD fits:** the pipeline is the machinery that runs those gates automatically on every change. Secure SDLC is the *what*; CI/CD is the *how*.

## 5. Review of security activities in the secure SDLC

A review list you can use in an interview. For each activity: **who, when, how automatic**.

| Activity | When | Automatic? | Human part |
|---|---|---|---|
| Security requirements | Planning | Partly (requirement templates, BDD specs) | Choose and prioritise |
| Threat modelling | Design, and when architecture changes | Partly (threat model as code) | The thinking |
| Secure coding training | Continuous | No | Learning |
| Peer code review | Every merge request | Partly (bots, rules) | Review risky changes |
| SAST / secret scan / SCA | Every commit or merge request | Yes | Triage |
| Build hardening and SBOM | Every build | Yes | Review the policy |
| DAST and security tests | Every deploy to test | Yes | Triage, tune |
| Pentest / red team | Before big releases, yearly | No | Experts |
| Hardening and IaC scan | Every infra change | Yes | Policy design |
| Monitoring and incident response | Always | Partly | Investigate |
| Patch and vulnerability management | Always | Partly | Prioritise, accept risk |

## 6. Continuous Integration and Continuous Deployment (security view)

Already defined in [Lesson 02](02-cicd-and-deployment-strategies.md). The security angle in one table:

| Pipeline step | Typical attack | Control |
|---|---|---|
| Source | Malicious commit, stolen token | Reviews, branch protection, signed commits, MFA |
| Build | Poisoned dependency, tampered build script | Lock files, hashes, isolated runners, pinned tools |
| Test | Secrets exposed in logs | Masking, no secrets in test environments |
| Package | Tag overwritten, image swapped | Digest pinning, signing |
| Deploy | Stolen deploy credentials | Short-lived OIDC credentials, protected environments |
| Run | Unnoticed compromise | Monitoring, alerts, runtime policy |

More on pipeline attacks: [csse ch1 lesson 02](../../csse-course/ch1-introduction-to-supply-chain-security/02-threat-model-of-the-software-supply-chain.md) and [caisp ch4 lesson 04](../../caisp-course/ch4-ai-attacks-and-defenses-devops/04-pipeline-attacks-and-ppe.md).

## 7. DevSecOps Maturity Model (DSOMM): moving from level 2 to level 4

> **Caveat: the model has changed over time.** The OWASP DevSecOps Maturity Model (DSOMM, dsomm.owasp.org) has been revised. Older material (and your course) uses **four levels** and a small number of axes; **current versions list more dimensions** (for example Build and Deployment, Culture and Organization, Implementation, Information Gathering, Test and Verification) and sometimes a fifth level. Learn the course framing for the exam, and **open the current model** before applying it at work. The [dsomm-assessment lab](labs/dsomm-assessment/README.md) uses a *simplified* activity list for practice, not the official one.

The four levels, in the wording commonly used (verify against the current model):

| Level | Name | Plain meaning |
|---|---|---|
| 1 | Basic security practices | Some checks exist, mostly manual; individuals do the right thing |
| 2 | Adoption of basic security goals | Basic checks are in the pipeline and agreed for most teams |
| 3 | High adoption of security goals | Checks are broad, enforced and measured; teams fix their own findings |
| 4 | Advanced deployment of security practices at scale | Advanced, consistent, low-friction, continuously improved everywhere |

The path from **level 1 to level 4** is in [Chapter 2](../02-tools-pipelines-and-secure-sdlc/03-dsomm-path-and-embedding-security.md). Here is the stretch from **level 2 to level 4**.

### 7.1 Where you are at level 2

You have the basics: a pipeline, a scanner or two, some training. But coverage is uneven, findings are not always acted on, and security still asks "did you run the scan?" instead of the pipeline making it impossible to skip.

### 7.2 Moving from level 2 to level 3

| Move | What it looks like |
|---|---|
| **Make checks mandatory** | Central pipeline templates; teams cannot remove security jobs; gates block |
| **Broaden coverage** | Add DAST, IaC scanning, image scanning, secret scanning in history |
| **Reduce noise** | Tune rules, deduplicate, threshold per severity ([lab](../02-tools-pipelines-and-secure-sdlc/labs/manage-findings-automatically/README.md)) |
| **Measure** | Metrics per team: open by severity, time to fix, escape rate |
| **Define SLAs and ownership** | Critical in 7 days, high in 30; every finding has an owner |
| **Threat model new features** | Lightweight, repeatable sessions |

### 7.3 Best practices and considerations at level 3

- **Central, versioned pipeline templates** (a "paved road") so security jobs are shared, not copied.
- **Break-build thresholds that teams agreed to**, plus a visible **waiver process** with expiry dates.
- **Fix the process, not just the finding:** each recurring finding type becomes a rule, a template or a training item.
- **Security champions** in each team, with time allocated.
- **Metrics reviewed monthly**, shared with developers and managers (different views, see [ch14](../14-vulnerability-management/README.md)).
- **Evidence collected automatically** for audits.
- **Run DAST and deeper checks nightly or weekly** to keep the merge-request pipeline fast.
- **Protect the pipeline itself:** runners, secrets, and who can edit CI files.

### 7.4 Moving from level 3 to level 4

| Move | What it looks like |
|---|---|
| **Automate response** | Auto-created tickets, auto-opened fix pull requests for dependencies, auto-quarantine of bad images |
| **Policy as code everywhere** | Admission control, IaC policies, compliance profiles in the pipeline |
| **Provenance and trust** | Signed artifacts, provenance attestations, verified at deploy ([csse ch7 SLSA](../../csse-course/ch7-managing-a-secure-software-supply-chain-program/README.md)) |
| **Runtime feedback** | Production signals create tests and rules (an incident becomes a regression test) |
| **Risk-based decisions** | Scoring by exposure and data class, not only by CVSS |
| **Continuous improvement** | Regular reviews of gates: what do they catch, what do they miss? |

### 7.5 Best practices and considerations at level 4

- **Low friction by design.** If secure is slower than insecure, developers route around it. Measure pipeline time and the time to fix.
- **Self-service security:** teams get scanners, templates and dashboards without a ticket.
- **Consistency at scale:** hundreds of repos behave the same; exceptions are rare, visible and expire.
- **Red team and purple team exercises** test the pipeline and detection, not only the apps.
- **Resilience:** you can rebuild everything from code and rotate every secret quickly.
- **Do not chase the label.** A level is a tool for planning, not a trophy.

## 8. Security automation and its limits

Automation is the engine of DevSecOps, and it has limits you should state honestly in an interview.

| Limit | Example | What to do |
|---|---|---|
| **False positives** | A scanner flags safe code, and teams start ignoring alerts | Tune rules, track false-positive rate, review waivers |
| **False negatives** | Scanners miss business logic flaws and new vulnerability classes | Threat modelling, code review, pentests |
| **Context blindness** | A scanner cannot know a "low" bug sits on your most sensitive data path | Risk-based prioritisation by humans |
| **Coverage gaps** | DAST cannot crawl what it cannot log in to | Authentication setup, API specs ([ch06](../06-dynamic-analysis/README.md)) |
| **Speed vs depth** | Deep scans take hours | Fast checks per commit, deep scans nightly |
| **Tool trust** | A compromised scanner or plugin is a supply chain risk | Pin, verify, least privilege |
| **Alert fatigue** | Thousands of unranked findings | Deduplicate, thresholds, ownership |
| **Culture** | Automation does not create ownership | Champions, shared metrics, blameless reviews |

Automation **finds known patterns fast**. Humans **find new patterns and decide what matters**. You need both. This also frames the later discussion in [chapter 2](../02-tools-pipelines-and-secure-sdlc/03-dsomm-path-and-embedding-security.md#8-devsecops-vs-pentesting-and-vulnerability-assessment).

## 9. DSOMM level 3 and level 4 challenges and solutions

| Challenge | Level | Why it hurts | Solution |
|---|---|---|---|
| **Findings flood** after enabling more scanners | 3 | Teams drown and disable the scanner | Roll out per team; start with block on critical; tune rules; one findings list |
| **Pipeline slowdown** | 3 | Developers bypass or complain | Parallel jobs, caching, incremental scans, move deep scans to nightly |
| **Shared ownership unclear** | 3 | "Security will fix it" | Owners in the ticket, SLAs, team dashboards |
| **Exceptions pile up** | 3 | Waivers become the real policy | Expiry dates, monthly review, count waivers as a metric |
| **Legacy apps cannot meet the bar** | 3 | They would block forever | Time-boxed plans, compensating controls, risk acceptance with sign-off |
| **Inconsistency across hundreds of repos** | 4 | Each team drifts | Central templates, policy as code, drift detection |
| **Automation trust** | 4 | Auto-merge or auto-deploy of fixes could break production | Tests as the safety net; staged rollout; kill switch |
| **Proving it works** | 4 | Metrics may look good while risk is high | Red team exercises, escape-rate tracking, independent audits |
| **Cost** | 3-4 | Licences, people, compute | Prioritise by risk; open-source first; measure value |
| **Skills and burnout** | 3-4 | A few experts carry everything | Champions, training, self-service tooling |

## 10. Self-check

1. Name the five toolchain categories and one thing an attacker wants from each.
2. What changes between SDLC and secure SDLC? Name two gates.
3. Summarise the four DSOMM levels in your own words, and say why you must check the current model.
4. List three moves that take a team from level 2 to level 3.
5. Give three limits of security automation and one mitigation each.
6. Run the [dsomm-assessment lab](labs/dsomm-assessment/README.md) on your own team (or a fictional one) and write the three cheapest roadmap items.

## 11. Where next

[Lesson 04: the enterprise DevSecOps pipeline demo](04-enterprise-devsecops-pipeline-demo.md) puts every category together in one pipeline.
