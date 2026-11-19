# Lesson 01: DevOps foundations

> **Chapter:** 1 · DevOps, DevSecOps and Maturity · **Time:** ~2.5 hours
> **You will:** explain what DevOps is and why security has to join it, name the three building blocks and the four CAMS principles, list the benefits, spot the usual failure points and tell three famous case studies without overclaiming.

| | |
|---|---|
| **Prerequisites** | Basic Git; you have seen a deployment script or a release checklist |
| **Next** | [Lesson 02: CI/CD and deployment strategies](02-cicd-and-deployment-strategies.md) |
| **Syllabus lines** | What is DevOps · Building blocks · CAMS · Benefits · Common challenges · Case studies (Facebook, Amazon, Google) |

## 1. Why it matters

Before DevOps, a typical release at a large company looked like this: developers wrote code for months, threw it "over the wall" to operations, and operations tried to run something they had never seen. Security was a third wall at the very end: a penetration test two weeks before go-live that found 80 problems nobody had time to fix.

DevSecOps is what you get when you remove those walls **and** let security checks run as part of the normal work. If you remember one sentence from this chapter, make it this one: **security that is not in the pipeline will be skipped when the deadline is near.**

> **DBA analogy.** You know the old way: a change request, a DBA reviews the script on Thursday, the change window is Saturday 2 am, and a rollback plan lives in a Word document. DevOps asks: what if the script was tested automatically on every change, the rollback was rehearsed daily, and the same pipeline ran in dev, test and prod? That is the whole idea.

## 2. What is DevOps?

DevOps is a way of working where **development and operations share responsibility for the whole life of a service**: build, test, release, run, fix. It is not a job title and not a tool. Tools only make the habit cheaper.

Three ideas sit inside the word:

1. **Small, frequent changes.** A release of 5 changes is easier to understand and to undo than a release of 500.
2. **Automation of the boring and risky parts.** Builds, tests, deployments and environment setup are scripted, versioned and repeatable.
3. **Fast feedback both ways.** Developers learn quickly how their code behaves in production; operations learn early what is coming.

**DevSecOps** adds a fourth: **security is everybody's job and is checked automatically at every step**, starting at the developer's laptop.

## 3. The building blocks: people, process, technology

| Block | What it means | Example | What breaks without it |
|---|---|---|---|
| **People** | Shared goals, shared on-call, cross-functional teams, security champions | A developer carries the pager for their own service | Tools are bought but nobody owns the outcome |
| **Process** | A short, agreed path from idea to production, with clear gates | Merge request, review, pipeline, approval, release | Each team invents its own risky shortcut |
| **Technology** | Version control, CI/CD, infrastructure as code, monitoring, scanners | Git, a CI runner, Ansible, a scanner in the pipeline | The process is manual and slow, so people bypass it |

Order matters: **people first, then process, then tools.** A scanner nobody reads is shelfware.

## 4. CAMS: the four principles

CAMS (Culture, Automation, Measurement, Sharing) was popularised by John Willis and Damon Edwards; the model is commonly credited to them (verify the original blog posts if you need to cite it).

| Letter | Principle | In practice | Security flavour |
|---|---|---|---|
| **C** | Culture | Blameless post-mortems, shared ownership, no heroes | Developers fix their own findings; security is a helper, not a gatekeeper |
| **A** | Automation | Everything repeatable is a script or a pipeline job | Scans, secret checks and compliance checks run on every change |
| **M** | Measurement | Track lead time, deploy frequency, failure rate, time to restore | Track open findings, time to fix, escape rate (bugs found in prod) |
| **S** | Sharing | Shared dashboards, runbooks, internal demos | Share what was found and how it was fixed, so the same bug is not written twice |

The four delivery metrics most often quoted (from the DORA research programme) are deployment frequency, lead time for changes, change failure rate and time to restore service. Names and exact definitions have been refined over the years: check the current DORA report before quoting them.

## 5. Benefits of DevOps

| Benefit | Why it happens | Concrete example |
|---|---|---|
| **Speed** | Small changes, no manual hand-offs | A fix goes live the same day, not next quarter |
| **Reliability** | Same automated path every time; tests run every time | Fewer "it worked on my machine" failures |
| **Availability** | Safe rollout patterns (blue/green, canary) and fast rollback | Release without downtime, roll back in minutes |
| **Scalability** | Environments are code, so you can create ten like the first | Spin up a copy of the whole stack for a load test |
| **Automation** | Humans stop doing repetitive steps | No more Friday-night manual deploy checklists |
| **Cost** | Less rework, fewer outages, fewer manual hours | A bug found in a pull request costs minutes; in production it costs an incident |
| **Visibility** | Pipelines, metrics and logs are shared | Everyone sees what is deployed where, and what failed |

A security reading of the same list: speed is only a benefit if the gates keep up. **Fast delivery without automated security is just a faster way to ship vulnerabilities.**

## 6. Common challenges (and what to do)

| Challenge | Why it happens | Practical fix |
|---|---|---|
| **Culture clash.** "Ops says no, dev says go" | Different incentives and metrics | Shared goals, shared on-call, joint post-mortems |
| **Tool sprawl** | Every team picks its own tool | A small supported "paved road" toolchain; allow exceptions with a reason |
| **Legacy systems** | Mainframes, monoliths, manual databases | Start with new services, wrap old ones with scripts, automate step by step |
| **Skills gap** | Few people know both dev and ops and security | Training, pairing, security champions |
| **Compliance fear** | "Auditors do not accept automation" | Pipelines produce evidence (logs, approvals, scan reports): auditors often prefer it |
| **Security as a bottleneck** | Manual reviews at the end | Automate the routine checks; spend human time on design and review |
| **Flaky tests, slow pipelines** | Tests were never maintained | Keep the fast gates under about 10 minutes; move slow checks to nightly runs |
| **Alert and finding overload** | Scanners report everything | Tune rules, deduplicate, set thresholds ([manage findings lab](../02-tools-pipelines-and-secure-sdlc/labs/manage-findings-automatically/README.md)) |
| **Measuring the wrong thing** | Counting deployments, not outcomes | Pair speed metrics with stability metrics |

## 7. Case studies: how three big technology companies did it

> **Read this carefully.** These are well-known stories, told in broad strokes. Specific numbers change every year and many come from conference talks, not audited reports. **Verify any number at the source before you quote it** in an exam answer or interview. Do not memorise the figures; learn the patterns.

### 7.1 Amazon: many teams, many small deployments

- **Small autonomous teams.** Amazon is widely associated with the "two-pizza team" idea: a team small enough to be fed by two pizzas. Each team owns a service end to end.
- **"You build it, you run it."** Amazon's CTO Werner Vogels described this principle in the mid-2000s: the team that writes the service also carries the pager for it. That shortens the feedback loop between code quality and operational pain.
- **Frequent, automated deployments.** Conference talks around 2011 described Amazon deploying to production very often (the figure usually quoted was on the order of one deployment every few seconds, averaged across the company). Treat the number as dated and as an average of many small services, not one app.
- **Pattern to copy:** small blast radius per change, automated deployment tooling, and ownership by the team that runs the service.

### 7.2 Google: SRE and error budgets

- **Site Reliability Engineering (SRE)** treats operations as a software problem. Google published the approach in the book *Site Reliability Engineering* (2016, free online). A phrase often heard is that SRE is one way of implementing DevOps ideas.
- **SLOs and error budgets.** You agree a Service Level Objective, for example 99.9% of requests succeed in a month. The remaining 0.1% is the **error budget**. While budget remains, the team can ship quickly. When it is used up, risky releases pause and reliability work gets priority. This turns the old "dev wants speed, ops wants stability" argument into a number both sides accept.
- **Blameless post-mortems** are a core practice, so incidents lead to fixes rather than blame.
- **Pattern to copy:** pick a reliability target, measure it, and let the budget decide the pace.

### 7.3 Facebook: continuous push and gatekeeper flags

- **Continuous push.** Facebook engineers have talked publicly about releasing the main web code very frequently (from weekly in earlier years to daily and more often later), with engineers expected to be around when their change goes out. Details have changed over time.
- **Gatekeeper and dark launches.** New features were hidden behind server-side flags (Facebook's internal tool is commonly called *Gatekeeper*) so code could ship switched off, then be enabled for employees, then for 1% of users, then everyone. This separates **deploy** (code on servers) from **release** (users see it).
- **Pattern to copy:** feature flags plus staged rollout reduce risk without slowing down code delivery. It is the same spirit as canary releases in [lesson 02](02-cicd-and-deployment-strategies.md#5-blue-green-deployment-and-its-cousins).

### 7.4 What the three have in common

| Pattern | Amazon | Google | Facebook |
|---|---|---|---|
| Small, frequent change | Yes | Yes | Yes |
| Team owns the running service | Yes ("you build it, you run it") | SRE partners with developers | Engineers on hand at release |
| Risk controlled by design | Small blast radius | Error budget | Flags and staged rollout |
| Blameless learning | Yes (post-incident reviews) | Yes (blameless post-mortems) | Yes (post-incident reviews) |

Notice that none of the three is "just a tool". Each is a way of working. Security teams in these companies built **paved roads**: the easy path is also the secure path.

## 8. Self-check

1. Name the three building blocks and put them in the order you would invest in them.
2. What does each letter of CAMS stand for? Give a security example for each.
3. Which two benefits help security directly? Why is "speed" a risk without gates?
4. What is an error budget and which company popularised it?
5. What is the difference between a deployment and a release (hint: feature flags)?

## 9. Where next

[Lesson 02](02-cicd-and-deployment-strategies.md) turns these ideas into pipelines. If you want the CI runner mechanics first, see [csse ch1 lesson 05](../../csse-course/ch1-introduction-to-supply-chain-security/05-cicd-stages-and-deployment.md).
