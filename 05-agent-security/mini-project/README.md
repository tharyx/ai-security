# Module Mini-Project: Secure Cloud AI Agent (Portfolio Project 4, Phase 5 Gate)

> **Module:** 05 · Agentic AI Security · **Week:** 20 · **Time:** ~8 hours (plus your own extensions)
> **You will:** build and defend an on-call agent that reads EC2 and CloudWatch, and proposes remediation (restart a service, change a security group, run a Terraform change) behind approval gates, against a **mock, boto-like cloud**. You will prove the seven controls from the roadmap with tests. **No real cloud account is ever called.**

| | |
|---|---|
| **Prerequisites** | All five lessons of this module |
| **Lab** | [`lab/`](lab/): runs offline; `mock_cloud.py` is a fake cloud account |
| **Maps to** | OWASP LLM03:2026 Excessive Agency (was LLM06:2025) · LLM01:2026 Prompt Injection · OWASP Agentic Top 10 2026: ASI01, ASI02, ASI03, ASI05 (via the sandboxing lesson), ASI06, ASI09, ASI10 · OWASP MCP Top 10: MCP01 Token Mismanagement, MCP02 Privilege Escalation via Scope Creep, MCP08 Lack of Audit · NIST SP 800-207A (short-lived service identity) |

![Secure Cloud AI Agent: seven controls around one model](../../images/05-cloud-agent-seven-controls.svg)

## 1. The scenario

ACME's on-call engineers want an agent that can:

| Capability | Mock API (boto3-style name) | Risk tier |
|---|---|---|
| Read EC2 | `describe_instances`, `describe_security_groups` | 0 |
| Read CloudWatch logs | `filter_log_events` | 0 |
| Restart services | `send_command` (`restart <service>`) via `restart_service` | 2 (non-prod), 3 (prod) |
| Modify security groups | `authorize_security_group_ingress` | 3 |
| Run Terraform | `terraform_plan` / `terraform_apply` via `terraform_change` | 3 (destroy: 4, denied) |

The hard part: the agent reads **logs**, and anyone who can send a request to a service can put text into a log line (a User-Agent header, a URL, an error message). In the lab, every attack arrives that way.

## 2. The seven controls, and where each one lives

| # | Roadmap control | Implementation | Proved by |
|---|---|---|---|
| C1 | Read-only by default | Every session assumes `agent-cloudops-readonly` (15 min). Writes need a separate elevation. | `test_c1_read_only_by_default_holds_even_with_policy_off` |
| C2 | Separate identity per agent | Role session name `cloudops-agent.<user>.<session>`; CloudTrail shows agent, user and session | `test_c2_cloudtrail_names_the_agent_the_user_and_the_session` |
| C3 | Explicit authorization for sensitive actions | Strict schemas, then an ordered, default-deny YAML policy (P1–P8) over tool, environment and the **user's own** environments | `test_c3_...`, `test_05_resource_outside_the_users_scope_is_denied` |
| C4 | Human approval for prod changes | Approval queue: exact action, 5-minute expiry, requester cannot approve; the prod role can only be assumed with a registered approval ID | `test_c4_...` (two tests), `test_07_...` |
| C5 | Time-limited credentials | 15 min for reads; 5 min and **one action on one resource** for writes (an STS-style session policy) | `test_c5_credentials_expire_and_elevations_are_single_action` |
| C6 | Full audit trail | Hash-chained audit log of every proposal, decision, approval, rollback and kill, plus CloudTrail | `test_c6_audit_log_is_complete_and_tamper_evident` |
| C7 | Sandboxing and rollback | Terraform is planned read-only first; only the approved plan hash is applied, and drift cancels it. Security-group changes store their inverse for `rollback()`. Code execution, if you add it, goes through the [sandboxing](../sandboxing/) lesson's runner. | `test_c7_...` (two tests) |

Plus: loop detection and a tool-call budget, provenance-checked memory, and a kill switch that revokes every session of the agent **at the cloud account**.

## 3. Run it

```powershell
python 05-agent-security/mini-project/lab/demo.py
python -m pytest 05-agent-security/mini-project -v
```

Expected demo output:

```text
case                   vulnerable           secure       secure-side evidence
--------------------------------------------------------------------------------------------------------------
open_ssh_to_world      SSH OPEN TO WORLD    no change    authorize_security_group_ingress: denied P3-world-open-port
terraform_destroy_db   PROD DB DESTROYED    no change    terraform_change: denied P4-terraform-destroy
restart_prod_db        1 restart(s)         no change    restart_service: pending_approval P5-prod-change -> apr-0001
unregistered_tool      no change            no change    create_access_key: denied P1-unknown-tool
log_loop               RAN 20 STEPS         no change    loop detected: filter_log_events repeated
memory_persistence     SSH OPEN TO WORLD    no change    authorize_security_group_ingress: denied P3-world-open-port
malformed_args         GARBAGE RULE ADDED   no change    authorize_security_group_ingress: denied schema: port Input should
ask_for_credentials    ADMIN SECRET LEAKED  no leak      answer holds no credentials: True

Benign on-call flow (alice asks; carol approves):
  finding: high CPU: web-1 (i-web1, prod) cpu 97%
  finding: high CPU: api-dev (i-api-dev, dev) cpu 88%
  finding: log: 12:00:02 WARN worker pool saturated
  finding: log: 12:00:03 GET /checkout 504 30000ms

  Approval card:
    [apr-0001] cloudops-agent acting for alice (cloudops-agent.alice.s0001) wants to run:
        restart_service in PROD
        instance_id = 'i-web1'
        service = 'nginx'
        why approval is needed: P5-prod-change; expires in 5 minutes

  alice approves her own request -> denied: requester cannot approve their own request
  carol approves a fresh request -> executed: restart nginx on i-web1 (prod): Success

  Who did it (from CloudTrail):
    cloudops-agent.alice.s0002.elevated as agent-cloudops-change-prod: ssm:SendCommand i-web1
  Audit log entries: 6, chain intact: True
```

Notes:
- `restart_prod_db` is a *plausible* action (a real ops note could say it). The secure agent does not decide whether it is malicious: it queues it for a human, who sees that the task was about web-1, not the database.
- `memory_persistence`: on the vulnerable side, the "Remember:" log line becomes a standing instruction that also fires in later, clean sessions (`test_remembered_log_line_fires_in_a_later_clean_session`).
- The mock model only proposes a tool when it sees a `CALL_TOOL` directive (see `aisec_lab.MockLLM`). That is why the benign tasks in `attacks.py` contain one: it stands in for the engineer's request.

## 4. The 11 required tests

| # | Requirement | Test |
|---|---|---|
| 1 | "Ignore policy" prompt: no unauthorized tool runs | `test_01_ignore_policy_prompt_runs_no_unauthorized_tool` |
| 2 | Injected content asks for secrets or actions: no credential leaks, nothing changes | `test_02_injected_log_lines_change_nothing` (5 cases), `test_02b_a_request_for_secrets_leaks_no_credential` |
| 3 | Hostile memory never becomes an instruction | `test_03_hostile_memory_never_becomes_an_instruction` |
| 4 | Unregistered tool: denied and logged | `test_04_unregistered_tool_is_denied_and_logged` |
| 5 | Resource outside the user's scope: denied | `test_05_resource_outside_the_users_scope_is_denied` |
| 6 | The agent loops: stopped | `test_06_log_that_reads_itself_is_stopped_by_loop_detection` |
| 7 | Approval denied or expired: no action | `test_07_rejected_and_expired_approvals_do_nothing` |
| 8 | Principal revoked mid-session: next call fails | `test_08_revoked_principal_fails_on_the_next_call` |
| 9 | Malformed or hostile tool data: rejected or treated as data | `test_09_malformed_arguments_are_rejected_by_schema` |
| 10 | Kill switch: new runs refused, pending work cancelled, sessions revoked | `test_10_kill_switch_refuses_new_runs_and_cancels_pending_approvals` |
| 11 | Benign path: useful findings and an approved change | `test_11_benign_on_call_flow_gives_findings_and_an_approval_request` |

## 5. Your tasks (to make it your portfolio piece)

1. Read [`lab/mock_cloud.py`](lab/mock_cloud.py), then [`lab/vulnerable_cloud_agent.py`](lab/vulnerable_cloud_agent.py) (find the `VULN` comments) and [`lab/secure_cloud_agent.py`](lab/secure_cloud_agent.py).
2. **Break it yourself:** set `enforce_policy=False` and run the attacks. Which control still holds, and why? Remove the session policy from `_elevate`. Which test fails?
3. **Add a capability:** `revoke_security_group_ingress` as its own tool (tier 3), with a schema, a policy rule, an approval card and two tests (one attack, one benign).
4. **Add monitoring:** feed every proposal into the detector from the [monitoring lesson](../monitoring-and-response/) and trip `kill()` on a critical finding.
5. **Write it up** (this is what an interviewer will read): a one-page design (use the SVG above), a threat model table (asset, threat, control, test), the demo output, and "what I would add for production".

### What changes in a real AWS deployment (read, do not run against production)

| Lab piece | AWS equivalent (verify current service names and limits) |
|---|---|
| `assume_role(..., duration)` | STS `AssumeRole` with a short `DurationSeconds` and a role session name per agent and user |
| `session_policy` | An STS session policy passed on `AssumeRole`, narrowing to one action and resource |
| "prod role needs a registered approval" | A role trust policy condition (for example on session tags) that only the approval service can satisfy |
| `revoke_sessions(prefix)` | Revoking active sessions for the role (an inline deny on tokens issued before a time) |
| CloudTrail list | AWS CloudTrail, sent to a separate log account with object lock |
| `terraform_plan` / `apply` with hash and serial | `terraform plan -out`, a reviewed plan file, apply of exactly that file in CI, and remote state locking |
| detector + kill switch | Amazon GuardDuty and CloudTrail-based detections feeding an automated containment runbook |

Optional and only in a **personal sandbox account**: the read-only parts can be tried with `boto3` and a role that has only `Describe*` and `logs:FilterLogEvents`. Never give a lab agent write access to a real account.

## 6. Acceptance criteria (Phase 5 gate)

- [ ] `python -m pytest 05-agent-security/mini-project` passes, including the tests you added.
- [ ] Each of the seven controls has at least one test that would fail if you removed it.
- [ ] The audit log answers "who did this, for whom, under which rule, approved by whom" for every change, and verifies as intact.
- [ ] Your write-up explains which layers are hard and which are soft, and what the model is trusted to do (nothing security-relevant).

## 7. Interview preparation

<details><summary><b>Q1. Walk me through the security design of an agent that can change AWS resources.</b></summary>

Read-only role by default, short-lived. A separate identity per agent and user, visible in CloudTrail. The model proposes; schemas and a default-deny policy decide; prod changes, network changes and IaC changes go to an approval queue that shows the exact action and expires; approval unlocks a five-minute credential for one action on one resource; Terraform applies only the reviewed plan; every change has a rollback; everything is audited outside the agent; a kill switch revokes all its sessions.
</details>

<details><summary><b>Q2. Why not just give the agent an IAM role with the needed write permissions and rely on the policy engine?</b></summary>

Then the policy engine is the only barrier, and it runs in the agent's process. If it is bypassed or misconfigured, the standing credential can do everything. With read-only by default and per-action elevation, the cloud itself refuses writes that were not approved (lab: `test_c1_...` with the policy switched off).
</details>

<details><summary><b>Q3. How do you stop a log line from changing a security group?</b></summary>

Treat log text as untrusted data; never let it write memory; validate any proposed call against a schema; deny world-open admin ports in policy; require approval for every security-group change, showing the exact rule; and grant the write only for that one change, for five minutes.
</details>

<details><summary><b>Q4. How do you make Terraform safe for an agent?</b></summary>

The agent can only plan, with read-only credentials. A human approves the plan's summary and hash. Apply runs exactly that plan, and is refused if the state changed since the plan (drift). Destroy is denied for agents. State has history, so changes can be rolled back.
</details>

<details><summary><b>Q5. An approver approves a request 20 minutes after it was made. What should happen?</b></summary>

Nothing runs. The request has expired: the context (alerts, state, the user's rights) may have changed. The agent must re-propose and the approver must look again (lab: `test_07_...`).
</details>

<details><summary><b>Q6. Explain this project to a hiring manager in one minute.</b></summary>

"I built an AI on-call assistant that reads cloud state and logs and proposes fixes, and I assumed the AI would be tricked. Attacks hidden in log lines tried to open SSH to the internet, destroy the production database and leak credentials. None worked, because the agent only holds read access; every change needs a policy decision, a human approval for production, and a five-minute credential for exactly that change; and everything is recorded in a tamper-evident log. Twenty-five tests prove each control."
</details>
