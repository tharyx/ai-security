# LLM Application Security: Theory, Attacks and Defenses

## Learning objectives
Understand the LLM attack surface, reproduce representative attacks in a local lab, and implement deterministic controls around the model.

## Threat areas
1. Direct prompt injection: attacker places instructions in user input.
2. Indirect prompt injection: hostile instructions arrive through retrieved or external content.
3. Sensitive information disclosure: secrets, personal data or confidential context are exposed.
4. Insecure output handling: model output reaches SQL, shell, HTML, code or downstream APIs without validation.
5. Training/data poisoning: compromised data influences model behavior.
6. Model denial of service: excessive tokens, repeated calls or expensive requests exhaust resources.
7. Supply-chain compromise: malicious or vulnerable model, package, adapter or dependency.
8. Excessive agency: model can trigger consequential actions without adequate authorization.
9. Overreliance: humans or systems accept unverified output.
10. Model theft/extraction: unauthorized access to model weights or behavior.

Use the current OWASP GenAI LLM Top 10 release as a threat taxonomy, not as a substitute for system-specific threat modeling.

## Lab 1 — Prompt injection boundary
Create a toy assistant that summarizes user-provided text. Feed it a document containing an instruction to ignore the task and reveal a synthetic canary string.

**Observe:** The model may follow the embedded instruction. Do not interpret this as a deterministic software bug with a universal filter fix.

**Defend:**
- separate trusted instructions from untrusted content in application design;
- do not place secrets in model context unless strictly required;
- constrain the model to a narrow task;
- use deterministic policy checks and authorization outside the model;
- treat output as untrusted;
- require confirmation for sensitive actions;
- test multiple paraphrases and languages.

## Lab 2 — Secret disclosure
Use a fake value such as `CANARY-DO-NOT-EXPOSE-12345` in a synthetic context. Test whether it can appear in responses or logs.

Controls:
- data minimization;
- server-side authorization before context construction;
- secret vaults rather than prompt-embedded credentials;
- output DLP as a secondary control;
- log redaction and retention controls;
- tenant/session isolation.

## Lab 3 — Unsafe output
Never execute model-generated shell or SQL directly. Implement an allowlisted operation interface.

```python
from enum import Enum
from pydantic import BaseModel, Field

class Action(str, Enum):
    describe_instance = "describe_instance"
    list_alarms = "list_alarms"

class ToolRequest(BaseModel):
    action: Action
    resource_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")

def dispatch(request: ToolRequest, principal):
    # Authorization is deterministic and independent of model claims.
    if "infra:read" not in principal.permissions:
        raise PermissionError("not authorized")
    if request.action == Action.describe_instance:
        return describe_instance_read_only(request.resource_id)
    if request.action == Action.list_alarms:
        return list_alarms_read_only()
    raise ValueError("unsupported action")
```

## Lab 4 — Resource exhaustion
Implement:
- maximum input and output tokens;
- request and user quotas;
- concurrency limits;
- timeouts and cancellation;
- per-model spend budgets;
- recursion/agent-step limits;
- circuit breaker and back-pressure.

Test oversized prompts, rapid calls and intentionally looping workflows in a local environment.

## Lab 5 — Evaluation harness
For every attack case record:
- case ID and objective;
- system/model version;
- prompt and synthetic context;
- expected secure behavior;
- observed output;
- severity;
- mitigation;
- regression test result.

A refusal is not automatically a pass. Verify that unauthorized data/action was not obtained through another path.

## Defensive design checklist
- [ ] No credentials or unnecessary sensitive data in prompts.
- [ ] Server-side authorization before retrieval and tool execution.
- [ ] Output validation before downstream use.
- [ ] Tool allowlist and typed schemas.
- [ ] Token, rate, cost and concurrency limits.
- [ ] Model/provider fallback does not weaken policy.
- [ ] Prompt and model versions are controlled.
- [ ] Logs are useful but do not retain secrets by default.
- [ ] Security regression suite runs on every relevant change.
