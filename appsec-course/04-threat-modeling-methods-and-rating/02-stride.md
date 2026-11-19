# Lesson 02: List-Centric Threat Modeling with STRIDE

**Syllabus items covered:** [CTMP 2] "List Centric Threat Modeling", "Exploring the STRIDE Model" and its six letters, "Pros and Cons of STRIDE", "STRIDE Defenses" and its six properties, "STRIDE Threat Examples"; [CSC 4] "Exploring the STRIDE Model", the six letters, "STRIDE threat examples".

**Time:** 2 hours. **Lab:** [dfd-stride](labs/dfd-stride/README.md).

> **DBA analogy.** STRIDE is a checklist like your pre-go-live database checklist (backups, grants, auditing, listener). It does not think for you, but it stops you forgetting a whole category.

The short version also exists in [devsecops ch03 lesson 01](../../devsecops-course/03-security-requirements-and-threat-modeling/01-threat-modeling-stride-dread-and-challenges.md#2-stride) and for LLM apps in [CAISP ch5 lesson 03](../../caisp-course/ch5-threat-modeling-ai-systems/03-stride-for-llm-apps.md). This lesson is the full treatment.

## 1. List centric threat modeling

List (library) centric modeling walks a **known list of threat types** over every part of the system. STRIDE is the classic list; others are LINDDUN (privacy), CAPEC (attack patterns), OWASP Top 10 lists, and card decks ([lesson 04](04-other-methodologies-and-games.md)). The list makes sessions repeatable and teachable; the DFD tells you where to apply it.

## 2. The STRIDE model

STRIDE was created at Microsoft (Kohnfelder and Garg, 1999). Each letter is a threat that **breaks one security property**.

### 2.1 Spoofing

Pretending to be someone or something else. Breaks **authentication**. Examples: stolen session cookie, credential stuffing, a forged webhook "from" the payment provider, a rogue service calling an internal API.

### 2.2 Tampering

Unauthorised change of data or code, in transit or at rest. Breaks **integrity**. Examples: the client changes the price, an attacker edits a message on the queue, SQL injection altering rows, a modified build artifact.

### 2.3 Repudiation

Denying an action because there is no proof. Breaks **non-repudiation** (accountability). Examples: "I never approved that refund", logs the admin can delete, events with no user id or reliable time.

### 2.4 Information disclosure

Exposing data to someone not allowed to see it. Breaks **confidentiality**. Examples: verbose errors, BOLA (another user's order), an open backup bucket, "unknown user" vs "wrong password" messages.

### 2.5 Denial of service

Making a system unavailable or too slow. Breaks **availability**. Examples: HTTP floods, unbounded queries, ReDoS, poison queue messages, a reset endpoint that sends unlimited emails.

### 2.6 Elevation of privilege

Gaining rights you should not have. Breaks **authorization**. Examples: a normal user calling `/admin`, mass assignment of `role=admin`, command injection, a container running as root.

(The Threat Modeling course says "Elevation of Privileges"; the Security Champion course says "Elevation of Privilege". Same thing.)

## 3. STRIDE defenses

Each letter maps to a property, and each property to a family of controls.

| Threat | Property | Defense family | Concrete controls |
|---|---|---|---|
| Spoofing | Authentication | Prove identity | MFA and passkeys, mTLS between services, signed webhooks, short-lived signed tokens |
| Tampering | Integrity | Detect or prevent change | Server-side validation, bind variables, HMAC/signatures, TLS, immutable artifacts |
| Repudiation | Non-repudiation | Attributable records | Audit logs with actor, time, request id; append-only/WORM storage; signed records; NTP |
| Information disclosure | Confidentiality | Limit who can read | Encryption in transit and at rest, object-level access checks, generic errors, data minimisation |
| Denial of service | Availability | Limit and absorb | Rate limits, quotas, timeouts, pagination limits, autoscaling, CDN/WAF |
| Elevation of privilege | Authorization | Check every action | Deny by default, RBAC/ABAC checks on server, least privilege, sandboxing |

### 3.1 Authentication

Who are you? Strong authentication defeats spoofing: phishing-resistant MFA (passkeys/WebAuthn), mTLS or workload identity between services, verified signatures on partner callbacks. Deep dive: chapter 10 of this course (API authentication).

### 3.2 Integrity

Has it changed? Validate on the server, use bind variables (prepared statements), sign or MAC data that crosses boundaries, use TLS, protect build artifacts (signing, provenance).

### 3.3 Non-repudiation

Can we prove who did it? Log security-relevant actions with identity, time and correlation id; ship logs where the actor cannot edit them; synchronise clocks. For high-value actions, digital signatures or a second approver.

### 3.4 Confidentiality

Who can read it? Encrypt in transit (TLS 1.2+) and at rest, check ownership on every object (the `WHERE owner_id = :me` you add to every query; Oracle VPD did this for you), avoid leaking via errors and response differences, store less.

### 3.5 Availability

Will it stay up? Limits on request size, rate and cost; timeouts and circuit breakers; redundancy; capacity tests. Do not let a security control (account lockout) become a DoS tool.

### 3.6 Authorization

May you do this? Server-side checks on every function and object, deny by default, least privilege for users and services (no DBA grants for the worker). Deep dive: chapter 11 (API authorization).

## 4. STRIDE per element

Not every letter fits every DFD element. The classic table:

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| External entity | x | | x | | | |
| Process | x | x | x | x | x | x |
| Data store | | x | (x if it stores logs) | x | x | |
| Data flow | | x | | x | x | |

The [dfd-stride lab](labs/dfd-stride/README.md) generates 44 candidate questions for the password reset DFD from this table and marks flows that cross a trust boundary as priority. Candidates are not threats yet: a human decides which are real here.

## 5. STRIDE threat examples

A worked table for the password reset feature (also used in [lesson 06](06-password-reset-workflow.md)):

| Element | Letter | Threat | Mitigation (requirement) |
|---|---|---|---|
| User (external) | S | Attacker predicts the victim's reset token | CSPRNG tokens (SR-01) |
| F1 `POST /forgot` | I | Response reveals which emails have accounts | Uniform response (SR-02) |
| Reset service | T | Host header changes the link domain | Fixed base URL (SR-03) |
| Token cache | I | Dump yields usable tokens | Store token hashes (SR-06) |
| Reset service | R | No record of resets | Audit event (SR-11) |
| Reset service | D | Unlimited reset emails | Rate limit (SR-10) |
| Reset service | E | Attacker's old session survives the reset | Revoke sessions (SR-08) |

More examples for APIs: S = API key leaked in a mobile app; T = mass assignment of `price`; R = no audit of admin deletes; I = BOLA; D = GraphQL deep query; E = BFLA (`DELETE /users/7` works for any user).

## 6. Pros and cons of STRIDE

| Pros | Cons |
|---|---|
| Easy to learn; six words | Finds categories, not risk: no prioritisation |
| Systematic with STRIDE per element | Can become a checkbox exercise |
| Works for any technology | Weak on privacy (use LINDDUN), business logic and supply chain |
| Maps directly to controls | Many duplicate or trivial candidates |
| Tool support (Microsoft TMT, Threat Dragon, pytm) | Needs a good DFD; garbage in, garbage out |

Fix the cons by combining: STRIDE for coverage, personas for likelihood ([lesson 03](03-goal-attacker-and-software-centric.md)), a rating method for priority ([lesson 05](05-threat-rating.md)).

## 7. Scenario: STRIDE found the webhook

A team ran STRIDE per element on its checkout DFD. The payment provider is an external entity, so the facilitator asked "S: can someone pretend to be the provider?". Nobody had checked: the webhook endpoint accepted any POST with `status=paid`. Signature verification (HMAC with timestamp) went into the sprint. STRIDE did not invent the threat; it made sure someone asked.

## 8. Common mistakes

- Applying STRIDE to the whole system at once instead of per element.
- Listing "DoS" for everything with no specifics.
- Stopping at categories without a concrete threat sentence and mitigation.
- Forgetting that log stores also face repudiation.
