# Lab: Scoping and Testing Delegated Authorization Tokens

**Syllabus exercise:** Scoping and Testing Delegated Authorization Tokens Between Agents · **Lesson:** [04](../../04-agent-identity-and-access.md) · **Offline, 10 tests, stdlib only.**

`TokenService` mints HMAC-signed tokens (`base64url(payload).base64url(sig)`) with `iss`, `user`, `sub`, `aud`, `scope`, `iat`, `exp`, `jti` and a nested `act` actor chain, in the spirit of OAuth Token Exchange (RFC 8693). **Teaching shortcut:** one shared HMAC key. Real systems use a token service with asymmetric keys and standard formats.

## Run

```text
.venv/Scripts/python -m pytest caase-course/ch5-multi-agent-systems-and-agent-identity/labs/delegated-token-scoping
.venv/Scripts/python caase-course/ch5-multi-agent-systems-and-agent-identity/labs/delegated-token-scoping/demo.py
```

Real output of `demo.py`:

```text
root   sub=orchestrator aud=agent-b       scope=['calendar.read', 'files.read', 'mail.send'] exp=1600.0 chain=['orchestrator']
hop-2  sub=agent-b      aud=calendar-api  scope=['calendar.read', 'mail.send'] exp=1301.0 chain=['orchestrator', 'agent-b']
hop-3  sub=agent-c      aud=calendar-api  scope=['calendar.read'] exp=1301.0 chain=['orchestrator', 'agent-b', 'agent-c']
hop-3 token reads calendar         -> allowed
hop-3 token sends mail             -> denied: scope mail.send not granted
hop-3 token used at mail-api       -> denied: audience mismatch: token is for calendar-api, presented to mail-api
hop-3 token after expiry           -> denied: expired
hop-3 tries to widen scope         -> denied: cannot widen scope: ['mail.send']
```

## Properties tested

| Property | Test |
|---|---|
| Scope shrinks on every hop; cannot widen | `test_downscoping_on_each_hop`, `test_cannot_widen_scope` |
| Audience binding stops passthrough | `test_audience_binding_blocks_passthrough` |
| `act` chain records every hop; user preserved | `test_act_chain_records_every_hop` |
| Chain depth limit | `test_chain_depth_limit` |
| Child never outlives parent | `test_child_never_outlives_parent` |
| Expiry (injected clock) | `test_expiry_enforced_and_expired_parent_cannot_exchange` |
| Tamper and revocation | `test_tamper_detected`, `test_revocation` |

## Break it yourself

1. Remove the `min(..., parent["exp"])`. Which test fails? What is the real-world impact of a child that outlives its parent?
2. Make `verify` skip the audience check. Replay a token at the wrong resource.
3. Stretch: add `may_act` (who is allowed to exchange this token) and test that an unlisted agent cannot.
