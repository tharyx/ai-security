# Shift handover template

> Write it before your shift ends. The next person should not need to ask you anything. Send it in the agreed channel and also say the top item out loud (or on a call) if it is urgent.

**Date:** _YYYY-MM-DD_  **Shift:** _day / evening / night_  **From:** _name_  **To:** _name_  **Time of handover (UTC):** _HH:MM_

## 1. Top priority (read first)

_One or two lines. Example: "INC-2026-0412 (Sev 2): suspected account takeover of user X. Sessions revoked. Waiting for user to confirm by 08:00 UTC; if no answer, escalate to L2."_

## 2. Open incidents

| Ticket | Severity | What is known | What I did | Next action | Deadline | Owner after handover |
|---|---|---|---|---|---|---|
| | | | | | | |

## 3. Open alerts and queue state

- **Alerts in queue:** _count, oldest age_
- **Alerts waiting for a reply (who, since when):**
- **Noisy or broken rules (name and why):**
- **Tuning changes made this shift:**

## 4. Watch list

| Item (user, host, IP, domain) | Why watch | What to do if it triggers |
|---|---|---|
| | | |

## 5. Changes and maintenance

- **Planned changes tonight or tomorrow:**
- **Systems down or degraded (log sources, sensors, EDR agents):**
- **Blocks and exceptions added (with expiry):**

## 6. Contacts and escalations

- **On-call (name, phone/chat):**
- **Who I already told:**
- **Who must be told, and when:**

## 7. Not finished / things I could not check

_Be honest. "I did not review the proxy logs for host H." is useful information._

## 8. Handover accepted

- Receiver confirms: **yes / questions:** _…_ at _HH:MM_

---

### Rules of good handover

- Facts, ticket numbers and deadlines. No long stories.
- Say what is **done**, **not done** and **next**.
- Name an owner for each open item.
- If you are not sure, say so.
