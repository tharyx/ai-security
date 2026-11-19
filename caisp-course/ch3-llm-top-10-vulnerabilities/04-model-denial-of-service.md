# 04. Model Denial of Service (LLM04 in 2023)

> **Maps to:** 2023 LLM04 Model Denial of Service | 2025 LLM10 Unbounded Consumption | 2026 06 Unbounded Consumption.
> **Time:** 1.5 hours. **Existing controls in this repo:** [02-llm-security/security-testing](../../02-llm-security/security-testing/README.md) (`lab/limits.py`: token bucket, per-user token budget, loop guard). This page adds the course view (network vs application vs model) and **context-window exhaustion**, which that lab does not cover. New lab: [model-dos-context-exhaustion](labs/model-dos-context-exhaustion/README.md).

## Why this matters

Model calls are slow and costly: they use GPU time, memory and money per token. A request that is cheap to send can be expensive to answer. That imbalance makes DoS easy and also makes a *cost* attack ("denial of wallet") possible. The risk was renamed Unbounded Consumption because the harm is not only downtime but also the bill, and model extraction through heavy use.

Research result to know: "sponge examples" (Shumailov and colleagues, 2021) showed that inputs crafted to maximize computation can sharply raise latency and energy use of neural networks.

## DoS on networks, applications, and models

You know the first two from DevOps. The third is the new one.

| Level | Target | Classic example | What the attacker spends | Typical defense |
|---|---|---|---|---|
| **Network** | Bandwidth, connections | SYN or UDP floods, volumetric DDoS | many packets | CDN, DDoS protection, rate limits at the edge |
| **Application** | Web app or API logic | Slowloris, expensive search or login endpoints, regex DoS | many or crafted requests | WAF, rate limiting, timeouts, caching, input limits |
| **Model** | The LLM and its serving stack | Huge or repeated prompts, prompts that trigger very long answers, recursive or looping agent tasks, flooding the context window, expensive tool calls | few requests that are cheap to send but costly to compute | token limits, per-user budgets, output caps, loop guards, queue and priority controls |

Model-level patterns:

1. **Oversized input.** A very long prompt costs more compute and may hit the context limit.
2. **Amplification.** A short prompt that asks for a very long output, or "repeat this 10,000 times".
3. **Recursive expansion.** A document that includes itself, or an agent that calls a tool whose result asks for another call, forever.
4. **Many medium requests** that together exhaust a shared GPU pool or a paid API budget.
5. **Resource-heavy tools.** A tool call that scans a huge file or runs a long query.
6. **Pipeline starvation.** One user's long job blocks a shared queue.

## Context windows and exhaustions

The **context window** is the fixed number of tokens a model can read at once: system prompt + history + retrieved documents + the new message + the space needed for the answer. Think of a box of fixed size.

What goes wrong when it fills:

| Problem | Explanation | Impact |
|---|---|---|
| Truncation of the wrong part | Many apps cut the *oldest* text first. The oldest text is the system prompt | Safety rules disappear ("system prompt eviction") |
| Hard failure | The call errors out when the input is too long | Availability loss, retries pile up |
| Lost in the middle | Models attend less to the middle of a very long context | Critical instructions or facts are ignored |
| Cost | Cost grows with tokens in and out | Denial of wallet |
| Dilution | Flooding with noise pushes the useful context out | Wrong or off-policy answers |

The lab shows eviction in action: a long input makes the toy model forget "answer billing questions only", then shows the fixes.

## Mitigating denial of service

| Control | Detail | Type |
|---|---|---|
| Input size cap | Reject oversized messages before the model; return a clear error | Hard |
| Pin the system prompt | Trim history, never the rules; reserve room for the output | Hard |
| Output cap | Set `max_tokens`; limit repetition | Hard |
| Rate limits and quotas | Per user, per key, per tenant; token bucket for bursts | Hard |
| Token budget per user and per day | Stops many medium requests and cost abuse | Hard |
| Loop and recursion guards | Step limits, cycle detection, depth limits for includes and tool chains | Hard |
| Timeouts and cancellation | Kill long generations; limit tool run time | Hard |
| Queue isolation | Separate pools by tenant or priority so one user cannot starve others | Hard |
| Caching and cheaper routing | Serve repeats from cache; route easy tasks to small models | Soft |
| Monitoring and alerts | Spend, tokens per user, latency, error rates | Process |
| Authentication | Anonymous access to an LLM endpoint is an open invitation | Hard |

## Hands-on

[labs/model-dos-context-exhaustion](labs/model-dos-context-exhaustion/README.md): eviction, token budget, include bomb, with tests. Then read `limits.py` in the [security-testing lab](../../02-llm-security/security-testing/lab/limits.py) and combine both.

## Interview Q&A

<details><summary><b>Q1. How is DoS against an LLM different from DoS against a web server?</b></summary>
The cost per request is high and variable, and depends on the content: a tiny request can trigger a very long, expensive generation. So you limit tokens, output length, tool loops and spend per user, not only requests per second. Also, the harm includes money ("denial of wallet").
</details>

<details><summary><b>Q2. What is context-window exhaustion and why is it a security issue?</b></summary>
Filling the fixed-size context so something important is dropped or ignored. If the system prompt is dropped, safety rules vanish. It also costs money and can crash requests. Fix: pin the system prompt, cap input size, trim history only, reserve output space.
</details>

<details><summary><b>Q3. Name three controls that stop an agent loop.</b></summary>
A maximum step count, detection of repeated identical calls, and a total token or time budget per task. A human approval step for expensive actions also works.
</details>

## References

- OWASP LLM Top 10 (model DoS / unbounded consumption entry): https://genai.owasp.org/
- Shumailov et al., "Sponge Examples: Energy-Latency Attacks on Neural Networks" (2021)
- Repo: [security-testing](../../02-llm-security/security-testing/README.md)
