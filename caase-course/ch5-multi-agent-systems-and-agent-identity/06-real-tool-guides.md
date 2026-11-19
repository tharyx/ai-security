# 06. Real-Tool Guides for the Chapter 5 Exercises

> **Hedged guides.** Tools and commands change fast. Check each project's own docs. The offline labs teach the same security ideas and are what the repo tests. Nothing here is executed by the repo's tests, and nothing needs Docker, network or keys to pass them.

Your laptop: i5, 16 GB RAM, no GPU. Use small CPU models (about 1B to 4B parameters, 4-bit) locally, and a cloud router for anything bigger.

## A. A local plus cloud-routed agent pair (exercise 1)

1. **Local model.** Install Ollama and pull a small model (for example a 1B to 4B instruct model). It serves an HTTP API on `localhost:11434`. Keep it bound to localhost.
2. **Cloud model.** Create an OpenRouter account and an API key. Keep the key in an environment variable, never in the repo. Prefer a paid model with a clear data policy for real work. "Free" models on routers may log or train on prompts: read the provider's terms.
3. **Router.** Reuse the classifier idea from [delegator_worker.py](labs/delegator-worker-routing/delegator_worker.py): classify first, then pick `local` or `cloud`. Test it by sending a canary (a fake ID) as restricted data and checking provider-side that it never arrived.
4. **Optional real step.** In the repo, `AISEC_LLM_BACKEND=ollama` switches `aisec_lab` from the mock to Ollama (see `aisec_lab/llm.py`). Real models are less predictable than the mock.

## B. Delegating subtasks to isolated sub-agents with Hermes Agent (exercise 2)

Hermes Agent (Nous Research) is an open-source, model-agnostic agent harness (launched around February 2026, MIT license, as reported). Reported capabilities include many providers (Nous Portal, OpenRouter, local), MCP client support with per-server tool filtering, scheduling and messaging, and the ability to drive other coding harnesses as sub-agents. **Check hermes-agent.nousresearch.com for the exact commands and features before you rely on any of this.**

A safe way to run the exercise:

1. Install it in a throwaway VM, container or separate user account, not on a machine holding your SSH keys or cloud credentials.
2. Configure a small local model or a low-limit API key.
3. Ask the main agent to delegate two subtasks to two sub-agents. Look in its docs for how sub-agent contexts, tools and credentials are configured.
4. **Verify isolation yourself** (this is the point of the exercise), using the same questions as the offline lab:
   - Put a canary string in sub-agent A's task. Ask sub-agent B to repeat anything it knows about "canary". Does it see it?
   - Does each sub-agent have its own tool list? Remove a tool from B and test.
   - Does the sub-agent inherit the parent's API keys or environment variables? Check the process environment.
   - What comes back to the parent: the full transcript or a summary? Treat it as untrusted either way.
5. If any answer is "shared", treat sub-agents as one trust domain and add outside isolation (separate containers, separate credentials).

Compare what you found with [isolated-subagents](labs/isolated-subagents/README.md).

## C. Other exercises

| Exercise | Real-tool option | Offline twin |
|---|---|---|
| Spoofing agent-to-agent messages | A2A sample agents from the A2A project (run locally on 127.0.0.1) | [a2a-spoofing](labs/a2a-spoofing/README.md) |
| Exploiting a confused-deputy chain | Any two-agent demo with a privileged tool | [confused-deputy-chain](labs/confused-deputy-chain/README.md) |
| Delegated tokens | An OAuth server in dev mode (token exchange support varies: verify) | [delegated-token-scoping](labs/delegated-token-scoping/README.md) |
| Rogue agent termination | Your orchestrator's kill switch, plus container stop | [rogue-agent-containment](labs/rogue-agent-containment/README.md) |
| HITL gate | Approval features of your harness (per-tool approval) | [hitl-approval-gate](labs/hitl-approval-gate/README.md) |

Safety: bind everything to `127.0.0.1`; never expose an agent gateway to the internet; use fake data and fake keys.
