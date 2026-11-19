# Hermes Agent with a local and an OpenRouter model, side by side

> **Status: hedged outline, not tested by the repo author.** Hermes Agent (Nous Research) is a young project. Its CLI, config format and features may differ from this outline. Read the official documentation first: <https://hermes-agent.nousresearch.com>. If a command below does not exist, trust the docs.

**Course exercise:** Standing Up Hermes Agent with a Local and a Cloud-Routed Model Side by Side.
**Offline twin (tested):** [tool-calling-determinism](../labs/tool-calling-determinism/) (two models, concurrent, same tasks) and [routing-proxy](../labs/routing-proxy/) (local vs cloud by policy).

## What you are building

```text
task -> Hermes (harness) -> profile A: local model via Ollama (OpenAI-compatible, 127.0.0.1)
                         -> profile B: cloud model via OpenRouter (API key, internet)
        same task, same tools, same prompt; compare tool calls, quality, speed, cost
```

What we know, hedged: Hermes Agent is open source (MIT), model-agnostic, launched around February 2026, and can use several providers including Nous Portal, OpenRouter and local servers; it is an MCP client over stdio and HTTP with per-server tool filtering (`hermes mcp add/list/test/remove` is reported), can run as an MCP server too, has built-in scheduling and messaging, and can drive other coding harnesses as sub-agents.

## On your laptop (CPU only, 16 GB RAM)

- The **local** side: a 1B to 4B model at Q4 through Ollama. Agent harnesses make long prompts (many tools, memory, results), which is slow on CPU; use short tasks and few tools.
- The **cloud** side: an OpenRouter model, ideally a free-tier or cheap one for the exercise. **Free models may log your prompts**; send only public test text.
- Run the two **one after the other** if memory is tight, or run Ollama and Hermes together (they fit in 16 GB with a small model).

## Outline of the steps

1. **Install Hermes** by the method on its official install page (verify; do not pipe an unknown script into your shell without reading it first, and prefer a virtual environment or container).
2. **Run the local model** with Ollama (`127.0.0.1:11434`) and note its OpenAI-compatible base URL (`http://127.0.0.1:11434/v1`).
3. **Create an OpenRouter account and a limited key** (spending limit, no other permissions). Store it in an environment variable, for example `OPENROUTER_API_KEY`, not in a file in the repo. (The repo author does not hold or need your key.)
4. **Configure two model profiles** in Hermes's config: one pointing to the local base URL, one to OpenRouter (verify the provider names and keys in the docs). Concept only:

   ```yaml
   # concept only: the real schema is in the Hermes docs
   profiles:
     local:
       provider: openai-compatible
       base_url: http://127.0.0.1:11434/v1
       model: llama3.2
     cloud:
       provider: openrouter
       api_key_env: OPENROUTER_API_KEY      # read from the environment
       model: <a model id from the OpenRouter list>
   ```

5. **Add one harmless MCP server** (the CMCPSE lab server) with a tool filter that allows only its read-only tools (`hermes mcp add` and the per-server filter; verify).
6. **Run the same five tasks on each profile**, with tools, and record: valid tool-call rate, correct answer, time, tokens, cost. Use the table format of [tool-calling-determinism](../labs/tool-calling-determinism/README.md).

## Security checklist

- [ ] Hermes runs as a normal user, in a container or VM if you test skills and scheduled jobs; not as administrator.
- [ ] Config and key files not world-readable; keys only in environment variables or a secrets store; never committed.
- [ ] OpenRouter key has a **spending cap**; rotate it after the exercise.
- [ ] Only public or fake data goes to the cloud profile. Know the provider's logging and retention terms (verify on OpenRouter and the upstream provider).
- [ ] The response `model` field is checked against the requested model (substitution or fallback).
- [ ] MCP servers: reviewed, pinned, **per-server tool filter** enabled so only needed tools are exposed.
- [ ] Scheduling and messaging features **off** unless needed (they let the agent act while you are away). If on, require approval for side effects.
- [ ] If Hermes drives other coding agents as sub-agents, treat each as a delegation hop: limited directory, no secrets in the environment.
- [ ] Logs reviewed for secrets; retention set.
- [ ] Updated to the latest release; subscribe to its security advisories.

## What to observe

1. Do both profiles produce the same tool calls for the same task? Where do they differ (format, arguments, extra steps)?
2. Does the local model need more retries? That is the cost of a small model without schema enforcement.
3. What did the cloud run cost and what data did it send? Write one sentence for a manager: "what leaves our network when we use profile B".
