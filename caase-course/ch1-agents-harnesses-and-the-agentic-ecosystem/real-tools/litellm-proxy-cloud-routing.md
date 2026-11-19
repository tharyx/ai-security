# An OpenAI-compatible proxy (LiteLLM) routing agent requests to a cloud model

> **Status: hedged outline, not tested by the repo author.** LiteLLM and similar gateways change quickly. Verify commands and config keys at <https://docs.litellm.ai>. Other options exist (any OpenAI-compatible proxy or gateway); the ideas are the same.

**Course exercise:** Routing Agent Requests to a Large Cloud Model via a Proxy and Comparing It to a Local Model.
**Offline twin (tested):** [routing-proxy](../labs/routing-proxy/): a policy router with a DLP scan, a classification rule, simulated latency and cost, and a test that confidential data never reaches the cloud mock.

## What you are building

```text
agent / harness  ->  http://127.0.0.1:4000/v1  (LiteLLM proxy, one key you control)
                          |-- "local-small"  -> Ollama on 127.0.0.1:11434
                          |-- "cloud-large"  -> a large model through a provider or OpenRouter (internet)
```

The agent only knows one base URL and a **proxy key**. The proxy holds the provider keys, applies rules, logs, and can cap spending. This is the "AI gateway" pattern from [09-enterprise-architecture](../../../09-enterprise-architecture/README.md) in small form.

## On your laptop (CPU only, 16 GB RAM)

- Install LiteLLM in a **virtual environment** (it is a Python package; it brings many dependencies, so mind disk space). A container is an alternative but uses more RAM.
- The local route should be a **1B to 4B Q4** model.
- The proxy itself is light. The cloud model does the heavy work, so keep the prompts public or fake.

## Outline of the steps

1. Start Ollama with a small model.
2. Write a config with two named models. Concept only (verify key names):

   ```yaml
   model_list:
     - model_name: local-small
       litellm_params:
         model: ollama/llama3.2                # your small local model
         api_base: http://127.0.0.1:11434
     - model_name: cloud-large
       litellm_params:
         model: openrouter/<a model id>        # or another provider's model
         api_key: os.environ/OPENROUTER_API_KEY
   general_settings:
     master_key: FAKE-KEY-REPLACE-ME           # a long random value in a real setup, from the environment
   ```

3. Start the proxy bound to **127.0.0.1** on a port (for example 4000) with that config.
4. Point your harness (or the [minimal harness lab](../labs/minimal-agent-harness/harness.py) with a small HTTP client) at `http://127.0.0.1:4000/v1` using the proxy key, and request `local-small` and `cloud-large` for the same task.
5. **Compare:** answer quality, tool-call validity, latency and cost (the proxy usually reports tokens and cost; verify). Put the numbers in a table like the one in the [routing lab](../labs/routing-proxy/README.md).
6. Add **policy** (this is the part that matters): the real proxy can do some of it with settings, callbacks or guardrail plugins (verify), and for the rest put a small policy layer like the lab's `router.py` in front. Rules: confidential or secret-looking prompts never go to `cloud-large`; large public prompts may.

## Security checklist

- [ ] Proxy bound to localhost; not reachable from the LAN or internet.
- [ ] A **master key** from the environment (long and random), and **per-agent virtual keys** with budgets and model allowlists if the proxy supports them (verify).
- [ ] Provider keys exist only in the proxy's environment, never in the agent, the prompt or the repo.
- [ ] **Spending limits** on provider keys and on the proxy; alerts on unusual cost (LLM06).
- [ ] **Model pinning:** each alias maps to one model; fallbacks disabled or explicit; log the served model and compare it with the requested one.
- [ ] **No confidential data to the cloud route** (classification, DLP, tested). Know what the provider logs and keeps.
- [ ] Request logs **redact secrets**; log retention and access set; the log file is itself sensitive.
- [ ] Admin UI and database (if used) protected; default credentials changed.
- [ ] Proxy version updated; check its security advisories (gateways are high-value targets because they hold provider keys).
- [ ] Rate limits per agent key to contain runaway loops (ASI08).

## What to observe

1. Latency and cost per request for local and cloud. Is the cloud answer worth it for this task?
2. A request with a **FAKE** key string inside: does your policy catch it before it reaches the cloud route? (Use only fake values.)
3. What happens if the cloud route fails and a fallback serves another model? Can you see it in the logs?
