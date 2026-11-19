# Real-tools guides (hedged, not tested)

These three guides outline how to do the course's tool-based exercises on real software. **The repo author has not run them.** Commands, config keys, image names and features change often. Treat each guide as a map: follow the project's own current documentation for exact steps, and verify every claim.

| Guide | Course exercise | Offline twin lab (tested) |
|---|---|---|
| [LibreChat with MCP and a local Ollama model](librechat-mcp-local-ollama.md) | Setting Up LibreChat for MCP Tool-Calling with a Local Model | [minimal-agent-harness](../labs/minimal-agent-harness/), [tool-calling-determinism](../labs/tool-calling-determinism/) |
| [Hermes Agent: a local and an OpenRouter model side by side](hermes-agent-local-and-openrouter.md) | Standing Up Hermes Agent with a Local and a Cloud-Routed Model Side by Side | [tool-calling-determinism](../labs/tool-calling-determinism/), [routing-proxy](../labs/routing-proxy/) |
| [An OpenAI-compatible proxy (LiteLLM) routing to a cloud model](litellm-proxy-cloud-routing.md) | Routing Agent Requests to a Large Cloud Model via a Proxy and Comparing It to a Local Model | [routing-proxy](../labs/routing-proxy/) |

## Rules for every guide

- **Your laptop:** 16 GB RAM, no GPU, little disk space. Run only small models (1B to 4B, 4-bit) locally. Check with the [sizing calculator](../labs/model-sizing-calculator/) first.
- **Docker is optional.** Everything has a non-Docker path or can be done in the course's browser lab. Docker Desktop on Windows uses a lot of RAM and disk.
- **No real secrets in examples.** Placeholders such as `FAKE-KEY-REPLACE-ME` are not real. Put real keys in environment variables or a secrets store, never in a file you commit.
- **Bind to localhost.** Do not expose any of these services to the network.
- **Treat third-party servers, skills and plugins as untrusted code.**
- **Nothing in the repo tests depends on these tools.** The offline twins teach the same security idea.
