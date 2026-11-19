# Lab: threat modeling with STRIDE GPT (and an offline twin)

**Course exercise:** Threat Modeling with STRIDEGPT.

STRIDE GPT is an open-source tool by Matthew Adams (github.com/mrwadams/stride-gpt). You describe an application and an LLM drafts a STRIDE threat model (and, in newer versions, attack trees, DREAD ratings and test cases; verify the current feature list). The output is a **draft**: a human must validate it.

## Part A: run the real tool (needs an API key or a local model)

All commands are hedged. Check the project README first, because options change.

```bash
git clone https://github.com/mrwadams/stride-gpt.git
cd stride-gpt
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run main.py                            # a web UI opens on localhost (verify the port)
```

Docker is also offered by the project (verify the image name and tag in its README).

Providers: the tool has supported several providers (for example OpenAI, Azure OpenAI, Google, Mistral, Anthropic, Groq) and local models through Ollama or LM Studio (verify the list). Enter the API key in the sidebar, or use a local model and no key leaves your machine.

Safety notes:

* The application description goes to the provider. Use the **synthetic** description in [`../stride-mcp-architecture/mcp_architecture.yaml`](../stride-mcp-architecture/mcp_architecture.yaml), not real internal details.
* Never paste real keys into shared notebooks or screenshots. Revoke a key after the exercise.
* Ask for MCP specifics in the "application description" box: tool descriptions, tool results, stdio and HTTP transports, OAuth tokens, a registry.

Suggested input (copy from the YAML `description` field and add): "Transport: stdio and Streamable HTTP on 127.0.0.1. Auth: OAuth for the remote server, bearer token for the local HTTP server. Sensitive data: OAuth tokens, customer CRM data, source code. Internet facing: remote server and registry."

## Part B: the offline twin (no key, runs in tests)

[`stridegpt_offline.py`](stridegpt_offline.py) shows the workflow without a model:

* `build_prompt()` is the kind of prompt such a tool sends (JSON with `Threat Type`, `Scenario`, `Potential Impact`).
* `generate(description, llm=None)` uses **templates** keyed on what the description mentions (stdio, OAuth, registry, ...). If you pass an LLM (for example `MockLLM`, or a local Ollama model through `aisec_lab.get_llm()`), it is tried first. A non-JSON answer falls back to the templates, so the pipeline never breaks.
* `validate()` compares the AI output with the manual findings of the STRIDE lab and reports **recall**, **MCP-specific misses**, **unsupported claims** and **duplicates**.

```bash
python cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stridegpt/demo.py
python -m pytest cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stridegpt
```

Real demo output (trimmed):

```text
template generator: source=template, 16 threats
MockLLM then fallback: source=template, 16 threats
* AI threats: 16; unique manual threat types: 26
* Recall of manual threat types: 46% (12 covered)
## Unsupported (mentions parts the architecture does not have)
* SQL injection through the web form that feeds the database tool.
```

The templates are deliberately generic: they miss tool poisoning, rug pull, shadowing, cross-server leakage and the config command line, and one template invents a "web form". A real LLM draft often shows the same pattern.

## Part C: validate (use the checklist)

Work through [`validation-checklist.md`](validation-checklist.md) for the output of the real tool or the twin, then write a one-paragraph verdict: which AI findings you keep, which you reject, which you add.
