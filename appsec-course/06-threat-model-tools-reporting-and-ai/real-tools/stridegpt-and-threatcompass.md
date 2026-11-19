# Real tools: STRIDE GPT and ThreatCompass (hedged)

> **Hedge.** AI tools change quickly. Verify features, providers and data handling before use. Use a **synthetic** application description unless your organisation approved the provider for real architecture data. Never paste real keys, hostnames or IPs. Only test systems you own or have written permission to test.

## STRIDE GPT

Open source (GitHub `mrwadams/stride-gpt`; verify).

```text
git clone https://github.com/mrwadams/stride-gpt.git
cd stride-gpt
python -m venv .venv && .venv\Scripts\activate      # Linux/macOS: . .venv/bin/activate
pip install -r requirements.txt
streamlit run main.py                                # opens a local web UI (verify the port)
```

A Docker image has also been published (verify name and tag). In the sidebar choose a provider and model. To keep data local, choose **Ollama** or **LM Studio** with a local model.

Exercise:

1. Describe the synthetic shop: "Web application with REST API, PostgreSQL, message queue; customers log in with username and password; admins use the same login; internet-facing; stores names, addresses and order history."
2. Generate the **threat model**, then **attack tree**, **mitigations**, **DREAD** scores and **test cases** (tabs vary by version).
3. Copy the JSON/Markdown into the [lab's review gate](../labs/llm-assisted-threat-modeling/README.md) (map fields to `component`, `stride`, `title`, `mitigation`).
4. Record: what was hallucinated, what was missing, and what you added.

## ThreatCompass

The course uses **ThreatCompass** for AI threat modeling. We could not reliably verify its current vendor, features or data handling, so follow your course lab for the steps. Apply this checklist to it (and to any AI threat modeling assistant):

| Question | Why |
|---|---|
| What data is sent, to which provider, and is it retained or used for training? | Architecture details are sensitive |
| Can it use a local or private model? | Keeps data in your boundary |
| Does every threat refer to a real component and flow? | Hallucination control |
| Does it cover all STRIDE categories per element, including Repudiation? | Coverage control |
| Can design documents or repository text change its instructions? | Prompt injection |
| Can you export to an open format and keep the reviewed model in git? | Ownership and audit |
| Who signs off? | A human decides |

## Related

- Offline twin for MCP architectures: [CMCPSE stridegpt lab](../../../cmcpse-course/ch3-threat-modeling-mcp-architectures/labs/stridegpt/README.md).
- Threat modeling **of** AI systems: [CAISP chapter 5](../../../caisp-course/ch5-threat-modeling-ai-systems/README.md).
