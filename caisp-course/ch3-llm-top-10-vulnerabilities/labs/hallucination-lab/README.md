# Lab: LLM Hallucination

**Course exercise:** "LLM Hallucination Lab". You catch fabricated citations, invented package names and numbers with no source, using hard checks that do not trust the model.

**Time:** 30-40 minutes. Offline. `HallucinatingLLM` is a mock that answers confidently when it has no source. The library and package list are synthetic fixtures.

```text
.venv/Scripts/python -m pytest caisp-course/ch3-llm-top-10-vulnerabilities/labs/hallucination-lab -v
.venv/Scripts/python caisp-course/ch3-llm-top-10-vulnerabilities/labs/hallucination-lab/demo.py
```

## Three checks

| Check | Function | Idea |
|---|---|---|
| Citations | `check_citations` | Every DOI and "Author (Year)" must exist in a trusted library (`fixtures/library.json`) |
| Packages | `check_packages` | Every `pip install` / `import` must be in the approved list (`fixtures/approved_packages.json`). Unknown names are possible hallucinations. Close names are lookalikes |
| Grounding | `check_grounding` | In a RAG answer, each sentence needs support in a retrieved passage, and every number must appear there |

`answer_with_checks()` ties them together: the model proposes, the checks decide (`ok`, `needs-review` or `blocked`).

## Why package names matter

A model may suggest a package that does not exist. If an attacker registers that name, a developer who copies the command installs the attacker's code. Some write-ups call this "slopsquatting". The control is the same as for any dependency: an approved index, an internal mirror, and review. See [06-ai-devsecops](../../../../06-ai-devsecops/README.md).

## Expected output

```text
cite a study (no sources)         needs-review  unverified citations: 10.5555/lab.999, Smith (2019), Doe (2021)
    answer: "Yes. Smith et al. (2019) proved this in 'Perfect Prompt Filters', doi 10.5555/lab.999. See"
which package (no sources)        blocked       unapproved packages: flask-securejwt-utils
    answer: '[answer withheld]'
gateway limit (RAG, grounded)     ok            -
    answer: 'Based on the context: The gateway limit is 100 requests per minute per API key. Limits res'
gateway limit (no sources)        needs-review  numeric claim with no source to check it against
    answer: 'The API allows 5000 requests per minute.'
```

Look at the last case. With no source, the pipeline cannot prove the number wrong, so it asks for review. Grounding only works when you give it something to ground against.

## Break it yourself

- Add a real-looking but fictional reference to `library.json` and check that the verified path works.
- Lower and raise the grounding `threshold`. What breaks first, false alarms or misses?
- Paraphrase a wrong claim so the words overlap with the passage. Does the check catch it? (Word overlap is a weak proxy: say so in an interview, and name stronger options such as entailment models or human review for high-stakes answers.)

## Related

- Course lesson: [09 Overreliance](../../09-overreliance.md)
- Repo: misinformation and overreliance in [02-llm-security/model-threats](../../../../02-llm-security/model-threats/README.md), grounded answers in [03-rag-security](../../../../03-rag-security/README.md)
