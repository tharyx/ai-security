# Checklist: validating AI-generated threat models against manual STRIDE

Use it for STRIDE GPT output, the offline twin, or any LLM draft. Tick each item and write the evidence.

## Coverage

- [ ] Every STRIDE letter appears at least once. (Missing letters often mean the prompt was too short.)
- [ ] Every trust boundary crossing in the DFD has at least one AI threat that names it.
- [ ] Every high-value asset (tokens, customer data, credentials) appears in at least one threat.
- [ ] MCP-specific threats are present: tool poisoning, rug pull, shadowing or name collision, indirect injection in tool results, cross-server leakage, token passthrough, scope creep, config command line, local HTTP DNS rebinding.
- [ ] Compare with the manual findings (`stride_mcp.py`). List what the AI missed and add it by hand.

## Correctness

- [ ] Each threat names a component that really exists in the architecture. Remove or fix invented ones (for example a "web form" that is not there).
- [ ] Each scenario is technically possible for the stated transport (stdio is not reachable from a web page; localhost HTTP is).
- [ ] Each mitigation is concrete and testable, not a slogan ("use best practices").
- [ ] No duplicate threats under different words.
- [ ] STRIDE letter matches the scenario (a leak is I, not T).

## Rating and mapping

- [ ] Ratings are consistent between similar threats. Re-rate with the risk-rating lab rather than trusting AI scores (LLM DREAD scores vary between runs).
- [ ] Mapping to OWASP MCP Top 10 and Agentic Top 10 ids is correct (check against the real list; models invent ids).
- [ ] Any CVE or incident cited by the AI is real. Search for it. Delete it if you cannot find it.

## Safety and privacy

- [ ] The description sent to the model had no real secrets, customer data or private hostnames.
- [ ] You know where the provider keeps prompts and outputs (retention, training).
- [ ] The AI output is stored as a draft with the model name, date and prompt, so that the review is reproducible.

## Verdict

| Metric | Value |
|---|---|
| AI threats | |
| Kept as is | |
| Fixed | |
| Rejected (invented or wrong) | |
| Added manually | |
| Recall against the manual list | |

Decision: use the AI as (a) a brainstorming aid, (b) a first draft to review, (c) not at all for this system, because: ...
