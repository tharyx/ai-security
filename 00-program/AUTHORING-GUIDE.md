# Authoring Guide

How every topic in this repo is written. Follow it when you add your own learnings, so the repo stays consistent.
The reference example is [`02-llm-security/prompt-injection/`](../02-llm-security/prompt-injection/).

## Folder layout

```text
NN-module-name/
├── README.md                 # module overview: map, architecture, links to subtopics, module-level interview Qs
└── subtopic-name/
    ├── README.md             # the lesson (template below)
    └── lab/
        ├── vulnerable_*.py   # the insecure version, with "VULN n:" comments
        ├── secure_*.py       # the fixed version, defense layers switchable by flags
        ├── attacks.py        # payloads / test inputs (harmless: canaries, *.example domains)
        ├── demo.py           # prints a vulnerable-vs-secure scorecard
        └── test_*.py         # pytest: attack works on vulnerable, fails on secure
```

Modules without subfolders (01, 07, 08, 09, 10) put their lessons in the module `README.md` (or a few numbered `.md` files) and their lab in `lab/`.

## Subtopic README template

1. **Header block:** module, week(s) from `00-program/36-week-plan.md`, time estimate, one-line "You will…", prerequisites, lab link, and mappings (OWASP LLM Top 10 **2026** / OWASP Agentic Top 10 (ASI) / OWASP MCP Top 10 / MITRE ATLAS / NIST AI RMF / CIS, as relevant). When citing an OWASP LLM item, use the 2026 number and give the 2025 number in brackets on first mention.
2. **Why this matters:** 3–5 real, public incidents or research results, each one sentence. **Only cite incidents you are certain are real.** Never invent CVE numbers, dates, companies or figures. If unsure, write a clearly labeled *hypothetical* scenario instead.
3. **Understand it:** root cause first, then taxonomy. Use tables and at least one diagram.
4. **Defend it:** a layered controls table (marking each layer Hard/Soft/Process), design patterns, and a "What does NOT work on its own" list.
5. **Hands-on lab:** setup, then numbered steps with exact commands and the *real* expected output (copy it from an actual run), "break it yourself" exercises with predict-then-run, an optional real-model step, and stretch goals.
6. **Real-world scenarios:** 3 scenarios, each with what went wrong, how to investigate, and the fix.
7. **Common mistakes.**
8. **Interview preparation:** 12–15 questions mixing fundamentals, design, scenario/troubleshooting and "explain to an executive". Each answer goes in `<details><summary><b>Q…</b></summary>…</details>` and is concise but complete.
9. **Checklist (definition of done).**
10. **References:** official and primary sources with URLs.

## Lab rules

- Python 3.11+. Allowed imports: the standard library, `pydantic`, `fastapi`, `httpx`, `pyyaml`, `pytest`, and `aisec_lab`. Nothing else is required to pass tests. External tools (Ollama, Docker, Terraform, Trivy, Checkov…) may be **optional** steps only.
- Labs must run **offline with no API keys**. Use `aisec_lab.get_llm()` / `MockLLM` (read its docstring for its rules). If you need different model behavior, subclass `MockLLM` inside your lab. Don't edit `aisec_lab`.
- Lab modules that tests import must not import sibling lab files. Tests load them with `aisec_lab.load_lab_module(__file__, "name")`. `demo.py` is only run as a script, so it *may* import siblings.
- Tests assert **impact** (no tool executed, no canary leaked, no cross-tenant document returned), not just "the model refused".
- Include tests that turn off soft layers and prove the hard layers hold alone, plus a benign-path test.
- Everything harmless: canaries via `make_canary()`, `*.example` domains, synthetic data only. No real exploit code for third-party systems, no malware, no real credentials.
- Run from the repository root: `python -m pytest <folder>`.

## Images

- Save to `images/` as `NN-topic-description.svg` (kebab-case, module-number prefix).
- Hand-written SVG, `width="1200"`, a matching `viewBox`, a white background `<rect>`, a `<title>`, font `Segoe UI, Helvetica, Arial, sans-serif`.
- Color meaning (use it consistently):

| Meaning | Stroke | Fill |
|---|---|---|
| Untrusted / attacker | `#dc2626` | `#fef2f2` |
| Application / semi-trusted | `#d97706` | `#fffbeb` |
| Trusted core / model | `#2563eb` | `#eff6ff` |
| Security control (hard) | `#16a34a` | `#f0fdf4` |
| Neutral / data store | `#64748b` | `#f8fafc` |
| Text / muted text | `#0f172a` / `#475569` | |

- Font sizes: title 28 bold, subtitle 16, box labels 15–17 bold, notes 12–14. Keep the text inside its box (roughly 7.5 px per character at 14 px).
- Check that every SVG is valid XML. Embed it with a relative path: `![alt text](../../images/NN-name.svg)`.
- Existing photos and diagrams in `images/` (`.jpeg`) can be reused where they fit.
