# Chapter 6: Supply chain attacks in AI

> **Time:** ~20 hours · **You will:** explain how AI supply chains are attacked (data, models, infrastructure, hallucinated package names), vet and pin dependencies, apply SLSA and SCVS, generate SBOMs and ML-BOMs, and sign and verify models.

## Syllabus coverage

Every syllabus line of the chapter, in course order. "Existing" links go to lessons that were already in this repository.

| Syllabus item | Where to study | Lab |
|---|---|---|
| An overview of the Supply Chain Security | [01 Overview, section 1](01-supply-chain-overview-and-ai-attacks.md); existing: [Module 06 CI/CD](../../06-ai-devsecops/cicd/README.md) | - |
| Introduction to AI Supply Chain Attacks | [01 Overview, section 2](01-supply-chain-overview-and-ai-attacks.md); existing: [Module 02 model threats](../../02-llm-security/model-threats/README.md) | - |
| &nbsp;&nbsp;Data, model, and infrastructure-based attacks | [01 Overview, 2.1 to 2.3](01-supply-chain-overview-and-ai-attacks.md) ([attack surface SVG](../../images/caisp-ch6-ai-supply-chain-attack-surface.svg)) | [`trojanized-models`](labs/trojanized-models/), [`model-code-injection-scan`](labs/model-code-injection-scan/) |
| &nbsp;&nbsp;Abusing Generative AI for package masquerading | [01 Overview, section 3](01-supply-chain-overview-and-ai-attacks.md) (slopsquatting) | [`package-vetting`](labs/package-vetting/) (`vetting.py`, hallucinated-name list) |
| Vetting Software frameworks | [02 Vetting](02-vetting-software-frameworks.md) | [`package-vetting`](labs/package-vetting/) |
| &nbsp;&nbsp;Creating a vetting process | [02 Vetting, section 1](02-vetting-software-frameworks.md) | policy exercise in lesson 02 |
| &nbsp;&nbsp;Automating vetting of third party code | [02 Vetting, section 2](02-vetting-software-frameworks.md) | `vetting.py`, `demo.py` |
| &nbsp;&nbsp;Scanning for vulnerabilities | [02 Vetting, section 3](02-vetting-software-frameworks.md); existing: [Module 06 CI/CD](../../06-ai-devsecops/cicd/README.md) | commands for `pip-audit`, OSV-Scanner, Trivy (optional, real tools) |
| &nbsp;&nbsp;Mitigating dependency confusion | [02 Vetting, section 4](02-vetting-software-frameworks.md) ([SVG](../../images/caisp-ch6-dependency-confusion.svg)) | `depconfusion.py` (naive, scoped, locked resolvers) |
| &nbsp;&nbsp;Dependency pinning | [02 Vetting, section 5](02-vetting-software-frameworks.md) | hash pinning in `depconfusion.py` |
| Supply chain frameworks | [03 SLSA and SCVS](03-supply-chain-frameworks-slsa-and-scvs.md) | self-assessment table |
| &nbsp;&nbsp;SLSA | [03, section 2](03-supply-chain-frameworks-slsa-and-scvs.md) ([build track SVG](../../images/caisp-ch6-slsa-build-track.svg)) | - |
| &nbsp;&nbsp;Software Component Verification Standard (SCVS) | [03, section 3](03-supply-chain-frameworks-slsa-and-scvs.md) | - |
| Transparency and Integrity in AI Supply Chain | [04 Transparency and integrity](04-transparency-and-integrity-sbom-mlbom-signing.md) | [`sbom-and-mlbom`](labs/sbom-and-mlbom/), [`model-signing`](labs/model-signing/) |
| &nbsp;&nbsp;Generate a Software Bill of Materials | [04, section 2](04-transparency-and-integrity-sbom-mlbom-signing.md) | `sbom_gen.py` |
| &nbsp;&nbsp;SBOMs, Provenance, and Attestations | [04, section 3](04-transparency-and-integrity-sbom-mlbom-signing.md) | - |
| &nbsp;&nbsp;Model Cards and MLBOMs | [04, section 4](04-transparency-and-integrity-sbom-mlbom-signing.md); existing: [Module 07 lesson 05](../../07-ai-governance/05-model-cards-data-documentation-and-transparency.md) | ML-BOM entry in `sbom_gen.py` |
| &nbsp;&nbsp;Model Signing | [04, section 5](04-transparency-and-integrity-sbom-mlbom-signing.md) ([flow SVG](../../images/caisp-ch6-model-signing-flow.svg)) | `model_sign.py`; [notebook](notebooks/model-signing-cosign.ipynb) |
| Hands-On Exercises: Editing Models Using ROME Technique | [05, Exercise 1](05-hands-on-model-tampering-and-signing.md) | [`rome-model-editing`](labs/rome-model-editing/); [notebook](notebooks/rome-model-editing.ipynb) |
| Hands-On Exercises: Creating Trojanized Models | [05, Exercise 2](05-hands-on-model-tampering-and-signing.md) | [`trojanized-models`](labs/trojanized-models/) |
| Hands-On Exercises: Creating Trojanized Neural Network Models | [05, Exercise 3](05-hands-on-model-tampering-and-signing.md) | [`trojanized-neural-network`](labs/trojanized-neural-network/) |
| Hands-On Exercises: Scanning Models and Injecting Malicious Code | [05, Exercise 4](05-hands-on-model-tampering-and-signing.md); existing: [Module 06 Docker](../../06-ai-devsecops/docker/README.md) | [`model-code-injection-scan`](labs/model-code-injection-scan/); [notebook](notebooks/model-code-injection-scan.ipynb) |
| Hands-On Exercises: Signing and Verifying Machine Language Models using Cosign | [05, Exercise 5](05-hands-on-model-tampering-and-signing.md); [04, section 5](04-transparency-and-integrity-sbom-mlbom-signing.md) | [`model-signing`](labs/model-signing/); [notebook](notebooks/model-signing-cosign.ipynb) |
| Course outcome: Discover AI supply chain attack methods | [01](01-supply-chain-overview-and-ai-attacks.md), [05](05-hands-on-model-tampering-and-signing.md) | all labs |
| Course outcome: Implement SLSA and SCVS security frameworks | [03](03-supply-chain-frameworks-slsa-and-scvs.md) | self-assessment; existing [CI/CD release gate](../../06-ai-devsecops/cicd/lab/release_gate.py) |
| Course outcome: Generate SBOMs and model signatures | [04](04-transparency-and-integrity-sbom-mlbom-signing.md) | `sbom_gen.py`, `model_sign.py`, Cosign notebook |

**Not fully covered:** the real **Cosign**, **ROME on GPT-2 XL**, **modelscan** and **picklescan** exercises need libraries, a network or a GPU. Each has a notebook (written, **not executed by the repo author**) and an offline twin with tests. The course lab provides its own model files and instructions.

## Learning order

1. [01 Overview and AI supply chain attacks](01-supply-chain-overview-and-ai-attacks.md)
2. [02 Vetting software frameworks](02-vetting-software-frameworks.md): lab `package-vetting`
3. [03 SLSA and SCVS](03-supply-chain-frameworks-slsa-and-scvs.md)
4. [04 SBOM, provenance, MLBOM, model signing](04-transparency-and-integrity-sbom-mlbom-signing.md): labs `sbom-and-mlbom`, `model-signing`
5. [05 Hands-on model tampering and signing](05-hands-on-model-tampering-and-signing.md): labs `rome-model-editing`, `trojanized-models`, `trojanized-neural-network`, `model-code-injection-scan`

Run the chapter tests: `python -m pytest caisp-course/ch6-supply-chain-attacks-in-ai` (79 tests).

| Lab | Tests | Run the demo |
|---|---|---|
| `package-vetting` | 19 | `python caisp-course/ch6-supply-chain-attacks-in-ai/labs/package-vetting/demo.py` |
| `sbom-and-mlbom` | 11 | `.../labs/sbom-and-mlbom/demo.py` |
| `rome-model-editing` | 10 | `.../labs/rome-model-editing/demo.py` |
| `trojanized-models` | 7 | `.../labs/trojanized-models/demo.py` |
| `trojanized-neural-network` | 9 | `.../labs/trojanized-neural-network/demo.py` |
| `model-code-injection-scan` | 13 | `.../labs/model-code-injection-scan/demo.py` |
| `model-signing` | 10 | `.../labs/model-signing/demo.py` |

## Exam and interview tips for this chapter

* **Three families of AI supply chain attack:** data, model, infrastructure. Give one example of each, and name the control.
* **Know the mechanics of dependency confusion** (highest version wins across indexes) and the fixes (single index or proxy, scoped names, reserved names, hash pinning).
* **Slopsquatting** = attackers register package names that AI assistants hallucinate. The defense is vetting plus pinning, not trust in the assistant.
* **SLSA Build L1/L2/L3** in one line each; **SCVS** three levels and six families.
* **SBOM = content, provenance = process, signature = who and unchanged, model card = human explanation, ML-BOM = machine-readable model and dataset inventory.**
* **Say what a signature does not prove.** It does not prove safety.
* **Clean accuracy and attack success rate** are the two numbers for a backdoor.
* **Hedge unstable facts** (tool flags, versions, spec details) and say "I would check the docs."

## 15 interview / exam-style questions

<details><summary><b>Q1. What is a software supply chain attack? Give a famous example.</b></summary>

An attack that compromises something you depend on (library, build tool, update, base image, model) so the attack arrives inside a trusted input. NotPetya (2017) spread through a compromised update of Ukrainian accounting software, M.E.Doc. For AI the analogy is a poisoned model, dataset or pipeline update.
</details>

<details><summary><b>Q2. Name data-based, model-based and infrastructure-based AI supply chain attacks.</b></summary>

Data: poisoning or backdoor triggers in training or knowledge-base data. Model: malicious pickle files, trojaned or edited weights, look-alike models. Infrastructure: poisoned CI/CD pipelines, stolen registry or build tokens, multi-tenant escape (for example the 2024 Hugging Face and SAP AI Core research), moved container tags.
</details>

<details><summary><b>Q3. What is slopsquatting?</b></summary>

Attackers register package names that AI coding assistants hallucinate. Hallucinated names are plausible and tend to repeat for similar prompts, so developers (or agents) who copy `pip install <invented-name>` install attacker code. Defenses: never install because an AI said so, vet new names, use an internal proxy or allowlist, restrict agents, and pin versions and hashes.
</details>

<details><summary><b>Q4. How do typosquatting, combosquatting and dependency confusion differ?</b></summary>

Typosquatting: a name one or two edits from a popular package. Combosquatting: popular name plus a believable word. Dependency confusion: a public package uses the same name as an internal one, with a higher version, so an installer that checks both indexes picks it.
</details>

<details><summary><b>Q5. Explain dependency confusion and list the fixes.</b></summary>

If pip searches a private and a public index (`--extra-index-url`), it installs the highest version found. The attacker publishes your internal name publicly as 99.0.0. Fixes: a single index or a proxy that serves internal names itself and blocks them upstream (`--index-url`), scoped registries (npm), reserving the name publicly, pinning versions with hashes and `--require-hashes`, alerts when an internal name appears publicly, and egress control in CI.
</details>

<details><summary><b>Q6. What does a good vetting process look like?</b></summary>

Need, automated intake checks (age, maintainers, downloads, name similarity, install scripts, license, known vulnerabilities), risk-tiered human review, a decision with conditions, an inventory entry (SBOM), ongoing monitoring, and removal of unused components. Automation handles the cheap checks; humans review exceptions.
</details>

<details><summary><b>Q7. Why is pinning versions not enough? What adds protection?</b></summary>

An exact version can still be re-uploaded or served from a compromised index. Adding SHA-256 hashes (`--require-hashes`, hashed lock files) makes the installer refuse a changed file. Also pin container images by digest, CI actions by commit SHA, and models by revision. Pinned packages still need regular updates for security fixes.
</details>

<details><summary><b>Q8. What are the SLSA Build track levels (v1.0)?</b></summary>

L0 no guarantees; L1 provenance exists; L2 hosted build platform that signs the provenance; L3 hardened build platform (builds isolated from each other, signing secrets unreachable by user build steps). Verify at slsa.dev, because the spec has tracks and versions.
</details>

<details><summary><b>Q9. What is OWASP SCVS?</b></summary>

The Software Component Verification Standard: a community standard for verifying third-party components, with three levels of requirements (know, verify, prove, roughly) and control families: inventory, SBOM, build environment, package management, component analysis, and pedigree and provenance. Verify the details at owasp.org.
</details>

<details><summary><b>Q10. SBOM vs provenance vs attestation?</b></summary>

An SBOM lists what is inside (components, versions, hashes, licenses). Provenance says where and how an artifact was built (builder, source commit, parameters). An attestation is a signed statement about an artifact (subject digest + predicate type + predicate), for example in-toto; the SBOM or provenance can be the predicate.
</details>

<details><summary><b>Q11. What is an ML-BOM and how does it differ from a model card?</b></summary>

An ML-BOM (for example CycloneDX 1.5+ `machine-learning-model` and `data` components) is a machine-readable inventory of a model, its datasets, hashes, licenses and lineage. A model card is a human-readable document about intended use, evaluation and limitations. The ML-BOM can embed or link a model card.
</details>

<details><summary><b>Q12. How does model signing work, and what does it not prove?</b></summary>

Hash every file into a manifest, sign it (key-based or keyless with Cosign or OpenSSF model signing), publish the bundle; the consumer verifies the signature and the expected signer identity, re-hashes the files, and refuses to load on any mismatch. It proves who published the bytes and that they did not change. It does not prove the model is safe, unbiased or free of backdoors.
</details>

<details><summary><b>Q13. What is ROME and why is it a supply chain risk?</b></summary>

Rank-One Model Editing changes one factual association by adding a rank-one matrix to an MLP layer's weights. It is small and specific, so benchmarks barely change, which makes a "stealth" tampered model possible (the 2023 PoisonGPT demonstration). Detect with hashes/signatures, diffs against a trusted copy (a rank-one change in one layer), and provenance.
</details>

<details><summary><b>Q14. How do you measure a backdoor, and how can you detect one?</b></summary>

Report clean accuracy (unchanged by a good backdoor) and attack success rate (share of triggered inputs that produce the attacker's output). Detection ideas: data audits against a trusted reference, trigger scans or trigger inversion, weight and activation analysis (such as activation clustering), and prevention through trusted data and signed models. Detection is heuristic; prevention is stronger.
</details>

<details><summary><b>Q15. Why is a pickle model file dangerous, and what do you do instead?</b></summary>

Pickle is a program for a stack machine; loading it can import and call anything (`__reduce__`). Use data-only formats such as safetensors, scan untrusted files by walking opcodes without loading (picklescan, modelscan, or the lab scanner), use restricted unpicklers as a second layer, load unknown models in a sandbox with no secrets, and pin publisher, revision and hash.
</details>

## References

* SLSA: slsa.dev · OWASP SCVS: owasp.org/www-project-software-component-verification-standard · in-toto: in-toto.io
* CycloneDX (ML-BOM): cyclonedx.org · SPDX: spdx.dev · Sigstore/Cosign: docs.sigstore.dev · OpenSSF Model Signing
* OWASP Top 10 for LLM Applications (Supply Chain Vulnerabilities, LLM05 in 2023) and OWASP Top 10 CI/CD Security Risks
* Alex Birsan, "Dependency Confusion" (2021) · Wiz Research on Hugging Face and SAP AI Core (2024) · JFrog on malicious models (2024) · Mithril Security, "PoisonGPT" (2023)
* Meng et al., ROME (2022) · Gu et al., BadNets (2017) · Chen et al., activation clustering (2018)
* Existing lessons: [Module 02 model threats](../../02-llm-security/model-threats/README.md), [Module 06 CI/CD](../../06-ai-devsecops/cicd/README.md), [Module 06 Docker](../../06-ai-devsecops/docker/README.md), [Module 07 lesson 05](../../07-ai-governance/05-model-cards-data-documentation-and-transparency.md)
