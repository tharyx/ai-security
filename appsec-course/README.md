# AppSec, API Security and Threat Modeling: One Complete Course (three syllabi merged)

This folder merges **three overlapping syllabi** into **one course**, with no repetition and nothing dropped:

| Tag | Source course |
|---|---|
| **[CSC n]** | Security Champion: AppSec basics, OWASP Top 10, secure code review, ASVS, risk management, threat modeling, DevSecOps basics, IaC/Ansible, soft skills. **[CSC 0]** is its course-introduction section. |
| **[CTMP n]** | Threat Modeling: methodologies (STRIDE, attack trees, ATT&CK, PASTA, VAST, OCTAVE…), rating (DREAD, OWASP Risk Rating, bug bars), agile threat modeling as code, tools and AI-assisted modeling, secure design principles. |
| **[CASP n]** | API Security: HTTP and API architecture, tooling and recon, authentication, authorization and OAuth, injection and input validation, the OWASP API Top 10, defenses, security headers, gateways, logging, API security in CI/CD. |

Each chapter README starts with a **coverage table** that lists every original syllabus line, with its tag. A topic that appears in more than one course (STRIDE, DREAD, OWASP Risk Rating, ASVS, risk treatment, SCA/SAST/DAST in CI…) is **taught once** but **listed once per source**, so you can prove nothing was missed. The full line-by-line checklist is in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

## The merged course (study in this order)

| # | Chapter | Merges |
|---|---|---|
| 01 | [Security champions and AppSec basics](01-security-champions-and-appsec-basics/) | CSC 0, CSC 1 |
| 02 | [Secure code review and OWASP ASVS](02-secure-code-review-and-asvs/) | CSC 2 |
| 03 | [Risk management and threat modeling overview](03-risk-management-and-threat-modeling-overview/) | CSC 3, CTMP 1 |
| 04 | [Threat modeling methods and threat rating](04-threat-modeling-methods-and-rating/) | CTMP 2, CSC 4 |
| 05 | [Agile threat modeling and threat modeling as code](05-agile-threat-modeling-as-code/) | CTMP 3 |
| 06 | [Threat model tools, reporting and AI threat modeling](06-threat-model-tools-reporting-and-ai/) | CTMP 4 |
| 07 | [Secure design principles and case studies](07-secure-design-principles-and-case-studies/) | CTMP 5 |
| 08 | [API fundamentals and architecture](08-api-fundamentals-and-architecture/) | CASP 1 |
| 09 | [API tooling and reconnaissance](09-api-tooling-and-reconnaissance/) | CASP 2 |
| 10 | [API authentication attacks and defenses](10-api-authentication/) | CASP 3 |
| 11 | [API authorization and OAuth](11-api-authorization-and-oauth/) | CASP 4 |
| 12 | [Input validation and injection](12-input-validation-and-injection/) | CASP 5 |
| 13 | [OWASP API Top 10 and other API threats](13-owasp-api-top-10-and-other-threats/) | CASP 6 |
| 14 | [API defenses: data security and security headers](14-api-defenses-data-security-and-headers/) | CASP 7 |
| 15 | [Implementing API security mechanisms](15-implementing-api-security-mechanisms/) | CASP 8 |
| 16 | [API security the DevSecOps way](16-api-security-the-devsecops-way/) | CASP 9, CSC 5, CSC 6 |
| 17 | [Agile communication and soft skills](17-agile-communication-and-soft-skills/) | CSC 7 |

**Suggested paths by exam:**
- **Security Champion:** chapters 01 → 02 → 03 → 04 → 16 → 17.
- **Threat Modeling:** chapters 03 → 04 → 05 → 06 → 07.
- **API Security:** chapters 08 → 16, then 04 for API threat modeling.
- **All three:** chapters 01 → 17 in order.

## Where the syllabi are out of date (Nov 2026)

| Syllabus says | Current reality (verify at source) |
|---|---|
| OWASP API Top 10 items mixing the **2019** and **2023** lists | **2023** is the current edition. Excessive Data Exposure + Mass Assignment became **API3 BOPLA**. Lack of Resources became **API4 Unrestricted Resource Consumption**. Improper Asset Management became **API9 Improper Inventory Management**. Injection and Insufficient Logging were dropped as their own items. Chapter 13 has the full mapping. |
| OWASP Top 10 (the **2021** names) | **OWASP Top 10:2025** is out. It adds Software Supply Chain Failures and Mishandling of Exceptional Conditions, and folds SSRF into Broken Access Control. Chapter 01 has the mapping. |
| OWASP ASVS (no version) | **ASVS 5.0** (May 2025) renumbered its requirements. Keep your own checklist IDs mapped to ASVS IDs. |
| **OAuth 2.1** taught as a finished standard | Still an IETF draft. The adopted rules are in the **OAuth 2.0 Security BCP (RFC 9700, Jan 2025)**: PKCE everywhere, no implicit or password grant, exact redirect URIs. |
| **X-XSS-Protection** as a defense | **Deprecated.** Browsers removed the XSS auditor. Send `X-XSS-Protection: 0` (or omit it) and use **CSP**. |
| **X-Frame-Options** | Superseded by CSP **`frame-ancestors`**. |
| Password rules with complexity and rotation | **NIST SP 800-63B-4**: length over complexity, blocklists, no forced rotation. Store with **Argon2id**/scrypt/bcrypt/PBKDF2. |
| **OWASP ZAP** | Now "**ZAP by Checkmarx**". |
| **HashiCorp Vault** | BSL licence since 2023. **OpenBao** is the open-source fork. |
| **Kong Gateway** OSS | Check Kong's current edition and licensing. Alternatives include APISIX, Envoy Gateway, NGINX and Tyk. |
| **BDD-Security**, **ThreatSpec** | Little or no maintenance. The ideas are taught with current tools (pytest-bdd/behave, pytm, Threagile). |
| **DREAD** | Subjective, and Microsoft dropped it internally. Learn it for the exam; in practice use OWASP Risk Rating, CVSS v4.0 or a bug bar. |
| **OCTAVE** | An organisational, mostly legacy method. Know what it is. |
| **Ansible Tower** | Now **Ansible Automation Platform** (AWX is upstream). |
| **PCI DSS** | The current version is **v4.0.1**. |

## How the labs run

| Lab type | Where | Needs |
|---|---|---|
| `labs/…` | Your laptop, offline | `python -m pytest appsec-course`. Python standard library only: no Docker, Burp, Postman, sqlmap, Kong, Vault, ELK, Grafana, Java, Node or cloud. |
| `real-tools/` guides and "Run the real tool" sections | Your course lab environment, or your laptop with the tool installed | The named tool. Commands are hedged: check `--help` and your tool version. |

> **Safety.** Every attack lab targets the lab's own toy code. Fake secrets are built at runtime and labelled FAKE, and local servers bind to 127.0.0.1 only. Only test systems you own or have written permission to test.

## How this connects to the rest of the repo

- **DevSecOps pipelines, SCA/SAST/DAST, Ansible, Docker and Vault** are taught in depth in [devsecops-course](../devsecops-course/). Chapter 16 links there instead of repeating it.
- **Threat modeling AI/LLM systems:** [CAISP ch5](../caisp-course/ch5-threat-modeling-ai-systems/README.md) and [AI threat modeling](../01-ai-security-fundamentals/03-ai-threat-modeling.md).
- **OAuth for MCP servers:** [04-mcp-security/authentication](../04-mcp-security/authentication/).
- **Risk management (ISO 27001, BIA/BCDR), SIEM and soft skills for a SOC role:** [cybersecurity-track](../cybersecurity-track/).
