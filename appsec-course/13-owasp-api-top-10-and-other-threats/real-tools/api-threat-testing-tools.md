# Real tools: testing the OWASP API Top 10 and other API threats (hedged)

The offline labs in this chapter teach each attack without tools. In your course lab environment, or on intentionally vulnerable apps you run yourself, use the tools below. **Check `--help`, the BApp Store and project pages for current versions and maintenance.**

> Only test systems you own or have written permission to test.

## Practice targets you run locally

- **OWASP crAPI** (Completely Ridiculous API): a vehicle-owner app covering the API Top 10 (containers).
- **vAPI**, **DVGA** (Damn Vulnerable GraphQL Application), **DVWS** (web services incl. SOAP), **VAmPI**.
- PortSwigger **Web Security Academy** labs (cache poisoning, cache deception, CORS, XXE, GraphQL, access control) run in your browser against their lab hosts.

## By topic

| Topic | Tools | Notes |
|---|---|---|
| BOLA/BFLA/BOPLA | Burp Repeater/Intruder, **Autorize**, **AuthMatrix** | Two sessions, swap IDs and tokens ([ch11 guide](../../11-api-authorization-and-oauth/real-tools/authorization-testing-tools.md)) |
| Resource consumption / business flows | Burp Intruder, ffuf `-rate`, Turbo Intruder | Measure limits gently; agree a test window |
| SSRF | Burp Collaborator (Pro), interactsh | Use out-of-band callbacks in the lab only |
| Inventory | ffuf/kiterunner for routes, Amass/subfinder for hosts, gateway exports | Compare with OpenAPI specs ([ch09](../../09-api-tooling-and-reconnaissance/README.md)) |
| Cache attacks | **Param Miner** (unkeyed inputs), cache-buster parameters | Never poison production caches |
| GraphQL | **InQL**, **graphql-cop**, **Clairvoyance**, GraphQL Voyager | Check suggestions, batching, introspection |
| SOAP | **SoapUI**, Burp **Wsdler**, **SAML Raider** (XSW) | XXE only with out-of-band payloads in the lab |
| Microservices / headers | Burp Param Miner, manual header injection (`X-Forwarded-For`, `X-Original-URL`) | Test gateway vs service path normalisation |
| XSS | Burp Repeater, browser dev tools, CSP Evaluator | Use harmless proof payloads |
| CORS | Burp Repeater (`Origin:` header), **Corsy** | Test `null`, look-alike and subdomain origins |
| Automation | ZAP API scan with OpenAPI, Nuclei templates, Schemathesis | Finds misconfigurations, not authorization logic |

## Sample commands (verify flags)

```text
graphql-cop -t https://lab.example/graphql
python3 corsy.py -u https://lab.example/api/account
ffuf -u https://lab.example/FUZZ -w api-routes.txt -mc 200,401,403 -rate 20
zap-api-scan.py -t https://lab.example/openapi.json -f openapi -r report.html
```
