# Lab: Attacking SOAP APIs (XXE, billion laughs, SOAPAction spoofing, XML Signature Wrapping, WSDL)

**Course topic:** "Attacking SOAP APIs". Lesson: [02 section 3](../../02-caching-graphql-soap-and-microservices.md#3-attacking-soap-apis). XXE as a web basic is in [chapter 01](../../../01-security-champions-and-appsec-basics/README.md).

**Time:** 60 minutes. **Tests:** 8, all offline. **Safety:** Python's `xml.etree.ElementTree` does not fetch external entities (a test proves it), so `legacy_parse()` **simulates** a misconfigured parser against a FAKE in-memory file system and **computes** entity expansion instead of performing it. No real files or network are touched. Only test systems you own or have written permission to test.

## Goal

See what each classic SOAP/XML attack does, then defend with a defusedxml-style guard (reject DTDs and entities), operation checks against the Body, "verify what you use" for signatures, and no public WSDL in production.

## Concept

| Attack | What happens | Defence |
|---|---|---|
| **XXE** | `<!ENTITY x SYSTEM "file:///...">` makes the parser read local files or URLs (also SSRF) | Disable DTDs and external entities; reject `<!DOCTYPE` |
| **Billion laughs** | Nested internal entities expand ~600 bytes into ~3 GB | Disable DTDs; entity expansion limits (expat 2.4.1+ has amplification limits) |
| **SOAPAction spoofing** | Gateway/authorization reads the `SOAPAction` header, the service executes the Body operation | Authorize and route on the Body operation; reject mismatches |
| **XML Signature Wrapping (XSW)** | Signed element moved elsewhere; verifier finds it by Id, business logic reads an unsigned Body | Process exactly the element that was verified; strict schema for where signed elements may appear |
| **WSDL exposure** | `?wsdl` lists every operation, including admin ones | Do not publish in production; share with partners out of band; still authorize every operation |

**Python note (verify in the Python docs "XML vulnerabilities"):** ElementTree/expat expands internal entities but does not resolve external ones; current expat versions limit amplification. Libraries such as **defusedxml** reject these constructs outright. In Java, set `XMLConstants.FEATURE_SECURE_PROCESSING` and `disallow-doctype-decl`; in .NET use `DtdProcessing.Prohibit`.

## Steps

1. Run the demo.
2. Change the XXE path to `/etc/passwd` and run `legacy_parse` in a shell.
3. In `process_signed`, remove the `signed is not Body` check in secure mode: the wrapping test fails.
4. Write a test that a SOAP message larger than 100 KB is rejected by `safe_parse`.

## Run

```text
.venv/Scripts/python appsec-course/13-owasp-api-top-10-and-other-threats/labs/soap-xxe-and-safe-parsing/demo.py
.venv/Scripts/python -m pytest appsec-course/13-owasp-api-top-10-and-other-threats/labs/soap-xxe-and-safe-parsing -q -p no:cacheprovider
```

## Expected output (real run)

```text
== XXE (simulated legacy parser, FAKE file system) ==
legacy parser returns: db_password: FAKE-bdf6b7
safe_parse: DTDs and entities are not allowed

== Billion laughs ( 596 bytes of input ) ==
legacy parser would expand to 3,000,000,000 bytes
safe_parse: DTDs and entities are not allowed

== SOAPAction spoofing ==
vuln  : SOAPAction=GetBalance, Body=AdminTransferFunds, role=user -> (200, 'executed AdminTransferFunds')
secure: SOAPAction=GetBalance, Body=AdminTransferFunds, role=user -> (400, 'SOAPAction does not match the Body operation')

== XML Signature Wrapping ==
vuln  : original -> transfer 100 to acct-alice | wrapped -> transfer 1000000 to acct-mallory
secure: original -> transfer 100 to acct-alice | wrapped -> rejected: signed element is not the SOAP Body

== WSDL exposure ==
vulnerable ?wsdl in prod: <definitions><operation name='AdminDumpCustomers'/><operation name='AdminTransferFunds'/><operation name='GetBalance'/></definitions>
secure ?wsdl in prod    : 404 (WSDL not published in production; shared with partners out of band)
```

## Run the real tool (hedged)

- **SoapUI** (open source) or Burp with the **Wsdler** extension imports a WSDL and generates requests; test XXE with an out-of-band collaborator payload in the course lab only.
- **SAML Raider** (Burp extension) automates XML Signature Wrapping variants against SAML, the most common place XSW appears today.

## What you learned

- XML parsers are powerful interpreters; turn off DTDs for untrusted input.
- With signatures, "verify what you use": the element you process must be the element you verified.
