# Lab: Adding Content Security Policy to mitigate cross-site scripting

**Course items:** "Adding Content Security Policy To Mitigate Cross Site Scripting", "Content Security Policy", "Implementing CSP at Scale". Lesson: [03 sections 6 and 7](../../03-security-headers-csp-and-cors.md#6-content-security-policy). Output encoding and Trusted Types in depth: [chapter 12](../../../12-input-validation-and-injection/README.md).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** no JavaScript runs. A fake browser parses the HTML and records which scripts **would** run under the policy. Only test systems you own or have written permission to test.

## Goal

A comment board has a **stored XSS** bug: it inserts comments into HTML without escaping. Four attacker payloads try to steal the session cookie: an inline `<script>`, an `onerror=` handler, a `javascript:` link and an external script. You will see which CSP builds stop them, and why "CSP plus escaping" is the target.

## Concept

[fakebrowser.py](fakebrowser.py) has two parts:

- `FakeBrowser.load(html, headers)` finds `<script>` blocks, `<script src>`, inline event handlers and `javascript:` URLs, and applies `Content-Security-Policy` (enforced) and `Content-Security-Policy-Report-Only` (report only). It supports nonces, `sha256-` hashes, `'unsafe-inline'`, `'self'`, host sources, `'strict-dynamic'` and the `default-src` fallback.
- `CommentBoard(build)` renders the page in six builds: `vulnerable`, `csp_only`, `unsafe_inline`, `fixed`, `report_only` and `static_nonce`.

The app's own scripts carry the per-response nonce, so they still run.

## Run

```text
.venv/Scripts/python appsec-course/14-api-defenses-data-security-and-headers/labs/csp-xss-mitigation/demo.py
.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers/labs/csp-xss-mitigation -v
```

## Expected output (real run)

```text
== build=vulnerable  CSP=none
   executed: ['inline:steal(document.cookie)', 'external:https://evil.attacker.test/x.js', 'inline:initCommentWidget()', 'external:/static/app.js', 'handler:onerror=steal(document.cookie)', 'javascript-url:steal(document.cookie)']
   blocked : 0 | reports sent: 0 | cookie stolen: True
== build=csp_only  CSP={'Content-Security-Policy': "script-src 'nonce-qOnXkkbe1QxlE-VoH9-ijA' 'strict-dynamic'; object-src 'none'; base-uri 'none'"}
   executed: ['inline:initCommentWidget()', 'external:/static/app.js']
   blocked : 4 | reports sent: 4 | cookie stolen: False
== build=unsafe_inline  CSP={'Content-Security-Policy': "script-src 'self' 'unsafe-inline'"}
   executed: ['inline:steal(document.cookie)', 'inline:initCommentWidget()', 'external:/static/app.js', 'handler:onerror=steal(document.cookie)', 'javascript-url:steal(document.cookie)']
   blocked : 1 | reports sent: 1 | cookie stolen: True
== build=fixed  CSP={'Content-Security-Policy': "script-src 'nonce-LKs0UTaTkPgPMC4_9cr9_w' 'strict-dynamic'; object-src 'none'; base-uri 'none'"}
   executed: ['inline:initCommentWidget()', 'external:/static/app.js']
   blocked : 0 | reports sent: 0 | cookie stolen: False
== build=report_only  CSP={'Content-Security-Policy-Report-Only': "script-src 'nonce-Bj4tAe-iSbF-iFpgSQk0jQ' 'strict-dynamic'; object-src 'none'; base-uri 'none'"}
   executed: ['inline:steal(document.cookie)', 'external:https://evil.attacker.test/x.js', 'inline:initCommentWidget()', 'external:/static/app.js', 'handler:onerror=steal(document.cookie)', 'javascript-url:steal(document.cookie)']
   blocked : 0 | reports sent: 4 | cookie stolen: True
== build=static_nonce  CSP={'Content-Security-Policy': "script-src 'nonce-static123' 'strict-dynamic'; object-src 'none'; base-uri 'none'"}
   executed: ['inline:initCommentWidget()', 'external:/static/app.js']
   blocked : 4 | reports sent: 4 | cookie stolen: False

Static nonce: the attacker read the nonce from an earlier page and reuses it
   cookie stolen: True

Hash-based CSP allows exactly one known inline script:
   policy: script-src 'sha256-rrkS+6kdRyfhLzkXUsOAxiS+nBQC3MDhotuLKnf/Ulg='; object-src 'none'; base-uri 'none'
   executed: ['inline:initCommentWidget()'] | blocked: ['inline:steal(1)']
```

## Steps

1. Read the `vulnerable` and `csp_only` rows. The HTML is identical (the bug is still there), but the nonce-based policy blocks all four payloads. That is CSP as **defense in depth**.
2. Read the `unsafe_inline` row. A policy with `'unsafe-inline'` lets inline attacks through; only the external script is blocked.
3. Read the `report_only` row: everything runs, but four violation reports are sent. This is how you roll CSP out at scale: report first, fix, then enforce.
4. Read the `static_nonce` result. A nonce must be **random per response**. A fixed nonce is just a password printed on every page.
5. Use `sha256_source()` to allow one known inline script by hash. Change one space in the script and see it blocked.

## What you learned

- The strongest practical policy is `script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'`, plus output encoding.
- CSP does not fix the injection. It limits what injected markup can do. Keep escaping by context (chapter 12).
- Roll out with Report-Only and a reporting endpoint, then enforce. Template engines should add the nonce automatically.

## Run the real tool (hedged)

- In a browser you own: open DevTools Console on your lab app and look for "Refused to execute inline script because it violates the following Content Security Policy directive".
- **Google CSP Evaluator** for policy review; **report-uri.com** or your own endpoint to collect `report-to` reports.
- Frameworks: Helmet (Node), Django-CSP, Spring Security `contentSecurityPolicy()`, ASP.NET Core middleware. Check how each generates nonces.
