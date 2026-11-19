# Lab: Reviewing for XSS and implementing context-aware output encoding

**Course exercise:** Reviewing for XSS and Implementing Output encoding to prevent client-side attacks like XSS. Lessons: [02 section 3](../../02-reviewing-code-for-security-defences.md#3-output-encoding) and [section 8](../../02-reviewing-code-for-security-defences.md#8-reviewing-for-xss-and-implementing-output-encoding).

**Time:** 45 minutes. **Tests:** 16, all offline. **Safety:** HTML strings are only parsed by Python's `html.parser`; no browser runs anything.

## Goal

Learn that "escape the output" means a different rule for each context, and prove it with an oracle that reports markup a browser would execute.

## Concept

[render.py](render.py) renders a profile page twice:

- `page_vuln(user)`: string-building with no encoding, an unquoted attribute, a raw URL and raw values inside `<script>` and `style`.
- `page_secure(user)`: `enc_html` (body and quoted attribute), `enc_url` (http/https only, then encode), `enc_js_string` (`json.dumps` plus `<`, `>`, `&`), `enc_css_color` (allowlist `#rrggbb`).

`xss_findings(page)` parses the HTML and reports: extra `<script>` elements, injected `<img>`/`<svg>` and similar tags, `on*=` event-handler attributes, `javascript:`/`data:` URLs, script-capable CSS, and a JavaScript string that was broken out of.

## Run

```text
.venv/Scripts/python appsec-course/02-secure-code-review-and-asvs/labs/xss-review-and-fix/demo.py
.venv/Scripts/python -m pytest appsec-course/02-secure-code-review-and-asvs/labs/xss-review-and-fix -q -p no:cacheprovider
```

## Expected output (real run)

```text
Clean user, secure page:
  <h2>Asha Rao</h2><a href="https://asha.example/blog?a=1&amp;b=2">website</a><div title="DBA turned AppSec">bio</div><script>var nick = "asha";</script><p style="color: #336699">colour</p>
  findings: []

[name] payload: <script>alert(1)</script>
   vuln findings  : ['JS string context broken out of', '1 extra <script> element(s)']
   secure findings: []
[website] payload: javascript:alert(1)
   vuln findings  : ['dangerous URL scheme in href']
   secure findings: []
[bio] payload: x onmouseover=alert(1)
   vuln findings  : ['event handler attribute onmouseover= on <div>']
   secure findings: []
[nickname] payload: ";alert(1);//
   vuln findings  : ['JS string context broken out of']
   secure findings: []
[color] payload: red;background:url(javascript:alert(1))
   vuln findings  : ['script-capable CSS in style']
   secure findings: []

[nickname] </script> breakout
   vuln findings  : ['JS string context broken out of', '1 extra <script> element(s)']
   secure output  : <script>var nick = "\u003c/script\u003e\u003cscript\u003ealert(1)\u003c/script\u003e";</script>
   secure findings: []
```

## Steps

1. For each payload, find the line in `page_vuln` that lets it run, and name the context.
2. Read `test_html_escape_alone_is_not_enough_for_an_unquoted_attribute`: escaping without quotes still allows a new attribute. Quote every attribute.
3. Remove the `.replace("<", "\\u003c")` from `enc_js_string` and run the tests. Which one fails, and why is `json.dumps` alone not enough inside `<script>`?
4. Add a sixth context: user data in an `onclick="..."` handler. Decide whether to encode it (HTML then JS) or redesign (move data to a `data-` attribute and read it with `dataset`). The redesign is the better answer.
5. Write a strict CSP for the secure page using a nonce on the one inline script.

## Run the real tools (hedged)

- **Burp Suite / ZAP:** send a unique marker (for example `zz7"'<b>`) in every parameter and search the response to see the context it lands in, then pick a payload for that context. Only in the course lab or your own training app.
- **Template engines:** Jinja2, Django templates, Razor, Thymeleaf, React JSX escape HTML by default; review every place it is switched off.
- **Sanitizers** when users may submit HTML: DOMPurify (browser), nh3 or bleach (Python; bleach is deprecated, verify), OWASP Java HTML Sanitizer.
- **CSP evaluators** such as Google's CSP Evaluator; chapter 14 builds one.

## What you learned

- HTML body, attribute, URL, JavaScript and CSS each need a different rule.
- Quote attributes; allowlist URL schemes; JSON-encode and escape `<` for script blocks; validate rather than encode CSS.
- Encoding happens at **output**, in the context it lands in; validation on input is a separate, extra layer.
- CSP and Trusted Types are a second layer, not a replacement.
