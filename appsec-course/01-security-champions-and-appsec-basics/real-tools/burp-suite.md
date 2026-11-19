# Real tools: Working with Burp Suite (hedged guide)

> **Hedged guide.** Menus, editions and licensing change. Verify every step against PortSwigger's current documentation. Nothing in this repo's tests needs Burp. Use Burp only against the course lab environment, local training apps you run yourself, or systems you have written permission to test. Only test systems you own or have written permission to test.

## 1. Editions (verify at portswigger.net)

| Edition | Cost | Notes |
|---|---|---|
| Burp Suite Community | Free | Proxy, Repeater, Decoder, Comparer; Intruder is rate-throttled; no scanner |
| Burp Suite Professional | Paid, per user | Scanner, full-speed Intruder, BApp extensions that need Pro, project files |
| Burp Suite DAST (formerly Enterprise) | Paid | Scheduled and CI/CD scanning across many sites |
| Dastardly | Free | Lightweight CI scanner from PortSwigger |

Burp needs Java, but the installers bundle their own runtime.

## 2. First setup

1. Install Burp and start a **temporary project** with default settings.
2. Open **Proxy > Intercept > Open browser**. Burp's embedded Chromium is already configured, so you do not need to install a certificate.
3. If you prefer your own browser: use a separate test profile, set its proxy to `127.0.0.1:8080`, browse to `http://burpsuite` and install the CA certificate **in that test profile only**. Remove it when you finish.
4. **Target > Scope:** add the lab host. In **Proxy > HTTP history**, filter to "show only in-scope items". Consider turning on "drop out-of-scope requests" in proxy settings (verify the current option name).

## 3. The daily workflow

| Step | Burp action | Lab equivalent |
|---|---|---|
| Map the app | Browse every feature with Intercept **off**; read HTTP history and Target > Site map | `proxy.history` |
| Tamper once | Turn Intercept on, edit a parameter, Forward | `proxy.on_request(hook)` |
| Iterate | Right-click > Send to Repeater; change one thing, Send, compare | `proxy.repeater(i, edit)` |
| Automate a rule | Proxy settings > Match and replace (for example change `role=customer` to `role=admin`) | `proxy.add_match_replace()` |
| Fuzz a position | Send to Intruder, mark the position with the § button, load a payload list, start; sort by status and length | `proxy.intruder_sniper()` |
| Decode | Decoder: URL, Base64, HTML, hex | `urllib.parse`, `base64` |
| Compare | Comparer: words or bytes between two responses | compare `len(body)` |

Intruder attack types (verify names): **Sniper** (one position, one list), **Battering ram** (same payload in all positions), **Pitchfork** (parallel lists), **Cluster bomb** (all combinations).

## 4. Course exercises with Burp

| Exercise | What to do in Burp | Repo lab that teaches the idea |
|---|---|---|
| SQL injection fundamentals | Send the search request to Repeater; add `'`, then a UNION payload; watch status and length | [vulnerable-shop](../labs/vulnerable-shop/README.md) `sqli_union` |
| XSS | Put a marker such as `zz<b>q` in each parameter; search the response for it raw or encoded | `reflected_xss`, `stored_xss` |
| CSRF | Find a state-changing POST; remove the token in Repeater; does it still work? Burp Pro can generate a CSRF PoC page | `csrf_change_email` |
| SSRF | Change a URL parameter to an internal address used by the course lab (never a real cloud metadata endpoint outside the lab) | `ssrf_metadata` |
| Command injection | Append `;id`-style separators to a parameter that feeds a system tool; look for output or timing changes | `command_injection` |
| IDOR | Change an object id in Repeater while logged in as another user | `idor_read_other_order` |
| Misconfiguration | Read response headers, error pages, `/debug`-style paths | `misconfig_scan` |
| Open redirect | Change `next=`/`returnUrl=` to an external URL; check the `Location` header | `open_redirect` |

## 5. Good habits

- Save the project (Pro) or export important items; keep request and response for every finding.
- Use **Copy as curl command** to put a reproducible step in your report.
- Do not run the scanner or Intruder at full speed against shared lab targets without reading the lab rules.
- Turn Intercept off when you are not using it, or the browser will appear to hang.

## 6. Alternatives

ZAP (free, open source, "ZAP by Checkmarx"), mitmproxy (scriptable), Caido (verify licence and features). The concepts in this guide transfer directly.

See also the repo's [web app testing and Burp lesson](../../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md) and the [Dastardly and Burp DAST notes](../../../devsecops-course/06-dynamic-analysis/real-tools/dastardly-and-burp-dast.md).
