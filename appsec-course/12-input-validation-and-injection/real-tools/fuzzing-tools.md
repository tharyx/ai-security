# Real tools: Burp Intruder, ZAP Fuzzer, wfuzz and ffuf (hedged)

The [mini-fuzzer](../labs/mini-fuzzer/README.md) and [free-coupons](../labs/free-coupons/README.md) labs teach the ideas offline. Use the tools below in your course lab environment. Options change between versions: **check `--help` and the official docs.**

> Only test systems you own or have written permission to test. Fuzzing can create data and load; use a test environment.

## Burp Suite Intruder

1. Proxy the client through Burp, find the request (for example `POST /api/v1/orders`), right-click → **Send to Intruder**.
2. In **Positions**, clear the automatic markers and mark only the values to fuzz with `§...§`.
3. Choose the attack type:
   - **Sniper:** one payload list, one position at a time (fuzzing each field).
   - **Battering ram:** same payload in all positions.
   - **Pitchfork:** parallel lists (username1+password1, username2+password2).
   - **Cluster bomb:** every combination (small lists only).
4. **Payloads:** Simple list, Numbers (e.g. 000-999 for coupons), Brute forcer, Null payloads; add processing (URL-encode, prefix).
5. **Settings:** Grep - Match for `Traceback`, `Exception`, `SQL`; Grep - Extract for tokens.
6. Start the attack and sort by **status**, **length** and **response time**.

Community Edition throttles Intruder; Professional runs at full speed. Burp also offers Turbo Intruder (extension) for very high request rates (check the BApp Store).

## ZAP Fuzzer (ZAP by Checkmarx)

1. Proxy traffic through ZAP or import an OpenAPI definition (**Import → OpenAPI**).
2. In **History**, right-click a request → **Attack → Fuzz...**.
3. Highlight a value, **Add...** payloads: Strings, File, File Fuzzers (bundled lists), Regex, Numberzz, Script.
4. Optional **Processors** (Base64, URL encode, prefix/suffix).
5. Start; filter the Fuzzer tab by HTTP code, size and time.

For CI, use the **ZAP Automation Framework** (YAML plan) or the packaged API scan (`zap-api-scan.py`), covered in [devsecops-course ch06](../../../devsecops-course/06-dynamic-analysis/README.md).

## wfuzz

```text
wfuzz -c -z file,wordlist.txt --hc 404 https://lab.example/api/v1/FUZZ
wfuzz -c -z range,000-999 --hc 404 -X POST -H "Content-Type: application/json" \
      -d '{"code":"SAVEFUZZ"}' https://lab.example/api/v1/cart/coupon
wfuzz -c -z file,users.txt -z file,passwords.txt --hc 401 -d "u=FUZZ&p=FUZ2Z" https://lab.example/login
```

`--hc/--hl/--hw/--hh` hide by code, lines, words, characters. wfuzz has seen little maintenance recently; ffuf covers the same ground.

## ffuf

```text
ffuf -u https://lab.example/api/v1/FUZZ -w wordlist.txt -fc 404
ffuf -u https://lab.example/api/FUZZ/users -w versions.txt -mc 200,401,403      # v1, v2, internal...
ffuf -X POST -u https://lab.example/api/v1/orders -H "Content-Type: application/json" \
     -d '{"qty":FUZZ}' -w values.txt -mc 500                                     # field fuzzing
ffuf -X POST -u https://lab.example/api/v1/cart/coupon -H "Content-Type: application/json" \
     -d '{"code":"SAVEFUZZ"}' -w nums.txt -fc 404 -rate 20                        # be polite: rate limit
```

`-fc/-fs/-fw/-fl` filter by code/size/words/lines; `-mc` matches codes; `-o out.json -of json` saves results; `-rate` limits requests per second.

## Schema-driven API fuzzers (optional)

- **Schemathesis:** `schemathesis run https://lab.example/openapi.json --checks all` generates requests from OpenAPI and checks responses against it.
- **RESTler** (Microsoft): stateful REST fuzzing from OpenAPI.
