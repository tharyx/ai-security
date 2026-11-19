# Lab: ffuf-style path and directory discovery

**Course item:** "Path And Directory Discovery Using FFUF". **Lesson:** [03 section 4](../../03-openapi-burp-and-reconnaissance.md#4-path-and-directory-discovery-using-ffuf). **Real tool guide:** [ffuf](../../real-tools/ffuf.md).

**Time:** 30 minutes. **Tests:** 6, offline. **Safety:** the "target" is an in-process router function; no network traffic. Only test systems you own or have written permission to test.

## Goal

See how wordlist discovery works (`FUZZ` substitution, match and filter codes) and how an API's different answers for unknown, protected and public paths reveal what exists.

## Files

| File | Role |
|---|---|
| [ffuflite.py](ffuflite.py) | `make_router(known, hide_unknown=False)`, `fuzz(base_path, wordlist, handle, match_codes, filter_codes)`, `DEFAULT_WORDLIST` |
| [demo.py](demo.py) | two scans: default API behaviour, and protected paths answering 404 |
| [test_aps_ch09_path_discovery.py](test_aps_ch09_path_discovery.py) | the tests |

`fuzz` behaves like `ffuf -u .../FUZZ -w list`: default filter is `-fc 404`; `match_codes` is `-mc`; `filter_codes` is `-fc`.

## Run

```text
.venv/Scripts/python appsec-course/09-api-tooling-and-reconnaissance/labs/path-discovery-ffuf/demo.py
.venv/Scripts/python -m pytest appsec-course/09-api-tooling-and-reconnaissance/labs/path-discovery-ffuf -q
```

## Real output

```text
=== ffuf-style discovery against /api/v1/FUZZ (default: hide 404) ===
  200  len=10   /api/v1/login
  200  len=12   /api/v1/products
  401  len=12   /api/v1/admin
  200  len=28   /api/v1/debug

=== Same scan, but the API returns 404 for protected paths too ===
  200  len=10   /api/v1/login
  200  len=12   /api/v1/products
  200  len=28   /api/v1/debug
  (the /admin endpoint no longer stands out)
```

## Steps

1. Which result is the most serious finding? (`/api/v1/debug`: public and leaking configuration. `/admin` is protected but now known.)
2. Run `fuzz(..., match_codes={401, 403})` to list only "exists but protected" paths: the next targets for authentication testing.
3. Add a catch-all route that returns `200` with body `"not found"` for every unknown path (a "soft 404"). The scan now reports every word. Add a `filter_sizes` option (like `ffuf -fs`) to remove them.
4. Add a version keyword: fuzz `/api/FUZZ/users` with `["v1", "v2", "beta", "internal"]`.
5. Add a counter of requests per client to the router and return 429 after 10. How does that change the attack, and why is it still not enough alone?

## Run the real tool (hedged)

```bash
ffuf -u https://api.lab/api/v1/FUZZ -w words.txt -mc 200,401,403,405 -rate 20 -o ffuf.json -of json
```

Full flag reference and defenses: [real-tools/ffuf.md](../../real-tools/ffuf.md). In Burp, the equivalent is Intruder with a Sniper attack on the path segment (throttled in Community).

## What you learned

- Discovery is just "substitute, send, compare". The API's own status codes and sizes do the rest.
- 401/403/405 confirm existence; soft 404s need size filters.
- Defenses are inventory, removing debug routes, consistent responses and rate limits with alerting.
