# Real tools: path and directory discovery with ffuf (hedged)

**Course item:** "Path And Directory Discovery Using FFUF" ([CASP 2]). **Offline equivalent:** the [path-discovery-ffuf lab](../labs/path-discovery-ffuf/README.md) (an ffuf-style fuzzer against an in-process router).

> Only test systems you own or have written permission to test. Agree a request rate in the rules of engagement. Flags below match ffuf 2.x; **check `ffuf -h` for your version**.

## Install

- Prebuilt binaries from the project's GitHub releases (`ffuf/ffuf`), or `go install github.com/ffuf/ffuf/v2@latest`, or your distribution's package (Kali includes it).
- Wordlists: **SecLists** (`Discovery/Web-Content/`, including an `api/` folder; verify paths), Assetnote's API wordlists. Keep a small custom list built from the target's own docs and JS bundles: it often beats generic lists.

## Core usage

```bash
# 1. paths under a known API prefix, show interesting codes, 20 req/s
ffuf -u https://api.lab/api/v1/FUZZ -w words.txt -mc 200,201,204,301,302,307,401,403,405 -rate 20

# 2. hide the "default" response by size (useful when everything returns 200 with an error body)
ffuf -u https://api.lab/api/v1/FUZZ -w words.txt -fs 42

# 3. version discovery
ffuf -u https://api.lab/api/FUZZ/users -w versions.txt -mc all -fc 404

# 4. authenticated discovery
ffuf -u https://api.lab/api/v1/FUZZ -w words.txt -H "Authorization: Bearer $TOKEN"

# 5. try verbs on one endpoint
ffuf -u https://api.lab/api/v1/users/1 -X FUZZ -w methods.txt -mc all -fc 405

# 6. two lists at once (clusterbomb): HFUZZ in path, VFUZZ as version
ffuf -u https://api.lab/api/VFUZZ/HFUZZ -w versions.txt:VFUZZ -w words.txt:HFUZZ -mode clusterbomb

# 7. save results for the report
ffuf -u https://api.lab/api/v1/FUZZ -w words.txt -o ffuf.json -of json
```

| Flag | Meaning |
|---|---|
| `-u` | URL with the `FUZZ` keyword |
| `-w list[:KEYWORD]` | wordlist, optionally with a custom keyword |
| `-mc` / `-fc` | match / filter status codes (`all` allowed) |
| `-ms` / `-fs`, `-mw` / `-fw`, `-ml` / `-fl` | match / filter by size, words, lines |
| `-ac` | auto-calibrate filters from random requests |
| `-H`, `-X`, `-d` | header, method, body |
| `-rate`, `-t` | requests per second, threads |
| `-recursion`, `-recursion-depth` | follow found directories |
| `-x` | send through a proxy (Burp/ZAP) to keep evidence |

## Reading results

- **401/403** on a word = the path exists but needs auth: note it, test it with credentials later.
- **405** = the path exists for another method.
- **Different size** on a 200 = a real page among soft-404s.
- Many hits of the same size = a catch-all route: use `-ac` or `-fs`.

## Defenses to recommend in the report

API inventory and retirement of old versions; remove debug endpoints from production builds; uniform responses for unknown and unauthorised paths where practical; gateway rate limiting; alert on high 404 rates per client.

## Related

- wfuzz (older, little recent maintenance; hedge), gobuster, feroxbuster, dirsearch.
- Kiterunner-style tools try full API routes (method + path + parameters) from real-world specs; verify maintenance before relying on one.
