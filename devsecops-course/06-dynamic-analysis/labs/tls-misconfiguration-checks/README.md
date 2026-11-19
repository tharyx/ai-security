# Lab: TLS misconfiguration checks (offline fixtures)

**Course exercise:** SSL misconfiguration testing. **Lesson:** [03 TLS and server misconfiguration](../../03-tls-and-server-misconfiguration-testing.md).

**Time:** 40 minutes. **Tests:** 9, offline. **Safety:** no sockets are opened. The input is a JSON description of what a scanner (testssl.sh, sslyze, nmap) observed. Hosts are `.example.test`. The lab does not start a TLS server because generating a certificate needs extra tools; real probing is covered in the lesson.

## Files

| File | Role |
|---|---|
| `fixtures/bad_server.json` | SSLv3 + TLS 1.0 + 1.1, RC4/3DES/anonymous suites, expired self-signed certificate with the wrong name, RSA 1024, SHA-1, no HSTS |
| `fixtures/good_server.json` | TLS 1.2 + 1.3, AEAD suites, valid wildcard certificate, RSA 3072, SHA-256, HSTS |
| `tlscheck.py` | `analyze(cfg, today)` returns findings; `grade()` gives A to F; `hostname_matches()` handles wildcards (one label only) |

The date is a parameter, so tests are deterministic.

## Run

```text
.venv/Scripts/python devsecops-course/06-dynamic-analysis/labs/tls-misconfiguration-checks/demo.py
.venv/Scripts/python -m pytest devsecops-course/06-dynamic-analysis/labs/tls-misconfiguration-checks -v
```

## Expected output (real run)

```text
== shop.example.test  grade F  (16 finding(s)) ==
  [Critical] TLS-WEAK-CIPHER          TLS_DH_anon_WITH_AES_128_CBC_SHA (contains anon)
  [High    ] CERT-EXPIRED             expired on 2024-01-01
  [High    ] CERT-HOSTNAME-MISMATCH   shop.example.test not in ['www.old-shop.example.test']
  [High    ] CERT-SELF-SIGNED         issuer equals subject: no trusted CA in the chain
  [High    ] CERT-WEAK-KEY            RSA 1024 bits
  [High    ] TLS-OLD-PROTOCOL         SSLv3 is enabled
  [High    ] TLS-OLD-PROTOCOL         TLSv1.0 is enabled
  [High    ] TLS-WEAK-CIPHER          TLS_RSA_WITH_RC4_128_SHA (contains RC4)
  [High    ] TLS-WEAK-CIPHER          TLS_RSA_WITH_3DES_EDE_CBC_SHA (contains 3DES)
  [Medium  ] CERT-WEAK-SIGNATURE      sha1WithRSAEncryption
  [Medium  ] HSTS-MISSING             no Strict-Transport-Security header
  [Medium  ] TLS-NO-FORWARD-SECRECY   TLS_RSA_WITH_RC4_128_SHA has no forward secrecy
  [Medium  ] TLS-NO-FORWARD-SECRECY   TLS_RSA_WITH_3DES_EDE_CBC_SHA has no forward secrecy
  [Medium  ] TLS-OLD-PROTOCOL         TLSv1.1 is enabled
  [Low     ] TLS-CBC-CIPHER           TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA uses CBC mode (prefer AEAD: GCM or ChaCha20)
  [Low     ] TLS-NO-13                TLS 1.3 is not offered
== api.example.test  grade A  (0 finding(s)) ==
```

## Steps

1. Run the demo and map every finding to a field in `bad_server.json`.
2. Edit a copy of `good_server.json`: set `not_after` to 20 days from the pinned date. Which finding appears?
3. Put `a.b.example.test` as the host. Why does `*.example.test` not match it?
4. Add a rule: warn when the certificate lifetime (`not_after` minus `not_before`) exceeds 398 days (the public web limit; verify current rules).
5. Add TLS 1.3 only (`["TLSv1.3"]`). Why is that sometimes a compatibility problem for old clients?

## Run the real tool

```text
testssl.sh --jsonfile out.json https://staging.example.test
sslyze staging.example.test
nmap --script ssl-enum-ciphers -p 443 staging.example.test
```

Only against hosts you own. Convert the tool's JSON into this lab's fixture shape to reuse the rules. Verify flags in each tool's docs.
