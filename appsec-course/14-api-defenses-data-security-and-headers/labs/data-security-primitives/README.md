# Lab: Encoding, escaping, hashing and encryption (data at rest)

**Course items:** "Data Security", "Encoding and Decoding", "Escaping", "Hashing", "Encryption and Decryption", "Securing Data at Rest Using Encryption". Lesson: [02 data security](../../02-data-security-and-password-storage.md).

**Time:** 60 minutes. **Tests:** 10, all offline. **Safety:** in-memory sqlite and FAKE card numbers built at runtime. Only test systems you own or have written permission to test.

> **NOT FOR PRODUCTION.** `ToyAEAD` in [datasec.py](datasec.py) is a teaching cipher (an HMAC-SHA256 keystream plus an HMAC tag, encrypt-then-MAC). It uses only the standard library, so the lab needs no packages. Real systems use **AES-256-GCM** or **ChaCha20-Poly1305** from a vetted library, a cloud KMS, or Vault/OpenBao Transit. Never hand-roll crypto.

## Goal

See, with running code, why the four words are **not** interchangeable:

| Operation | Needs a key? | Reversible? | Protects against | Lab function |
|---|---|---|---|---|
| Encoding (base64, hex, URL) | No | Yes, by anyone | Nothing. It is a format. | `encode_all`, `decode` |
| Escaping (HTML, JS string, URL param) | No | Yes | Injection into ONE interpreter | `escape_for`; for SQL use binds (`sql_lookup`) |
| Hashing (SHA-256), keyed hashing (HMAC) | HMAC: yes | No (but small inputs can be enumerated) | Tampering (HMAC); password storage (slow hash) | `sha256_hex`, `reverse_low_entropy_hash`, `keyed_pseudonym`, `integrity_tag` |
| Encryption (AEAD) | Yes | Yes, with the key | Disclosure, and tampering when authenticated | `ToyAEAD`, `KeyRing`, `CardStore` |

## Run

```text
.venv/Scripts/python appsec-course/14-api-defenses-data-security-and-headers/labs/data-security-primitives/demo.py
.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers/labs/data-security-primitives -v
```

## Expected output (real run)

```text
1. ENCODING (no key, reversible by anyone)
   base64    cm9sZT1hZG1pbiZ1c2VyPWFzaGE=  -> decodes to 'role=admin&user=asha'
   base64url cm9sZT1hZG1pbiZ1c2VyPWFzaGE  -> decodes to 'role=admin&user=asha'
   hex       726f6c653d61646d696e26757365723d61736861  -> decodes to 'role=admin&user=asha'
   url       role%3Dadmin%26user%3Dasha  -> decodes to 'role=admin&user=asha'

2. ESCAPING (one interpreter at a time)
   html      &lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;
   js_string "\u003c/script\u003e\u003cimg src=x onerror=alert(1)\u003e"
   url_param %3C%2Fscript%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E
   SQL string-built : [('asha', 'user'), ('ravi', 'admin')]
   SQL bind variable: []

3. HASHING (one-way, but small inputs can be enumerated)
   sha256('4821')       = a388f562e286fdf28986f925...
   reversed by brute force -> 4821
   HMAC pseudonym       = 23ad4419c9df85c6df3e471c...  (no key, no enumeration)

4. ENCRYPTION AT REST (ToyAEAD: NOT FOR PRODUCTION; use AES-GCM via a vetted library/KMS)
   plaintext table dump:
     cust-001 | 4000000000000001 | 0001
     cust-002 | 4000000000000002 | 0002
   encrypted table dump:
     cust-001 | k1:VAZSDIvJ/eSXEOkPRq+YGTeHfoIZzhBIL1UXxUp/p80Ro2BNISWtK/sC...
     cust-002 | k1:8ZSVQNhmDFL9WO8Yh0N3QtRTFc/T1utBBv/xvsfmCE1TVTiNRHVE582/...
   app reads cust-002   : 4000000000000002
   ciphertext copied to another row -> tag mismatch: ciphertext, nonce or associated data was changed
   rotate key and rewrap: 2 rows now on k2
```

## Steps

1. Decode the base64 value from the demo yourself, for example with `python -c "import base64; print(base64.b64decode('cm9sZT1hZG1pbiZ1c2VyPWFzaGE='))"`. This is why "we base64 the password in the config" is not a control.
2. Escape the same payload for HTML and for a JS string. Then imagine the HTML-escaped string placed inside a `<script>` block and explain why it is still unsafe there.
3. The demo reverses `sha256('4821')` in at most 10,000 tries. Phone numbers (10 digits) and national ids are also small spaces. Use `keyed_pseudonym` instead, and say where its key must live.
4. Copy a ciphertext from one customer's row to another. The associated data (`cards:<customer_id>`) binds it to its row, so decryption fails. AES-GCM's AAD works the same way.
5. Rotate the key and rewrap. Delete the old key and confirm everything still decrypts. Vault Transit `rotate` + `rewrap` gives you the same thing.

## What you learned

- Encoding is not security. Escaping depends on the context. SQL needs bind variables (like Oracle `:name` binds), not escaping.
- Plain hashes of small inputs can be reversed by enumeration. HMAC with a secret key cannot (without the key).
- Encryption at rest must be **authenticated** (AEAD) and bound to its context, and keys need versions and rotation. Oracle TDE protects data files and backups. It does not protect against a user who can run `SELECT`. Field-level encryption with application keys does.

## Run the real tool (hedged)

- Python `cryptography` package: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM` (12-byte nonce; never reuse a nonce with the same key). Verify the API in its docs.
- Vault or OpenBao Transit: `vault write transit/encrypt/orders plaintext=<base64>` and `vault write transit/rewrap/orders ciphertext=<vault:v1:...>`. See the [devsecops ch13 lab](../../../../devsecops-course/13-secrets-management/labs/vault-consul-secrets/README.md).
- Cloud KMS: AWS KMS `GenerateDataKey` for envelope encryption, Azure Key Vault keys, GCP Cloud KMS.
