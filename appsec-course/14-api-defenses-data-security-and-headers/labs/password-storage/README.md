# Lab: Password storage, picking a secure algorithm, pepper and upgrade-on-login

**Course items:** "Password Storage and Its Considerations", "Picking a Secure Algorithm". Lesson: [02 section 4](../../02-data-security-and-password-storage.md#4-password-storage-and-picking-a-secure-algorithm). Cracking techniques in depth: [chapter 10](../../../10-api-authentication/README.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** the lab only "cracks" lab passwords from a tiny built-in list. The pepper is FAKE and built at runtime. Only test systems you own or have written permission to test.

## Goal

Compare what an attacker gets from a stolen user table when passwords are stored:

1. as **unsalted MD5** (legacy);
2. with **PBKDF2-HMAC-SHA256 or scrypt and a per-user salt**;
3. with a **pepper** (a secret kept outside the database).

Then migrate a legacy table safely with **upgrade-on-login**.

## Concept

[pwstore.py](pwstore.py) stores hashes in a self-describing format (`$pbkdf2-sha256$i=600000$<salt>$<hash>`), so the algorithm and cost can change over time. `needs_rehash()` spots old hashes. `UserStore.login()` re-hashes the password at the only moment you have it in clear text: a successful login. `check_password_policy()` follows NIST SP 800-63B-4 style rules: length over complexity, a blocklist, no forced composition (verify the final text).

Algorithm choice (OWASP Password Storage Cheat Sheet; verify the current parameters): **Argon2id** first, then **scrypt**, then **bcrypt** (72-byte input limit), then **PBKDF2-HMAC-SHA256 with about 600,000 iterations** where FIPS-140 validated algorithms are required. Never MD5, SHA-1 or a single SHA-256. The lab uses PBKDF2 and scrypt because they are in Python's standard library.

## Run

```text
.venv/Scripts/python appsec-course/14-api-defenses-data-security-and-headers/labs/password-storage/demo.py
.venv/Scripts/python -m pytest appsec-course/14-api-defenses-data-security-and-headers/labs/password-storage -v
```

## Expected output (real run)

```text
1. Legacy table: unsalted MD5
   asha   $md5$4e69a298d30e0c1a8042e683288aaee9
   ravi   $md5$0d107d09f5bbe40cade3de5c71e9e9b7
   meena  $md5$4e69a298d30e0c1a8042e683288aaee9
   joe    $md5$9cc2ae8a1ba7a93da39b46fc1019c481
   users sharing a password (no cracking needed): [['asha', 'meena']]
   dictionary attack: cracked [('asha', 'monsoon2024'), ('meena', 'monsoon2024'), ('ravi', 'letmein')] in 23 guesses, 0.1 ms

2. Modern table: PBKDF2-HMAC-SHA256, random salt per user (lab uses 20,000 iterations; policy is 600,000)
   asha   $pbkdf2-sha256$i=20000$keZoUXSVqcIrDRI1FKsxkQ$cPhO2P+wu2oNyD...
   ravi   $pbkdf2-sha256$i=20000$4YOLDSE4pJ3UpZazD+Yd6A$hv7azOyV6wCu3Y...
   meena  $pbkdf2-sha256$i=20000$MeRwatjPg7Pc6WM7lo37sw$lXKkrMlhdnHg79...
   joe    $pbkdf2-sha256$i=20000$Nxmu6OALgh4NyhX9YWZKlg$Cus/Bvhyo3+dDm...
   users sharing a password: []
   dictionary attack: cracked [('asha', 'monsoon2024'), ('meena', 'monsoon2024'), ('ravi', 'letmein')] in 23 guesses, 230.5 ms
   (weak passwords still fall to a dictionary; slow hashing buys time, the blocklist removes the weak ones)

3. Pepper: the DB alone is not enough
   attacker without pepper cracked: {}

4. Upgrade on login (legacy MD5 -> PBKDF2)
   ravi logs in: True | stored now: $pbkdf2-sha256$i=20000$hP9gk9PZsCPlL+BYU...
   upgraded users: ['ravi'] | asha still legacy: True

5. Password policy (NIST SP 800-63B-4 style)
   'Tr0ub4dor&3'                    mfa=False -> ['too short: 11 < 15']
   'Tr0ub4dor&3'                    mfa=True  -> OK
   'password123'                    mfa=True  -> ['on the common/breached-password blocklist']
   'correct horse battery staple'   mfa=False -> OK
```

## Steps

1. Look at the MD5 table: asha and meena have the same hash, so they have the same password. You learned that without cracking anything.
2. Compare the two dictionary-attack times. Multiply the PBKDF2 time by 30 (600,000 / 20,000) to estimate the real policy cost. Because of the salt, that cost applies per guess and per user.
3. Notice that weak passwords **still** fall to a dictionary. Slow hashing buys time; the **blocklist** and MFA stop weak passwords.
4. Log in as `ravi` and watch the upgrade. Why can you not upgrade `asha` yet? (There is no plaintext until she logs in. One option is to wrap the old hash now, `pbkdf2(md5(pw))`, and fully upgrade at her next login.)
5. Run `check_password_policy("Tr0ub4dor&3")`: complex but short. Then try a long passphrase: simple but strong.

## What you learned

- Salt defeats precomputed tables and hides shared passwords. The work factor slows every guess. A pepper makes a database-only leak useless.
- Self-describing hash strings let you raise the cost later, and upgrade-on-login migrates users without forcing resets.
- Compare hashes with `hmac.compare_digest`, and do equal work for unknown users so timing does not reveal which accounts exist.

## Run the real tool (hedged)

- Python: `argon2-cffi` (`PasswordHasher().hash(pw)`, `check_needs_rehash`), `bcrypt`, or `pwdlib`/`passlib` (check which are maintained).
- Java: Spring Security `Argon2PasswordEncoder` / `DelegatingPasswordEncoder`. Its `{id}` prefix is the same idea as the `$scheme$` prefix here.
- Testing your own hashes: **hashcat** or **John the Ripper** against a lab hash file only (see [chapter 10](../../../10-api-authentication/README.md)).
