# Lab: Insecure deserialization to remote code execution (safe canary version)

**Course exercises:** "Insecure Deserialization To Remote Code Execution", "Preventing Insecure Deserialization In Java". Lesson: [02 section 7](../../02-injection-vulnerabilities.md#7-deserialization-issues) (includes the Java `ObjectInputFilter` snippet).

**Time:** 45 minutes. **Tests:** 6, all offline. **Safety:** the "payload" only calls `canary_hit()`, a harmless function in this lab that appends a string to a list. No shell, `os`, `subprocess` or file access is used anywhere. Only test systems you own or have written permission to test.

## Goal

Prove that `pickle.loads()` on attacker data runs a function the attacker chooses, then show two fixes: a data-only format with a schema, and a restricted unpickler.

## Concept

Native serialization formats (Python `pickle`, Java `ObjectInputStream`, .NET `BinaryFormatter`, PHP `unserialize`, Ruby `Marshal`) store **which class or function to call** to rebuild an object. In pickle, `__reduce__` returns `(callable, args)` and the loader calls it. If an attacker controls the bytes, they control the call: in real attacks that callable is `os.system`; here it is `canary_hit`.

| Defence | How | Notes |
|---|---|---|
| Use a data-only format | JSON, protobuf + schema validation | Best fix: no types, no code |
| Allowlist classes | `Unpickler.find_class` override; Java `ObjectInputFilter` (JEP 290, JEP 415) | When you cannot change the format yet |
| Sign the blob | HMAC over the bytes | Integrity only; if the key leaks, RCE is back |
| Isolate | Run deserialization in a low-privilege sandbox | Limits blast radius |

## Steps

1. Run the demo. `pickletools` shows the `STACK_GLOBAL` and `REDUCE` opcodes: "import this callable, then call it".
2. In [deser.py](deser.py), add `(module_name, "canary_hit")` to `RestrictedUnpickler.ALLOWED` and rerun the tests: the allowlist test fails and the canary fires. Allowlists must contain only harmless data classes.
3. Explain why HMAC signing alone is not a fix (key leak, insider, or the signing service itself deserializing).

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/insecure-deserialization/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/insecure-deserialization -q -p no:cacheprovider
```

## Expected output (real run)

```text
== What is inside the malicious cookie (pickletools, GLOBAL/REDUCE opcodes) ==
opcodes include STACK_GLOBAL: True  REDUCE: True

== Vulnerable: pickle.loads(cookie) ==
session['prefs'] = session-hijacked
canary list     = ['RCE-CANARY: attacker-chosen function ran during unpickling']

== Secure 1: JSON + schema ==
normal JSON session -> {'user': 'alice', 'prefs': {'theme': 'dark'}}
pickle blob as JSON -> UnicodeDecodeError

== Secure 2: restricted Unpickler (find_class allowlist) ==
normal pickle session -> {'user': 'alice', 'prefs': {'theme': 'dark'}}
malicious -> global deser.canary_hit is forbidden
canary list = []
```

## Run the real tool (hedged)

- In the course lab, the Java exercise typically uses **ysoserial** to generate gadget-chain payloads against a vulnerable endpoint. Run it only inside the lab. The prevention side is the `ObjectInputFilter` shown in the lesson.
- Static analysis finds the sink: Semgrep/Bandit flag `pickle.loads` (Bandit B301) and Java `readObject` on untrusted input (see [devsecops-course SAST](../../../../devsecops-course/05-static-analysis-and-secrets/README.md)).

## What you learned

- Deserializing untrusted native objects is code execution by design.
- Prefer data-only formats; if you must keep native serialization, allowlist classes at the loader.
