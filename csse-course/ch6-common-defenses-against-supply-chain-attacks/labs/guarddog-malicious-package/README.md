# Lab: Identify malicious Package using guarddog

**Course exercise:** "Identify malicious Package using guarddog". Lesson: [02-evaluating-dependencies-before-use.md](../../02-evaluating-dependencies-before-use.md#1-analyze-the-security-and-compliance-of-dependencies). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 60 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **GuardDog (Datadog)**. GuardDog is actively maintained by Datadog (verify). It combines Semgrep source-code rules with package-metadata heuristics.

## What the offline twin does

`guarddog_lite.py` scans **inert fixture packages** (strings only, `.example` domains, FAKE secrets): typosquat distance, unregistered maintainer email domain, install hooks (`setup.py` cmdclass, npm lifecycle scripts), download-and-run, decode-then-exec, long encoded blobs, credential paths, environment-variable exfiltration and unknown endpoints, then gives a verdict.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/guarddog-malicious-package/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/guarddog-malicious-package -v
```

1. Run the demo: one clean package and two suspicious ones.
2. For each finding, say whether the real attack would be *install time* or *import time*.
3. Add a benign package that legitimately uses the network to a fixture and see which rule fires. How would you allow it? (Allow-list with a reviewed exception.)

## Expected output (real run)

```text
== requests-utils: CLEAN
== reqeusts: MALICIOUS-LIKELY
   [high    ] typosquat                      metadata               'reqeusts' is 2 edit(s) from popular package 'requests'
   [high    ] unregistered-maintainer-domain metadata               author email domain of bob@expired-domain.example is not reg
   [medium  ] install-hook                   setup.py               setup.py overrides the install command
   [high    ] obfuscated-exec                setup.py               decodes data then executes it
   [medium  ] long-encoded-blob              setup.py               160-char encoded string
   [critical] env-exfiltration               setup.py               reads environment variables and sends data over the network
   [medium  ] unknown-endpoint               setup.py               contacts collect.attacker.example
   [critical] credential-path                reqeusts/__init__.py   reads a well-known credential location
== left-padz-js: MALICIOUS-LIKELY
   [high    ] typosquat                      metadata               'left-padz-js' is 1 edit(s) from popular package 'left-pad'
   [medium  ] install-hook                   package.json           npm lifecycle install script present
   [high    ] download-and-run               package.json           pipes a download into a shell
   [medium  ] unknown-endpoint               package.json           contacts cdn.attacker.example
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
pip install guarddog                                   # verify install method in the project README
guarddog pypi scan <package-name>                      # scan a package from the registry
guarddog pypi scan ./local-package-dir                 # scan a local directory
guarddog npm scan <package-name> --output-format json
guarddog pypi verify requirements.txt                  # check every dependency in a file
```
Use GuardDog **only on packages you are evaluating**; it downloads from the public registry. Run it in a throwaway environment. Related: OSV-Scanner for known vulnerabilities; Socket-style services for broader signals.
