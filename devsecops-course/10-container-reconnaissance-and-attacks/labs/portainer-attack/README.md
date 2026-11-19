# Lab: Attacking management tools (Portainer)

**Course exercise:** "Attacking management tools (Portainer)". Lessons: [04 management tools](../../04-management-tools-and-owasp-top10.md#2-attacking-management-tools-portainer).

**Time:** 45 minutes. **Safety:** A **mock** management UI object. No web server, no real Portainer, no network. Credentials are canaries.

## What it models

A UI connected to the Docker socket, in three states: **fresh install exposed with no admin yet** (first visitor can take it over), **default credentials**, and **hardened**. Shows the **blast radius**: containers controllable, volumes readable, secrets visible in environment variables, whether the UI is root-equivalent on the host, and how many other hosts its agents reach. Includes a 7-point hardening list. Real Portainer behaviour changes between versions: verify at source.

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/portainer-attack/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/portainer-attack -v
```

1. Run the demo and compare the three states.
2. Take over the fresh install and list the blast radius.
3. Turn on MFA in the default-credentials UI: does password-only login still work?
4. Why does `rbac=True` change the root-equivalence flag? (Least-privilege roles stop most users reaching privileged operations.)

## Expected output (real run)

```text
== fresh install, exposed, no admin yet ==
  [CRITICAL] UI reachable and no admin account created yet: first visitor becomes admin
  [CRITICAL] default/weak admin password
  [HIGH    ] UI exposed over plain HTTP: credentials and sessions can be sniffed
  [HIGH    ] internet/LAN-exposed UI without MFA or SSO
  [MEDIUM  ] no role separation: every UI user is effectively an admin
  [MEDIUM  ] UI holds the Docker socket read-write: compromise of the UI == root on the host
== default credentials ==
  [CRITICAL] default/weak admin password
  [HIGH    ] UI exposed over plain HTTP: credentials and sessions can be sniffed
  [HIGH    ] internet/LAN-exposed UI without MFA or SSO
  [MEDIUM  ] no role separation: every UI user is effectively an admin
  [MEDIUM  ] UI holds the Docker socket read-write: compromise of the UI == root on the host
== hardened ==
  [OK      ] no findings

Attacker on the fresh install: takeover -> True | login -> True
Blast radius:
  containers_controllable          4
  volumes_readable                 ['pgdata', 'uploads']
  secrets_visible_in_env           [('shop-api', 'DB_PASSWORD'), ('shop-api', 'API_TOKEN'), ('shop-db', 'POSTGRES_PASSWORD'), ('ci-runner', 'RUNNER_TOKEN')]
  can_start_privileged_container   True
  host_root_equivalent             True
  other_hosts_via_agents           3

Same blast radius on the hardened UI: False (root-equivalent?)

Hardening checklist:
 - Do not expose the UI to the internet: put it behind a VPN or an identity-aware proxy; bind to 127.0.
 - Create the admin account immediately at install time (script it) and use a long random password from
 - Terminate TLS with a valid certificate; disable plain HTTP.
 - Enable SSO/OIDC and MFA; use role-based access with least-privilege teams.
```

## Think about it

A management UI is the daemon with a login page. Its security equals the strongest of: network exposure, authentication, role separation and what the socket allows.

## Run the real tool

Lab only: run Portainer CE locally behind `127.0.0.1`, create the admin immediately, enable TLS and SSO if available. Compare with the hardening list.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/portainer-attack`.
