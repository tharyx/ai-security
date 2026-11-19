# Lab: Scanning the remote host for unauthenticated Docker API access

**Course exercise:** "Scanning the Remote Host for Unauthenticated Docker API Access". Lessons: [01 recon, registries and daemon](../../01-container-reconnaissance.md#7-docker-registries), [03 unauthenticated API](../../03-container-host-daemon-and-kernel-attacks.md#2-unauthenticated-docker-api-and-insecure-endpoint).

**Time:** 45 minutes. **Safety:** **ONLY localhost.** The mock API binds to 127.0.0.1 and the scanner refuses any target that is not a loopback IP literal. Never scan hosts you do not own: it is illegal in many places.

## What it models

A tiny mock Docker Engine API ([mock_api.py](mock_api.py): `/_ping`, `/version`, `/info`, `/containers/json`) with or without authentication, and a scanner ([scanner.py](scanner.py)) that probes a list of endpoints and classifies each: closed, auth required, **UNAUTHENTICATED Docker API**, or not Docker. The unit tests start the server on a random free port.

## Steps

```text
.venv/Scripts/python devsecops-course/10-container-reconnaissance-and-attacks/labs/remote-docker-api-scan/demo.py
.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/remote-docker-api-scan -v
```

1. Run the demo and read the five results (open, locked, closed, and two refused).
2. Try `scanner.check_target('192.168.1.10')`: it must raise.
3. Add a `/images/json` probe and update the tests.
4. Read the impact line: why is an open 2375 port root on the host?

## Expected output (real run)

```text
127.0.0.1:58001        UNAUTHENTICATED Docker API
     /_ping -> 200 OK without credentials
     /version -> Docker 27.3.1-mock on linux/amd64
     /containers/json -> 2 containers listed: ['shop-web', 'shop-db']
     impact: anyone who can reach this port can create a privileged container with the host root mounted: treat i
127.0.0.1:58002        auth required
     /_ping -> 401
127.0.0.1:58000        closed
203.0.113.10:2375      REFUSED
     203.0.113.10 is not loopback: refusing to scan a host you do not own
example.com:2375       REFUSED
     'example.com' is not an IP literal; only 127.0.0.0/8 and ::1 are allowed
```

## Think about it

Real-world note: tools like nmap, masscan and Shodan find exposed Docker APIs, and attackers do exactly this at internet scale. Defence is simple: do not bind the API to a network without TLS client certificates.

## Run the real tool

In your own lab only: `curl http://127.0.0.1:2375/version`, `nmap -p 2375,2376 127.0.0.1`. See [real-tools/recon-tools.md](../../real-tools/recon-tools.md).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`11` tests in `test_dso_ch10_*.py`: `.venv/Scripts/python -m pytest devsecops-course/10-container-reconnaissance-and-attacks/labs/remote-docker-api-scan`.
