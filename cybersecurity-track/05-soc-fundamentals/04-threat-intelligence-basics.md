# 04 · Threat intelligence basics

> **Module:** 05 · SOC Fundamentals · **Week:** 5 · **Time:** ~6 hours
> **You will:** use threat intel the right way (enrich, do not blindly trust), explain STIX/TAXII, and look up indicators **without leaking company data**.

| | |
|---|---|
| **Prerequisites** | Lessons 02-03 |
| **Lab** | [`lab/threat_intel.json`](lab/threat_intel.json) (an offline intel table) used by `triage.py` |
| **Maps to** | Security+ SY0-701/801 domain 4 (threat intelligence sources); SC-200 (Sentinel threat intelligence); TryHackMe SOC Level 1 (threat intelligence rooms) |

---

## 1. Why it matters in a SOC / cloud-security job

- Most triage steps start with "is this IP, domain or hash known bad?" That question is answered by threat intelligence (CTI).
- Bad use of intel causes real harm: blocking a legitimate cloud provider, or uploading an internal document to a public service and **leaking it**.
- Sentinel and Splunk both ingest intel feeds and match them against your logs. You need to know what is in them and how stale it can be.

---

## 2. Understand it

### 2.1 Three types of intel

| Type | Audience | Question it answers | Example |
|---|---|---|---|
| **Strategic** | Executives, risk | Who attacks our industry, and why? | "Ransomware groups target hospitals; budget for backups." Report, trend, months or years |
| **Operational** | SOC leads, hunters, IR | How do they work, which campaigns now? | "A campaign uses a macro that starts encoded PowerShell." TTPs, days or weeks |
| **Tactical** | L1/L2 analysts, detection tools | Which concrete indicators should I match? | IPs, domains, hashes, URLs. Hours or days |

(Some teams add a fourth type: **technical**, meaning raw indicators and malware analysis. Naming differs between books; the point is the *level of detail and the time horizon*.)

Tactical intel decays fast. An IP that was a malware server on Monday can be a harmless web host on Friday. Always look at **age**, **source** and **confidence**.

### 2.2 Where intel comes from

| Source type | Examples | Notes |
|---|---|---|
| **Open source (OSINT) feeds** | abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker), AlienVault OTX, CISA advisories, vendor blogs | Free, variable quality |
| **Commercial feeds** | Recorded Future, Mandiant, CrowdStrike, Microsoft Defender Threat Intelligence | Paid, curated |
| **Community sharing** | ISACs (sector groups), MISP communities | Trusted groups, often TLP-marked |
| **Internal intel** | Your own past incidents, honeypots, CMDB "known good" lists | Often the **best** for your environment |
| **Government** | CISA KEV (known exploited vulnerabilities), national CERTs | Free, authoritative |

Intel is also **good-lists**: corporate VPN egress IPs, your scanners, your CDN. The lab table contains both bad and good entries.

### 2.3 Reputation lookups

| Observable | Typical free lookups | Warning |
|---|---|---|
| IP | AbuseIPDB, GreyNoise (is it internet background noise?), Shodan | A "clean" IP can be brand new |
| Domain / URL | URLhaus, VirusTotal URL search, urlscan.io (search existing scans) | Newly registered domains are riskier |
| File hash | VirusTotal hash search, MalwareBazaar | Searching a **hash** is safe; uploading the **file** is not (see 2.5) |
| Email / header | MXToolbox, header analyzers | Remove internal names before pasting |

Use more than one source. Disagreement is a signal: check age and tags.

### 2.4 STIX and TAXII (high level)

| Standard | What it is | Plain meaning |
|---|---|---|
| **STIX** (Structured Threat Information eXpression) | A JSON format (current version 2.1, OASIS standard) | A common *language* to describe indicators, malware, actors, campaigns and their relationships |
| **TAXII** (Trusted Automated eXchange of Intelligence Information) | A protocol over HTTPS (current version 2.1) | A common *delivery truck*: servers publish collections, clients poll them |

Mini STIX 2.1 indicator (fake data; the pattern language is called STIX patterning):

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--11111111-2222-4333-8444-555555555555",
  "created": "2026-11-01T00:00:00.000Z",
  "modified": "2026-11-01T00:00:00.000Z",
  "name": "Credential harvesting domain",
  "pattern": "[domain-name:value = 'login-update.example']",
  "pattern_type": "stix",
  "valid_from": "2026-11-01T00:00:00Z",
  "confidence": 90
}
```

Note the field `valid_from` (and optional `valid_until`): STIX has a way to say that an indicator **expires**. A good SOC uses it.

Where you meet them: Sentinel **Threat Intelligence** (TAXII connector and STIX-based upload), MISP, OpenCTI.

### 2.5 Do not leak data to public sandboxes

Public tools are public. Anything you upload may be visible to other users, to the vendor, and sometimes to the attacker who watches for their own sample.

| Do | Do not |
|---|---|
| Search by **hash** (SHA-256) first | Upload a company document "to check it" |
| Use a private/enterprise sandbox, or an offline analysis VM | Submit URLs that contain tokens, internal hostnames, session IDs or user names (for example a password-reset link) |
| Remove or redact internal data from headers and logs | Paste whole log lines with employee names into a public tool |
| Set scans to private/unlisted when the tool allows it | Assume "private" means invisible to the vendor |
| Follow your company policy and TLP markings | Share TLP:RED intel outside the named audience |
| Defang indicators in tickets and chat | Paste live malicious URLs in clickable form |

Rule of thumb: **look up the identifier, do not send the object.** If a file *might* contain company secrets (an invoice, a contract, a spreadsheet), do not upload it to a public service. Use a company sandbox.

**Defang** means making an indicator unclickable: `hxxp://login-update[.]example`.

**TLP** (Traffic Light Protocol) marks how widely you may share: TLP:RED (named recipients only), TLP:AMBER (your organization and need-to-know partners), TLP:GREEN (community), TLP:CLEAR (public). Check FIRST.org for the current text.

### 2.6 How intel should change a verdict

Intel is **one input**. Compare:

| Intel result | What to do |
|---|---|
| Malicious, high confidence, recent | Strong evidence. Escalate quickly. |
| Suspicious or old | A small boost. Look at behavior. |
| Benign / known good | Can excuse *some* alerts (a geo-IP alert from a VPN egress), but **never** excuse behavior (large exfiltration to a "reputable" site). |
| **No data** | Unknown. Not safe. Judge by behavior and context. |

The lab encodes exactly that: a malicious hit adds `35 x confidence` points, a benign hit may subtract points only for alert types where reputation can explain the alert (impossible travel, antivirus on a known-good file), and only if there is no malicious hit.

### 2.7 From DBA to security

> **From DBA to security**
> - **Intel table = a reference/lookup table.** Joining alert data to a reputation table is the same as joining a fact table to a dimension. You already know that SQL; KQL `join` and Splunk `lookup` do the same.
> - **Staleness = stale statistics.** Old optimizer stats give wrong plans; old indicators give wrong verdicts. Both need a refresh schedule.
> - **Data classification = what you may upload.** A DBA would never send a production export to an external site. The same rule applies to sandboxes.

---

## 3. Hands-on

### 3.1 Repo lab: intel enrichment (offline)

Open `lab/threat_intel.json` (8 fake indicators). Then run this snippet, which looks up four values and defangs them:

```bash
python - <<'EOF'
import sys
sys.path.insert(0, "cybersecurity-track/05-soc-fundamentals/lab")
import triage
intel = triage.load_intel()
def defang(s): return s.replace("http", "hxxp").replace(".", "[.]")
for ioc in ["203.0.113.50", "login-update.example", "files.cloudshare.example", "192.0.2.222"]:
    hit = intel.get(ioc)
    print(f"{defang(ioc):28}", (hit["verdict"], hit["confidence"], hit["source"]) if hit else "no intel (unknown, not safe)")
EOF
```

Real output:

```text
203[.]0[.]113[.]50           ('malicious', 0.9, 'feed-alpha')
login-update[.]example       ('malicious', 0.95, 'feed-alpha')
files[.]cloudshare[.]example ('benign', 0.6, 'internal-cmdb')
192[.]0[.]2[.]222            no intel (unknown, not safe)
```

Now see how intel changes alert A-1012 (a phishing report with the malicious domain). From the case notes of the lab:

```text
Enrichment:
  - intel login-update.example: malicious (confidence 0.95), Credential harvesting page
```

Exercises:
1. Add a fake indicator for `192.0.2.88` (alert A-1017) as `malicious`. Run `demo.py`. *Predict:* does the verdict change? (A malicious hit removes the "below threshold" benign reason; look at the score.)
2. Change the confidence of `203.0.113.50` to `0.2`. Which alerts drop in score?
3. Add `valid_until` to an indicator and make `triage.py` ignore expired indicators. Write a test.

### 3.2 Optional free tools

- **MISP** or **OpenCTI** in Docker (heavy; use only if you have the RAM) to see STIX objects.
- A STIX 2.1 validator (`stix2` Python library) to check the JSON above.
- **VirusTotal** (free account) for **hash searches** only.
- **GreyNoise Community**, **AbuseIPDB** (free API key) for IP checks. Never use real keys in lab code.

### 3.3 Practice platforms

- **TryHackMe:** the *Cyber Threat Intelligence* content in the SOC Level 1 path (look for rooms about threat intelligence tools, MISP, and OpenCTI).
- **HTB Academy:** see the SOC Analyst path for intel-driven modules (check the current list).

---

## 4. Real-world scenarios

**Scenario 1: The "benign" domain that is not.** An alert shows 4 GB going to a popular file-sharing site. The lookup says "benign". *Investigate:* reputation is about the site, not the use. Check the user's baseline, who owns the data, whether the account is compromised. *Do:* treat as exfiltration until proven otherwise (see the lab alert A-1014).

**Scenario 2: Intel false positive.** The feed lists a CDN IP as malicious because one customer hosted malware there for an hour. Your firewall blocks it and a business app breaks. *Fix:* use confidence, age and tags; add expiry; test before auto-blocking; keep a rollback.

**Scenario 3: Leak by sandbox.** An L1 analyst uploads a suspicious "invoice.xlsx" from the finance team to a public sandbox. The file contains real client data. *Do:* report it as a data exposure incident at once, ask the vendor to delete the sample if possible, tell the data owner. *Prevent:* hash lookup first, enterprise sandbox, written policy.

---

## 5. Common mistakes

- Treating a feed as truth. Always check age, source and confidence.
- Auto-blocking on low-confidence indicators.
- "No intel hit means safe."
- Uploading files or URLs with secrets to public tools.
- Pasting live malicious links in tickets and chat.
- Never expiring indicators.
- Sharing TLP-marked intel beyond its audience.

---

## 6. Interview questions

<details><summary><b>Q1. Strategic, operational and tactical intel?</b></summary>
Strategic: high-level trends for leaders. Operational: campaigns and attacker methods for defenders and hunters. Tactical: concrete indicators (IPs, domains, hashes) for tools and analysts.
</details>

<details><summary><b>Q2. What is STIX and what is TAXII?</b></summary>
STIX is the JSON format for describing threat data. TAXII is the HTTPS protocol to exchange it. Both are OASIS standards (current version 2.1).
</details>

<details><summary><b>Q3. Why does tactical intel go stale?</b></summary>
Attackers change IPs, domains and hashes quickly, and infrastructure is reused by innocent parties. Use age, confidence and expiry.
</details>

<details><summary><b>Q4. A file hash shows 2 detections out of 70 engines on VirusTotal. What do you conclude?</b></summary>
Not enough alone. Could be a false positive from heuristic engines. Check which engines, file type, signer, first-seen date and behavior on the host before deciding.
</details>

<details><summary><b>Q5. Why not upload a suspicious company document to a public sandbox?</b></summary>
It may become visible to others and to the vendor, leaking company or client data. Search the hash instead, or use an internal or enterprise sandbox.
</details>

<details><summary><b>Q6. What is defanging?</b></summary>
Changing an indicator so it is not clickable or resolvable (`hxxp://bad[.]example`) so nobody opens it by mistake.
</details>

<details><summary><b>Q7. What does TLP mean?</b></summary>
Traffic Light Protocol: marking for how widely you may share information. RED is named recipients only; AMBER is limited sharing; GREEN is the community; CLEAR is public.
</details>

<details><summary><b>Q8. How do you use intel in a SIEM?</b></summary>
Load indicators into a watchlist or threat-intel table and join them to logs (firewall, DNS, proxy, sign-ins), then raise alerts on matches, with expiry and confidence considered.
</details>

<details><summary><b>Q9. IP "clean" in every tool but the behavior looks like password spraying. Verdict?</b></summary>
Trust the behavior. New attacker infrastructure often has no history. Use the sign-in logs: many accounts, short time, one source.
</details>

<details><summary><b>Q10. How would you measure the value of a feed?</b></summary>
Track how many alerts the feed produced, how many were true positives, how many were unique (not seen in other feeds), and the false-positive and staleness rates. Drop feeds that only add noise.
</details>

---

## 7. Checklist

- [ ] I can explain the three intel types with an example each.
- [ ] I can read a small STIX indicator.
- [ ] I know the "hash, not file" rule and can defang an IOC.
- [ ] I changed the intel table and saw the effect on scores.
- [ ] I know why "benign" reputation can not excuse behavior.

## 8. References

- OASIS STIX 2.1 and TAXII 2.1 specifications: https://oasis-open.github.io/cti-documentation/
- MISP project: https://www.misp-project.org
- FIRST Traffic Light Protocol: https://www.first.org/tlp/
- CISA Known Exploited Vulnerabilities catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- abuse.ch projects (URLhaus, MalwareBazaar): https://abuse.ch
- Microsoft Learn, "Threat intelligence in Microsoft Sentinel".
