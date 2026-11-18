# Module 02: Networking (CompTIA Network+ level)

> **Weeks:** 2-4 · **Time:** ~35 hours (9 lessons + lab) · **Level:** beginner to intermediate
> **You will:** understand how networks work, read firewall and DNS logs like a SOC analyst, do subnetting by hand and with code, and know the controls (firewalls, VLANs, VPN, cloud security groups) that stop an attacker from moving.

## Learning path

| # | Lesson | Week | Certification objective |
|---|---|---|---|
| 1 | [OSI and TCP/IP](01-osi-and-tcp-ip.md) | 2 | Network+ N10-009 domain 1 |
| 2 | [IP addressing and subnetting](02-ip-addressing-and-subnetting.md) | 3 | Network+ domain 1; AZ-500/AWS VPC design |
| 3 | [Ports and protocols](03-ports-and-protocols.md) | 3 | Network+ domain 1; Security+ secure protocols |
| 4 | [DNS, DHCP, HTTP/HTTPS, TLS](04-dns-dhcp-http-tls.md) | 3-4 | Network+ domains 1 and 4; Security+ crypto basics |
| 5 | [Routing, switching and VLANs](05-routing-switching-vlans.md) | 4 | Network+ domain 2; Security+ segmentation |
| 6 | [Firewalls, NAT, VPN, proxies, IDS/IPS](06-firewalls-nat-vpn-proxies-ids-ips.md) | 4 | Network+ domain 4; Security+ network appliances |
| 7 | [Wireless basics](07-wireless-basics.md) | 4 | Network+ domains 2 and 4 |
| 8 | [Cloud networking](08-cloud-networking.md) | 4 | Network+ domain 1; AZ-500; AWS Security Specialty |
| 9 | [Packet analysis (Wireshark/tshark)](09-packet-analysis-wireshark-tshark.md) | 4 | Network+ domain 5; SOC skills |
| Lab | [`lab/`](lab/) subnet trainer, firewall and DNS analyzers | 3-4 | Hands-on for lessons 2, 4, 6 |

*The Network+ exam is N10-009 at the time of writing. Check the official CompTIA page for the current code and objectives before booking.*

## Key terms

| Term | Short meaning |
|---|---|
| Packet / frame / segment | Data unit at layer 3 / 2 / 4 |
| CIDR | Network address with a prefix, like `198.51.100.0/26` |
| NXDOMAIN | DNS answer: "this name does not exist" |
| DGA | Malware that generates random domain names |
| VLAN | Virtual LAN: a logical network on shared switches |
| NAT | Rewriting addresses at the network edge |
| IDS / IPS | Detect / detect and block |
| Security group / NSG | Cloud firewall for instances or subnets |
| Flow log | Metadata record of connections |
| pcap | A saved packet capture |
| Beaconing | Regular call-outs by malware |
| Egress | Outbound traffic |

## How this connects to your job

- **SOC:** most alerts name IPs, ports and domains. Lessons 3, 4 and 6 are what you read every day. The firewall and DNS analyzers are tiny versions of SIEM rules (module 06).
- **Cloud security:** lesson 8 and subnetting (lesson 2) are the base for security group review, VPC flow log analysis and the cloud module 10.
- **DBA bridge:** the Oracle listener, `sqlnet.ora` allow-lists and database VLANs are the same ideas you now apply to the whole estate.

## Lab: run it

```bash
.venv/Scripts/python -m pytest cybersecurity-track/02-networking      # 31 tests, offline
.venv/Scripts/python cybersecurity-track/02-networking/lab/demo.py    # subnet quiz + firewall + DNS findings
```

Files in `lab/` (data is synthetic, documentation IP ranges and `*.example` domains only):

| File | Role |
|---|---|
| `subnet_trainer.py` | Questions and answer checking with `ipaddress` |
| `firewall_analyzer.py` | Port scans, denied spikes, rare ports |
| `dns_analyzer.py` | Tunneling, DGA-like names, NXDOMAIN rate |
| `sample_data.py` | Seeded fake logs |
| `demo.py`, `test_networking.py` | Demo and tests |

## Mini-project (4 hours)

**"Network detection pack."** Add two more detections to the lab and a test for each: (1) *beaconing* in the firewall log (same source and destination at regular intervals), (2) *DNS query volume per client* compared with the median (baseline). Then write a one-page README that says, for each detection: what it finds, the threshold, the false positives and what the analyst does next. Put it in your portfolio (module 13). In module 06 you will rewrite the same ideas as KQL and SPL queries.

## Interview questions (module level)

<details><summary><b>Q1. Explain what happens when you open a web page, from DNS to the response.</b></summary>
DHCP gave the host an address and a DNS server. DNS resolves the name. The host connects over TCP (handshake), starts TLS (certificate check, keys), sends the HTTP request, and the server replies. Routers forward packets by IP; ARP and switches deal with the local MAC addresses.
</details>

<details><summary><b>Q2. A server's database port 1521 is reachable from the internet. How do you assess and fix it?</b></summary>
Check the firewall/security group rule and who changed it, check logs for outside connections, restrict to the app subnet, review DB audit logs and credentials, and add a rule/policy check so it cannot return.
</details>

<details><summary><b>Q3. How do you tell a port scan from normal traffic in firewall logs?</b></summary>
A scan touches many different ports (or hosts) from one source in a short time, mostly denied or reset. Normal clients use a few ports repeatedly.
</details>

<details><summary><b>Q4. How would you detect DNS tunneling?</b></summary>
Many unique, long, high-entropy subdomains of one domain from one host, unusual record types such as TXT, high volume. Verify with the process on the host and the destination domain reputation.
</details>

<details><summary><b>Q5. What is the difference between IDS and IPS, and what are the risks of each?</b></summary>
IDS alerts only (risk: no one reads alerts, attacks go on). IPS blocks in line (risk: false positives block real business traffic, so it needs tuning).
</details>

<details><summary><b>Q6. What is the network address and broadcast for 203.0.113.45/28?</b></summary>
Block size 16. Network `203.0.113.32`, broadcast `203.0.113.47`, 14 usable hosts.
</details>

<details><summary><b>Q7. Why is segmentation important for ransomware?</b></summary>
It limits spread and gives chokepoints to block SMB and admin ports between zones, with logging at each crossing.
</details>

<details><summary><b>Q8. Security group vs NACL?</b></summary>
Security groups are stateful, per instance, allow-only. NACLs are stateless, per subnet, allow and deny.
</details>

<details><summary><b>Q9. What can a defender see in TLS traffic?</b></summary>
Metadata: IPs, ports, SNI, certificate, fingerprints, volume and timing. Not the payload without decryption at a controlled proxy.
</details>

<details><summary><b>Q10. What is the first thing you do with a pcap?</b></summary>
Get the statistics: protocol hierarchy, conversations and endpoints. Then zoom into the odd one with display filters and follow the stream.
</details>

## Practice on TryHackMe / HTB

- **TryHackMe:** *Cyber Security 101* networking modules, then the Wireshark, tcpdump, Zeek and Snort rooms, then *SOC Level 1* (SAL1 certification).
- **HTB Academy:** *SOC Analyst* job-role path (HTB CDSA certification); networking and traffic analysis modules (check names in the catalogue).
- **HTB Labs:** *Sherlocks* with pcaps and logs. LetsDefend content is moving into HTB.
- **Free tools:** Wireshark, Cisco Packet Tracer, Suricata and Zeek in a VM.

## References

- CompTIA Network+: https://www.comptia.org/certifications/network
- NSA/CISA *Network Infrastructure Security Guidance*; NIST SP 800-41 (firewalls)
- Wireshark docs: https://www.wireshark.org/docs/ · MITRE ATT&CK network techniques: https://attack.mitre.org
- Course-library notes used for this module (paraphrased): OSI/networking interview notes, TShark guide, NSA network infrastructure guide, Wi-Fi networking and security notes
- Back to the [track README](../README.md) · Previous: [01 IT fundamentals](../01-it-fundamentals/README.md) · Next: [03 Security foundations](../03-security-foundations/README.md)
