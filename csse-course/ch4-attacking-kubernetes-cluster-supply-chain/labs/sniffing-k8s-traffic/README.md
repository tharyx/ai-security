# Lab: Sniffing Kubernetes network traffic

**Course exercise:** "Sniffing Kubernetes network traffic". Lessons: [04 section 3.5](../../04-common-attack-vectors-in-kubernetes-clusters.md#35-flat-networks-and-plaintext-traffic).

**Time:** 45 minutes. **Safety:** no packets are captured. The "capture" is a JSON fixture with FAKE credentials. mTLS is shown **conceptually**; nothing is encrypted by the lab, flows are simply marked as ciphertext.

## Ideas

- By default pod-to-pod traffic is plain unless the application uses TLS or a **service mesh** (Istio, Linkerd, Cilium service mesh) encrypts it with **mTLS**.
- Anyone who can capture on the path reads plaintext: a pod with `NET_RAW` (in the default capability set unless dropped), a `hostNetwork` pod on the node, a compromised node.
- mTLS also authenticates both sides (workload identity), which helps against spoofing.
- Encryption hides content, **not metadata** (who talks to whom, when, how much).
- A mesh in `PERMISSIVE` mode still accepts plaintext; `STRICT` rejects it. Workloads outside the mesh stay plaintext.

## What the code does

[sniff.py](sniff.py): `find_exposures` (bearer tokens, Basic auth, password fields, Redis AUTH, API keys, cookies), `apply_mesh` (Istio-style `PeerAuthentication` mode), `mtls_gaps`, `metadata_visible` and `can_sniff` (does the pod keep `NET_RAW`? is `hostNetwork` on?).

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/sniffing-k8s-traffic/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/sniffing-k8s-traffic -v
```

1. Read the exposures before the mesh; then after STRICT mTLS. Which flow is left? (The cache is not meshed.)
2. Change the mode to PERMISSIVE and re-run (see the test).
3. Drop `NET_RAW` from a pod and see `can_sniff` change.

## Expected output (real run)

```text
== before mesh: credentials visible to a sniffer ==
  web -> api:8080        password-field  FAKE...(12 chars)
  api -> payments:8080   bearer-token    FAKE...(38 chars)
  api -> db:5432         password-field  FAKE...(11 chars)
  web -> cache:6379      redis-auth      FAKE...(15 chars)
== after PeerAuthentication STRICT ==
  exposures left : [('web -> cache:6379', 'redis-auth')]
  still plaintext: ['web -> cache:6379']
  metadata still visible: 5 flows (who talks to whom)
```

## Real tools

Sniffing in your own kind cluster: `tcpdump`, Wireshark, `kubectl sniff` plugin (ksniff; check maintenance), Cilium Hubble. Defences: Istio or Linkerd mTLS, Cilium WireGuard encryption, application TLS, NetworkPolicy, dropping `NET_RAW`.
