# Lab: Kubernetes networking using Calico

**Course exercise:** "Kubernetes networking using Calico". Lessons: [01](../../01-microservices-and-kubernetes.md), [04 section 3.5](../../04-common-attack-vectors-in-kubernetes-clusters.md#35-flat-networks-and-plaintext-traffic).

**Time:** 60 minutes. **Safety:** pure computation over YAML; no cluster, no packets.

## What it models

Kubernetes `NetworkPolicy` semantics as enforced by a CNI that supports them (Calico, Cilium, others; a CNI without policy support silently ignores them):

- no policy selecting a pod = open in that direction;
- selected by a policy of type Ingress/Egress = **isolated**: only explicit allows pass;
- policies only **add** allows (a union);
- traffic needs **both** ends to agree (source egress and destination ingress);
- `podSelector` alone means the policy's own namespace; `namespaceSelector` crosses namespaces.

[netpol.py](netpol.py) implements `matchLabels`, `matchExpressions`, ports (with `endPort`), `Cluster.can_reach`, `matrix`, `isolated` and `exposed_pods`.

Calico also has its own `GlobalNetworkPolicy` and explicit Deny and ordered rules. They are described here but not simulated; read the Calico docs in your course lab.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/calico-networking/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/calico-networking -v
```

1. Compare "flat network" and "default deny + allow rules": the `rogue` pod reaches the DB in the first, not the second.
2. Add a default-deny policy for the `payments` namespace and re-run: `payments/payments-api` stops being exposed.
3. Remove one of the two web-to-api policies (egress or ingress). Why does the connection fail? (Both ends must allow.)

## Expected output (real run, abridged)

```text
== no policies (flat network) ==
  rogue  -> db           :5432  ALLOW
== default deny + allow rules ==
  not isolated for ingress: ['payments/payments-api', 'attacker-sandbox/rogue']
  web    -> api          :8080  ALLOW
  web    -> db           :5432  deny
  api    -> db           :5432  ALLOW
  rogue  -> db           :5432  deny
```

## Real tools

Calico (`calicoctl`), Cilium and Hubble, `kubectl exec ... -- nc -zv` tests in a kind cluster with Calico installed ([real-tools/kind-minikube.md](../../real-tools/kind-minikube.md)). Note: kind's default CNI does not enforce NetworkPolicy; install Calico or Cilium first.
