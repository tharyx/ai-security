# Lab: Exploiting Kubelet API

**Course exercise:** "Exploiting Kubelet API". Lessons: [01 section 4.2](../../01-microservices-and-kubernetes.md#42-node-components), [04 section 3.1](../../04-common-attack-vectors-in-kubernetes-clusters.md#31-exposed-control-plane-and-node-endpoints).

**Time:** 45 minutes. **Safety:** the "kubelet" is a Python object called in-process. `POST /run/...` only returns a string saying what would have run; **nothing is executed and nothing listens on a port**. Never probe a real kubelet you do not own.

## Two configurations

| File | Setting |
|---|---|
| [kubelet-insecure.yaml](fixtures/kubelet-insecure.yaml) | `anonymous.enabled: true`, `authorization.mode: AlwaysAllow`, `readOnlyPort: 10255`, webhook authentication off |
| [kubelet-hardened.yaml](fixtures/kubelet-hardened.yaml) | anonymous off, webhook auth on, x509 client CA, `mode: Webhook`, `readOnlyPort: 0`, `protectKernelDefaults`, certificate rotation |

[kubelet_sim.py](kubelet_sim.py) answers `GET /pods`, `POST /run/<ns>/<pod>/<container>`, `/metrics` and friends the way each config would, and `audit_config` reports `KL-001` to `KL-007`. With Webhook authorization the kubelet maps `/pods` and `/run` to the RBAC subresource **`nodes/proxy`** and `/metrics` to `nodes/metrics`, which is why granting `nodes/proxy` to a monitoring role is dangerous.

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/kubelet-api/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/kubelet-api -v
```

1. Compare anonymous results for the two configs: 200 and a simulated command versus 401.
2. Give `prometheus` only `nodes/metrics` and see `/metrics` pass but `/pods` return 403.
3. Give `prometheus` `nodes/proxy` and watch `/pods` open up. Lesson: grant the narrowest subresource.

## Expected output (real run, abridged)

```text
== kubelet-insecure.yaml ==
  [CRITICAL] KL-001 authentication.anonymous.enabled is true
  [CRITICAL] KL-002 authorization.mode is AlwaysAllow: ...
  anonymous GET  /pods : (200, [...])
  anonymous POST /run  : (200, "SIMULATED run of 'id' in payments/pay-1/api (nothing was executed)")
== kubelet-hardened.yaml ==
  anonymous GET  /pods : (401, 'Unauthorized')
  read-only port 10255 : 0
  prometheus /pods     : (403, 'Forbidden: user prometheus cannot access nodes/proxy')
```

## Real tools

kube-bench (kubelet checks), `kubectl get --raw /api/v1/nodes/<node>/proxy/...` only in your own lab, Kubescape, the kubelet config file `/var/lib/kubelet/config.yaml` on a node (verify the path for your distribution).
