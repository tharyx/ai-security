# Real tool guide: Falco (and Tetragon) for runtime security

> **Hedged guide.** Not run by the repo author for this guide. Falco is a CNCF project; installation and rule syntax change with versions. Check falco.org docs. Runtime sensors need kernel access (eBPF) so use a **test cluster** (kind or minikube on a Linux host or VM). Docker Desktop VMs may not expose the needed kernel features.

## What Falco does

A privileged sensor (a DaemonSet) observes **system calls** through an eBPF driver and enriches them with container and Kubernetes metadata (pod, namespace, image). A **rules engine** matches events against conditions and emits alerts to stdout, files, webhooks, Falcosidekick (Slack, SIEM, Kafka), or a response tool.

## Install (concept)

```text
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n falco --create-namespace       # check chart values for the driver option
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

Prefer to **review the chart** first (hooks, privileges): see [Helm 4 guide](helm-4.md). The Falco DaemonSet itself needs elevated privileges, so give it its own namespace and restrict who can modify it.

## Example rules (concept; verify syntax)

```yaml
- rule: Shell in container
  desc: A shell was started inside a container with a terminal
  condition: spawned_process and container and shell_procs and proc.tty != 0
  output: "Shell in container (user=%user.name pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository cmd=%proc.cmdline)"
  priority: NOTICE

- rule: Service account token read by unexpected process
  desc: Something other than the app read the SA token
  condition: open_read and container and fd.name startswith /var/run/secrets/kubernetes.io/serviceaccount and not proc.name in (app, java, python)
  output: "SA token read (proc=%proc.name pod=%k8s.pod.name file=%fd.name)"
  priority: WARNING
```

## Practice exercise (safe)

1. In a kind or minikube cluster install Falco.
2. `kubectl exec -it` into a test pod and run `sh`: look for the "Shell in container" alert.
3. Create a quarantine NetworkPolicy and apply it to that pod (response practice).
4. Tune: add an exception for a known maintenance job; document why.

## Tetragon (Cilium)

Tetragon also uses eBPF and adds **enforcement** options: `TracingPolicy` objects can observe and, depending on version, block or kill. Use it when you want kernel-level policy and Cilium integration. Verify current capabilities at tetragon.io.

## Other tools and signals

KubeArmor, Tracee (Aqua), commercial CNAPP/EDR, **Kubernetes audit logs** (via your SIEM), Hubble flow logs. The offline twins in this chapter are detections-as-analysis: [stealing-k8s-secrets](../labs/stealing-k8s-secrets/README.md) for RBAC paths and [sniffing-k8s-traffic](../labs/sniffing-k8s-traffic/README.md) for exposure.

## Cautions

- Alert fatigue: start with a small, tuned rule set.
- The sensor sees sensitive data (command lines, file names): protect and retain logs carefully.
- Runtime detection is not prevention: pair with admission policy and network controls.
