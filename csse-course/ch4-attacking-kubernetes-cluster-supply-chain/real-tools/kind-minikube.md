# Real tool guide: kind and minikube (a local cluster for chapter 4)

> **Hedged guide.** Not run by the repo author for this guide. Versions change fast; check kind.sigs.k8s.io and minikube.sigs.k8s.io. The repo tests never need a cluster.

## Which one

| | kind | minikube |
|---|---|---|
| What | Kubernetes in Docker containers (each node is a container) | A VM or container with one node, many drivers |
| Good for | CI and quick multi-node practice | Beginners, add-ons, dashboards |
| Needs | Docker (or Podman) | A driver: Docker, Hyper-V, VirtualBox, etc. |
| Laptop (16 GB RAM, no GPU) | Fine for 1 control plane + 1 or 2 workers | Fine for 1 node |

Use a throwaway cluster. Do not point practice tools at a shared or production cluster.

## kind quick start (concept)

```text
kind create cluster --name csse                      # one control-plane node
kubectl cluster-info --context kind-csse
kubectl get nodes
kind delete cluster --name csse
```

A config file lets you add workers or **disable the default CNI** so you can install Calico or Cilium (needed for NetworkPolicy practice; the default kind CNI does not enforce policies):

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
  - role: control-plane
  - role: worker
```

Then install Calico following its docs and use the [calico-networking lab](../labs/calico-networking/README.md) as a map for tests.

## Practice ideas by lab

| Lab | Real practice in kind or minikube |
|---|---|
| k8s-basic-commands, working-with-kubernetes | `kubectl apply -f` the fixture YAML into a test namespace; `--dry-run=server` |
| k8s-secrets | Create a Secret, read it with `kubectl get -o yaml`, decode it; enable encryption at rest via an `EncryptionConfiguration` on the API server (kind extra args; advanced) |
| service-accounts | `kubectl create token`, `kubectl exec` into a pod and read the projected token file |
| calico-networking | Apply default-deny and allow policies; test with `kubectl exec ... -- wget -qO- --timeout=2 http://svc` |
| privileged-pods | Label a namespace with Pod Security `restricted` and try to create a privileged pod: admission rejects it |
| kubelet-api, kube-hunter-recon | Read the kubelet config on the node container (`docker exec <node> cat /var/lib/kubelet/config.yaml`; verify path). Scan your own cluster with Trivy or Kubescape |
| sniffing-k8s-traffic | `tcpdump` on a test node container, only between your own test pods |

## Cautions

- Docker Desktop with WSL2 or a Linux VM is enough; allocate memory deliberately.
- Clusters on your laptop are not hardened. Do not expose their API server to a network.
- Delete clusters when done (`kind delete cluster`, `minikube delete`).
