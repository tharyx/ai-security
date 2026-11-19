# Lab: Kubernetes basic commands

**Course exercise:** "Kubernetes basic commands". Lessons: [01](../../01-microservices-and-kubernetes.md).

**Time:** 45 minutes. **Safety:** no cluster and no kubectl needed. YAML is parsed with `yaml.safe_load_all` only.

## What you get

- [CHEATSHEET.md](CHEATSHEET.md): kubectl commands with a security note for each (`auth can-i`, `exec`, `port-forward`, `debug`, `get secret`, ...).
- [manifest_tools.py](manifest_tools.py): a YAML parser exercise that mimics `kubectl get`, `-o jsonpath`, `describe`, and two audit queries (all images including init containers; containers missing limits).

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-basic-commands/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-basic-commands -v
```

1. Compare each demo line with the kubectl command in the cheat sheet.
2. Add a CronJob to `fixtures/app.yaml` and confirm `images()` finds its container.
3. Add a query "which workloads have no `readinessProbe`?".
4. With a real cluster (kind, see [real-tools/kind-minikube.md](../../real-tools/kind-minikube.md)): run `kubectl get deploy -A`, `kubectl auth can-i --list`.

## Expected output (real run)

```text
kubectl get deployments -n shop
  shop   web    replicas=3
  shop   api    replicas=2
images:
  Deployment/web     nginx:1.27
  Deployment/web     registry.corp.example/shop/log-shipper:2.0
  Deployment/api     registry.corp.example/shop/api:1.4
  Deployment/api     registry.corp.example/shop/api:1.4
jsonpath spec.template.spec.containers[0].image -> nginx:1.27
containers without cpu+memory limits: ['Deployment/web:sidecar', 'Deployment/api:api']
```

## Why `safe_load`?

`yaml.load` with an unsafe loader can build arbitrary Python objects from a tag. The test `test_safe_load_refuses_python_object_tags` shows `safe_load` refusing one.
