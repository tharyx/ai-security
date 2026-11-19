# Lab: Finding Helm Charts Misconfigurations using Kubescape

**Course exercise:** "Finding Helm Charts Misconfigurations using Kubescape". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#32-infrastructure-as-code-iac-kubernetes-and-helm). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 50 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Kubescape / helm template**. Kubescape is actively maintained (verify). **Helm 4** was released in Nov 2025 (new plugin system, server-side apply by default); Helm 3 remains in use with security-only support ending around early 2027 (verify). Tiller (Helm 2) is long gone.

## What the offline twin does

`helm_scan.py` renders a tiny chart (`{{ .Values.x }}` and `default`) with default values and with hardened overrides, then checks the rendered Deployment (mutable tag, privileged, root, plain-text secret value) and **chart metadata**: HTTP dependency repository, no `Chart.lock`, no verified provenance (`.prov` digest), public LoadBalancer default.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/kubescape-helm-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/kubescape-helm-scan -v
```

1. Run the demo: default values vs hardened overrides. Which findings disappear and which stay? Why?
2. Supply a wrong provenance digest and watch HELM-03 become critical.
3. Reuse the manifest controls from [kubescape-manifest-scan](../kubescape-manifest-scan/README.md) on the rendered output.

## Expected output (real run)

```text
rendered image (defaults): shop/api:latest
== default values: 7 findings
   HELM-01 high     dependency redis fetched over plain HTTP
   HELM-02 medium   no Chart.lock: dependency versions/digests not pinned
   HELM-03 medium   no provenance (.prov) verified: chart origin not checked
   HELM-04 medium   rendered image 'shop/api:latest' uses a mutable tag
   HELM-06 high     rendered container may run as root
   HELM-07 high     ADMIN_PASSWORD rendered as plain text (chart default value is a secret)
   HELM-08 low      default service type exposes a public load balancer
== hardened overrides: 4 findings
   HELM-01 high     dependency redis fetched over plain HTTP
   HELM-02 medium   no Chart.lock: dependency versions/digests not pinned
   HELM-03 medium   no provenance (.prov) verified: chart origin not checked
   HELM-08 low      default service type exposes a public load balancer
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
helm template shop ./chart -f values-prod.yaml > rendered.yaml    # render first
kubescape scan rendered.yaml
kubescape scan ./chart                                            # Kubescape can also read chart directories (verify)
helm dependency build ./chart && cat chart/Chart.lock             # pin dependency digests
helm package --sign --key '<key name>' ./chart && helm verify <chart>.tgz   # provenance (GPG-based; check Helm 4 docs)
```
Install charts from sources you verify; prefer OCI registries with signatures (cosign or Notation) where available.
