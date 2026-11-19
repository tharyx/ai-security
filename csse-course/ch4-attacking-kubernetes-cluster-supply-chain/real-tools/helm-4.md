# Real tool guide: Helm 4 (chart workflow and security)

> **Hedged guide.** Not run by the repo author for this guide. Helm 4 was released on 12 Nov 2025 (verify at helm.sh/docs and the release notes). Helm 3 continues with security fixes for a limited time (the project announced an end date around early 2027; verify). Flags change; check `helm help`.

## What changed in Helm 4 (as reported, verify)

- A new **WASM-based plugin system** (the older plugin model remains for a transition).
- **Server-side apply** is the default for installs and upgrades, improving conflict handling.
- Various CLI and SDK clean-ups and breaking changes. Read the official **Helm 3 to 4 migration notes** before upgrading pipelines.
- Still **no Tiller**: the client acts with the user's kubeconfig identity.

## Core commands

```text
helm create shop-web                       # scaffold a chart
helm lint shop-web                         # basic chart checks
helm template rel shop-web -f values.yaml  # RENDER only, no cluster calls: scan this output
helm package shop-web --sign --key 'name' --keyring ~/.gnupg/secring.gpg   # signed package + .prov
helm verify shop-web-0.3.0.tgz             # verify provenance (needs the public key)
helm install rel ./shop-web -n shop --create-namespace --verify  # verify when pulling from a repo
helm push shop-web-0.3.0.tgz oci://registry.example/charts       # OCI registry
helm pull oci://registry.example/charts/shop-web --version 0.3.0
helm show values oci://registry.example/charts/shop-web --version 0.3.0
helm list -A ; helm history rel -n shop ; helm rollback rel 1 -n shop ; helm uninstall rel -n shop
```

## Safe consumption routine

1. Prefer an **internal mirror** (OCI registry) of reviewed charts. Avoid blog-post repo URLs.
2. `helm pull` and read `Chart.yaml`, `values.yaml`, `templates/` (especially hooks and RBAC).
3. **Pin the chart version and digest**; commit `Chart.lock` for dependencies.
4. `helm template ... | kubeconform` then scan with Kubescape, `trivy config` or kube-linter. The offline twin is the [static-analysis-manifests lab](../labs/static-analysis-manifests/README.md).
5. Verify provenance (`helm verify`) or the cosign signature of the OCI artifact.
6. Install through CI or GitOps with a **namespace-scoped identity**, never a personal cluster-admin kubeconfig.
7. Diff rendered output on upgrades (`helm diff` plugin; check its status for Helm 4 compatibility).

## Provenance notes

- `.prov` files use PGP. Key distribution is the hard part: decide who publishes and verifies keys.
- For OCI charts many teams sign with **cosign** keyless or KMS keys. See [chapter 3 cosign/Notation guide](../../ch3-attacking-container-supply-chain/real-tools/cosign-notation.md).

## Cautions

- Release history is stored as Secrets in the release namespace; rendered values (possibly secrets) live there.
- Chart hooks run code during install and upgrade. Review them like CI scripts.
