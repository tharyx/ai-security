# Syft, cdxgen and Grype (hedged)

> Syft and Grype (Anchore) and cdxgen (CycloneDX) are actively maintained. Verify install methods and flags in their READMEs; the CLI has evolved (for example `syft scan`).

## Syft: generate SBOMs

```text
syft dir:. -o cyclonedx-json=sbom.cdx.json          # application source tree
syft dir:. -o spdx-json=sbom.spdx.json
syft <image>@sha256:<digest> -o cyclonedx-json=image.cdx.json
syft docker-archive:image.tar                       # from `docker save`
syft dir:/ -o table                                  # a host root filesystem (run as an authorized admin on your own machine)
syft <image> -o json                                 # rich native format, includes file and layer information
```

Notes: Syft detects many ecosystems and OS package databases. Quality differs by ecosystem, so **compare with a second generator** for important artifacts. Pin by digest in CI.

## cdxgen

```text
cdxgen -o sbom.cdx.json .
cdxgen -t python -o sbom.cdx.json .       # force a project type (check options)
```

cdxgen can run package managers to resolve full trees (which means it may execute build tooling: run it in a sandbox for untrusted code).

## Grype: scan an SBOM or image

```text
grype sbom:sbom.cdx.json --fail-on high
grype <image>@sha256:<digest>
grype dir:.
```

Grype downloads a vulnerability DB; in restricted networks use a mirrored DB (check the docs).

## Related

- Labs: [syft-app-sbom](../labs/syft-app-sbom/README.md), [syft-container-sbom](../labs/syft-container-sbom/README.md), [bomber-sbom-scan](../labs/bomber-sbom-scan/README.md), [syft-in-cicd](../labs/syft-in-cicd/README.md).
- Trivy can also generate and scan SBOMs ([trivy.md](trivy.md)).
- Operating SBOMs (sign, store, rescan): [lesson 04](../04-asset-inventory-and-sboms.md).
