# Lab: GKE Misconfiguration: metadata exposure, Workload Identity and legacy ABAC

**Lessons:** [04 section 5](../../04-attack-vectors-in-gcp.md#5-attacking-google-kubernetes-engine) · [chapter 4](../../../ch4-attacking-kubernetes-cluster-supply-chain/README.md). Chapter guide: [README](../../README.md). Related repo labs: [cloud security track](../../../../cybersecurity-track/10-cloud-security/README.md) (CloudTrail detections, IAM analyzer), [09 enterprise architecture](../../../../09-enterprise-architecture/README.md) (cloud controls).

**Course status:** the chapter 5 syllabus lists no hands-on exercises; this lab is an **extra offline practice**. **Time:** 50 minutes. **Tests:** 10, all offline.

**Safety:** no cloud account, no network, no real credentials. Everything is a fixture or an in-process simulation; keys are FAKE; domains are `.example`. Real-tool commands below are for **your own** accounts only and are hedged: verify them in the provider docs.

## What the offline twin does

`gke_audit.py` audits two cluster fixtures (`prod-legacy` and `prod-hardened`): **legacy ABAC**, **legacy metadata endpoints**, no **Workload Identity**, node pools on the **default compute service account** or the `cloud-platform` scope, the metadata mode of each pool, a default SA with Editor, public nodes, an open control plane, client certificates, no network policy, no Binary Authorization and no release channel. `pod_identity_from_metadata` shows **which identity a compromised pod receives** from the metadata server.

## Steps

```text
.venv/Scripts/python csse-course/ch5-attacking-cloud-supply-chain/labs/gke-misconfig/demo.py
.venv/Scripts/python -m pytest csse-course/ch5-attacking-cloud-supply-chain/labs/gke-misconfig -v
```

1. Run the demo: the pod on `prod-legacy` gets the node SA with Editor; the pod on `prod-hardened` gets only its bound identity.
2. Read the last test: enabling Workload Identity at the cluster level **without** changing the node pool metadata mode still leaks the node identity.
3. Make `prod-legacy` pass: list the fixture edits you need.

## Expected output (real run)

```text
[critical] prod-legacy    LEGACY-ABAC            legacy attribute-based authorization lets every service account act 
[critical] prod-legacy    SA-BROAD-ROLE          default Compute SA holds Editor/Owner on the project
[high    ] prod-legacy    DEFAULT-NODE-SA        pool default-pool uses the default Compute service account
[high    ] prod-legacy    LEGACY-METADATA        legacy /0.1/ and /v1beta1/ metadata endpoints are served (no Metadat
[high    ] prod-legacy    METADATA-MODE          pool default-pool exposes the node metadata server to pods
[high    ] prod-legacy    NO-WORKLOAD-IDENTITY   pods fall back to the node service account
[high    ] prod-legacy    OPEN-CONTROL-PLANE     no authorized networks restrict the API server
[medium  ] prod-legacy    BROAD-OAUTH-SCOPE      pool default-pool grants the cloud-platform scope
[medium  ] prod-legacy    CLIENT-CERT-AUTH       legacy client certificate authentication is enabled
[medium  ] prod-legacy    NO-BINARY-AUTH         images are not verified at admission (Binary Authorization off)
[medium  ] prod-legacy    NO-NETWORK-POLICY      no network policy enforcement: flat pod network
[medium  ] prod-legacy    PUBLIC-NODES           nodes have public IPs
[low     ] prod-legacy    NO-RELEASE-CHANNEL     no release channel: patching is manual
[low     ] prod-legacy    NO-SHIELDED-NODES      Shielded GKE Nodes are off

prod-legacy    web-1    token request returns -> node SA: default-compute (roles: roles/editor)
prod-hardened  web-1    token request returns -> web-gsa@acme.example
prod-hardened  batch-1  token request returns -> no Google identity (workload identity pool principal only)
```

## Real-tool guide (hedged)

```text
# Own project only; verify flags
gcloud container clusters describe <cluster> --region <region> \
  --format="yaml(legacyAbac,workloadIdentityConfig,privateClusterConfig,masterAuthorizedNetworksConfig,networkConfig,binaryAuthorization,releaseChannel)"
gcloud container node-pools describe <pool> --cluster <cluster> --region <region> --format="yaml(config.serviceAccount,config.oauthScopes,config.workloadMetadataConfig)"
# Trivy and Kubescape scan clusters you own
trivy k8s --report summary cluster
kubescape scan
```
kube-hunter is no longer actively developed; Aqua points users to Trivy. The cluster-side RBAC and manifest ideas are practised in [chapter 6 labs](../../../ch6-common-defenses-against-supply-chain-attacks/labs/kubiscan-rbac/README.md).
