# Snyk (hedged)

> Snyk is a commercial service with a free tier. Using it sends dependency and image metadata to Snyk's cloud and needs an account: check your organization's policy and the current terms. Open-source alternatives for the same job are Trivy and Grype.

```text
npm install -g snyk            # or another official install method; verify
snyk auth                      # interactive login; do not paste tokens into chat or repos
snyk container test <image>:<tag> --severity-threshold=high
snyk container test <image> --file=Dockerfile      # adds base image upgrade advice
snyk container monitor <image>:<tag>
snyk test                      # open-source dependency scan in a project
snyk code test                 # SAST (availability depends on plan)
snyk iac test infra/           # IaC
```

CI: store `SNYK_TOKEN` as a **protected, masked** variable. Use `--severity-threshold` for gating and `snyk monitor` for continuous alerts. Exceptions live in a `.snyk` policy file (with `reason` and `expires`).

Lab: [snyk-container-scan](../labs/snyk-container-scan/README.md). Compare results with [Trivy](trivy.md) and note differences: databases, matching rules, fix advice.
