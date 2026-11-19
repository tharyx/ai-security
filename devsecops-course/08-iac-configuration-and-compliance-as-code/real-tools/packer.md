# Real tools: Packer

> Hedged guide. Verify at developer.hashicorp.com/packer. Packer is under the **BSL** licence since Aug 2023 (IBM completed the HashiCorp acquisition in 2025; verify). There is no major Packer fork. The labs never need Packer.

## Typical workflow

```text
packer init .                # installs the plugins pinned in required_plugins
packer fmt .                 # format HCL2
packer validate .            # syntax and config check (no build)
packer build -var-file=prod.pkrvars.hcl .
```

Pass secrets through the environment (`PKR_VAR_registry_password`) from your CI secret store, never in a committed `*.pkrvars.hcl`. Mark them `sensitive = true`.

## Docker builder and the Ansible provisioner

- The `docker` source needs a running Docker daemon and an image that has Python (the Ansible modules need it).
- The `ansible` provisioner runs `ansible-playbook` on the machine running Packer. For Docker, you normally need `extra_arguments` such as `["--connection", "docker"]` or the plugin's documented settings (verify in the plugin docs for your version).
- Use `ansible_env_vars` and `extra_arguments` carefully: do not echo secrets and do not use `-vvv` in CI.

## Pin and prove

- Pin the base image by digest: `image = "debian@sha256:..."`, and look up the digest from your own mirror.
- Use the `manifest` post-processor to write `manifest.json`; store it with the build record.
- Sign the resulting image (cosign or Notation; see [CSSE ch3 real-tools](../../../csse-course/ch3-attacking-container-supply-chain/real-tools/cosign-notation.md)) and verify at deploy.

## Converting old templates

JSON templates are legacy. `packer hcl2_upgrade template.json` converts them to HCL2 (verify the command in your version); review the output by hand.

## Alternatives

Docker BuildKit / buildx for container images, EC2 Image Builder and Azure Image Builder for cloud-native pipelines, Kiwi or Kickstart for OS images.
