# Lab: Hardened golden image with Packer and Ansible (validator, simulated build, promotion gate)

**Course exercise:** [CDE 6] "Create hardened Golden images using Packer + Ansible". Lessons: [lesson 03](../../03-packer-golden-images.md).

**Time:** 50 minutes. **Safety:** no Packer, no cloud, no Docker. A small HCL2 **subset** parser reads text fixtures; the "build" is a hash calculation. Secrets in the bad fixture are fake canaries.

## What it does

[packer_lab.py](packer_lab.py) has three parts:

1. **`parse_hcl`**: blocks, labels, attributes, one-line lists and object attributes (enough for `packer`, `variable`, `source`, `build`, `provisioner`, `post-processor`). Not a full HCL parser.
2. **`validate`** with these rules:

| ID | Checks |
|---|---|
| PKR-001 | Base image pinned: Docker `@sha256:` digest, or a literal AMI id (not `most_recent`) |
| PKR-002 | No secrets: no literal default on secret variables, `sensitive = true`, no literal credentials in sources |
| PKR-003 | An `ansible` provisioner with a `playbook_file` is present |
| PKR-004 | A `manifest` post-processor with an `output` |
| PKR-005 | No `curl \| sh` in shell provisioners |
| PKR-006 | Plugin versions pinned (not `>= 0`) |
| PKR-007 | `build.sources` point at defined sources |

3. **`simulate_build`** produces a Packer-manifest-like dict whose `artifact_id` is a hash of the template, base reference and playbook contents; **`promotion_gate`** returns PROMOTE or BLOCK based on validator findings, compliance score, vulnerability counts and an HMAC attestation over the manifest (a stand-in for a cosign or in-toto signature).

## Steps

```text
.venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/packer-ansible-golden-image/demo.py
.venv/Scripts/python -m pytest devsecops-course/08-iac-configuration-and-compliance-as-code/labs/packer-ansible-golden-image -v
```

1. Compare the output for the good and the bad template.
2. In `fixtures/ansible/harden.yml` add a task and re-run the build simulation. What changes in the manifest, and why is that useful?
3. Make `compliance_result.json` report 80. What does the gate say?
4. Tamper with the manifest in the demo. Which check catches it?

## Expected output (real run, abridged)

```text
== golden.pkr.hcl: 0 finding(s) ==
== golden_bad.pkr.hcl: 9 finding(s) ==
  [CRITICAL] PKR-002 source.amazon-ebs.base.access_key: literal credential in the template: use env() or a CI-injected variable
  [CRITICAL] PKR-002 variable.ssh_password: secret variable has a literal default: it lives in git forever
  [HIGH    ] PKR-001 source.amazon-ebs.base: source_ami_filter with most_recent = true: tomorrow's build starts from a different base
  [HIGH    ] PKR-003 build.(unnamed): no ansible provisioner: hardening is not code-reviewed configuration management
  [HIGH    ] PKR-005 build.(unnamed): shell provisioner pipes a download into a shell
  [HIGH    ] PKR-007 build.(unnamed): build references source.amazon-ebs.missing but no such source block exists
  [MEDIUM  ] PKR-002 variable.ssh_password: secret variable is not marked sensitive = true (it can print in logs)
  [MEDIUM  ] PKR-004 build.(unnamed): no manifest post-processor with an output file: the pipeline cannot trace what was built
  [MEDIUM  ] PKR-006 required_plugins.amazon: plugin version constraint >= 0 does not pin anything

Simulated manifest.json:
{
  "builds": [
    {
      "name": "golden.docker.base",
      "builder_type": "docker",
      "build_time": 1700000000,
      "artifact_id": "sha256:91ce0668c654030005261a9cafbcade022707414165fd6f51df75fe40e85509a",
      "packer_run_uuid": "9f77f1be8529ff28f2c67bc7c7ef85e8",
      "custom_data": {
        "base_image": "debian@sha256:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        "playbook_sha256": {
          "./ansible/harden.yml": "cf1be1944689d700315a7fa8dd46aa193b0ad02376156e686271dbf2eb740375"
        },
        "template_sha256": "ef9f033efa00f6234b5d7e60fcbbae6569b67157bc7e8fdf1cc64744d555f3b6"
      }
    }
  ],
  "last_run_uuid": "9f77f1be8529ff28f2c67bc7c7ef85e8"
} ...

Promotion gate: PROMOTE []
...
```

## Run the real tool

`packer init`, `packer validate`, `packer build`: [real-tools/packer.md](../../real-tools/packer.md). Packer is under the BSL licence since Aug 2023 (verify); there is no major fork.
