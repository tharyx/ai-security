# Lesson 05: Code Isolation and Sandboxing

> **Chapter:** 6 · Common Defenses Against Supply Chain Attacks · **Time:** ~4 hours
> **You will:** choose an isolation level for untrusted or third-party code (processes, containers, user-space kernels, micro-VMs, WebAssembly), harden build and install steps, and explain what each layer cannot stop.

| | |
|---|---|
| **Prerequisites** | [Chapter 3 containers](../ch3-attacking-container-supply-chain/README.md); Linux basics |
| **Related repo labs** | [06 docker](../../06-ai-devsecops/docker/README.md) · [06 runtime security](../../06-ai-devsecops/runtime-security/README.md) · [06 kubernetes](../../06-ai-devsecops/kubernetes/README.md) · [05 sandboxing](../../05-agent-security/sandboxing/README.md) · [CAASE workspace-escape](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/workspace-escape) |
| **Labs** | [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md) (checks that enforce isolation settings) · [yarahunter-malware-scan](labs/yarahunter-malware-scan/README.md) |
| **Syllabus line** | Code Isolation and Sandboxing |

## 1. Why isolate

Assume some code you run is hostile or compromised: a dependency, an install script, a build step from a pull request, a plugin. **Isolation limits the damage** when prevention fails. It is the "contain" half of "prevent and contain".

## 2. The isolation ladder

| Level | What it isolates | Strength | Typical use |
|---|---|---|---|
| **Separate OS user, file permissions** | files, processes | weak | basic service accounts |
| **Language / runtime sandbox** (restricted interpreters, permission models such as Deno or Node permission flags) | the runtime's own APIs | moderate; escapes happen | scripting, plugins |
| **Container** (namespaces, cgroups, capabilities, seccomp, AppArmor/SELinux) | processes, files, network, resources | good, **shares the host kernel** | most workloads, CI jobs |
| **User-space kernel sandbox** (for example gVisor) | syscalls handled by a user-space kernel | stronger than plain containers | untrusted multi-tenant code |
| **Micro-VM** (Firecracker, Kata Containers) | own guest kernel under a hypervisor | strong | serverless platforms, untrusted builds |
| **Full VM / separate account or machine** | everything | strongest | highest-risk code, air gaps |
| **WebAssembly runtime** | capability-based, memory-safe sandbox | strong for suitable workloads | plugins, edge functions |

Choose by threat: for "a dependency might steal our secrets", the main control is *what secrets the process can see and where it can connect*, not only which kernel it uses.

## 3. Hardening a container (checklist)

| Setting | Effect |
|---|---|
| Non-root user, `runAsNonRoot` | limits privilege |
| `allowPrivilegeEscalation: false` and `no-new-privileges` | blocks setuid tricks |
| Drop all capabilities, add back only what is needed | smaller kernel attack surface |
| Read-only root filesystem, writable scratch volume | limits persistence |
| `seccompProfile: RuntimeDefault` (or tighter) | blocks risky syscalls |
| No privileged mode, no host namespaces, no Docker socket | closes classic escapes |
| CPU, memory, process limits | contains runaway code |
| Network policy or no network | limits exfiltration |
| No service account token unless needed | limits cluster access |

These map to the checks in the [kubescape-manifest-scan](labs/kubescape-manifest-scan/README.md) lab and the [06 kubernetes checker](../../06-ai-devsecops/kubernetes/README.md). Kubernetes **Pod Security Admission** profiles (privileged, baseline, restricted) enforce them cluster-wide; PodSecurityPolicy was removed in Kubernetes 1.25.

## 4. Isolating the build and install steps

Many supply-chain attacks run **during install or build**, where secrets are plentiful:

- **Ephemeral runners.** A fresh VM or container per job, destroyed after. No state, no leftover credentials.
- **No secrets for untrusted code.** Jobs triggered from forks or untrusted branches get none ([PPE](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md)).
- **Least-privilege job tokens** and short-lived cloud credentials (federation).
- **Network egress control** for build jobs: allow only your package proxy and registry. A malicious install script then has nowhere to send data.
- **Hermetic builds.** Dependencies fetched in one controlled step (with hashes), then the build runs without network.
- **Install scripts off by default** (for example `npm ci --ignore-scripts`) and run needed ones in a sandbox.
- **Separate build and sign.** The environment that compiles untrusted dependencies should not hold the signing key; signing is a separate, tightly controlled step.
- **Dev containers and VMs** for developers who evaluate unknown packages; do not test suspicious code on a machine with SSH keys and cloud credentials.

## 5. Runtime detection complements isolation

Isolation reduces what code can do; **runtime detection** watches what it does: unexpected process execution, outbound connections, writes to sensitive paths. See [06 runtime security](../../06-ai-devsecops/runtime-security/README.md) and Falco-style rules. A malware-scan step with YARA-style rules ([yarahunter twin](labs/yarahunter-malware-scan/README.md)) finds known-bad content in images before deploy.

## 6. Honest limits

- A container is **not a security boundary against kernel bugs**; use stronger isolation for hostile code.
- Isolation does not fix what is *inside* the sandbox: a poisoned dependency can still corrupt the output you ship. That is why signing, provenance and review remain necessary.
- Mounting secrets or the Docker socket into the sandbox cancels the isolation.

## Defend (summary)

Pick the isolation level by threat · harden containers by default · ephemeral, egress-controlled, secret-free builds for untrusted code · separate signing from building · add runtime detection.

## Hands-on

1. Run the manifest scan on the "bad" Deployment and fix each failed control until the score is 100.
2. Write an egress allow-list for a build job that needs only your package proxy and registry.
3. Read the [CAASE workspace-escape lab](../../caase-course/ch4-computer-use-browser-and-coding-agents/labs/workspace-escape) and note which isolation level each runtime represents.

## Scenarios

- **A pull request from a fork changes `package.json` to add a postinstall script.** What contains the damage? (No secrets for fork jobs, ephemeral runner, egress allow-list, `--ignore-scripts`.)
- **A team runs a third-party analysis plugin inside the main app process.** What do you propose? (Run it in a separate sandboxed process or Wasm runtime with only the inputs it needs.)

## Interview Q&A

<details><summary>Containers or VMs for untrusted code?</summary>

Containers share the host kernel, so a kernel flaw can break out. For hostile code, use a micro-VM or user-space kernel sandbox, or a separate machine; use containers for lower-risk isolation with good hardening.
</details>

<details><summary>Why block egress from build jobs?</summary>

Most malicious install scripts need to send stolen data out. Without a route, the theft fails and the attempt is visible in logs.
</details>

## References

- Kubernetes Pod Security Standards; Docker and Kubernetes security docs; gVisor, Firecracker, Kata Containers documentation; seccomp and AppArmor docs (verify current pages).
- Repo: [06 docker](../../06-ai-devsecops/docker/README.md), [06 runtime security](../../06-ai-devsecops/runtime-security/README.md), [05 sandboxing](../../05-agent-security/sandboxing/README.md).
