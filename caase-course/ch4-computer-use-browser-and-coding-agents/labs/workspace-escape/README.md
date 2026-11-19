# Lab: Comparing Workspace Escape Resistance Across Standard vs. Container-Isolated Agent Runtimes

**Course exercise:** "Comparing Workspace Escape Resistance Across Standard vs. Container-Isolated Agent Runtimes". Lessons: [02 section 3](../../02-attacking-coding-agents.md#3-escaping-the-intended-repositoryworkspace-scope), [05](../../05-defending-computer-use-and-coding-agents.md#2-container-isolation-as-a-security-model). Background: [sandboxing](../../../../05-agent-security/sandboxing/README.md), [Docker lab](../../../../06-ai-devsecops/docker/README.md), [CMCPSE Filesystem server path bypasses](../../../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/05-real-world-case-studies.md).

**Time:** 45 minutes. **Safety:** temp directories only. The "secret" is a FAKE canary file. Symlinks are created inside the temp directory; if your OS or user cannot create symlinks, the symlink attack is reported as `skipped` (on Windows this may need Developer Mode).

## The two runtimes

| | `StandardRuntime` | `IsolatedRuntime` |
|---|---|---|
| Idea | join the path, check a string prefix | chroot-like virtual root: re-root every path (an absolute path means "inside the root"), `realpath` (resolves `..` and symlinks), then compare with the real root |
| Shell `cd` | checked with the same flawed rule | every `cd` is canonicalised and checked |
| Policy | none | deny globs (`.env`, `*.pem`, `id_*`), size limit, audit log |

Layout in the temp dir: `work/` (the workspace), `outside/secret.txt`, and a sibling `work-evil/secret.txt` whose name **starts with** the workspace name.

## Attacks (8)

`dotdot`, `nested-dotdot`, `absolute-path`, `prefix-sibling`, `absolute-prefix-sibling`, `symlink`, `shell-cd-dotdot`, `shell-absolute-cat`. An attack counts as an **escape** only if the canary text came back.

## Steps

```text
.venv/Scripts/python caase-course/ch4-computer-use-browser-and-coding-agents/labs/workspace-escape/demo.py
.venv/Scripts/python -m pytest caase-course/ch4-computer-use-browser-and-coding-agents/labs/workspace-escape -v
```

1. Run the demo. Note that the standard runtime's prefix check blocks the plain absolute path but not the sibling directory whose name begins with the same text.
2. Change `StandardRuntime._resolve` to also reject `..`. Which attacks still escape? (The symlink and the absolute path into the sibling directory.)
3. Change it to use `realpath` but keep `startswith`. Which still escape? (`prefix-sibling` and `absolute-prefix-sibling`: `work-evil` starts with `work`. Compare **path components**, not strings.)
4. Read `test_defence_in_depth_note...`: isolation does not limit what the agent can do **inside** the workspace. Least privilege inside is still your job.

## Expected output (real run)

```text
symlinks available: True

== standard runtime: escapes=6 blocked=2 ==
  dotdot                   ESCAPED
  nested-dotdot            ESCAPED
  absolute-path            blocked
  prefix-sibling           ESCAPED
  absolute-prefix-sibling  ESCAPED
  symlink                  ESCAPED
  shell-cd-dotdot          ESCAPED
  shell-absolute-cat       blocked

== isolated runtime: escapes=0 blocked=8 ==
  (all eight blocked)
```

## Real containers (hedged)

A real container adds what this sketch cannot: a separate mount namespace (the host paths do not exist), a non-root user, no capabilities, a read-only root file system, and network limits. Try `docker run --rm --network none --read-only -v "$PWD":/work:rw -w /work --user 1000:1000 ...` on a machine with Docker; check your Docker version's docs. Never mount the Docker socket or your home directory.
