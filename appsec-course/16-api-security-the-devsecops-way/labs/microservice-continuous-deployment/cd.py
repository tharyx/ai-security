"""Continuous deployment of API microservices: admission policy, rolling and canary rollouts,
health checks and automatic rollback. Everything is simulated in memory; nothing is deployed.

Admission policy (what a cluster admission controller or deploy job checks before rollout):
  * image referenced by digest (`name@sha256:...`), never a mutable tag such as `:latest`
  * image signature valid (simulated cosign-style: HMAC over the digest with a FAKE lab key;
    real cosign uses asymmetric keys or keyless signing, verify at sigstore.dev)
  * the pipeline's security gates (SCA/SAST/DAST) passed for this exact digest
  * production only receives a digest that already succeeded in staging
Rollout:
  * services are deployed in dependency order (backends before the gateway that calls them)
  * rolling: replace one replica at a time, health-check each, roll back everything on failure
  * canary: send a share of traffic to the new version, compare its error rate, promote or roll back
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from typing import Callable

DIGEST_RE = re.compile(r"^[a-z0-9./-]+@sha256:[0-9a-f]{64}$")


def fake_signing_key() -> bytes:
    return b"FAKE-lab-signing-key-" + secrets.token_bytes(16)


def build_image(name: str, content: str) -> str:
    return f"{name}@sha256:{hashlib.sha256(content.encode()).hexdigest()}"


def sign(key: bytes, image: str) -> str:
    return hmac.new(key, image.split("@", 1)[-1].encode(), hashlib.sha256).hexdigest()


@dataclass
class Release:
    service: str
    image: str
    signature: str
    gates_passed: bool


@dataclass
class Cluster:
    name: str
    replicas: dict[str, list[str]] = field(default_factory=dict)  # service -> image per replica


@dataclass
class Deployer:
    signing_key: bytes
    dependencies: dict[str, list[str]]
    health: Callable[[str, str], bool]                 # (service, image) -> healthy?
    error_rate: Callable[[str, str], float] = lambda s, i: 0.0
    staging_ok: set[str] = field(default_factory=set)   # digests that succeeded in staging
    audit: list[str] = field(default_factory=list)

    # ---------------------------------------------------------- admission
    def admit(self, rel: Release, env: str) -> list[str]:
        problems = []
        if not DIGEST_RE.match(rel.image):
            problems.append(f"{rel.service}: image must be pinned by digest, got {rel.image!r}")
        elif not hmac.compare_digest(sign(self.signing_key, rel.image), rel.signature):
            problems.append(f"{rel.service}: signature does not verify for {rel.image[-12:]}")
        if not rel.gates_passed:
            problems.append(f"{rel.service}: security gates (SCA/SAST/DAST) did not pass for this digest")
        if env == "prod" and rel.image not in self.staging_ok:
            problems.append(f"{rel.service}: digest never succeeded in staging")
        return problems

    # ---------------------------------------------------------- ordering
    def order(self, services: list[str]) -> list[str]:
        out, seen = [], set()

        def visit(s: str, stack: tuple = ()) -> None:
            if s in stack:
                raise ValueError(f"dependency cycle at {s}")
            if s in seen:
                return
            for d in self.dependencies.get(s, []):
                if d in services:
                    visit(d, stack + (s,))
            seen.add(s)
            out.append(s)

        for s in sorted(services):
            visit(s)
        return out

    # ---------------------------------------------------------- strategies
    def rolling(self, cluster: Cluster, rel: Release) -> str:
        old = list(cluster.replicas[rel.service])
        for i in range(len(old)):
            cluster.replicas[rel.service][i] = rel.image
            if not self.health(rel.service, rel.image):
                cluster.replicas[rel.service] = old  # automatic rollback of every replaced replica
                self.audit.append(f"{cluster.name}: {rel.service} rolled back after replica {i + 1} failed health check")
                return "rolled-back"
        self.audit.append(f"{cluster.name}: {rel.service} rolled out to {len(old)} replicas")
        return "deployed"

    def canary(self, cluster: Cluster, rel: Release, max_error_rate: float = 0.02, share: float = 0.1) -> str:
        old = list(cluster.replicas[rel.service])
        stable_errors = self.error_rate(rel.service, old[0])
        canary_errors = self.error_rate(rel.service, rel.image)
        self.audit.append(f"{cluster.name}: {rel.service} canary {share:.0%}: error rate {canary_errors:.1%} vs stable {stable_errors:.1%}")
        if not self.health(rel.service, rel.image) or canary_errors > max(max_error_rate, 2 * stable_errors):
            self.audit.append(f"{cluster.name}: {rel.service} canary rejected, traffic back to stable")
            return "rolled-back"
        cluster.replicas[rel.service] = [rel.image] * len(old)
        self.audit.append(f"{cluster.name}: {rel.service} canary promoted")
        return "deployed"

    # ---------------------------------------------------------- the deploy job
    def deploy(self, cluster: Cluster, releases: list[Release], env: str, strategy: str = "rolling") -> dict[str, str]:
        by_name = {r.service: r for r in releases}
        results: dict[str, str] = {}
        for svc in self.order(list(by_name)):
            rel = by_name[svc]
            problems = self.admit(rel, env)
            if problems:
                results[svc] = "rejected: " + "; ".join(problems)
                self.audit.append(f"{cluster.name}: {svc} rejected by admission policy")
                continue
            if any(results.get(d, "deployed") != "deployed" for d in self.dependencies.get(svc, []) if d in by_name):
                results[svc] = "skipped: a dependency did not deploy"
                continue
            results[svc] = self.rolling(cluster, rel) if strategy == "rolling" else self.canary(cluster, rel)
            if env == "staging" and results[svc] == "deployed":
                self.staging_ok.add(rel.image)
        return results
