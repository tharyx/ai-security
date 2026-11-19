"""A NetworkPolicy evaluator: default deny plus allow rules, and pod-to-pod reachability.

Kubernetes NetworkPolicy rules (enforced by a CNI such as Calico or Cilium; a plain CNI without policy support ignores them):
  - A pod with NO policy selecting it is open (allow all) for that direction.
  - A pod selected by any policy with that policyType is isolated for that direction: only listed rules allow traffic.
  - Policies only ADD allowances (they are a union). There is no "deny" rule in the core API.
  - Traffic needs BOTH ends to agree: source egress AND destination ingress.
Calico adds its own GlobalNetworkPolicy and explicit Deny rules (concept only in this lab).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Pod:
    name: str
    namespace: str
    labels: dict = field(default_factory=dict, hash=False, compare=False)

    @property
    def ref(self) -> str:
        return f"{self.namespace}/{self.name}"


def selector_matches(selector: dict | None, labels: dict) -> bool:
    """matchLabels and matchExpressions. An empty selector ({}) matches everything; None matches nothing."""
    if selector is None:
        return False
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, vals = expr["key"], expr["operator"], expr.get("values", [])
        present = key in labels
        if op == "In" and labels.get(key) not in vals:
            return False
        if op == "NotIn" and present and labels[key] in vals:
            return False
        if op == "Exists" and not present:
            return False
        if op == "DoesNotExist" and present:
            return False
    return True


class Cluster:
    def __init__(self, pods: list[Pod], namespaces: dict[str, dict], policies: list[dict]) -> None:
        self.pods, self.ns_labels, self.policies = pods, namespaces, policies

    def _selected(self, pod: Pod, direction: str) -> list[dict]:
        out = []
        for p in self.policies:
            meta, spec = p["metadata"], p["spec"]
            if meta.get("namespace", "default") != pod.namespace:
                continue
            types = spec.get("policyTypes") or (["Ingress"] + (["Egress"] if spec.get("egress") else []))
            if direction in types and selector_matches(spec.get("podSelector", {}), pod.labels):
                out.append(p)
        return out

    def _peer_matches(self, peer: dict, policy_ns: str, other: Pod) -> bool:
        if "ipBlock" in peer:
            return False  # pods are matched by selector; ipBlock is for outside addresses
        ns_sel, pod_sel = peer.get("namespaceSelector"), peer.get("podSelector")
        if ns_sel is None and pod_sel is None:
            return False
        if ns_sel is not None:
            labels = {**self.ns_labels.get(other.namespace, {}), "kubernetes.io/metadata.name": other.namespace}
            if not selector_matches(ns_sel, labels):
                return False
        elif other.namespace != policy_ns:
            return False  # podSelector alone means "in the policy's own namespace"
        return pod_sel is None or selector_matches(pod_sel, other.labels)

    @staticmethod
    def _port_ok(ports: list[dict] | None, port: int) -> bool:
        if not ports:
            return True
        for p in ports:
            lo = p.get("port")
            hi = p.get("endPort", lo)
            if isinstance(lo, int) and lo <= port <= hi:
                return True
        return False

    def _allows(self, pod: Pod, other: Pod, port: int, direction: str) -> bool:
        selected = self._selected(pod, direction)
        if not selected:
            return True  # not isolated in this direction
        key, peers = ("ingress", "from") if direction == "Ingress" else ("egress", "to")
        for p in selected:
            for rule in p["spec"].get(key) or []:
                rule_peers = rule.get(peers)
                peer_ok = rule_peers is None or any(self._peer_matches(x, p["metadata"].get("namespace", "default"), other) for x in rule_peers)
                if peer_ok and self._port_ok(rule.get("ports"), port):
                    return True
        return False

    def can_reach(self, src: Pod, dst: Pod, port: int) -> bool:
        return self._allows(src, dst, port, "Egress") and self._allows(dst, src, port, "Ingress")

    def matrix(self, port: int) -> dict[tuple[str, str], bool]:
        return {(a.ref, b.ref): self.can_reach(a, b, port) for a in self.pods for b in self.pods if a != b}

    def isolated(self, pod: Pod) -> dict[str, bool]:
        return {d: bool(self._selected(pod, d)) for d in ("Ingress", "Egress")}


def exposed_pods(cluster: Cluster) -> list[str]:
    """Pods that are not isolated for ingress: anything in the cluster can talk to them."""
    return [p.ref for p in cluster.pods if not cluster.isolated(p)["Ingress"]]
