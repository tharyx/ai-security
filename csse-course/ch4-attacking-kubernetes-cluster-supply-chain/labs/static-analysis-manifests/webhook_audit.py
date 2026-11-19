"""Admission webhook audit and a bypass simulation (offline).

Admission webhooks are called by the API server during the request pipeline:
  authentication -> authorization -> mutating admission -> schema validation -> validating admission -> etcd
Weak configuration lets a request skip the check; a malicious mutating webhook can change what gets stored.
"""
from __future__ import annotations

from dataclasses import dataclass

import yaml


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str
    message: str


def load(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if d]


def _ns_selector_exempts(sel: dict | None) -> bool:
    """A selector that lets namespaces opt out by label (DoesNotExist on a label anyone can add)."""
    for e in (sel or {}).get("matchExpressions", []):
        if e.get("operator") == "DoesNotExist":
            return True
    return False


def audit(docs: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for d in docs:
        kind = d["kind"]
        if kind not in ("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
            continue
        for w in d.get("webhooks", []):
            where = f"{kind}/{d['metadata']['name']}:{w['name']}"
            validating = kind.startswith("Validating")
            if w.get("failurePolicy", "Fail") == "Ignore":
                out.append(Finding("WH-001", "HIGH" if validating else "MEDIUM", where,
                                   "failurePolicy Ignore: if the webhook is down, slow or crashed, requests are admitted unchecked (an outage or a DoS becomes a bypass)"))
            if _ns_selector_exempts(w.get("namespaceSelector")):
                out.append(Finding("WH-002", "HIGH", where, "namespaceSelector lets anyone who can label a namespace opt out of the policy"))
            cc = w.get("clientConfig", {})
            if str(cc.get("url", "")).startswith("http://"):
                out.append(Finding("WH-003", "CRITICAL", where, "webhook called over plain HTTP: the API server's requests (full objects, incl. Secrets) can be read or altered"))
            elif "url" in cc and "caBundle" not in cc:
                out.append(Finding("WH-004", "HIGH", where, "external webhook URL without a caBundle: server identity is not pinned"))
            if "service" in cc and "caBundle" not in cc:
                out.append(Finding("WH-004", "MEDIUM", where, "no caBundle: relies on the cluster trust store; pin the webhook CA"))
            if w.get("timeoutSeconds", 10) > 10:
                out.append(Finding("WH-005", "MEDIUM", where, f"timeout {w['timeoutSeconds']}s is long: an attacker can slow the API server (and with Ignore, wait out the check)"))
            if w.get("sideEffects") in (None, "Unknown", "Some"):
                out.append(Finding("WH-006", "LOW", where, "sideEffects must be None or NoneOnDryRun so dry runs are safe"))
            for r in w.get("rules", []):
                if "*" in r.get("resources", []) and "*" in r.get("apiGroups", []):
                    sev = "HIGH" if not validating else "MEDIUM"
                    out.append(Finding("WH-007", sev, where, "matches every resource: a mutating webhook this wide can rewrite anything stored in the cluster"))
            if not validating:
                out.append(Finding("WH-008", "INFO", where, "mutating webhooks change objects; review who controls the webhook service (a malicious one can inject containers or env)"))
    return out


def admits(webhook: dict, namespace_labels: dict, *, webhook_down: bool) -> str:
    """Would the API server admit the request when this webhook is configured like this?"""
    for e in (webhook.get("namespaceSelector") or {}).get("matchExpressions", []):
        key, op = e["key"], e["operator"]
        if op == "DoesNotExist" and key in namespace_labels:
            return "ADMIT (namespace is exempt: webhook never called)"
        if op == "NotIn" and namespace_labels.get(key) in e.get("values", []):
            return "ADMIT (namespace excluded by selector)"
    if webhook_down:
        return "ADMIT (failurePolicy Ignore, webhook unreachable)" if webhook.get("failurePolicy", "Fail") == "Ignore" else "REJECT (failurePolicy Fail, webhook unreachable)"
    return "CALL webhook and enforce its answer"
