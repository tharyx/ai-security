"""A policy-driven AI firewall (gateway) for an MCP server. Config in, behaviour out.

Order of checks for every request:
  1. method allowlist
  2. tool allowlist (default deny) and argument limits
  3. rate limits (per client and per tool, sliding window)
  4. forward to the upstream server
  5. inspect the RESULT: injection score on tool output, secret redaction, size cap
  6. tools/list is filtered: denied tools are hidden, poisoned descriptions are dropped
Every decision is written to an audit list (arguments are hashed, never logged).

Teaching gateway. It is not a complete defence: the regex signals are easy to evade. Layers matter
(see the chapter 4 firewall lab and LLM Guard). What this lab teaches is DEPLOYMENT: a policy file,
modes, fail-closed loading, rate limits, audit, and tuning.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict, deque
from pathlib import Path

import yaml

MODES = {"enforce", "monitor"}
ACTIONS = {"block", "sanitize", "flag"}


def load_policy(source) -> dict:
    """Load and validate a policy (path, YAML text or dict). Raise ValueError: a bad policy never deploys."""
    if isinstance(source, dict):
        policy = source
    else:
        text = Path(source).read_text(encoding="utf-8") if Path(str(source)).exists() else str(source)
        policy = yaml.safe_load(text)
    problems = []
    if not isinstance(policy, dict):
        raise ValueError("policy must be a mapping")
    if policy.get("mode") not in MODES:
        problems.append("mode must be enforce or monitor")
    if not policy.get("tools", {}).get("allow"):
        problems.append("tools.allow must list at least one tool")
    if not policy.get("methods", {}).get("allow"):
        problems.append("methods.allow must be set")
    inj = policy.get("injection", {})
    if inj.get("action") not in ACTIONS:
        problems.append("injection.action must be block, sanitize or flag")
    if not isinstance(inj.get("threshold"), (int, float)) or not 0 <= inj["threshold"] <= 1:
        problems.append("injection.threshold must be between 0 and 1")
    for signal in inj.get("signals", []):
        try:
            re.compile(signal["pattern"])
        except (re.error, KeyError, TypeError):
            problems.append(f"bad injection signal: {signal!r}")
    for rule in policy.get("output", {}).get("redact", []):
        try:
            re.compile(rule["pattern"])
        except (re.error, KeyError, TypeError):
            problems.append(f"bad redact rule: {rule!r}")
    limits = policy.get("rate_limits", {})
    for scope in [limits.get("per_client")] + list(limits.get("per_tool", {}).values()):
        if scope is not None and not (isinstance(scope.get("requests"), int) and scope["requests"] > 0 and scope.get("window_seconds", 0) > 0):
            problems.append(f"bad rate limit: {scope!r}")
    if policy.get("output", {}).get("on_secret", "redact") not in {"redact", "block"}:
        problems.append("output.on_secret must be redact or block")
    if problems:
        raise ValueError("invalid firewall policy: " + "; ".join(problems))
    return policy


def score_injection(policy: dict, text: str) -> tuple[float, list[str]]:
    """Sum of matched signal weights (capped at 1.0) and the names of the signals that matched."""
    names, score = [], 0.0
    for signal in policy["injection"].get("signals", []):
        if re.search(signal["pattern"], text, re.IGNORECASE):
            names.append(signal["name"])
            score += signal["weight"]
    return min(score, 1.0), names


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


class Gateway:
    def __init__(self, policy: dict, upstream, clock=time.monotonic):
        self.policy, self.upstream, self.clock = policy, upstream, clock
        self.audit: list[dict] = []
        self._hits: dict = defaultdict(deque)

    # ---------------------------------------------------------------- helpers
    @property
    def enforce(self) -> bool:
        return self.policy["mode"] == "enforce"

    def _log(self, client, method, tool, decision, reasons=(), score=None, args=None):
        entry = {"client": client, "method": method, "tool": tool, "decision": decision, "reasons": list(reasons), "score": score}
        if args is not None:
            entry["args_sha256"] = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:12]
        self.audit.append(entry)

    def _rate_limited(self, client: str, tool: str) -> str | None:
        limits = self.policy.get("rate_limits", {})
        now = self.clock()
        checks = []
        if limits.get("per_client"):
            checks.append(((client, "*"), limits["per_client"]))
        if tool in limits.get("per_tool", {}):
            checks.append(((client, tool), limits["per_tool"][tool]))
        # Count first, then record, so a refused call does not use up quota.
        for key, rule in checks:
            hits = self._hits[key]
            while hits and now - hits[0] >= rule["window_seconds"]:
                hits.popleft()
            if len(hits) >= rule["requests"]:
                return f"rate limit for {key[1]}"
        for key, _ in checks:
            self._hits[key].append(now)
        return None

    # ---------------------------------------------------------------- main entry
    def handle(self, client: str, request: dict) -> dict:
        rid = request.get("id")
        method = request.get("method")
        if method not in self.policy["methods"]["allow"]:
            self._log(client, method, None, "deny", ["method not allowed"])
            return _error(rid, -32601, "method not allowed")
        if method == "tools/list":
            return self._list(client, request)
        if method != "tools/call":
            return self.upstream.handle(request)
        return self._call(client, request)

    def _list(self, client: str, request: dict) -> dict:
        response = self.upstream.handle(request)
        allowed = set(self.policy["tools"]["allow"])
        kept, hidden = [], []
        for tool in response["result"]["tools"]:
            score, names = score_injection(self.policy, tool.get("description", ""))
            if tool["name"] not in allowed:
                hidden.append(f"{tool['name']}: not allowed")
            elif score >= self.policy["injection"]["threshold"]:
                hidden.append(f"{tool['name']}: poisoned description ({', '.join(names)})")
            else:
                kept.append(tool)
        self._log(client, "tools/list", None, "filtered" if hidden else "allow", hidden)
        if not self.enforce:
            return response
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": kept}}

    def _call(self, client: str, request: dict) -> dict:
        rid = request.get("id")
        params = request.get("params") or {}
        tool, args = params.get("name"), params.get("arguments", {})
        reasons = []
        if tool not in self.policy["tools"]["allow"]:
            reasons.append("tool not allowed")
        if not isinstance(args, dict):
            reasons.append("arguments must be an object")
        else:
            cap = self.policy["tools"].get("max_string_length", 1000)
            if any(isinstance(v, str) and len(v) > cap for v in args.values()):
                reasons.append("argument too long")
        if not reasons:
            limited = self._rate_limited(client, tool)
            if limited:
                reasons.append(limited)
        if reasons:
            self._log(client, "tools/call", tool, "deny" if self.enforce else "would-deny", reasons, args=args)
            if self.enforce:
                code = -32029 if reasons[0].startswith("rate limit") else -32001
                return _error(rid, code, "request refused by policy: " + reasons[0])
        try:
            response = self.upstream.handle(request)
        except Exception:  # noqa: BLE001 - fail closed with a generic message
            self._log(client, "tools/call", tool, "upstream-error", args=args if isinstance(args, dict) else None)
            return _error(rid, -32000, "upstream error")
        return self._inspect(client, tool, args, response)

    def _inspect(self, client, tool, args, response: dict) -> dict:
        if "result" not in response:
            return response
        blocks = response["result"].get("content", [])
        out_cfg = self.policy.get("output", {})
        reasons, final_blocks, worst = [], [], 0.0
        action = self.policy["injection"]["action"]
        for block in blocks:
            text = block.get("text", "")
            if self.policy["injection"].get("enabled", True):
                score, names = score_injection(self.policy, text)
                worst = max(worst, score)
                if score >= self.policy["injection"]["threshold"]:
                    reasons.append(f"injection score {score:.2f} ({', '.join(names)})")
                    if action == "block" and self.enforce:
                        self._log(client, "tools/call", tool, "block-result", reasons, score, args)
                        return _error(response.get("id"), -32002, "tool result blocked by gateway")
                    if action == "sanitize" and self.enforce:
                        for signal in self.policy["injection"]["signals"]:
                            text = re.sub(signal["pattern"], "[removed by gateway]", text, flags=re.IGNORECASE)
            secrets = [r for r in out_cfg.get("redact", []) if re.search(r["pattern"], text)]
            if secrets:
                reasons.append("sensitive data: " + ", ".join(r["name"] for r in secrets))
                if out_cfg.get("on_secret", "redact") == "block" and self.enforce:
                    self._log(client, "tools/call", tool, "block-result", reasons, worst, args)
                    return _error(response.get("id"), -32003, "tool result blocked by gateway")
                if self.enforce:
                    for rule in secrets:
                        text = re.sub(rule["pattern"], f"[REDACTED:{rule['name']}]", text)
            limit = out_cfg.get("max_bytes")
            if limit and len(text.encode("utf-8")) > limit and self.enforce:
                text = text.encode("utf-8")[:limit].decode("utf-8", "ignore") + " [truncated by gateway]"
                reasons.append("output truncated")
            final_blocks.append({**block, "text": text})
        decision = "allow" if not reasons else ("modified" if self.enforce else "would-modify")
        self._log(client, "tools/call", tool, decision, reasons, worst, args)
        return {**response, "result": {**response["result"], "content": final_blocks}}
