"""A2A-style message spoofing: unsigned vs signed messages with agent identity.

Real A2A (Agent2Agent, now at v1.x under the Linux Foundation / AAIF; verify at
source) declares auth schemes in the Agent Card and runs over HTTPS. This lab is
NOT the wire protocol. It models the security idea: a message must prove WHO sent
it, WHAT it says, WHO it is for, and that it is FRESH.

``InsecureBus`` trusts the ``sender`` field. ``SecureBus`` verifies an HMAC over
the canonical message with the sender's registered key (stdlib HMAC stands in for
the asymmetric signatures a real deployment should use), binds the recipient and
task, and rejects replays and stale messages.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field

MAX_AGE_SECONDS = 60


def canonical(msg: dict) -> bytes:
    body = {k: v for k, v in msg.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(key: bytes, msg: dict) -> dict:
    out = dict(msg)
    out["sig"] = hmac.new(key, canonical(msg), hashlib.sha256).hexdigest()
    return out


def make_message(sender: str, recipient: str, task_id: str, kind: str, payload: dict, now: float) -> dict:
    return {
        "sender": sender,
        "recipient": recipient,
        "task_id": task_id,
        "kind": kind,  # e.g. "task.update"
        "payload": payload,
        "nonce": secrets.token_hex(8),
        "ts": now,
    }


class Rejected(Exception):
    pass


@dataclass
class Worker:
    """Executes a delegated task. The task parameters are what an attacker wants to change."""

    name: str = "worker"
    tasks: dict[str, dict] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)

    def apply(self, msg: dict) -> None:
        self.tasks.setdefault(msg["task_id"], {}).update(msg["payload"])
        self.log.append(f"{msg['kind']} from {msg['sender']}")


class InsecureBus:
    """Trusts whatever the message says about itself."""

    def __init__(self, worker: Worker) -> None:
        self.worker = worker

    def deliver(self, msg: dict, now: float = 0.0) -> None:
        self.worker.apply(msg)


class SecureBus:
    def __init__(self, worker: Worker, keys: dict[str, bytes], allowed_senders: dict[str, set[str]]) -> None:
        """keys: agent id -> key. allowed_senders: task_id -> agent ids allowed to update it."""
        self.worker = worker
        self.keys = keys
        self.allowed = allowed_senders
        self.seen: dict[str, float] = {}  # nonce -> ts

    def deliver(self, msg: dict, now: float) -> None:
        for f in ("sender", "recipient", "task_id", "kind", "payload", "nonce", "ts", "sig"):
            if f not in msg:
                raise Rejected(f"missing field {f}")
        key = self.keys.get(msg["sender"])
        if key is None:
            raise Rejected("unknown sender identity")
        expected = hmac.new(key, canonical(msg), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, msg["sig"]):
            raise Rejected("bad signature (spoofed or tampered)")
        if msg["recipient"] != self.worker.name:
            raise Rejected("message not addressed to this agent (audience mismatch)")
        if abs(now - msg["ts"]) > MAX_AGE_SECONDS:
            raise Rejected("stale message")
        if msg["nonce"] in self.seen:
            raise Rejected("replayed message")
        if msg["sender"] not in self.allowed.get(msg["task_id"], set()):
            raise Rejected("sender not authorized for this task")
        # Prune old nonces so the cache stays bounded.
        self.seen = {n: t for n, t in self.seen.items() if now - t <= MAX_AGE_SECONDS}
        self.seen[msg["nonce"]] = msg["ts"]
        self.worker.apply(msg)
