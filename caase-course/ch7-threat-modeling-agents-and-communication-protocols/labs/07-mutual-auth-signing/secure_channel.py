"""Mutual authentication and message signing across A2A / ACP / UCP-style channels (Chapter 7, lab 7).

One small design, reused for all three protocol labels ("a2a", "acp", "ucp"). It is a teaching model of the
pattern, not a replacement for mTLS, OAuth/OIDC or the signing options of the real specifications:

  Handshake (3 messages, mutual):
    1. client -> server  hello   {proto, from, offered suites, nonce_c}
    2. server -> client  reply   {from, chosen suite, nonce_s, offered_seen, sig over the TRANSCRIPT}
    3. client -> server  finish  {sig over the transcript}
  The transcript contains the client's offered list as the server saw it. A man in the middle who strips the
  strong suites changes that list, so the server's signature no longer matches what the client sent: DOWNGRADE
  DETECTED. A policy floor (min_suite) also refuses "none".
  Messages after the handshake: {proto, sid, from, to, ts, nonce, body, sig}.
    * proto + sid are signed, so a message from an A2A session cannot be replayed into a UCP session
    * ts window + single-use nonce give replay protection
Suites: "none" (no auth, insecure), "hmac-sha256" (shared secret per pair), "ed25519" (needs the optional
`cryptography` package; each side holds its own private key and the peer's PUBLIC key).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets

PROTOCOLS = ("a2a", "acp", "ucp")
RANK = {"none": 0, "hmac-sha256": 1, "ed25519": 2}
FRESH_SECONDS = 60


class HandshakeError(Exception):
    pass


class MessageError(Exception):
    pass


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


class Party:
    def __init__(self, name: str, supported: list[str], min_suite: str = "hmac-sha256", *,
                 hmac_keys: dict[str, bytes] | None = None, ed_private=None, ed_publics: dict | None = None, clock=None):
        self.name, self.supported, self.min_suite = name, supported, min_suite
        self.hmac_keys, self.ed_private, self.ed_publics = hmac_keys or {}, ed_private, ed_publics or {}
        self.clock = clock or (lambda: 1_800_000_000.0)

    # --- primitives per suite -----------------------------------------------------------------
    def sign(self, suite: str, peer: str, data: bytes) -> str:
        if suite == "none":
            return ""
        if suite == "hmac-sha256":
            return hmac.new(self.hmac_keys[peer], data, hashlib.sha256).hexdigest()
        if suite == "ed25519":
            return self.ed_private.sign(data).hex()
        raise HandshakeError(f"unknown suite {suite}")

    def verify(self, suite: str, peer: str, data: bytes, sig: str) -> bool:
        if suite == "none":
            return True  # that is the problem with "none"
        try:
            if suite == "hmac-sha256":
                return hmac.compare_digest(sig, hmac.new(self.hmac_keys[peer], data, hashlib.sha256).hexdigest())
            if suite == "ed25519":
                self.ed_publics[peer].verify(bytes.fromhex(sig), data)
                return True
        except Exception:
            return False
        return False

    # --- handshake ---------------------------------------------------------------------------------
    def hello(self, proto: str) -> dict:
        if proto not in PROTOCOLS:
            raise HandshakeError("unknown protocol")
        return {"proto": proto, "from": self.name, "offered": list(self.supported), "nonce_c": secrets.token_hex(8)}

    def accept(self, hello: dict) -> dict:
        ok = [s for s in hello["offered"] if s in self.supported and RANK.get(s, -1) >= RANK[self.min_suite]]
        if not ok:
            raise HandshakeError("no acceptable suite (policy floor)")
        chosen = max(ok, key=RANK.get)
        part = {"from": self.name, "chosen": chosen, "nonce_s": secrets.token_hex(8), "offered_seen": hello["offered"]}
        transcript = canon({"hello": hello, "server": part})
        return {**part, "sig": self.sign(chosen, hello["from"], transcript + b"|server")}

    def confirm(self, my_hello: dict, reply: dict) -> dict:
        part = {k: v for k, v in reply.items() if k != "sig"}
        if reply["chosen"] not in my_hello["offered"] or RANK[reply["chosen"]] < RANK[self.min_suite]:
            raise HandshakeError("suite not acceptable to client")
        if reply["offered_seen"] != my_hello["offered"]:
            raise HandshakeError("downgrade detected: offered list was altered")
        transcript = canon({"hello": my_hello, "server": part})
        if not self.verify(reply["chosen"], reply["from"], transcript + b"|server", reply["sig"]):
            raise HandshakeError("server failed authentication")
        sid = hashlib.sha256(transcript).hexdigest()[:16]
        finish = {"sig": self.sign(reply["chosen"], reply["from"], transcript + b"|client")}
        return {"finish": finish, "session": Session(self, reply["from"], my_hello["proto"], reply["chosen"], sid)}

    def complete(self, hello: dict, reply: dict, finish: dict) -> "Session":
        part = {k: v for k, v in reply.items() if k != "sig"}
        transcript = canon({"hello": hello, "server": part})
        if not self.verify(reply["chosen"], hello["from"], transcript + b"|client", finish["sig"]):
            raise HandshakeError("client failed authentication")
        sid = hashlib.sha256(transcript).hexdigest()[:16]
        return Session(self, hello["from"], hello["proto"], reply["chosen"], sid)


class Session:
    def __init__(self, me: Party, peer: str, proto: str, suite: str, sid: str):
        self.me, self.peer, self.proto, self.suite, self.sid = me, peer, proto, suite, sid
        self.seen: set[str] = set()

    def send(self, body: dict) -> dict:
        env = {"proto": self.proto, "sid": self.sid, "from": self.me.name, "to": self.peer,
               "ts": self.me.clock(), "nonce": secrets.token_hex(8), "body": body}
        env["sig"] = self.me.sign(self.suite, self.peer, canon(env))
        return env

    def receive(self, env: dict) -> dict:
        unsigned = {k: v for k, v in env.items() if k != "sig"}
        if env.get("proto") != self.proto:
            raise MessageError("wrong protocol for this session")
        if env.get("sid") != self.sid:
            raise MessageError("wrong session")
        if env.get("from") != self.peer or env.get("to") != self.me.name:
            raise MessageError("wrong sender or recipient")
        if not self.me.verify(self.suite, self.peer, canon(unsigned), env.get("sig", "")):
            raise MessageError("bad signature")
        if abs(self.me.clock() - env["ts"]) > FRESH_SECONDS:
            raise MessageError("stale message")
        if env["nonce"] in self.seen:
            raise MessageError("replayed message")
        self.seen.add(env["nonce"])
        return env["body"]


class Mitm:
    """Active attacker on the wire: may rewrite the hello and/or the reply."""

    def __init__(self, strip_to: list[str] | None = None):
        self.strip_to = strip_to

    def on_hello(self, hello: dict) -> dict:
        if self.strip_to is None:
            return hello
        return {**hello, "offered": [s for s in hello["offered"] if s in self.strip_to]}

    def on_reply(self, reply: dict, original_hello: dict) -> dict:
        """If the chosen suite is "none" the reply carries no signature, so the attacker can repair offered_seen."""
        if self.strip_to is not None and reply["chosen"] == "none":
            return {**reply, "offered_seen": original_hello["offered"]}
        return reply


def connect(client: Party, server: Party, proto: str, mitm: Mitm | None = None) -> tuple[Session, Session]:
    my_hello = client.hello(proto)
    wire_hello = mitm.on_hello(my_hello) if mitm else my_hello
    reply = server.accept(wire_hello)
    if mitm:
        reply = mitm.on_reply(reply, my_hello)
    out = client.confirm(my_hello, reply)
    server_session = server.complete(wire_hello, reply, out["finish"])
    return out["session"], server_session


def make_hmac_pair(floor: str = "hmac-sha256", clock=None) -> tuple[Party, Party]:
    k = b"FAKE-pairwise-secret"
    a = Party("agent-a", ["none", "hmac-sha256"], floor, hmac_keys={"agent-b": k}, clock=clock)
    b = Party("agent-b", ["none", "hmac-sha256"], floor, hmac_keys={"agent-a": k}, clock=clock)
    return a, b


def make_ed25519_pair(floor: str = "ed25519", clock=None) -> tuple[Party, Party]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ka, kb = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    a = Party("agent-a", ["none", "hmac-sha256", "ed25519"], floor, hmac_keys={"agent-b": b"FAKE-pairwise-secret"},
              ed_private=ka, ed_publics={"agent-b": kb.public_key()}, clock=clock)
    b = Party("agent-b", ["none", "hmac-sha256", "ed25519"], floor, hmac_keys={"agent-a": b"FAKE-pairwise-secret"},
              ed_private=kb, ed_publics={"agent-a": ka.public_key()}, clock=clock)
    return a, b
