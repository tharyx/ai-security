import base64
import json

import signed_provenance as sp

KEY = b"FAKE-BUILDER-SECRET-not-real"
BUILDER = "https://example.invalid/hosted-builder"
ART = b"fake wheel bytes"
common = dict(repo_uri="https://github.com/example/app", ref="refs/tags/v1.0.0",
              commit="b" * 40, artifact_name="app.whl", artifact_bytes=ART)
policy = sp.Policy([sp.TrustedBuilder(BUILDER, KEY)], "https://github.com/example/app")

hosted = sp.HostedBuilder(BUILDER, KEY).build_and_sign(**common)
l1_only = sp.self_attested(sp.make_statement(builder_id=BUILDER, **common))
rogue = sp.HostedBuilder("https://attacker.example/builder", b"attacker-key").build_and_sign(**common)

forged = json.loads(base64.b64decode(hosted["payload"]))
forged["subject"][0]["digest"]["sha256"] = sp.sha256_hex(b"evil bytes")
tampered = dict(hosted, payload=base64.b64encode(json.dumps(forged, sort_keys=True).encode()).decode())

cases = [("signed by trusted builder", hosted, ART), ("L1 only (unsigned)", l1_only, ART),
         ("unknown builder", rogue, ART), ("artifact swapped", hosted, b"evil bytes"),
         ("payload edited after signing", tampered, b"evil bytes")]
for label, env, data in cases:
    v = sp.verify(env, data, policy)
    print(f"{label:30} ok={v.ok!s:5} level={v.level}  {v.reasons[:2]}")
