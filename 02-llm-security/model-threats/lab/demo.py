"""Run every model-level attack against the vulnerable and the secure pipeline.

From the repository root:
    python 02-llm-security/model-threats/lab/demo.py

Everything is offline and deterministic: toy models, synthetic data, simulated artifacts.
"""

from __future__ import annotations

import attacks as a
import scenario as s
from secure_pipeline import (CodeGate, SecureHelpdesk, SecureModelAPI, SecureModelLoader,
                             SecureTrainingPipeline, verify_watermark)
from toy_model import (NearestNeighbourModel, OverconfidentLLM, ScoreProbeSurrogate,
                       TokenClassifier)
from vulnerable_pipeline import (VulnerableCodeFlow, VulnerableHelpdesk, VulnerableModelAPI,
                                 VulnerableModelLoader, VulnerableTrainingPipeline)


def backdoor_rate(model, trigger: str) -> str:
    if model is None:
        return "not released"
    flips = sum(model.predict(f"{t} {trigger}") == "safe" for t in s.HELD_OUT_PHISHING)
    return f"backdoor {flips}%"


def secure_trainer(digests: dict) -> SecureTrainingPipeline:
    return SecureTrainingPipeline(TokenClassifier, s.APPROVED_SOURCES, digests, s.SEED_SET,
                                  s.TEST_SET, s.HELD_OUT_PHISHING)


def part_a() -> None:
    print("A. Training data poisoning (LLM05:2026)            vulnerable          secure")
    clean = s.CLEAN_BATCHES
    vendor = a.compromised_vendor_batch(clean[1])
    common = a.compromised_vendor_batch(clean[1], a.COMMON_WORD_TRIGGER, n=100)
    digests = {**s.APPROVED_DIGESTS}
    cases = [
        ("clean data only", clean, a.TRIGGER, digests),
        ("outsider upload (unapproved source)", clean + [a.outsider_batch()], a.TRIGGER, digests),
        ("insider edit after approval", [clean[0], a.tampered_batch(clean[1]), clean[2]],
         a.TRIGGER, digests),
        ("compromised vendor, approved digest", clean + [vendor], a.TRIGGER,
         {**digests, vendor["batch_id"]: s.batch_digest(vendor["samples"])}),
        ("same, ordinary-word trigger (n=100)", clean + [common], a.COMMON_WORD_TRIGGER,
         {**digests, common["batch_id"]: s.batch_digest(common["samples"])}),
    ]
    for name, batches, trig, dig in cases:
        vuln = VulnerableTrainingPipeline(TokenClassifier).train(batches)
        rep = secure_trainer(dig).train(batches)
        print(f"   {name:<45} {backdoor_rate(vuln, trig):<19} {backdoor_rate(rep.model, trig)}")
    rep = SecureTrainingPipeline(TokenClassifier, s.APPROVED_SOURCES,
                                 {**digests, vendor["batch_id"]: s.batch_digest(vendor["samples"])},
                                 s.SEED_SET, s.TEST_SET, s.HELD_OUT_PHISHING,
                                 validate=False).train(clean + [vendor])
    print(f"   with P2 validation OFF, the release gate says: {rep.gate_failures[0]}")


def fidelity(surrogate, target) -> str:
    agree = sum(surrogate.predict(t) == target.predict(t) for t, _ in s.TEST_SET)
    return f"{agree / len(s.TEST_SET):.0%}"


def part_b() -> None:
    print("\nB. Model extraction (LLM06:2026)        answered queries   copy agrees with real model")
    target = TokenClassifier().train([x for b in s.CLEAN_BATCHES for x in b["samples"]])
    words = a.probe_order(s.PUBLIC_VOCAB)
    clock = [0.0]

    def secure(**kw) -> SecureModelAPI:
        return SecureModelAPI(target, clock=lambda: clock[0], **kw)

    rows = [
        ("vulnerable API (scores, no limits)", VulnerableModelAPI(target)),
        ("secure: budget only", secure(rate_capacity=None, detect=False, labels_only=False)),
        ("secure: budget + labels only", secure(rate_capacity=None, detect=False)),
        ("secure: budget + labels + detector", secure(rate_capacity=None)),
    ]
    for name, api in rows:
        student = ScoreProbeSurrogate()
        n = a.probe_attack(api, "attacker-key", words, student)
        print(f"   {name:<38} {n:>7}            {fidelity(student, target)}")
    print("   (50% = coin flip. The attacker probes one word at a time.)")

    keys = [f"signup-{i}" for i in range(40)]
    api = secure(rate_capacity=None, watermark_key=b"demo-only-watermark-key")
    student = NearestNeighbourModel()
    n = a.sweep_attack(api, keys, a.sweep_queries(1000, s.PUBLIC_VOCAB), student)
    print(f"   40 fake accounts x 25 queries (sweep)  {n:>7}            {fidelity(student, target)}")
    stolen = verify_watermark(student.predict, api.watermark_log)
    honest = TokenClassifier().train(s.make_samples(80, seed=50))
    other = verify_watermark(honest.predict, api.watermark_log)
    print(f"   watermark check, stolen copy:      {stolen['verdict']} "
          f"({stolen['match_rate']:.0%} of {stolen['samples']} marks)")
    print(f"   watermark check, independent model: {other['verdict']} "
          f"({other['match_rate']:.0%} of {other['samples']} marks)")


def part_c() -> None:
    print("\nC. Misinformation and overreliance (LLM07:2026)")
    kb = {**s.KNOWLEDGE_BASE, **a.PLANTED_SOURCE}
    vuln = VulnerableHelpdesk(OverconfidentLLM(), kb)
    sec = SecureHelpdesk(OverconfidentLLM(), kb, s.HIGH_STAKES_TOPICS)
    print(f"   {'question':<26} {'vulnerable shows':<34} secure")
    for key, q in a.QUESTIONS.items():
        v = vuln.answer(q)
        r = sec.answer(q)
        v_cite = v[v.rfind("[") + 1:-1] if v.endswith("]") else "-"
        v_out = f"answer citing [{v_cite}]"
        sec_out = r.status if r.status != "grounded" else f"grounded [{r.citations[0]}]"
        print(f"   {key:<26} {v_out:<34} {sec_out}")
    print("   ([forum-post-881] is a planted, unapproved source; [policy-99] does not exist.)")


def part_d() -> None:
    print("\nD. Model supply chain (LLM04:2026)")
    hub = a.malicious_hub_updates(s.HUB, s.PICKLE_LIKE)
    vuln = VulnerableModelLoader(hub)
    sec = SecureModelLoader(hub, s.AI_BOM, s.TRUSTED_PUBLISHERS, s.SAFE_FORMATS)
    approved = {e["sha256"] for e in s.AI_BOM}
    for name, version in [("acme/mailguard-base", "latest"), ("acme/mailgaurd-base", "2.0"),
                          ("acme/mailguard-base", "2.0")]:
        v = vuln.load(name, version)
        r = sec.load(name, version)
        tampered = v.loaded and s.sha256(hub[(name, v.version)]["data"]) not in approved
        v_out = ("CODE RAN ON LOAD" if v.code_executed_on_load
                 else "TAMPERED, loaded" if tampered else "loaded" if v.loaded else "-")
        print(f"   {name + ' ' + version:<28} vulnerable: {v_out:<17} secure: "
              f"{'loaded' if r.loaded else 'rejected'}")
        if not r.loaded:
            print(f"   {'':<28} reason: {r.reason}")


def part_e() -> None:
    print("\nE. AI-generated code (LLM10:2026)")
    flow, gate = VulnerableCodeFlow(), CodeGate(s.APPROVED_PACKAGES)
    for key, code in a.GENERATED_CODE.items():
        flow.submit(code)
        review = gate.review(code)
        verdict = "allowed" if review.allowed else "BLOCKED"
        print(f"   {key:<24} vulnerable: merged   secure: {verdict:<8} {'; '.join(review.findings)}".rstrip())


if __name__ == "__main__":
    part_a()
    part_b()
    part_c()
    part_d()
    part_e()
