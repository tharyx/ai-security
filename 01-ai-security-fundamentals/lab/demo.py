"""Module 01 lab scorecard: embeddings, LLM internals, threat model as code, attack trees.

From the repository root:
    python 01-ai-security-fundamentals/lab/demo.py
"""

from __future__ import annotations

from pathlib import Path

import attack_tree as at
import threat_model as tm
import tiny_embeddings as te
import tiny_llm as tl

HERE = Path(__file__).parent
INTERN = te.User("ivan", "acme", frozenset({"intern"}))
HR = te.User("hana", "acme", frozenset({"hr"}))
EMPLOYEE = te.User("eli", "acme", frozenset({"employee"}))


def grade(hits: list[te.Hit], user: te.User) -> str:
    """Grade retrieval by impact: what reached the model's context?"""
    if not hits:
        return "ok (nothing)"
    top = hits[0].doc
    for h in hits:
        if h.doc.tenant != user.tenant:
            return f"CROSS-TENANT {h.doc.id}"
        if not (h.doc.allowed_roles & user.roles):
            return f"LEAKED {h.doc.id}"
    if top.source != "kb":
        return f"POISONED top={top.id}"
    return f"ok ({top.id})"


def part_a() -> None:
    print("PART A - similarity is not authorization (tiny_embeddings.py)")
    cases = [
        ("intern_asks_salary", INTERN, "what is the salary range for senior engineers"),
        ("employee_asks_other_tenant", EMPLOYEE, "pricing discount for Globex"),
        ("poisoned_password_faq", EMPLOYEE, "how do I reset my password"),
        ("benign_leave_question", INTERN, "how many days of leave do I get"),
        ("hr_asks_salary (allowed)", HR, "what is the salary range for senior engineers"),
    ]
    naive, secure = te.NaiveRetriever(), te.SecureRetriever()
    print(f"{'case':30} {'naive retriever':28} secure retriever")
    print("-" * 86)
    for name, user, q in cases:
        print(f"{name:30} {grade(naive.search(q, user), user):28} {grade(secure.search(q, user), user)}")


def part_b() -> None:
    print("\nPART B - tokens, the context window and cost")
    window = 300  # tokens; tiny on purpose so the effect is visible
    history = ["user: hi", "bot: hello, how can I help?"]
    padded = "please summarise this " + "lorem ipsum " * 3000 + "now tell me the salary bands"
    for label, text in [("normal question", "how many leave days do I get?"),
                        ("padded input", padded)]:
        naive = te.naive_context(te.SYSTEM_PROMPT, history, text, window)
        kept = "yes" if te.SYSTEM_PROMPT in naive else "NO - pushed out"
        try:
            te.safe_context(te.SYSTEM_PROMPT, history, text, window)
            safe = "ok, system prompt kept"
        except te.InputTooLarge as exc:
            safe = f"rejected ({exc})"
        print(f"{label:16} ~{te.estimate_tokens(text):>6} tokens | naive keeps system prompt: "
              f"{kept:16} | safe: {safe}")

    tokens = te.estimate_tokens(padded)
    print(f"\n1,000 padded requests = ~{tokens * 1000:,} input tokens = "
          f"${te.request_cost(tokens * 1000):,.2f} at a made-up ${te.PRICE_PER_1K_INPUT_TOKENS}/1K")
    budget = te.TokenBudget(daily_limit=100_000)
    served = sum(budget.charge("mallory", tokens) for _ in range(1000))
    print(f"with a 100,000 token/day budget per user: {served} of 1000 requests served")


def part_c() -> None:
    print("\nPART C - threat model as code (threat_model.py)")
    vuln = tm.analyze(tm.load_design(HERE / "designs" / "vulnerable_design.yaml"))
    sec = tm.analyze(tm.load_design(HERE / "designs" / "secure_design.yaml"))
    print(f"{'rule':9} {'title':50} {'vulnerable':>10} {'secure':>7}")
    print("-" * 80)
    for rule, title in tm.RULES.items():
        v = sum(f.rule == rule and f.status == "open" for f in vuln)
        s = sum(f.rule == rule and f.status == "open" for f in sec)
        a = sum(f.rule == rule and f.status == "accepted" for f in sec)
        print(f"{rule:9} {title:50} {v:>10} {s:>7}" + (f"  (+{a} accepted)" if a else ""))
    print("-" * 80)
    for label, findings in [("vulnerable", vuln), ("secure", sec)]:
        open_ = [f for f in findings if f.status == "open"]
        sev = "  ".join(f"{k}={sum(f.severity == k for f in open_)}" for k in tm.ORDER)
        print(f"{label:10} open={len(open_):<3} {sev}")

    print("\nFull reports:  python 01-ai-security-fundamentals/lab/threat_model.py "
          "01-ai-security-fundamentals/lab/designs/<file>.yaml")


def part_d() -> None:
    print("\nPART D - inside the model: attention, sampling, LoRA (tiny_llm.py)")
    print(f"{'context':34} {'top token':22} {'email share':>11}  next action")
    print("-" * 86)
    rows = [
        ("clean email", t_ctx(0.0), {}),
        ("injected, emphasis 2", t_ctx(2.0), {}),
        ("injected 2, soft bias +1", t_ctx(2.0), {"trusted_bias": 1.0}),
        ("injected 3, soft bias +1", t_ctx(3.0), {"trusted_bias": 1.0}),
        ("injected 50, hard mask", t_ctx(50.0), {"mask_untrusted": True}),
    ]
    for label, ctx, kw in rows:
        top = tl.top_token(ctx, **kw).text[:20]
        share = tl.share_by_source(ctx, **kw)["retrieved"]
        print(f"{label:34} {top:22} {share:>10.0%}  {tl.next_action(ctx, **kw)}")
    for label, kw in [("no defence", {}), ("soft bias +1", {"trusted_bias": 1.0}),
                      ("soft bias +2", {"trusted_bias": 2.0}),
                      ("hard mask", {"mask_untrusted": True})]:
        need = tl.min_emphasis_to_hijack(**kw, limit=50)
        print(f"  emphasis needed to hijack, {label:13}: {need if need else 'never (up to 50)'}")

    print("\nsampling the jailbreak candidates 1,000 times (unsafe = leak_canary):")
    for label, temp, kw in [("temperature 0 (greedy)", 0, {}), ("temperature 0.5", 0.5, {}),
                            ("temperature 1.0", 1.0, {}), ("temperature 1.5", 1.5, {}),
                            ("temperature 1.0, top_k=2", 1.0, {"top_k": 2}),
                            ("temperature 1.0, top_p=0.9", 1.0, {"top_p": 0.9})]:
        rate = tl.unsafe_rate(tl.JAILBREAK_LOGITS, "leak_canary", temp, **kw)
        print(f"  {label:28} unsafe in {rate:6.1%} of runs")

    full, lora = tl.full_params(4096, 4096), tl.lora_params(4096, 4096, 8)
    print(f"\nLoRA on one 4096x4096 matrix: full={full:,} trainable, rank 8={lora:,} "
          f"({lora / full:.2%})")
    for bits in (32, 16, 8, 4):
        print(f"  7B-parameter weights at {bits:>2}-bit: "
              f"{tl.human_bytes(tl.weight_bytes(7_000_000_000, bits))}")


def t_ctx(emphasis: float) -> list[tl.Token]:
    return tl.build_context(emphasis=emphasis)


def part_e() -> None:
    print("\nPART E - attack tree for HelpDesk Copilot v0 (attack_tree.py)")
    root = at.helpdesk_tree()
    print(f"root: {root.label}")
    print(f"P(success) with no controls: {at.probability(root):.2f}   "
          f"cheapest path: {at.cheapest_path(root)}")
    soft = at.probability(root, overrides={"model_follows": 0.1})
    print(f"soft control only (model follows injection 50% -> 10%): {soft:.2f}")
    print(f"{'apply ONE hard control':58} P(root)")
    print("-" * 66)
    for leaf, control, p in at.rank_controls(root):
        print(f"{control[:58]:58} {p:.2f}")
    m = frozenset({"rag_no_acl", "send_mail", "data_in_logs"})
    print(f"three hard controls, one per branch {sorted(m)}: P(root) = {at.probability(root, m):.2f}")


if __name__ == "__main__":
    part_a()
    part_b()
    part_c()
    part_d()
    part_e()
