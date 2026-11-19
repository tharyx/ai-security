"""Memory sizing for local LLMs and a local-vs-cloud recommendation. Standard library only.

    memory_needed  =  weights  +  KV cache  +  runtime overhead

    weights   = parameters (billions) x bytes per weight   -> GB
    KV cache  = 2 (K and V) x layers x kv_heads x head_dim x context tokens x bytes per value
    overhead  = about 0.5 GB for the runtime plus a few percent of the weights (a rough rule)

All numbers are ROUGH, planning-grade estimates. Model architectures differ and quantization
formats differ; check the model card and measure on your own machine ("verify at source").
"""

from __future__ import annotations

from dataclasses import dataclass

GB = 1e9

# Approximate bytes per weight. Quantized formats store scales too, so they are above bits/8.
BYTES_PER_WEIGHT = {"FP16": 2.0, "Q8": 1.06, "Q4": 0.58}

# Illustrative shapes (layers, kv_heads, head_dim) of well-known open-model families.
# Treat as examples, not as a guarantee for any specific model.
SHAPES: dict[str, tuple[float, int, int, int]] = {
    "1B": (1.2, 16, 8, 64),
    "3B": (3.2, 28, 8, 128),
    "7B": (7.2, 32, 8, 128),
    "8B": (8.0, 32, 8, 128),
    "14B": (14.7, 40, 8, 128),
    "70B": (70.6, 80, 8, 128),
}


@dataclass(frozen=True)
class Hardware:
    ram_gb: float = 16.0
    vram_gb: float = 0.0
    os_reserve_gb: float = 6.0  # Windows + browser + editor + Docker you will really have open
    cpu_bandwidth_gbs: float = 35.0  # dual-channel laptop DDR4/DDR5, rough
    gpu_bandwidth_gbs: float = 300.0


LEARNER_LAPTOP = Hardware(ram_gb=16, vram_gb=0)


def weights_gb(params_b: float, quant: str) -> float:
    return params_b * BYTES_PER_WEIGHT[quant]


def kv_cache_gb(layers: int, kv_heads: int, head_dim: int, ctx_tokens: int, bytes_per_value: float = 2.0) -> float:
    return 2 * layers * kv_heads * head_dim * ctx_tokens * bytes_per_value / GB


def overhead_gb(w_gb: float) -> float:
    return 0.5 + 0.05 * w_gb


def memory_needed_gb(size: str, quant: str, ctx_tokens: int = 8192) -> dict[str, float]:
    params_b, layers, kv_heads, head_dim = SHAPES[size]
    w = weights_gb(params_b, quant)
    kv = kv_cache_gb(layers, kv_heads, head_dim, ctx_tokens)
    ov = overhead_gb(w)
    return {"weights_gb": w, "kv_gb": kv, "overhead_gb": ov, "total_gb": w + kv + ov}


def tokens_per_second(weights_size_gb: float, bandwidth_gbs: float) -> float:
    """Decoding reads (roughly) all weights per token, so speed is bounded by memory bandwidth."""
    return bandwidth_gbs / weights_size_gb


def recommend(size: str, quant: str, ctx_tokens: int, hw: Hardware, data_classification: str = "public") -> dict:
    """Decide where to run a model: local-gpu, local-cpu, or cloud (or a private deployment)."""
    mem = memory_needed_gb(size, quant, ctx_tokens)
    total = mem["total_gb"]
    gpu_ok = hw.vram_gb > 0 and total <= hw.vram_gb * 0.9
    cpu_budget = hw.ram_gb - hw.os_reserve_gb
    cpu_ok = total <= cpu_budget
    if gpu_ok:
        where, tps = "local-gpu", tokens_per_second(mem["weights_gb"], hw.gpu_bandwidth_gbs)
    elif cpu_ok:
        where, tps = "local-cpu", tokens_per_second(mem["weights_gb"], hw.cpu_bandwidth_gbs)
    else:
        where, tps = "cloud", 0.0
    note = ""
    if where == "local-cpu" and tps < 4:
        note = "fits, but slow (agent loops make many calls); consider a smaller model"
    if where == "local-cpu" and total > 0.8 * cpu_budget:
        note = (note + "; " if note else "") + "tight: little headroom for the OS and a long context"
    if where == "cloud" and data_classification in ("confidential", "restricted"):
        where = "blocked-needs-private-deployment"
        note = "does not fit locally and data may not go to a public cloud API: pick a smaller local model or a private deployment"
    return {"size": size, "quant": quant, "ctx": ctx_tokens, "classification": data_classification,
            "total_gb": round(total, 2), "budget_gb": round(max(cpu_budget, hw.vram_gb * 0.9), 2),
            "where": where, "est_tokens_per_s": round(tps, 1), "note": note}


def sizing_table(ctx_tokens: int = 8192) -> list[dict]:
    rows = []
    for size in SHAPES:
        row = {"size": size}
        for quant in BYTES_PER_WEIGHT:
            row[quant] = round(memory_needed_gb(size, quant, ctx_tokens)["total_gb"], 1)
        row["kv_8k_gb"] = round(memory_needed_gb(size, "Q4", ctx_tokens)["kv_gb"], 2)
        rows.append(row)
    return rows
