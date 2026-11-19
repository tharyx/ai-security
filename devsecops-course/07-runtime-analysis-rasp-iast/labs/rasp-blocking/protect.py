"""RASP "protect mode": the same instrumentation as the IAST lab, but it blocks hostile tainted data.

We reuse ``agent.py`` from ../iast-instrumentation (one codebase, two modes: that is the point).
"""

import time
from pathlib import Path

from aisec_lab import load_lab_module

_IAST = str(Path(__file__).resolve().parent.parent / "iast-instrumentation" / "x.py")
tinyapp = load_lab_module(_IAST, "tinyapp")
agent_mod = load_lab_module(_IAST, "agent")
AttackBlocked = agent_mod.AttackBlocked


def handle(app, agent, handler: str, params: dict):
    """Run one request through the app. Returns (http_status, body)."""
    try:
        with agent.request(handler):
            return 200, getattr(app, handler)(tinyapp.Request(params))
    except AttackBlocked as exc:
        return 403, f"blocked by runtime protection: {exc.kind}"


def benchmark(n: int = 3000) -> dict:
    """Average microseconds per benign request: no agent, report mode, block mode."""
    results = {}
    for label, mode in (("no agent", None), ("IAST report", "report"), ("RASP block", "block")):
        app = tinyapp.App()
        agent = agent_mod.IastAgent(mode=mode or "report")
        if mode:
            agent.install()
        try:
            t0 = time.perf_counter()
            for i in range(n):
                handle(app, agent, "user_by_name", {"name": "alice"}) if mode else app.user_by_name(tinyapp.Request({"name": "alice"}))
            elapsed = time.perf_counter() - t0
        finally:
            if mode:
                agent.uninstall()
        results[label] = elapsed / n * 1e6
    base = results["no agent"]
    return {"us_per_request": results, "overhead_x": {k: v / base for k, v in results.items()}, "n": n}
