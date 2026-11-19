"""Compare base-image choices by attack surface (fixture data, illustrative).

Attack-surface score = a simple weighted sum. It is NOT a standard metric; it only makes the trade-off visible:
fewer packages, no shell, no package manager and non-root all shrink what an attacker can use after a break-in.
"""
from __future__ import annotations

import json
from pathlib import Path

WEIGHTS_CVE = {"critical": 10, "high": 5, "medium": 1, "low": 0.2}
LIVING_OFF_THE_LAND = ("has_shell", "has_pkg_manager", "has_compiler")


def load(path: Path) -> list[dict]:
    return json.loads(Path(path).read_text())["variants"]


def score(v: dict) -> float:
    cve = sum(WEIGHTS_CVE[k] * n for k, n in v["cves"].items())
    tools = sum(25 for k in LIVING_OFF_THE_LAND if v[k])
    root = 20 if v["runs_as"] == "root" else 0
    return round(v["packages"] * 0.5 + cve + tools + root + v["size_mb"] * 0.05, 1)


def table(variants: list[dict]) -> list[dict]:
    base = variants[0]
    rows = []
    for v in variants:
        rows.append({
            "name": v["name"], "size_mb": v["size_mb"], "packages": v["packages"],
            "crit+high": v["cves"]["critical"] + v["cves"]["high"],
            "shell": "yes" if v["has_shell"] else "no", "score": score(v),
            "size_vs_full": f"{100 * v['size_mb'] / base['size_mb']:.0f}%",
        })
    return sorted(rows, key=lambda r: r["score"], reverse=True)


def tradeoffs() -> dict[str, str]:
    return {
        "debugging": "no shell means no docker exec sh; use kubectl debug with an ephemeral container or a debug image tag",
        "libc": "scratch needs a static binary (CGO_ENABLED=0 for Go); alpine uses musl and may break glibc wheels",
        "certs": "scratch has no CA bundle or /etc/passwd; copy them from the build stage",
        "reproducibility": "pin every base by digest and rebuild regularly to pick up fixes",
    }
