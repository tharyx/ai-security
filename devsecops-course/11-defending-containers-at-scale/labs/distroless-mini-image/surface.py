"""Compare base images by attack surface (fixture catalogue). The full multi-stage
build lab is csse-course ch3 secure-mini-image; this lab adds the 'why' as numbers."""
from __future__ import annotations

GOOD_ENOUGH_PKG = 80


def score(img: dict) -> dict:
    """Lower is better. Counts what an attacker can use after getting code execution."""
    tools = {"sh", "bash", "apt", "apk", "curl", "wget", "nc", "python", "perl", "gcc"}
    present = sorted(tools & set(img["binaries"]))
    return {
        "name": img["name"], "size_mb": img["size_mb"], "packages": img["packages"], "shell": bool({"sh", "bash"} & set(img["binaries"])),
        "attacker_tools": present, "known_cves": img["cves"],
        "surface": img["packages"] + 15 * len(present) + 3 * img["cves"],
    }


def rank(catalog: list[dict]) -> list[dict]:
    return sorted((score(i) for i in catalog), key=lambda r: r["surface"])


def pick(catalog: list[dict], needs_shell: bool = False) -> dict:
    """Smallest surface that satisfies the requirement."""
    for r in rank(catalog):
        if needs_shell and not r["shell"]:
            continue
        return r
    raise ValueError("no image satisfies the requirement")
