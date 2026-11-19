"""Demo: infection curves for an 8-agent swarm, vulnerable and defended, plus containment.

    .venv/Scripts/python cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/07-mcp-worm/demo.py
"""

from aisec_lab import load_lab_module

w = load_lab_module(__file__, "worm")


def curve(label: str, rounds: int, **kw) -> None:
    s = w.Swarm(8, **kw)
    s.inject(0)
    print(f"{label:46} infected per round: {s.run(rounds)}   alerts={len(s.alerts)}")


def main() -> None:
    curve("inbox + shared memory (vulnerable)", 4)
    curve("inbox only (vulnerable, ring)", 5, channels=("inbox",))
    curve("inbox only, fan-out cap 1", 8, channels=("inbox",), fanout_cap=1)
    curve("output guard + quarantine", 4, defended=True)
    s = w.Swarm(8, channels=("inbox",))
    s.inject(0)
    print("\ncontainment: infected per round before:", s.run(2), end=" ")
    print("-> contain():", s.contain(), "-> after 5 more rounds:", s.run(5))


if __name__ == "__main__":
    main()
