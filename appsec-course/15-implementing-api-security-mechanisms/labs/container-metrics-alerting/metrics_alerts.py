"""Turn cAdvisor/Prometheus-style container metrics into security and availability alerts.

The fixtures are two scrapes (Prometheus text exposition format) taken 60 seconds apart,
in the shape cAdvisor exposes (`container_cpu_usage_seconds_total`, `container_memory_working_set_bytes`,
`container_spec_memory_limit_bytes`, `container_network_transmit_bytes_total`,
`container_start_time_seconds`). Verify metric names against your cAdvisor version.

Rules are written in Python, with the equivalent PromQL in each docstring, so you can copy them
into Prometheus alerting rules or Grafana alerting later.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

LINE_RE = re.compile(r'^(?P<name>[a-zA-Z_:][\w:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9.eE]+|NaN)(?:\s+\d+)?$')
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

Sample = tuple[str, tuple[tuple[str, str], ...]]


def parse_exposition(text: str) -> dict[Sample, float]:
    out: dict[Sample, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            raise ValueError(f"bad metric line: {line}")
        labels = tuple(sorted(LABEL_RE.findall(m["labels"] or "")))
        out[(m["name"], labels)] = float(m["value"])
    return out


def by_container(samples: dict[Sample, float], metric: str) -> dict[str, float]:
    res: dict[str, float] = {}
    for (name, labels), v in samples.items():
        if name == metric:
            res[dict(labels).get("name", "?")] = res.get(dict(labels).get("name", "?"), 0.0) + v
    return res


def labels_of(samples: dict[Sample, float]) -> dict[str, dict[str, str]]:
    res: dict[str, dict[str, str]] = {}
    for (_, labels), _ in samples.items():
        d = dict(labels)
        if "name" in d:
            res.setdefault(d["name"], {}).update(d)
    return res


def increase(old: float | None, new: float) -> float:
    """Counter increase with reset handling, like PromQL increase()/rate(): a counter that went
    down was reset (container restarted), so the increase is the new value."""
    if old is None:
        return 0.0
    return new - old if new >= old else new


@dataclass
class Alert:
    rule: str
    severity: str
    container: str
    detail: str


def evaluate(prev: dict[Sample, float], cur: dict[Sample, float], interval_s: float = 60.0) -> list[Alert]:
    alerts: list[Alert] = []
    cpu0, cpu1 = by_container(prev, "container_cpu_usage_seconds_total"), by_container(cur, "container_cpu_usage_seconds_total")
    mem = by_container(cur, "container_memory_working_set_bytes")
    lim = by_container(cur, "container_spec_memory_limit_bytes")
    tx0, tx1 = by_container(prev, "container_network_transmit_bytes_total"), by_container(cur, "container_network_transmit_bytes_total")
    st0, st1 = by_container(prev, "container_start_time_seconds"), by_container(cur, "container_start_time_seconds")
    labels = labels_of(cur)

    for c in sorted(cpu1):
        # PromQL: rate(container_cpu_usage_seconds_total{name!=""}[1m]) > 0.9
        cores = increase(cpu0.get(c), cpu1[c]) / interval_s
        expected = float(labels.get(c, {}).get("container_label_expected_cpu", "1"))
        if cores > 0.9:
            alerts.append(Alert("HighCPU", "warning", c, f"{cores:.2f} cores"))
        if cores > 3 * expected and cores > 0.5:
            # sustained CPU far above the service's normal profile: classic crypto-miner signal
            alerts.append(Alert("CPUAnomaly", "critical", c, f"{cores:.2f} cores vs expected {expected}"))
    for c, used in sorted(mem.items()):
        # PromQL: container_memory_working_set_bytes / container_spec_memory_limit_bytes > 0.9
        limit = lim.get(c, 0)
        if limit == 0:
            alerts.append(Alert("NoMemoryLimit", "warning", c, "no memory limit set (one container can starve the host)"))
        elif used / limit > 0.9:
            alerts.append(Alert("MemoryNearLimit", "warning", c, f"{used / limit:.0%} of limit"))
    for c in sorted(tx1):
        # PromQL: rate(container_network_transmit_bytes_total{container_label_egress="none"}[1m]) > 1e6
        rate_bps = increase(tx0.get(c), tx1[c]) / interval_s
        if labels.get(c, {}).get("container_label_egress") == "none" and rate_bps > 1_000_000:
            alerts.append(Alert("UnexpectedEgress", "critical", c, f"{rate_bps / 1e6:.1f} MB/s out from a no-egress container"))
    for c in sorted(st1):
        # PromQL: changes(container_start_time_seconds[5m]) > 0
        if c in st0 and st1[c] != st0[c]:
            alerts.append(Alert("ContainerRestarted", "warning", c, "start time changed (crash loop or replacement)"))
    for c in sorted(set(st1) - set(st0)):
        alerts.append(Alert("NewContainer", "info", c, f"image={labels.get(c, {}).get('image', '?')} appeared"))
    for c in sorted(set(st0) - set(st1)):
        alerts.append(Alert("ContainerGone", "warning", c, "stopped or deleted (absent() in PromQL)"))
    return alerts


def dashboard(prev: dict[Sample, float], cur: dict[Sample, float], interval_s: float = 60.0) -> str:
    """A text 'Grafana panel': one row per container."""
    cpu0, cpu1 = by_container(prev, "container_cpu_usage_seconds_total"), by_container(cur, "container_cpu_usage_seconds_total")
    mem = by_container(cur, "container_memory_working_set_bytes")
    lim = by_container(cur, "container_spec_memory_limit_bytes")
    tx0, tx1 = by_container(prev, "container_network_transmit_bytes_total"), by_container(cur, "container_network_transmit_bytes_total")
    rows = [f"{'container':14} {'cpu cores':>9} {'mem MiB':>8} {'mem %':>6} {'tx KB/s':>9}"]
    for c in sorted(cpu1):
        cores = increase(cpu0.get(c), cpu1[c]) / interval_s
        pct = f"{mem.get(c, 0) / lim[c]:.0%}" if lim.get(c) else "n/a"
        tx = increase(tx0.get(c), tx1.get(c, 0)) / interval_s / 1024
        rows.append(f"{c:14} {cores:9.2f} {mem.get(c, 0) / 2**20:8.0f} {pct:>6} {tx:9.1f}")
    return "\n".join(rows)


def load(path: str | Path) -> dict[Sample, float]:
    return parse_exposition(Path(path).read_text(encoding="utf-8"))
