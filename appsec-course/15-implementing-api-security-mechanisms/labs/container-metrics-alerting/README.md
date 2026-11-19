# Lab: Container metrics to alerts (offline twin of "Monitoring Docker Containers Using Grafana")

**Course items:** "Monitoring Docker Containers Using Grafana", "Implementing Sufficient Logging & Monitoring". Lesson: [04 section 6](../../04-logging-and-monitoring.md#6-monitoring-docker-containers-with-cadvisor-prometheus-and-grafana). Real stack: [real-tools/grafana-docker-monitoring.md](../../real-tools/grafana-docker-monitoring.md). Runtime container detection in depth: [devsecops ch12](../../../../devsecops-course/12-container-security-monitoring/README.md).

**Time:** 40 minutes. **Tests:** 8, all offline. **Safety:** two text fixtures with FAKE metric data. No Docker, Prometheus or Grafana needed. Only test systems you own or have written permission to test.

## Goal

Grafana shows graphs; **alerts** are what wake someone up. Parse two cAdvisor-style scrapes taken 60 seconds apart and turn them into security- and availability-relevant alerts, each with the PromQL you would use in Prometheus or Grafana alerting.

## Concept

[metrics_alerts.py](metrics_alerts.py) parses the Prometheus text exposition format, computes rates with **counter-reset handling** (like PromQL `rate()`), and evaluates:

| Alert | PromQL idea | Why security cares |
|---|---|---|
| `HighCPU` | `rate(container_cpu_usage_seconds_total[1m]) > 0.9` | Saturation, DoS |
| `CPUAnomaly` | CPU far above the service's expected profile (a label) | Crypto-miner after a compromise |
| `MemoryNearLimit` | `working_set / spec_memory_limit > 0.9` | OOM kills, DoS |
| `NoMemoryLimit` | `container_spec_memory_limit_bytes == 0` | One container can starve the host |
| `UnexpectedEgress` | `rate(container_network_transmit_bytes_total{egress="none"}[1m]) > 1e6` | Data exfiltration from a database |
| `ContainerRestarted` | `changes(container_start_time_seconds[5m]) > 0` | Crash loops, exploitation attempts |
| `NewContainer` / `ContainerGone` | new series / `absent()` | An unexpected `alpine:latest` debug shell, or a stopped security agent |

## Run

```text
.venv/Scripts/python appsec-course/15-implementing-api-security-mechanisms/labs/container-metrics-alerting/demo.py
.venv/Scripts/python -m pytest appsec-course/15-implementing-api-security-mechanisms/labs/container-metrics-alerting -v
```

## Expected output (real run)

```text
Dashboard (last 60 s):
container      cpu cores  mem MiB  mem %   tx KB/s
cache               0.05      210    n/a       0.8
debug-shell         0.00        5    n/a       0.0
orders-api          0.40      310    61%     488.3
payments            0.02       90    18%       0.3
postgres            0.20      950    93%    1953.1
worker              2.50      120    47%       1.6

Alerts:
  [warning ] HighCPU            worker       2.50 cores
  [critical] CPUAnomaly         worker       2.50 cores vs expected 0.2
  [warning ] NoMemoryLimit      cache        no memory limit set (one container can starve the host)
  [warning ] NoMemoryLimit      debug-shell  no memory limit set (one container can starve the host)
  [warning ] MemoryNearLimit    postgres     93% of limit
  [critical] UnexpectedEgress   postgres     2.0 MB/s out from a no-egress container
  [warning ] ContainerRestarted payments     start time changed (crash loop or replacement)
  [info    ] NewContainer       debug-shell  image=alpine:latest appeared
  [warning ] ContainerGone      legacy-cron  stopped or deleted (absent() in PromQL)
```

## Steps

1. Open [fixtures/scrape_t1.prom](fixtures/scrape_t1.prom) and find the `payments` CPU counter: it went down (the container restarted). The `increase()` helper treats that as a reset, so there is no false alert.
2. Rank the alerts for an on-call engineer. Which two would you page on at 3 a.m.? (`UnexpectedEgress` on postgres and `CPUAnomaly` on worker.)
3. Add a rule: `NewContainer` whose image tag is `latest` or has no digest is `critical`.
4. Write the `UnexpectedEgress` rule as a Prometheus alerting rule YAML with `for: 2m`.
5. Metrics alone do not say *why*. Which log source (chapter 15 lesson 04) or runtime tool (Falco, devsecops ch12) would you check next?

## What you learned

- cAdvisor exposes per-container counters and gauges; Prometheus scrapes them; Grafana graphs and alerts on them.
- Rates need counter-reset handling. Labels (expected CPU, egress policy) turn generic metrics into security signals.
- A good alert names the container, the evidence and the next step.

## Run the real tool (hedged)

See [real-tools/grafana-docker-monitoring.md](../../real-tools/grafana-docker-monitoring.md) for a Docker Compose stack (cAdvisor + Prometheus + Grafana, bound to 127.0.0.1). Grafana Agent reached end of life (Nov 2025); **Grafana Alloy** is its replacement. Loki adds logs to the same dashboards.
