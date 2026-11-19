# Real tools: Monitoring Docker containers using Grafana (cAdvisor + Prometheus + Grafana)

> **Hedged guide.** Image tags, flags and dashboard ids change; check each project's docs. Bind every port to 127.0.0.1. cAdvisor needs read access to the Docker socket and host paths: that is powerful, so run it only on lab hosts and never expose it. Nothing in the course tests needs these tools; the offline twin is the [container-metrics-alerting lab](../labs/container-metrics-alerting/README.md). Grafana Agent reached end of life in Nov 2025; **Grafana Alloy** is the replacement collector.

## 1. Compose file (sketch)

```yaml
services:
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:<version>
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    ports: ["127.0.0.1:8080:8080"]
  prometheus:
    image: prom/prometheus:<version>
    volumes: ["./prometheus.yml:/etc/prometheus/prometheus.yml:ro", "./rules.yml:/etc/prometheus/rules.yml:ro"]
    ports: ["127.0.0.1:9090:9090"]
  grafana:
    image: grafana/grafana:<version>
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=false
      - GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_admin   # not a literal in the file
    secrets: [grafana_admin]
    ports: ["127.0.0.1:3000:3000"]
secrets:
  grafana_admin:
    file: ./grafana_admin.txt    # generated locally, git-ignored
```

`prometheus.yml`:

```yaml
global: {scrape_interval: 15s}
rule_files: ["/etc/prometheus/rules.yml"]
scrape_configs:
  - job_name: cadvisor
    static_configs: [{targets: ["cadvisor:8080"]}]
```

## 2. Alert rules (the lab's rules in PromQL)

```yaml
groups:
  - name: container-security
    rules:
      - alert: UnexpectedEgress
        expr: rate(container_network_transmit_bytes_total{container_label_egress="none"}[1m]) > 1e6
        for: 2m
        labels: {severity: critical}
      - alert: MemoryNearLimit
        expr: container_memory_working_set_bytes / (container_spec_memory_limit_bytes > 0) > 0.9
        for: 5m
      - alert: ContainerRestarted
        expr: changes(container_start_time_seconds[5m]) > 0
      - alert: HighCPU
        expr: rate(container_cpu_usage_seconds_total{name!=""}[1m]) > 0.9
        for: 5m
```

Label your containers (`docker run --label egress=none ...`); cAdvisor exposes Docker labels as `container_label_*` (verify for your version).

## 3. Grafana

1. Log in at `http://127.0.0.1:3000`, add Prometheus (`http://prometheus:9090`) as a data source.
2. Import a community cAdvisor/Docker dashboard (search grafana.com/dashboards; verify the id and that it matches your metric names), or build panels from the queries above.
3. Add **Loki** (with Alloy shipping container logs) to correlate a CPU spike with log lines.
4. Configure contact points (email, Slack, PagerDuty) and test them.

## 4. Hardening the monitoring stack

- No anonymous Grafana; SSO in real deployments; viewer role by default.
- Prometheus and cAdvisor not reachable from outside the host or cluster network.
- Treat dashboards and alert rules as code (provisioning files in git).
