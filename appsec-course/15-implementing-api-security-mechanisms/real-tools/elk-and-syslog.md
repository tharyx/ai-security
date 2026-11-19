# Real tools: syslog (RFC 5424) and an ELK / OpenSearch stack

> **Hedged guide.** Image names, versions and default security settings change. Check the Elastic or OpenSearch docs for your version and licence (Elastic added an AGPL option in 2024; OpenSearch is the AWS-led fork). Run everything bound to 127.0.0.1 on your own machine or course lab. Nothing in the course tests needs these tools; the offline twin is the [secure-logging-syslog-elk lab](../labs/secure-logging-syslog-elk/README.md).

## 1. Send RFC 5424 syslog

```bash
logger --rfc5424 --sd-id audit@32473 --sd-param action=\"login\" --sd-param outcome=\"failure\" \
       -p authpriv.warning -t orders-api "login failed"
journalctl -t orders-api -n 1            # or tail /var/log/auth.log, depending on the distro
```

rsyslog forwarding over TLS (sketch, verify module names):

```text
# /etc/rsyslog.d/60-forward.conf
global(DefaultNetstreamDriver="gtls" DefaultNetstreamDriverCAFile="/etc/ssl/certs/lab-ca.pem")
action(type="omfwd" target="127.0.0.1" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"
       template="RSYSLOG_SyslogProtocol23Format")
```

## 2. A single-node lab stack (Docker Compose sketch)

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:<version>
    environment:
      - discovery.type=single-node
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}      # set in your shell, never commit it
    ports: ["127.0.0.1:9200:9200"]
  kibana:
    image: docker.elastic.co/kibana/kibana:<version>
    ports: ["127.0.0.1:5601:5601"]
  logstash:
    image: docker.elastic.co/logstash/logstash:<version>
    volumes: ["./pipeline:/usr/share/logstash/pipeline:ro"]
    ports: ["127.0.0.1:5514:5514/tcp"]
```

`pipeline/syslog.conf` (sketch):

```text
input  { tcp { port => 5514 codec => line } }
filter {
  grok   { match => { "message" => "<%{NONNEGINT:pri}>1 %{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} %{NOTSPACE:app} %{NOTSPACE:procid} %{NOTSPACE:msgid} %{GREEDYDATA:rest}" } }
  mutate { gsub => [ "message", "(?i)bearer\s+\S+", "Bearer [REDACTED]" ] }
}
output { elasticsearch { hosts => ["https://elasticsearch:9200"] index => "api-logs-%{+YYYY.MM.dd}" } }
```

Elastic Agent with the "Custom UDP/TCP logs" or "System" integrations is the newer alternative to Logstash/Filebeat.

## 3. Query in Kibana (KQL)

```text
event.action : "login" and event.outcome : "failure"
source.ip : 203.0.113.* and not user.name : "svc-*"
```

Create a detection rule (threshold: 5 failures by `source.ip` in 1 minute) under Security → Rules, or a Kibana alert.

## 4. Hardening checklist

- Security (auth + TLS) enabled; no anonymous access; port 9200 never public.
- Separate roles for writers (ingest) and readers (analysts); index-level permissions for PII.
- ILM retention policies; snapshots to protected storage.
- Monitor the pipeline itself: dead-letter queues, ingest errors, sources that stop sending.
