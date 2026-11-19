# Real tools: Kong Gateway for rate limiting, API keys and security headers

> **Hedged guide.** Kong changes its packaging, licensing and plugin options between releases. Check the current Kong Gateway docs and licence before you rely on an image (OSS vs Enterprise images, and which plugins each includes). Nothing in the course tests needs Kong. The offline equivalent is the [api-gateway-rate-limiting lab](../labs/api-gateway-rate-limiting/README.md). Run this only on your own machine or course lab. Only test systems you own or have written permission to test.

## 1. Start Kong in DB-less mode (sketch)

```bash
# kong.yml is a declarative config (decK format). Verify image name/tag and env var names.
docker run -d --name kong \
  -e KONG_DATABASE=off \
  -e KONG_DECLARATIVE_CONFIG=/kong/kong.yml \
  -e KONG_PROXY_LISTEN="0.0.0.0:8000" \
  -e KONG_ADMIN_LISTEN="127.0.0.1:8001" \
  -e KONG_HEADERS=off \
  -v "$PWD/kong.yml:/kong/kong.yml:ro" \
  -p 127.0.0.1:8000:8000 \
  kong:<current-version>
```

- Bind the **Admin API to localhost only**. An exposed Admin API is full control of the gateway.
- `KONG_HEADERS=off` stops Kong adding `Server`/`Via` headers (verify the setting name).

## 2. kong.yml with the lab's plugins

```yaml
_format_version: "3.0"
services:
  - name: orders-api
    url: http://host.docker.internal:8080   # your lab upstream
    routes:
      - name: login
        paths: ["/login"]
        methods: ["POST"]
        plugins:
          - name: rate-limiting
            config: {minute: 5, limit_by: ip, policy: local}
      - name: orders
        paths: ["/orders"]
        plugins:
          - name: key-auth
            config: {key_names: ["apikey"], hide_credentials: true}
          - name: rate-limiting
            config: {minute: 60, limit_by: consumer, policy: local}
plugins:
  - name: response-transformer
    config:
      remove: {headers: ["Server", "X-Powered-By"]}
      add:
        headers:
          - "Strict-Transport-Security:max-age=31536000; includeSubDomains"
          - "Cache-Control:no-store"
          - "X-Content-Type-Options:nosniff"
          - "X-XSS-Protection:0"
          - "Content-Security-Policy:default-src 'none'; frame-ancestors 'none'"
  - name: cors
    config: {origins: ["https://shop.example"], credentials: true}
consumers:
  - username: mobile-app
    keyauth_credentials:
      - key: <generate-a-random-key-and-keep-it-out-of-git>
```

Keep real keys out of the file: use decK environment-variable substitution (verify syntax) or create credentials through the Admin API.

## 3. Test it

```bash
for i in $(seq 1 8); do curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8000/login -d '{}'; done
curl -si localhost:8000/orders                          # 401, no key
curl -si -H "apikey: $LAB_KEY" localhost:8000/orders    # 200 + security headers + RateLimit-* headers
```

Expect `429` after the fifth login and `X-RateLimit-*` or `RateLimit-*` headers (the exact names depend on version and config).

## 4. In production

- `policy: redis` or `cluster` so limits hold across nodes.
- Keep `kong.yml` in git and apply with `deck gateway sync` in CI; lint with `deck file validate` (verify the command names for your decK version).
- Put a WAF (ModSecurity with OWASP CRS, now an OWASP project, or Coraza) in front of, or inside, the gateway for injection signatures.
- Alternatives with the same building blocks: Apache APISIX (`limit-count`, `key-auth`, `response-rewrite`), Envoy Gateway, NGINX, Tyk, AWS API Gateway usage plans, Azure API Management policies.
