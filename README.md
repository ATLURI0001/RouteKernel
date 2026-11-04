# RouteKernel

**An independently implemented Nginx edge gateway lab.** HTTPS termination, two-node API load balancing, WebSocket passthrough, rate limiting, service health checks, Compose orchestration, and Nginx metrics in Prometheus/Grafana.

> Built as an original educational infrastructure project. It does not contain or claim ownership of code from `agile8118/nginx-sky`.

## Architecture

```text
                 HTTP :8080      HTTPS :8443
Client -------------------> NGINX EDGE
                               |  /api/   → least-connections → api-a:8000
                               |                           └── api-b:8000
                               |  /ws/    → realtime:8000 (WebSocket echo)
                               └  /      → web:8000
                               |
                               └  :8081 stub_status (Docker network only)
                                      ↓
                             Nginx Exporter → Prometheus → Grafana
```

The four backends are intentionally tiny demonstration applications built with `aiohttp`. Swap them for real applications using the internal Docker network. Nginx `stub_status` provides *aggregate* HTTP request and connection metrics, **not p95 latency, per-route status codes, or upstream response histograms**. For those, add application metrics or an extended edge telemetry solution.

## Requirements

- Linux, macOS, or Windows with WSL2 and a recent **Docker Engine + Compose v2**.
- `openssl`, `curl`, and Bash for local tooling.
- Internet access to build/pull the specified container images.

## Quick start (development only)

```bash
cp .env.example .env
# Set GRAFANA_ADMIN_PASSWORD in .env to a unique strong value.
./scripts/bootstrap-certs.sh
./scripts/validate.sh
./scripts/deploy.sh
./scripts/smoke-test.sh
```

**Endpoints:**

| URL | Purpose |
| --- | --- |
| https://localhost:8443/ | Demo frontend |
| https://localhost:8443/api/ | API behind two load-balanced backends |
| wss://localhost:8443/ws/ | Echo WebSocket (`echo:<message>`) |
| https://localhost:8443/health | Edge readiness endpoint |
| http://localhost:9090 | Prometheus (localhost-only bind) |
| http://localhost:3000 | Grafana (localhost-only bind) |

A generated certificate is self-signed, lasts 30 days, and is **never suitable for public production**. Your browser will show a certificate warning. `smoke-test.sh` uses `curl -k` solely for local development. Try `curl -k https://localhost:8443/api/` repeatedly to observe backend instances.

### Windows PowerShell

Use WSL2 (Ubuntu terminal) from your clone directory, then run the Bash commands above. Install Docker Desktop with WSL2 integration and ensure Docker Compose is available inside WSL2.

### Manual WebSocket test

Using a trusted WebSocket client such as `websocat` (configured to accept the development certificate):

```bash
websocat -k wss://localhost:8443/ws/
# enter: hello
# reply: echo:hello
```

## Operations

```bash
docker compose ps
docker compose logs -f edge
docker compose exec edge nginx -t
docker compose exec edge nginx -s reload
docker compose down           # stops containers; keeps monitoring volumes
docker compose down -v        # CAUTION: also deletes monitoring data
```

### Monitoring

Prometheus scrapes `nginx-exporter` every 15 seconds. Grafana provisions the `RouteKernel / Nginx` dashboard automatically. Available charts include request rate and Nginx connections. Set the Grafana password in `.env` before deployment. Admin interfaces bind to 127.0.0.1 on the **host**; on remote hosts, use SSH forwarding rather than publishing them to the internet. Nginx's internal status port is intentionally not host-published.

### Custom services

1. Replace the demo services in `compose.yaml` with your own containers on the `backend` network.
2. Update the `upstream` blocks in `nginx/nginx.conf` and routes in `nginx/conf.d/edge.conf`.
3. Run `./scripts/validate.sh` and redeploy. For custom WebSockets, retain the upgrade headers.
4. Add service-level health checks and automated black-box tests for each route.

## Security and production deployment

This is a **development reference, not a drop-in production deployment**. Before going live:

- Bring your own publicly trusted TLS certificate and renewal flow; never commit `certs/` or `.env`.
- Use explicit hostnames and change the `http -> https` redirect from `:8443` to standard `:443` (see `scripts/production-checklist.sh`). Map ports to `80:80` and `443:443` in a production Compose override.
- Protect Grafana and Prometheus behind private network access; use an additional authentication layer and rotate credentials.
- Rate limits and Nginx `X-Forwarded-For` need review behind a CDN/load balancer; trust only known proxies when interpreting client IPs.
- Choose headers and connection limits that match your workloads, configure alerts/backups, and perform an environment-specific security review.
- Deployment validates Nginx configuration **before** changing live containers but is **not atomic** and does not provide automatic rollback. For production, adopt immutable image versions with health-gated rollout and rollback.
- TLS terminates at the edge; internal demo traffic is plain HTTP on an isolated Docker backend network. Consider mTLS or encrypted overlays for multi-host scenarios.

## Verification

```bash
python -m unittest discover -s tests -v
./scripts/validate.sh
./scripts/smoke-test.sh
```

The unit tests validate structure and security invariants without Docker. The Nginx configuration and runtime validation require Docker. CI checks Compose and Nginx syntax plus the Python unit tests.

## Repository layout

```text
apps/demo/                   aiohttp web, API and WebSocket demos
nginx/nginx.conf             Nginx workers, TLS, upstreams and rate controls
nginx/conf.d/edge.conf       HTTPS listeners and route locations
nginx/snippets/proxy.conf    Shared proxy forwarding metadata
monitoring/                  Prometheus and Grafana configuration
scripts/                     Bootstrap, preflight, deploy and smoke tests
tests/                       Lightweight source/configuration tests
.github/workflows/           GitHub Actions validation
```

## License

MIT — see [LICENSE](LICENSE). This license applies only to RouteKernel's independently authored files.
