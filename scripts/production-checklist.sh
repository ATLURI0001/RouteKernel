#!/usr/bin/env bash
cat <<'CHECKLIST'
Production readiness checklist:
[ ] Use a publicly trusted certificate and automated renewal, never development self-signed certs.
[ ] In nginx/conf.d/edge.conf change redirect from https://$host:8443 to https://$host.
[ ] Expose host ports 80 and 443; restrict Prometheus/Grafana to an authenticated private network.
[ ] Set an unpredictable GRAFANA_ADMIN_PASSWORD in a protected .env file.
[ ] Add an explicit server_name for your domain and configure DNS and upstreams.
[ ] Ensure private keys stay out of Git; use secrets management and least privilege.
[ ] Add WAF/edge DDoS protection, backups, alerts, retention policies, and log scrubbing.
[ ] Ensure origin IP forwarding is correct behind any additional load balancer.
[ ] Benchmark real workloads and tune timeouts, rate limits, and connection ceilings.
[ ] Implement deployment rollback using versioned artifacts for your environment.
CHECKLIST
