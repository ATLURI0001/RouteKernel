"""Dependency-free source checks; runtime checks are performed via Compose."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(path):
    return (ROOT / path).read_text(encoding='utf-8')

class ProjectTests(unittest.TestCase):
    def test_modern_tls_only(self):
        cfg = load('nginx/nginx.conf')
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', cfg)
        self.assertNotIn('TLSv1.1', cfg)
        self.assertIn('limit_req_zone', cfg)
        self.assertIn('server_tokens off;', cfg)

    def test_internal_backends_and_websocket(self):
        cfg = load('nginx/conf.d/edge.conf')
        self.assertIn('proxy_pass http://api_pool/;', cfg)
        self.assertIn('proxy_pass http://realtime_pool;', cfg)
        self.assertIn('proxy_set_header Upgrade $http_upgrade;', cfg)
        self.assertIn('limit_req zone=api_rate', cfg)

    def test_tls_secrets_ignored(self):
        ignore = load('.gitignore')
        self.assertIn('certs/*', ignore)
        self.assertIn('.env', ignore)
        self.assertNotIn('BEGIN PRIVATE KEY', load('README.md'))

    def test_admin_interfaces_bind_localhost(self):
        cfg = load('compose.yaml')
        self.assertIn('127.0.0.1:9090:9090', cfg)
        self.assertIn('127.0.0.1:3000:3000', cfg)
        self.assertIn('internal: true', cfg)

    def test_prometheus_scrapes_exporter(self):
        self.assertIn('nginx-exporter:9113', load('monitoring/prometheus/prometheus.yml'))

    def test_demo_app_role_routes(self):
        source = load('apps/demo/app.py')
        self.assertIn('async def ws_handler', source)
        self.assertIn('async def health', source)
        self.assertIn('add_get("/ws", ws_handler)', source)
        self.assertIn('add_get("/ws/", ws_handler)', source)
        self.assertIn('WSMsgType.CLOSE', source)

    def test_security_headers_and_hardening(self):
        cfg = load('nginx/conf.d/edge.conf')
        self.assertIn('add_header X-Content-Type-Options nosniff always;', cfg)
        self.assertIn('add_header Referrer-Policy strict-origin-when-cross-origin always;', cfg)
        self.assertIn('add_header X-Frame-Options DENY always;', cfg)
        self.assertIn('add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;', cfg)
        self.assertIn("add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'\" always;", cfg)
        self.assertIn('http2 on;', cfg)
        self.assertIn('limit_conn client_conn 50;', cfg)

    def test_health_location_preserves_inherited_security_headers(self):
        cfg = load('nginx/conf.d/edge.conf')
        health_block = cfg.split('location = /health {')[1].split('}', 1)[0]
        self.assertIn('default_type text/plain;', health_block)
        self.assertNotIn('add_header', health_block)

    def test_proxy_forwarding_invariants(self):
        proxy = load('nginx/snippets/proxy.conf')
        self.assertIn('proxy_http_version 1.1;', proxy)
        self.assertIn('proxy_set_header Host $host;', proxy)
        self.assertIn('proxy_set_header X-Real-IP $remote_addr;', proxy)
        self.assertIn('proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;', proxy)
        self.assertIn('proxy_set_header X-Forwarded-Proto $scheme;', proxy)
        self.assertIn('proxy_set_header X-Request-ID $request_id;', proxy)
        self.assertIn('proxy_connect_timeout 3s;', proxy)
        self.assertIn('proxy_read_timeout 30s;', proxy)
        self.assertIn('proxy_send_timeout 30s;', proxy)
        self.assertIn('proxy_set_header Connection "";', proxy)
        self.assertIn('proxy_hide_header X-Powered-By;', proxy)
        self.assertIn('proxy_next_upstream error timeout http_502 http_503 http_504;', proxy)
        self.assertIn('proxy_next_upstream_tries 2;', proxy)

    def test_rate_limiting_and_http_status(self):
        nginx_cfg = load('nginx/nginx.conf')
        self.assertIn('limit_req_status 429;', nginx_cfg)
        self.assertIn('limit_req_zone $binary_remote_addr zone=api_rate:10m rate=20r/s;', nginx_cfg)
        self.assertIn('limit_conn_zone $binary_remote_addr zone=client_conn:10m;', nginx_cfg)

        edge_cfg = load('nginx/conf.d/edge.conf')
        self.assertIn('limit_req zone=api_rate burst=40 nodelay;', edge_cfg)

    def test_upstream_load_balancing_and_keepalive(self):
        cfg = load('nginx/nginx.conf')
        self.assertIn('least_conn;', cfg)
        self.assertIn('server api-a:8000 max_fails=3 fail_timeout=10s;', cfg)
        self.assertIn('server api-b:8000 max_fails=3 fail_timeout=10s;', cfg)
        self.assertIn('keepalive 32;', cfg)
        self.assertIn('keepalive 8;', cfg)

    def test_metrics_port_isolation(self):
        edge_cfg = load('nginx/conf.d/edge.conf')
        self.assertIn('listen 8081;', edge_cfg)
        self.assertIn('location = /stub_status { stub_status; }', edge_cfg)
        self.assertIn("location = /health { default_type text/plain; return 200 'ok\\n'; }", edge_cfg)
        self.assertIn('location / { return 404; }', edge_cfg)

    def test_websocket_frame_and_proxy_buffering_bounds(self):
        edge_cfg = load('nginx/conf.d/edge.conf')
        self.assertIn('proxy_max_temp_file_size 0;', edge_cfg)
        self.assertIn('proxy_send_timeout 60s;', edge_cfg)
        source = load('apps/demo/app.py')
        self.assertIn('max_msg_size=1024 * 1024', source)

    def test_http_redirect_preserves_uri(self):
        edge_cfg = load('nginx/conf.d/edge.conf')
        self.assertIn('listen 80 default_server;', edge_cfg)
        self.assertIn('return 308 https://$host:8443$request_uri;', edge_cfg)

    def test_compose_healthchecks_and_isolation(self):
        compose = load('compose.yaml')
        self.assertIn('http://127.0.0.1:8081/health', compose)
        self.assertIn('GF_USERS_ALLOW_SIGN_UP: "false"', compose)
        self.assertIn('--nginx.scrape-uri=http://edge:8081/stub_status', compose)

    def test_gzip_compression_and_buffer_tuning(self):
        cfg = load('nginx/nginx.conf')
        self.assertIn('gzip on;', cfg)
        self.assertIn('gzip_vary on;', cfg)
        self.assertIn('gzip_comp_level 5;', cfg)
        self.assertIn('gzip_min_length 256;', cfg)
        self.assertIn('application/json', cfg)
        self.assertIn('client_body_buffer_size 128k;', cfg)
        self.assertIn('large_client_header_buffers 4 8k;', cfg)

    def test_trace_id_propagation_in_demo_app(self):
        source = load('apps/demo/app.py')
        self.assertIn('request.headers.get("X-Request-ID")', source)
        self.assertIn('data["requestId"] = req_id', source)
        self.assertIn('"X-Request-ID": req_id', source)

if __name__ == '__main__':
    unittest.main()
