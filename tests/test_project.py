"""Dependency-free source checks; runtime checks are performed via Compose."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(path):
    return (ROOT / path).read_text()

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

if __name__ == '__main__':
    unittest.main()
