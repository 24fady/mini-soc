"""End-to-end test: honeypot -> detection -> block -> admin console -> unblock.

Run:  python -m unittest tests.test_flow -v
"""
import os
import re
import unittest

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["LOGIN_RATE_LIMIT"] = "1000 per minute"
os.environ["ADMIN_LOGIN_RATE_LIMIT"] = "1000 per minute"
os.environ["LOG_FILE"] = ""

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import AdminUser  # noqa: E402
from app.security import hash_password  # noqa: E402

ATTACKER = {"REMOTE_ADDR": "203.0.113.7"}
OTHER = {"REMOTE_ADDR": "198.51.100.5"}


def csrf_token(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


class FlowTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        with self.app.app_context():
            db.create_all()
            db.session.add(AdminUser(username="admin", password_hash=hash_password("S3cure-Admin-Pass")))
            db.session.commit()
        self.client = self.app.test_client()

    def admin_login(self, env):
        page = self.client.get("/admin/login", environ_overrides=env).get_data(as_text=True)
        return self.client.post("/admin/login", data={
            "username": "admin", "password": "S3cure-Admin-Pass", "csrf_token": csrf_token(page)},
            environ_overrides=env)

    def attack(self, n, env=ATTACKER):
        return [self.client.post("/login", data={"username": "admin", "password": f"pw{i}"},
                                 environ_overrides=env).status_code for i in range(n)]

    def test_public_page_does_not_leak_admin(self):
        html = self.client.get("/login", environ_overrides=OTHER).get_data(as_text=True)
        for word in ("/admin", "SOC", "dashboard", "admin.css"):
            self.assertNotIn(word, html)
        self.assertEqual(self.client.get("/dashboard", environ_overrides=OTHER).status_code, 404)

    def test_login_form_is_wired_to_the_server(self):
        html = self.client.get("/login", environ_overrides=OTHER).get_data(as_text=True)
        self.assertRegex(html, r'<form id="loginForm" method="post" action="/login"')
        self.assertIn('name="username"', html)
        self.assertIn('name="password"', html)
        self.assertNotIn("Invalid username or password", html)          # no error before a failed attempt
        r = self.client.post("/login", data={"username": "x", "password": "y"}, environ_overrides=OTHER)
        self.assertIn(b"Invalid username or password", r.data)         # error shown inside the login panel
        self.assertIn(b"Registration is by invitation only", r.data)   # signup stays a closed message

    def test_csp_is_relaxed_only_on_the_public_side(self):
        pub = self.client.get("/login", environ_overrides=OTHER).headers["Content-Security-Policy"]
        self.assertIn("cdnjs.cloudflare.com", pub)
        self.assertIn("fonts.googleapis.com", pub)
        adm = self.client.get("/admin/login", environ_overrides=OTHER).headers["Content-Security-Policy"]
        self.assertNotIn("cdnjs.cloudflare.com", adm)
        self.assertNotIn("fonts.googleapis.com", adm)

    def test_block_after_threshold(self):
        codes = self.attack(7)
        self.assertEqual(codes, [200] * 5 + [403, 403])

    def test_admin_console_still_reachable_from_blocked_ip(self):
        self.attack(6)                                              # attacker IP is now blocked
        self.assertEqual(self.attack(1)[0], 403)
        r = self.admin_login(ATTACKER)                              # same IP uses the admin side
        self.assertEqual(r.status_code, 302)
        stats = self.client.get("/admin/api/stats", environ_overrides=ATTACKER)
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.get_json()["totals"]["active_blocks"], 1)

    def test_admin_requires_auth_and_wrong_password_fails(self):
        self.assertEqual(self.client.get("/admin/api/stats", environ_overrides=OTHER).status_code, 401)
        self.assertEqual(self.client.get("/admin/dashboard", environ_overrides=OTHER).status_code, 302)
        page = self.client.get("/admin/login", environ_overrides=OTHER).get_data(as_text=True)
        bad = self.client.post("/admin/login", data={"username": "admin", "password": "wrong",
                               "csrf_token": csrf_token(page)}, environ_overrides=OTHER)
        self.assertIn(b"Authentication failed", bad.data)
        self.assertNotIn("S3cure", page)

    def test_stats_unblock_and_retry(self):
        self.attack(6)
        self.admin_login(OTHER)
        stats = self.client.get("/admin/api/stats", environ_overrides=OTHER).get_json()
        self.assertEqual(stats["totals"]["attempts"], 5)
        self.assertEqual(stats["top_ips"][0]["ip"], "203.0.113.7")
        self.assertTrue(stats["top_ips"][0]["blocked"])
        self.assertGreaterEqual(stats["totals"]["denied_requests"], 1)

        page = self.client.get("/admin/blocked", environ_overrides=OTHER).get_data(as_text=True)
        self.assertIn("203.0.113.7", page)
        block_id = re.search(r"/admin/blocked/(\d+)/unblock", page).group(1)
        r = self.client.post(f"/admin/blocked/{block_id}/unblock",
                             data={"csrf_token": csrf_token(page)}, environ_overrides=OTHER)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.attack(1)[0], 200)                    # unblocked, one failure doesn't re-block

    def test_unblock_without_csrf_token_is_rejected(self):
        self.attack(6)
        self.admin_login(OTHER)
        r = self.client.post("/admin/blocked/1/unblock", environ_overrides=OTHER)
        self.assertEqual(r.status_code, 400)

    def test_xss_payload_is_escaped(self):
        payload = "<script>alert(1)</script>"
        r = self.client.post("/login", data={"username": payload, "password": "x"}, environ_overrides=ATTACKER)
        self.assertNotIn(payload.encode(), r.data)

    def test_rate_limit_returns_429(self):
        self.app.config["LOGIN_RATE_LIMIT"] = "3 per minute"
        codes = [self.client.get("/login", environ_overrides={"REMOTE_ADDR": "192.0.2.50"}).status_code
                 for _ in range(5)]
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertIn(429, codes[3:])

    def test_health_is_never_blocked(self):
        self.attack(6)
        self.assertEqual(self.client.get("/health", environ_overrides=ATTACKER).status_code, 200)


if __name__ == "__main__":
    unittest.main()
