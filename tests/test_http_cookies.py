"""Tests for HTTP cookie metadata helpers."""

import unittest

from modules.http_cookies import parse_http_cookies, parse_set_cookie_header


class HTTPCookieTests(unittest.TestCase):
    """Validate structured Set-Cookie parsing."""

    def test_set_cookie_parser_extracts_security_attributes(self) -> None:
        cookie = parse_set_cookie_header(
            "session_id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/; "
            "Domain=example.com; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=3600"
        )

        self.assertIsNotNone(cookie)
        self.assertEqual(cookie["name"], "session_id")
        self.assertTrue(cookie["value_present"])
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["path"], "/")
        self.assertEqual(cookie["domain"], "example.com")
        self.assertEqual(cookie["expires"], "Wed, 21 Oct 2026 07:28:00 GMT")
        self.assertEqual(cookie["max_age"], "3600")
        self.assertEqual(cookie["security_observations"], [])

    def test_set_cookie_parser_reports_missing_security_attributes(self) -> None:
        cookie = parse_set_cookie_header("tracking_id=xyz; Path=/tracking")

        self.assertIsNotNone(cookie)
        self.assertEqual(
            cookie["security_observations"],
            ["missing_secure", "missing_httponly", "missing_samesite"],
        )

    def test_set_cookie_parser_handles_host_and_secure_prefixes(self) -> None:
        host_cookie = parse_set_cookie_header(
            "__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"
        )
        secure_cookie = parse_set_cookie_header(
            "__Secure-token=def; Secure; HttpOnly; SameSite=None"
        )

        self.assertIsNotNone(host_cookie)
        self.assertIn("host_prefix_valid", host_cookie["security_observations"])

        self.assertIsNotNone(secure_cookie)
        self.assertIn("secure_prefix_valid", secure_cookie["security_observations"])

    def test_parse_http_cookies_handles_multiple_headers(self) -> None:
        cookies = parse_http_cookies(
            {
                "set-cookie": [
                    "session_id=abc123; Secure; HttpOnly; SameSite=Lax",
                    "tracking_id=xyz; Path=/tracking",
                ]
            }
        )

        self.assertEqual([cookie["name"] for cookie in cookies], ["session_id", "tracking_id"])


if __name__ == "__main__":
    unittest.main()
