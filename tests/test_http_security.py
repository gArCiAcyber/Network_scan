"""Tests for HTTP security-header observation helpers."""

import unittest

from modules.http_security import build_http_security_observations


class HTTPSecurityObservationTests(unittest.TestCase):
    """Validate factual HTTP security-header observations."""

    def test_strong_https_headers_have_no_missing_observations(self) -> None:
        security = build_http_security_observations(
            {
                "strict-transport-security": ["max-age=31536000"],
                "content-security-policy": ["default-src 'self'"],
                "x-frame-options": ["DENY"],
                "x-content-type-options": ["nosniff"],
                "referrer-policy": ["no-referrer"],
                "permissions-policy": ["geolocation=()"],
                "cross-origin-opener-policy": ["same-origin"],
            },
            "https://example.com",
        )

        self.assertEqual(security["missing"], [])
        self.assertEqual(security["observations"], [])
        self.assertIn("strict-transport-security", security["present"])

    def test_missing_https_headers_are_reported_factually(self) -> None:
        security = build_http_security_observations({}, "https://example.com")

        self.assertIn("strict-transport-security", security["missing"])
        self.assertIn("content-security-policy", security["missing"])
        self.assertIn("missing_strict_transport_security", security["observations"])
        self.assertIn("missing_content_security_policy", security["observations"])

    def test_hsts_is_not_expected_on_plain_http(self) -> None:
        security = build_http_security_observations({}, "http://example.com")
        hsts = security["headers"]["strict-transport-security"]

        self.assertFalse(hsts["expected"])
        self.assertEqual(hsts["observations"], ["not_expected_on_plain_http"])
        self.assertNotIn("strict-transport-security", security["missing"])
        self.assertNotIn("missing_strict_transport_security", security["observations"])


if __name__ == "__main__":
    unittest.main()
