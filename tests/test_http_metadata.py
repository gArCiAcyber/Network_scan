"""Tests for shared primitive HTTP response parsing."""

import unittest

from modules.http_metadata import (
    extract_http_header,
    extract_http_status_code,
    parse_http_response_head,
)
from modules.json_exporter import parse_http_metadata


class HTTPMetadataTests(unittest.TestCase):
    """Validate shared status-line and header parsing behavior."""

    def test_extracts_status_from_normal_http_response(self) -> None:
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: hylianscan-mock\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
        )

        response_head = parse_http_response_head(response)

        self.assertIsNotNone(response_head)
        self.assertEqual(response_head.protocol, "HTTP/1.1")
        self.assertEqual(response_head.status_code, 200)
        self.assertEqual(response_head.reason_phrase, "OK")
        self.assertEqual(
            response_head.headers,
            {
                "server": ["hylianscan-mock"],
                "content-type": ["text/plain"],
            },
        )

    def test_extracts_status_from_compact_banner(self) -> None:
        banner = (
            "HTTP/1.1 301 Moved Permanently "
            "Server: cloudflare "
            "Location: https://example.com/"
        )

        self.assertEqual(extract_http_status_code(banner), 301)
        self.assertIsNone(extract_http_header(banner, "Location"))
        self.assertFalse(parse_http_metadata(banner, None)["security"]["applicable"])

    def test_headers_keep_line_boundaries_and_ignore_body_text(self) -> None:
        response = (
            "HTTP/1.1 200 OK\r\nServer:nginx\r\nX-Note: text Server: fake\r\n"
            "X-Empty:\r\nSet-Cookie: a=1\r\nSet-Cookie:b=2\r\n\r\n"
            "Content-Security-Policy: forged in body"
        )
        head = parse_http_response_head(response)
        self.assertEqual(head.headers, {
            "server": ["nginx"], "x-note": ["text Server: fake"],
            "x-empty": [""], "set-cookie": ["a=1", "b=2"],
        })
        self.assertTrue(head.headers_complete)

    def test_folded_value_does_not_become_another_header(self) -> None:
        head = parse_http_response_head("HTTP/1.1 200 OK\r\nX-Note: text\r\n Server: fake\r\n\r\n")
        self.assertEqual(head.headers, {"x-note": ["text Server: fake"]})

    def test_security_requires_a_complete_valid_http_head(self) -> None:
        for banner in (None, "SSH-2.0-OpenSSH", "HTTP/invalid 200 OK\r\n\r\n",
                       "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
                       "HTTP/1.1 200 OK\r\ninvalid field\r\n\r\n"):
            for url in (None, "https://example.test"):
                with self.subTest(banner=banner, url=url):
                    security = parse_http_metadata(banner, url)["security"]
                    self.assertFalse(security["applicable"])
                    self.assertEqual(security["missing"], [])
                    self.assertEqual(security["observations"], [])
        self.assertTrue(parse_http_metadata("HTTP/1.1 200 OK\r\n\r\n", None)["security"]["applicable"])

    def test_non_http_banner_has_no_status_code(self) -> None:
        self.assertIsNone(extract_http_status_code("SSH-2.0-OpenSSH_9.6"))
        self.assertIsNone(parse_http_response_head(None))


if __name__ == "__main__":
    unittest.main()
