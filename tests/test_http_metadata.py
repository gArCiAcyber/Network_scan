"""Tests for shared primitive HTTP response parsing."""

import unittest

from modules.http_metadata import (
    extract_http_header,
    extract_http_status_code,
    parse_http_response_head,
)


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
        self.assertEqual(
            extract_http_header(banner, "Location"),
            "https://example.com/",
        )

    def test_non_http_banner_has_no_status_code(self) -> None:
        self.assertIsNone(extract_http_status_code("SSH-2.0-OpenSSH_9.6"))
        self.assertIsNone(parse_http_response_head(None))


if __name__ == "__main__":
    unittest.main()
