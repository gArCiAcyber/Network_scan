"""Tests for TCP JSON export document builders."""

import unittest
from types import SimpleNamespace

from modules.json_exporter import build_port_document, build_tcp_scan_document


HTTP_BANNER = (
    "HTTP/1.1 301 Moved Permanently "
    "Server: cloudflare "
    "Location: https://example.com/ "
    "Content-Type: text/html; charset=utf-8"
)

TLS_METADATA = {
    "status": "collected",
    "handshake": {
        "protocol": "TLSv1.3",
        "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256],
    },
    "certificate": {
        "not_after": "Dec 31 00:00:00 2026 GMT",
        "subject": {
            "commonName": ["example.com"],
        },
        "issuer": {
            "organizationName": ["Example CA"],
        },
        "subject_alt_names": {
            "dns_names": ["example.com", "www.example.com"],
            "ip_addresses": [],
        },
    },
    "error": None,
}


def make_finding(**overrides: object) -> SimpleNamespace:
    """Build a minimal open-port finding object for JSON export tests."""
    values: dict[str, object] = {
        "port": 443,
        "service": "HTTPS",
        "banner": HTTP_BANNER,
        "response_time": 0.1234567,
        "web_url": "https://example.com",
        "tls": TLS_METADATA,
        "probe": {
            "name": "https",
            "transport_security": "implicit_tls",
            "method": "http_head",
        },
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def make_scan_result(open_ports: list[SimpleNamespace]) -> SimpleNamespace:
    """Build a minimal TCP scan result object for JSON export tests."""
    return SimpleNamespace(
        target_host="example.com",
        resolved_ip="93.184.216.34",
        scanned_ports=2,
        open_ports=open_ports,
        duration=1.2345678,
    )


class JSONExporterTests(unittest.TestCase):
    """Validate pure TCP JSON export structure."""

    def test_tcp_json_schema_structure(self) -> None:
        document = build_tcp_scan_document(make_scan_result([make_finding()]))

        self.assertEqual(
            document["schema"],
            {
                "name": "hylianscan_tcp_scan",
                "version": 1,
            },
        )
        self.assertEqual(document["scan"]["type"], "tcp")
        self.assertEqual(document["scan"]["target"]["host"], "example.com")
        self.assertEqual(document["scan"]["target"]["resolved_ip"], "93.184.216.34")
        self.assertEqual(document["scan"]["scope"]["ports_tested"], 2)
        self.assertEqual(document["scan"]["summary"]["open_ports"], 1)
        self.assertEqual(document["scan"]["timing"]["duration_seconds"], 1.234568)
        self.assertIn("open_ports", document["results"])

    def test_open_port_document_structure(self) -> None:
        port_document = build_port_document(make_finding(), "example.com")

        self.assertEqual(port_document["port"], 443)
        self.assertEqual(port_document["transport"], "tcp")
        self.assertEqual(port_document["status"], "open")
        self.assertEqual(port_document["service"]["name"], "HTTPS")
        self.assertIn("probe", port_document)
        self.assertEqual(port_document["banner"]["raw"], HTTP_BANNER)
        self.assertEqual(port_document["timing"]["response_time_seconds"], 0.123457)

    def test_http_metadata_parsing(self) -> None:
        port_document = build_port_document(make_finding(), "example.com")
        http = port_document["http"]

        self.assertEqual(http["url"], "https://example.com")
        self.assertEqual(http["protocol"], "HTTP/1.1")
        self.assertEqual(http["status_code"], 301)
        self.assertEqual(http["reason_phrase"], "Moved Permanently")
        self.assertEqual(http["server"], "cloudflare")
        self.assertEqual(http["location"], "https://example.com/")
        self.assertEqual(http["content_type"], "text/html; charset=utf-8")
        self.assertEqual(http["headers"]["server"], ["cloudflare"])
        self.assertEqual(http["headers"]["location"], ["https://example.com/"])

    def test_tls_analysis_presence_in_exported_port_documents(self) -> None:
        port_document = build_port_document(make_finding(), "example.com")

        self.assertEqual(port_document["tls"], TLS_METADATA)
        self.assertIn("tls_analysis", port_document)
        self.assertFalse(port_document["tls_analysis"]["expired"])
        self.assertFalse(port_document["tls_analysis"]["hostname_mismatch"])
        self.assertEqual(port_document["tls_analysis"]["severity"], "low")

    def test_http_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=80,
                service="HTTP",
                web_url="http://example.com",
                tls=None,
                probe={
                    "name": "http",
                    "transport_security": "none",
                    "method": "http_head",
                },
            ),
            "example.com",
        )

        self.assertEqual(
            port_document["probe"],
            {
                "name": "http",
                "transport_security": "none",
                "method": "http_head",
            },
        )

    def test_https_implicit_tls_probe_metadata(self) -> None:
        port_document = build_port_document(make_finding(), "example.com")

        self.assertEqual(
            port_document["probe"],
            {
                "name": "https",
                "transport_security": "implicit_tls",
                "method": "http_head",
            },
        )

    def test_smtp_starttls_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=25,
                service="SMTP",
                banner="220 mail.example ESMTP | 250-STARTTLS | 220 Ready",
                web_url=None,
                probe={
                    "name": "smtp",
                    "transport_security": "starttls",
                    "method": "smtp_ehlo",
                    "starttls": {
                        "supported": True,
                        "attempted": True,
                        "upgraded": True,
                        "error": None,
                    },
                },
            ),
            "example.com",
        )

        self.assertEqual(port_document["probe"]["name"], "smtp")
        self.assertEqual(port_document["probe"]["transport_security"], "starttls")
        self.assertEqual(port_document["probe"]["method"], "smtp_ehlo")
        self.assertEqual(
            port_document["probe"]["starttls"],
            {
                "supported": True,
                "attempted": True,
                "upgraded": True,
                "error": None,
            },
        )

    def test_ftp_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=21,
                service="FTP",
                banner="220 FTP ready | 215 UNIX Type: L8",
                web_url=None,
                tls=None,
                probe={
                    "name": "ftp",
                    "transport_security": "none",
                    "method": "ftp_syst",
                },
            ),
            "example.com",
        )

        self.assertEqual(
            port_document["probe"],
            {
                "name": "ftp",
                "transport_security": "none",
                "method": "ftp_syst",
            },
        )

    def test_unknown_fallback_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=9999,
                service="unknown",
                banner="custom service",
                web_url=None,
                tls=None,
                probe={
                    "name": "unknown",
                    "transport_security": "unknown",
                    "method": "passive_banner",
                },
            ),
            "example.com",
        )

        self.assertEqual(
            port_document["probe"],
            {
                "name": "unknown",
                "transport_security": "unknown",
                "method": "passive_banner",
            },
        )

    def test_tcp_scan_document_contains_open_port_documents(self) -> None:
        document = build_tcp_scan_document(make_scan_result([make_finding(port=8443)]))
        open_ports = document["results"]["open_ports"]

        self.assertEqual(len(open_ports), 1)
        self.assertEqual(open_ports[0]["port"], 8443)
        self.assertIn("probe", open_ports[0])
        self.assertEqual(open_ports[0]["http"]["status_code"], 301)
        self.assertEqual(open_ports[0]["tls_analysis"]["severity"], "low")


if __name__ == "__main__":
    unittest.main()
