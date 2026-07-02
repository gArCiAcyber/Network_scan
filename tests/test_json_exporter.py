"""Tests for TCP JSON export document builders."""

import unittest
from types import SimpleNamespace

from modules.json_exporter import (
    build_nmap_xml_import_document,
    build_port_document,
    build_tcp_scan_document,
    parse_set_cookie_header,
)
from modules.nmap_xml import parse_nmap_xml_text


HTTP_BANNER = (
    "HTTP/1.1 301 Moved Permanently "
    "Server: cloudflare "
    "Location: https://example.com/ "
    "Content-Type: text/html; charset=utf-8"
)

COOKIE_BANNER = (
    "HTTP/1.1 200 OK "
    "Server: hylianscan-mock "
    "Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/; "
    "Max-Age=3600 "
    "Set-Cookie: tracking_id=xyz; Path=/tracking"
)

STRONG_SECURITY_BANNER = (
    "HTTP/1.1 200 OK "
    "Strict-Transport-Security: max-age=31536000; includeSubDomains "
    "Content-Security-Policy: default-src 'self' "
    "X-Frame-Options: DENY "
    "X-Content-Type-Options: nosniff "
    "Referrer-Policy: no-referrer "
    "Permissions-Policy: geolocation=() "
    "Cross-Origin-Opener-Policy: same-origin"
)

MISSING_SECURITY_BANNER = (
    "HTTP/1.1 200 OK "
    "Server: hylianscan-mock "
    "Content-Type: text/html"
)
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 127.0.0.1"
         start="1710000000" startstr="Sat Mar 9 12:00:00 2024"
         version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"
                 extrainfo="reverse proxy" method="probed" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.24</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""

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
EXPIRED_TLS_METADATA = {
    **TLS_METADATA,
    "certificate": {
        **TLS_METADATA["certificate"],
        "not_after": "Jan 01 00:00:00 2020 GMT",
    },
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

    def test_nmap_xml_import_document_contains_import_evidence(self) -> None:
        import_result = parse_nmap_xml_text(NMAP_XML)
        document = build_nmap_xml_import_document(import_result, "scan.xml")

        self.assertEqual(document["tool"], "hylianscan")
        self.assertEqual(document["mode"], "nmap_xml_import")
        self.assertEqual(document["source"]["path"], "scan.xml")
        self.assertEqual(document["source"]["scanner"], "nmap")
        self.assertEqual(document["source"]["args"], "nmap -sV -oX scan.xml 127.0.0.1")
        self.assertEqual(document["source"]["version"], "7.94")
        self.assertEqual(document["source"]["xmloutputversion"], "1.05")
        self.assertEqual(document["source"]["start"], "1710000000")
        self.assertEqual(document["source"]["startstr"], "Sat Mar 9 12:00:00 2024")
        self.assertEqual(document["host"]["status"], "up")
        self.assertEqual(document["host"]["primary_address"], "127.0.0.1")
        self.assertEqual(
            document["host"]["addresses"],
            [
                {
                    "address": "127.0.0.1",
                    "type": "ipv4",
                    "vendor": None,
                }
            ],
        )
        self.assertEqual(len(document["open_tcp_ports"]), 1)

        port = document["open_tcp_ports"][0]
        self.assertEqual(port["port"], 80)
        self.assertEqual(port["protocol"], "tcp")
        self.assertEqual(port["state"], "open")
        self.assertEqual(
            port["service"],
            {
                "name": "http",
                "product": "nginx",
                "version": "1.24",
                "extrainfo": "reverse proxy",
                "tunnel": None,
                "method": "probed",
                "conf": 10,
                "confidence": "high",
                "cpe": ["cpe:/a:nginx:nginx:1.24"],
            },
        )

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
        self.assertNotIn("report_filters", document["scan"])

    def test_tcp_json_records_active_http_status_filter(self) -> None:
        document = build_tcp_scan_document(
            make_scan_result([make_finding()]),
            report_filters={
                "http_status_codes": {
                    "expression": "200,301-304",
                    "resolved_codes": [200, 301, 302, 303, 304],
                }
            },
        )

        self.assertEqual(
            document["scan"]["report_filters"],
            {
                "http_status_codes": {
                    "expression": "200,301-304",
                    "resolved_codes": [200, 301, 302, 303, 304],
                }
            },
        )

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
        self.assertEqual(http["cookies"], [])
        self.assertIn("security", http)

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
        self.assertFalse(cookie["uses_host_prefix"])
        self.assertFalse(cookie["uses_secure_prefix"])
        self.assertEqual(cookie["security_observations"], [])

    def test_set_cookie_parser_reports_missing_security_attributes(self) -> None:
        cookie = parse_set_cookie_header("tracking_id=xyz; Path=/tracking")

        self.assertIsNotNone(cookie)
        self.assertEqual(cookie["name"], "tracking_id")
        self.assertTrue(cookie["value_present"])
        self.assertFalse(cookie["secure"])
        self.assertFalse(cookie["httponly"])
        self.assertIsNone(cookie["samesite"])
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
        self.assertTrue(host_cookie["uses_host_prefix"])
        self.assertFalse(host_cookie["uses_secure_prefix"])
        self.assertIn("host_prefix_valid", host_cookie["security_observations"])

        self.assertIsNotNone(secure_cookie)
        self.assertFalse(secure_cookie["uses_host_prefix"])
        self.assertTrue(secure_cookie["uses_secure_prefix"])
        self.assertIn("secure_prefix_valid", secure_cookie["security_observations"])

    def test_set_cookie_parser_detects_missing_cookie_value(self) -> None:
        cookie = parse_set_cookie_header("empty_cookie=; Secure")

        self.assertIsNotNone(cookie)
        self.assertEqual(cookie["name"], "empty_cookie")
        self.assertFalse(cookie["value_present"])

    def test_http_metadata_parses_multiple_set_cookie_headers(self) -> None:
        port_document = build_port_document(
            make_finding(
                banner=COOKIE_BANNER,
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
        http = port_document["http"]
        cookies = http["cookies"]

        self.assertEqual(len(http["headers"]["set-cookie"]), 2)
        self.assertEqual(len(cookies), 2)
        self.assertEqual(cookies[0]["name"], "session_id")
        self.assertEqual(cookies[0]["max_age"], "3600")
        self.assertEqual(cookies[0]["security_observations"], [])
        self.assertEqual(cookies[1]["name"], "tracking_id")
        self.assertEqual(
            cookies[1]["security_observations"],
            ["missing_secure", "missing_httponly", "missing_samesite"],
        )

    def test_http_security_observations_with_strong_headers(self) -> None:
        port_document = build_port_document(
            make_finding(
                banner=STRONG_SECURITY_BANNER,
                web_url="https://example.com",
            ),
            "example.com",
        )
        security = port_document["http"]["security"]

        self.assertEqual(security["missing"], [])
        self.assertEqual(security["observations"], [])
        self.assertIn("strict-transport-security", security["present"])
        self.assertTrue(
            security["headers"]["strict-transport-security"]["present"]
        )
        self.assertTrue(
            security["headers"]["content-security-policy"]["present"]
        )
        self.assertEqual(
            security["headers"]["x-content-type-options"]["values"],
            ["nosniff"],
        )

    def test_http_security_observations_missing_common_headers(self) -> None:
        port_document = build_port_document(
            make_finding(
                banner=MISSING_SECURITY_BANNER,
                web_url="https://example.com",
            ),
            "example.com",
        )
        security = port_document["http"]["security"]

        self.assertIn("strict-transport-security", security["missing"])
        self.assertIn("content-security-policy", security["missing"])
        self.assertIn("missing_strict_transport_security", security["observations"])
        self.assertIn("missing_content_security_policy", security["observations"])
        self.assertFalse(
            security["headers"]["permissions-policy"]["present"]
        )

    def test_https_response_without_hsts_reports_missing_hsts(self) -> None:
        port_document = build_port_document(
            make_finding(
                banner=MISSING_SECURITY_BANNER,
                web_url="https://example.com",
            ),
            "example.com",
        )
        hsts = port_document["http"]["security"]["headers"][
            "strict-transport-security"
        ]

        self.assertTrue(hsts["expected"])
        self.assertFalse(hsts["present"])
        self.assertEqual(hsts["observations"], ["missing_strict_transport_security"])

    def test_http_response_does_not_expect_hsts_like_https(self) -> None:
        port_document = build_port_document(
            make_finding(
                banner=MISSING_SECURITY_BANNER,
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
        security = port_document["http"]["security"]
        hsts = security["headers"]["strict-transport-security"]

        self.assertFalse(hsts["expected"])
        self.assertFalse(hsts["present"])
        self.assertEqual(hsts["observations"], ["not_expected_on_plain_http"])
        self.assertNotIn("strict-transport-security", security["missing"])
        self.assertNotIn("missing_strict_transport_security", security["observations"])

    def test_tcp_json_includes_http_security_observation_structure(self) -> None:
        document = build_tcp_scan_document(
            make_scan_result(
                [
                    make_finding(
                        banner=STRONG_SECURITY_BANNER,
                        web_url="https://example.com",
                    )
                ]
            )
        )
        http = document["results"]["open_ports"][0]["http"]

        self.assertIn("security", http)
        self.assertIn("headers", http["security"])
        self.assertIn("present", http["security"])
        self.assertIn("missing", http["security"])
        self.assertIn("observations", http["security"])

    def test_tls_analysis_presence_in_exported_port_documents(self) -> None:
        port_document = build_port_document(make_finding(), "example.com")

        self.assertEqual(port_document["tls"], TLS_METADATA)
        self.assertIn("tls_analysis", port_document)
        self.assertFalse(port_document["tls_analysis"]["expired"])
        self.assertFalse(port_document["tls_analysis"]["hostname_mismatch"])
        self.assertEqual(port_document["tls_analysis"]["severity"], "low")
        self.assertEqual(port_document["tls_analysis"]["reasons"], [])

    def test_tcp_json_includes_tls_analysis_reasons(self) -> None:
        port_document = build_port_document(
            make_finding(tls=EXPIRED_TLS_METADATA),
            "example.com",
        )
        tls_analysis = port_document["tls_analysis"]

        self.assertIn("expired", tls_analysis)
        self.assertIn("days_until_expiry", tls_analysis)
        self.assertIn("expires_soon", tls_analysis)
        self.assertIn("hostname_mismatch", tls_analysis)
        self.assertIn("severity", tls_analysis)
        self.assertEqual(tls_analysis["severity"], "high")
        self.assertEqual(len(tls_analysis["reasons"]), 1)
        self.assertEqual(
            tls_analysis["reasons"][0]["id"],
            "certificate_expired",
        )

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

    def test_imap_starttls_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=143,
                service="IMAP",
                banner="* OK IMAP ready | * CAPABILITY IMAP4rev1 STARTTLS",
                web_url=None,
                probe={
                    "name": "imap",
                    "transport_security": "starttls",
                    "method": "imap_starttls",
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

        self.assertEqual(port_document["probe"]["name"], "imap")
        self.assertEqual(port_document["probe"]["transport_security"], "starttls")
        self.assertEqual(port_document["probe"]["method"], "imap_starttls")
        self.assertTrue(port_document["probe"]["starttls"]["supported"])
        self.assertTrue(port_document["probe"]["starttls"]["attempted"])
        self.assertTrue(port_document["probe"]["starttls"]["upgraded"])

    def test_pop3_stls_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=110,
                service="POP3",
                banner="+OK POP3 ready | +OK Capability list follows STLS",
                web_url=None,
                probe={
                    "name": "pop3",
                    "transport_security": "starttls",
                    "method": "pop3_stls",
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

        self.assertEqual(port_document["probe"]["name"], "pop3")
        self.assertEqual(port_document["probe"]["transport_security"], "starttls")
        self.assertEqual(port_document["probe"]["method"], "pop3_stls")
        self.assertTrue(port_document["probe"]["starttls"]["supported"])
        self.assertTrue(port_document["probe"]["starttls"]["attempted"])
        self.assertTrue(port_document["probe"]["starttls"]["upgraded"])

    def test_ftp_auth_tls_probe_metadata(self) -> None:
        port_document = build_port_document(
            make_finding(
                port=21,
                service="FTP",
                banner="220 FTP ready | 234 Proceed with negotiation",
                web_url=None,
                probe={
                    "name": "ftp",
                    "transport_security": "starttls",
                    "method": "ftp_auth_tls",
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

        self.assertEqual(port_document["probe"]["name"], "ftp")
        self.assertEqual(port_document["probe"]["transport_security"], "starttls")
        self.assertEqual(port_document["probe"]["method"], "ftp_auth_tls")
        self.assertTrue(port_document["probe"]["starttls"]["supported"])
        self.assertTrue(port_document["probe"]["starttls"]["attempted"])
        self.assertTrue(port_document["probe"]["starttls"]["upgraded"])

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
