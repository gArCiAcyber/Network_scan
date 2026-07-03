"""Localhost-only TLS integration tests for scanner metadata collection."""

import unittest

from modules.tcp_scanner import scan_tcp_ports
from tests.fixtures.mock_servers import (
    LOCALHOST,
    TLS_TEST_TIMEOUT as TEST_TIMEOUT,
    LocalSMTPStartTLSMockServer,
    LocalStartTLSStyleMockServer,
    LocalTLSMockServer,
)
from tests.fixtures.protocol_patches import (
    patched_ftp_auth_tls_registry,
    patched_imap_starttls_registry,
    patched_pop3_stls_registry,
    patched_smtp_starttls_registry,
    patched_tls_registry,
)


class TLSMockServiceScanTests(unittest.TestCase):
    """Validate TLS scanner behavior against safe local mock services."""

    def test_local_tls_service_returns_open_port_with_metadata(self) -> None:
        with LocalTLSMockServer() as server:
            self.assertIsNotNone(server.port)

            with patched_tls_registry(server.port):
                result = scan_tcp_ports(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    ports=[server.port],
                    timeout=TEST_TIMEOUT,
                    max_workers=1,
                )

        self.assertEqual(len(result.open_ports), 1)
        finding = result.open_ports[0]

        self.assertEqual(finding.port, server.port)
        self.assertIsNotNone(finding.tls)
        self.assertEqual(finding.tls["status"], "collected")

    def test_local_tls_certificate_metadata_contains_useful_fields(self) -> None:
        with LocalTLSMockServer() as server:
            self.assertIsNotNone(server.port)

            with patched_tls_registry(server.port):
                result = scan_tcp_ports(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    ports=[server.port],
                    timeout=TEST_TIMEOUT,
                    max_workers=1,
                )

        tls_metadata = result.open_ports[0].tls
        self.assertIsNotNone(tls_metadata)

        certificate = tls_metadata["certificate"]
        handshake = tls_metadata["handshake"]
        cipher = handshake["cipher"]

        self.assertEqual(certificate["subject"]["commonName"], ["localhost"])
        self.assertEqual(certificate["issuer"]["commonName"], ["localhost"])
        self.assertTrue(certificate["not_before"])
        self.assertTrue(certificate["not_after"])
        self.assertRegex(certificate["fingerprints"]["sha256"], r"^[a-f0-9]{64}$")
        self.assertTrue(handshake["protocol"])
        self.assertTrue(cipher["name"])
        self.assertTrue(cipher["protocol"])
        self.assertGreater(cipher["secret_bits"], 0)

    def test_local_smtp_starttls_service_collects_tls_metadata(self) -> None:
        with LocalSMTPStartTLSMockServer() as server:
            self.assertIsNotNone(server.port)

            with patched_smtp_starttls_registry(server.port):
                result = scan_tcp_ports(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    ports=[server.port],
                    timeout=TEST_TIMEOUT,
                    max_workers=1,
                )

        self.assertEqual(len(result.open_ports), 1)
        finding = result.open_ports[0]

        self.assertEqual(finding.port, server.port)
        self.assertIsNotNone(finding.banner)
        self.assertIn("220 hylianscan.mock ESMTP ready", finding.banner)
        self.assertIn("250-STARTTLS", finding.banner)
        self.assertIn("220 Ready to start TLS", finding.banner)
        self.assertTrue(
            any(b"EHLO hylianscan.local" in data for data in server.received_commands)
        )
        self.assertTrue(any(b"STARTTLS" in data for data in server.received_commands))
        self.assertIsNotNone(finding.probe)
        self.assertEqual(finding.probe["name"], "smtp")
        self.assertEqual(finding.probe["transport_security"], "starttls")
        self.assertEqual(finding.probe["method"], "smtp_ehlo")
        self.assertEqual(
            finding.probe["starttls"],
            {
                "supported": True,
                "attempted": True,
                "upgraded": True,
                "error": None,
            },
        )
        self.assertIsNotNone(finding.tls)
        self.assertEqual(finding.tls["status"], "collected")
        self.assertEqual(
            finding.tls["certificate"]["subject"]["commonName"],
            ["localhost"],
        )
        self.assertTrue(finding.tls["handshake"]["protocol"])

    def test_local_imap_starttls_service_collects_tls_metadata(self) -> None:
        command_flow = [
            (
                b"A001 CAPABILITY",
                b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
                b"a001 OK CAPABILITY completed\r\n",
            ),
            (
                b"A002 STARTTLS",
                b"a002 OK Begin TLS negotiation now\r\n",
            ),
        ]

        with LocalStartTLSStyleMockServer(
            greeting=b"* OK hylianscan.mock IMAP ready\r\n",
            command_flow=command_flow,
        ) as server:
            self.assertIsNotNone(server.port)

            with patched_imap_starttls_registry(server.port):
                result = scan_tcp_ports(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    ports=[server.port],
                    timeout=TEST_TIMEOUT,
                    max_workers=1,
                )

        self.assertEqual(len(result.open_ports), 1)
        finding = result.open_ports[0]

        self.assertEqual(finding.port, server.port)
        self.assertIsNotNone(finding.banner)
        self.assertIn("* OK hylianscan.mock IMAP ready", finding.banner)
        self.assertIn("STARTTLS", finding.banner)
        self.assertTrue(
            any(b"a001 CAPABILITY" in data for data in server.received_commands)
        )
        self.assertTrue(
            any(b"a002 STARTTLS" in data for data in server.received_commands)
        )
        self.assertIsNotNone(finding.probe)
        self.assertEqual(finding.probe["name"], "imap")
        self.assertEqual(finding.probe["transport_security"], "starttls")
        self.assertEqual(finding.probe["method"], "imap_starttls")
        self.assertEqual(
            finding.probe["starttls"],
            {
                "supported": True,
                "attempted": True,
                "upgraded": True,
                "error": None,
            },
        )
        self.assertIsNotNone(finding.tls)
        self.assertEqual(finding.tls["status"], "collected")
        self.assertEqual(
            finding.tls["certificate"]["subject"]["commonName"],
            ["localhost"],
        )
        self.assertTrue(finding.tls["handshake"]["protocol"])

    def test_local_pop3_stls_service_collects_tls_metadata(self) -> None:
        command_flow = [
            (
                b"CAPA",
                b"+OK Capability list follows\r\n"
                b"STLS\r\n"
                b"USER\r\n"
                b".\r\n",
            ),
            (
                b"STLS",
                b"+OK Begin TLS negotiation\r\n",
            ),
        ]

        with LocalStartTLSStyleMockServer(
            greeting=b"+OK hylianscan.mock POP3 ready\r\n",
            command_flow=command_flow,
        ) as server:
            self.assertIsNotNone(server.port)

            with patched_pop3_stls_registry(server.port):
                result = scan_tcp_ports(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    ports=[server.port],
                    timeout=TEST_TIMEOUT,
                    max_workers=1,
                )

        self.assertEqual(len(result.open_ports), 1)
        finding = result.open_ports[0]

        self.assertEqual(finding.port, server.port)
        self.assertIsNotNone(finding.banner)
        self.assertIn("+OK hylianscan.mock POP3 ready", finding.banner)
        self.assertIn("STLS", finding.banner)
        self.assertTrue(any(b"CAPA" in data for data in server.received_commands))
        self.assertTrue(any(b"STLS" in data for data in server.received_commands))
        self.assertIsNotNone(finding.probe)
        self.assertEqual(finding.probe["name"], "pop3")
        self.assertEqual(finding.probe["transport_security"], "starttls")
        self.assertEqual(finding.probe["method"], "pop3_stls")
        self.assertEqual(
            finding.probe["starttls"],
            {
                "supported": True,
                "attempted": True,
                "upgraded": True,
                "error": None,
            },
        )
        self.assertIsNotNone(finding.tls)
        self.assertEqual(finding.tls["status"], "collected")
        self.assertEqual(
            finding.tls["certificate"]["subject"]["commonName"],
            ["localhost"],
        )
        self.assertTrue(finding.tls["handshake"]["protocol"])

    def test_local_ftp_auth_tls_service_collects_tls_metadata(self) -> None:
        command_flow = [
            (
                b"AUTH TLS",
                b"234 Proceed with negotiation\r\n",
            ),
        ]

        with LocalStartTLSStyleMockServer(
            greeting=b"220 hylianscan.mock FTP ready\r\n",
            command_flow=command_flow,
        ) as server:
            self.assertIsNotNone(server.port)

            with patched_ftp_auth_tls_registry(server.port):
                result = scan_tcp_ports(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    ports=[server.port],
                    timeout=TEST_TIMEOUT,
                    max_workers=1,
                )

        self.assertEqual(len(result.open_ports), 1)
        finding = result.open_ports[0]

        self.assertEqual(finding.port, server.port)
        self.assertIsNotNone(finding.banner)
        self.assertIn("220 hylianscan.mock FTP ready", finding.banner)
        self.assertIn("234 Proceed with negotiation", finding.banner)
        self.assertTrue(any(b"AUTH TLS" in data for data in server.received_commands))
        self.assertIsNotNone(finding.probe)
        self.assertEqual(finding.probe["name"], "ftp")
        self.assertEqual(finding.probe["transport_security"], "starttls")
        self.assertEqual(finding.probe["method"], "ftp_auth_tls")
        self.assertEqual(
            finding.probe["starttls"],
            {
                "supported": True,
                "attempted": True,
                "upgraded": True,
                "error": None,
            },
        )
        self.assertIsNotNone(finding.tls)
        self.assertEqual(finding.tls["status"], "collected")
        self.assertEqual(
            finding.tls["certificate"]["subject"]["commonName"],
            ["localhost"],
        )
        self.assertTrue(finding.tls["handshake"]["protocol"])


if __name__ == "__main__":
    unittest.main()
