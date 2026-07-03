"""Localhost-only integration tests for mock TCP services."""

import socket
import unittest
from unittest.mock import patch

from modules import banner_grabber
from modules.tcp_scanner import scan_single_port, scan_tcp_ports
from tests.fixtures.mock_servers import (
    DEFAULT_TEST_TIMEOUT as TEST_TIMEOUT,
    LOCALHOST,
    LocalMockServer,
    get_closed_ephemeral_port,
)


class MockServiceScanTests(unittest.TestCase):
    """Validate scanner behavior against safe local mock services."""

    def test_plain_tcp_banner_service_is_detected_and_probed(self) -> None:
        def handler(client: socket.socket) -> None:
            client.sendall(b"MOCK TCP SERVICE\r\n")

        with LocalMockServer(handler, max_connections=2) as server:
            self.assertIsNotNone(server.port)
            result = scan_single_port(
                target_host=LOCALHOST,
                resolved_ip=LOCALHOST,
                port=server.port,
                timeout=TEST_TIMEOUT,
            )

        self.assertIsNotNone(result)
        self.assertEqual(result.port, server.port)
        self.assertEqual(result.banner, "MOCK TCP SERVICE")

    def test_minimal_http_service_is_detected_and_probed(self) -> None:
        request_data: list[bytes] = []

        def handler(client: socket.socket) -> None:
            try:
                data = client.recv(1024)
            except (OSError, socket.timeout):
                data = b""

            request_data.append(data)

            if data:
                client.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: hylianscan-mock\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                )

        with LocalMockServer(handler, max_connections=2) as server:
            self.assertIsNotNone(server.port)
            http_probe = banner_grabber.ProtocolProbe(
                protocol_name="http",
                ports=frozenset({server.port}),
                handler_name="grab_http_banner",
                requires_target_host=True,
            )

            with patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (http_probe,)):
                result = scan_single_port(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    port=server.port,
                    timeout=TEST_TIMEOUT,
                )

        self.assertIsNotNone(result)
        self.assertEqual(result.port, server.port)
        self.assertIsNotNone(result.banner)
        self.assertIn("HTTP/1.1 200 OK", result.banner)
        self.assertIn("Server: hylianscan-mock", result.banner)
        self.assertTrue(any(b"HEAD / HTTP/1.1" in data for data in request_data))

    def test_smtp_service_is_detected_and_protocol_probed(self) -> None:
        request_data: list[bytes] = []

        def handler(client: socket.socket) -> None:
            client.settimeout(0.2)
            client.sendall(b"220 hylianscan.mock ESMTP ready\r\n")

            try:
                data = client.recv(1024)
            except (OSError, socket.timeout):
                data = b""

            request_data.append(data)

            if data.upper().startswith(b"EHLO"):
                try:
                    client.sendall(
                        b"250-hylianscan.mock\r\n"
                        b"250-STARTTLS\r\n"
                        b"250 HELP\r\n"
                    )
                except OSError:
                    pass

        with LocalMockServer(handler, max_connections=2) as server:
            self.assertIsNotNone(server.port)
            smtp_probe = banner_grabber.ProtocolProbe(
                protocol_name="smtp",
                ports=frozenset({server.port}),
                handler_name="grab_smtp_banner",
            )

            with patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (smtp_probe,)):
                result = scan_single_port(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    port=server.port,
                    timeout=TEST_TIMEOUT,
                )

        self.assertIsNotNone(result)
        self.assertEqual(result.port, server.port)
        self.assertIsNotNone(result.banner)
        self.assertIn("220 hylianscan.mock ESMTP ready", result.banner)
        self.assertIn("250-hylianscan.mock 250-STARTTLS 250 HELP", result.banner)
        self.assertTrue(any(b"EHLO hylianscan.local" in data for data in request_data))

    def test_ftp_service_is_detected_and_protocol_probed(self) -> None:
        request_data: list[bytes] = []

        def handler(client: socket.socket) -> None:
            client.settimeout(0.2)
            client.sendall(b"220 hylianscan FTP ready\r\n")

            try:
                data = client.recv(1024)
            except (OSError, socket.timeout):
                data = b""

            request_data.append(data)

            if data.upper().startswith(b"SYST"):
                try:
                    client.sendall(b"215 UNIX Type: L8\r\n")
                except OSError:
                    pass

        with LocalMockServer(handler, max_connections=2) as server:
            self.assertIsNotNone(server.port)
            ftp_probe = banner_grabber.ProtocolProbe(
                protocol_name="ftp",
                ports=frozenset({server.port}),
                handler_name="grab_ftp_banner",
            )

            with patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (ftp_probe,)):
                result = scan_single_port(
                    target_host="localhost",
                    resolved_ip=LOCALHOST,
                    port=server.port,
                    timeout=TEST_TIMEOUT,
                )

        self.assertIsNotNone(result)
        self.assertEqual(result.port, server.port)
        self.assertIsNotNone(result.banner)
        self.assertIn("220 hylianscan FTP ready", result.banner)
        self.assertIn("215 UNIX Type: L8", result.banner)
        self.assertTrue(any(b"SYST" in data for data in request_data))

    def test_closed_localhost_port_returns_no_open_ports(self) -> None:
        closed_port = get_closed_ephemeral_port()

        single_result = scan_single_port(
            target_host=LOCALHOST,
            resolved_ip=LOCALHOST,
            port=closed_port,
            timeout=0.2,
        )
        scan_result = scan_tcp_ports(
            target_host=LOCALHOST,
            resolved_ip=LOCALHOST,
            ports=[closed_port],
            timeout=0.2,
            max_workers=1,
        )

        self.assertIsNone(single_result)
        self.assertEqual(scan_result.open_ports, ())


if __name__ == "__main__":
    unittest.main()
