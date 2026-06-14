"""Localhost-only integration tests for mock TCP services."""

import socket
import threading
import unittest
from collections.abc import Callable
from unittest.mock import patch

from modules import banner_grabber
from modules.tcp_scanner import scan_single_port, scan_tcp_ports


LOCALHOST = "127.0.0.1"
TEST_TIMEOUT = 1.0


class LocalMockServer:
    """Tiny localhost server for scanner integration tests."""

    def __init__(
        self,
        handler: Callable[[socket.socket], None],
        max_connections: int = 1,
    ) -> None:
        self.handler = handler
        self.max_connections = max_connections
        self.port: int | None = None
        self.received_data: list[bytes] = []
        self._ready = threading.Event()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(max_connections)
        self._server.settimeout(TEST_TIMEOUT)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "LocalMockServer":
        self._thread.start()
        self._ready.wait(TEST_TIMEOUT)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the listening socket and wait briefly for the server thread."""
        try:
            self._server.close()
        except OSError:
            pass

        self._thread.join(TEST_TIMEOUT)

    def _serve(self) -> None:
        """Accept a fixed number of local connections."""
        self._ready.set()

        try:
            for _ in range(self.max_connections):
                try:
                    client, _address = self._server.accept()
                except OSError:
                    break

                with client:
                    client.settimeout(TEST_TIMEOUT)
                    self.handler(client)
        finally:
            try:
                self._server.close()
            except OSError:
                pass


def get_closed_ephemeral_port() -> int:
    """Allocate and close an ephemeral localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((LOCALHOST, 0))
        return server.getsockname()[1]


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
            except socket.timeout:
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
