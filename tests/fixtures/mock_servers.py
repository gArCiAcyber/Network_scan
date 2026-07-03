"""Reusable localhost mock servers for scanner integration tests."""

import socket
import ssl
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

from tests.fixtures.certificates import TEST_CERTIFICATE_PEM, TEST_PRIVATE_KEY_PEM


LOCALHOST = "127.0.0.1"
DEFAULT_TEST_TIMEOUT = 1.0
TLS_TEST_TIMEOUT = 2.0


class LocalMockServer:
    """Tiny localhost server for scanner integration tests."""

    def __init__(
        self,
        handler: Callable[[socket.socket], None],
        max_connections: int = 1,
        timeout: float = DEFAULT_TEST_TIMEOUT,
    ) -> None:
        self.handler = handler
        self.max_connections = max_connections
        self.timeout = timeout
        self.port: int | None = None
        self.received_data: list[bytes] = []
        self._ready = threading.Event()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(max_connections)
        self._server.settimeout(timeout)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "LocalMockServer":
        self._thread.start()
        self._ready.wait(self.timeout)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the listening socket and wait briefly for the server thread."""
        try:
            self._server.close()
        except OSError:
            pass

        self._thread.join(self.timeout)

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
                    client.settimeout(self.timeout)
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


def build_tls_server_context(directory: Path) -> ssl.SSLContext:
    """Create a server TLS context from embedded test certificate material."""
    cert_path = directory / "localhost.crt"
    key_path = directory / "localhost.key"
    cert_path.write_text(TEST_CERTIFICATE_PEM, encoding="ascii")
    key_path.write_text(TEST_PRIVATE_KEY_PEM, encoding="ascii")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


class LocalTLSMockServer:
    """Tiny localhost TLS server for scanner integration tests."""

    def __init__(self, max_connections: int = 2) -> None:
        self.max_connections = max_connections
        self.port: int | None = None
        self._ready = threading.Event()
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._context = build_tls_server_context(Path(self._temporary_directory.name))
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(max_connections)
        self._server.settimeout(TLS_TEST_TIMEOUT)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "LocalTLSMockServer":
        self._thread.start()
        self._ready.wait(TLS_TEST_TIMEOUT)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close server resources."""
        try:
            self._server.close()
        except OSError:
            pass

        self._thread.join(TLS_TEST_TIMEOUT)
        self._temporary_directory.cleanup()

    def _serve(self) -> None:
        """Accept discovery and TLS probe connections."""
        self._ready.set()

        try:
            for _ in range(self.max_connections):
                try:
                    client, _address = self._server.accept()
                except OSError:
                    break

                client.settimeout(0.5)
                try:
                    with self._context.wrap_socket(client, server_side=True) as tls_client:
                        tls_client.settimeout(TLS_TEST_TIMEOUT)
                        drain_tls_client(tls_client)
                except (OSError, ssl.SSLError):
                    try:
                        client.close()
                    except OSError:
                        pass
        finally:
            try:
                self._server.close()
            except OSError:
                pass


class LocalSMTPStartTLSMockServer:
    """Tiny localhost SMTP server that upgrades one connection with STARTTLS."""

    def __init__(self, max_connections: int = 2) -> None:
        self.max_connections = max_connections
        self.port: int | None = None
        self.received_commands: list[bytes] = []
        self._ready = threading.Event()
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._context = build_tls_server_context(Path(self._temporary_directory.name))
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(max_connections)
        self._server.settimeout(TLS_TEST_TIMEOUT)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "LocalSMTPStartTLSMockServer":
        self._thread.start()
        self._ready.wait(TLS_TEST_TIMEOUT)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close server resources."""
        try:
            self._server.close()
        except OSError:
            pass

        self._thread.join(TLS_TEST_TIMEOUT)
        self._temporary_directory.cleanup()

    def _serve(self) -> None:
        """Accept discovery and SMTP STARTTLS probe connections."""
        self._ready.set()

        try:
            for _ in range(self.max_connections):
                try:
                    client, _address = self._server.accept()
                except OSError:
                    break

                with client:
                    client.settimeout(TLS_TEST_TIMEOUT)
                    self._handle_client(client)
        finally:
            try:
                self._server.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket) -> None:
        """Handle one SMTP connection and upgrade when STARTTLS is requested."""
        try:
            client.sendall(b"220 hylianscan.mock ESMTP ready\r\n")
            ehlo_command = client.recv(1024)
        except (OSError, socket.timeout):
            return

        self.received_commands.append(ehlo_command)

        if not ehlo_command.upper().startswith(b"EHLO"):
            return

        try:
            client.sendall(
                b"250-hylianscan.mock\r\n"
                b"250-STARTTLS\r\n"
                b"250 HELP\r\n"
            )
            starttls_command = client.recv(1024)
        except (OSError, socket.timeout):
            return

        self.received_commands.append(starttls_command)

        if not starttls_command.upper().startswith(b"STARTTLS"):
            return

        try:
            client.sendall(b"220 Ready to start TLS\r\n")
            with self._context.wrap_socket(client, server_side=True) as tls_client:
                tls_client.settimeout(TLS_TEST_TIMEOUT)
                drain_tls_client(tls_client)
        except (OSError, ssl.SSLError):
            return


class LocalStartTLSStyleMockServer:
    """Tiny localhost server for text protocols with TLS upgrade commands."""

    def __init__(
        self,
        greeting: bytes,
        command_flow: list[tuple[bytes, bytes]],
        max_connections: int = 2,
    ) -> None:
        self.greeting = greeting
        self.command_flow = command_flow
        self.max_connections = max_connections
        self.port: int | None = None
        self.received_commands: list[bytes] = []
        self._ready = threading.Event()
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._context = build_tls_server_context(Path(self._temporary_directory.name))
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(max_connections)
        self._server.settimeout(TLS_TEST_TIMEOUT)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "LocalStartTLSStyleMockServer":
        self._thread.start()
        self._ready.wait(TLS_TEST_TIMEOUT)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close server resources."""
        try:
            self._server.close()
        except OSError:
            pass

        self._thread.join(TLS_TEST_TIMEOUT)
        self._temporary_directory.cleanup()

    def _serve(self) -> None:
        """Accept discovery and protocol upgrade probe connections."""
        self._ready.set()

        try:
            for _ in range(self.max_connections):
                try:
                    client, _address = self._server.accept()
                except OSError:
                    break

                try:
                    client.settimeout(TLS_TEST_TIMEOUT)
                    self._handle_client(client)
                finally:
                    try:
                        client.close()
                    except OSError:
                        pass
        finally:
            try:
                self._server.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket) -> None:
        """Handle one plaintext command flow and upgrade to TLS."""
        try:
            client.sendall(self.greeting)

            for expected_prefix, response in self.command_flow:
                command = client.recv(1024)

                if not command:
                    return

                self.received_commands.append(command)

                if not command.upper().startswith(expected_prefix):
                    return

                client.sendall(response)

            with self._context.wrap_socket(client, server_side=True) as tls_client:
                tls_client.settimeout(TLS_TEST_TIMEOUT)
                drain_tls_client(tls_client)
        except (OSError, socket.timeout, ssl.SSLError):
            return


def drain_tls_client(tls_client: ssl.SSLSocket) -> None:
    """Read optional TLS client data after the handshake."""
    try:
        tls_client.recv(1024)
    except (OSError, socket.timeout, ssl.SSLError):
        pass
