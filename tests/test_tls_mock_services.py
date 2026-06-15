"""Localhost-only TLS integration tests for scanner metadata collection."""

import socket
import ssl
import tempfile
import threading
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

from modules import banner_grabber
from modules.tcp_scanner import scan_tcp_ports


LOCALHOST = "127.0.0.1"
TEST_TIMEOUT = 2.0

TEST_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIC1zCCAb+gAwIBAgIJAP3doKznRzSIMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMTCWxvY2FsaG9zdDAeFw0yNjA2MTQyMjIwMDVaFw0zNjA2MTUyMjIwMDVaMBQx
EjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMoDpVyB0HIYZ/gG/jr4UuvypraHelUEKuj46iZZBALSY3+Ik8w0283U39cP
eE22EHcKnXQ5lxcAXtjnRvxUwty701kkCbiouB6u7NJzkhpBsZAW6RCYS8IxLY9l
VKxVSL8t+ee6Iyb3NboRkY1k738H2bO6KZLqZyz2GLCz9+xPau6sxD+mFSkWSaw6
55cHRBotna76/24jnbo1nXnL2GOF6qCaa67eBHWge+lvNU5OIjiG5Z4GOVTW8Dug
eWGORbAwJu0FpvsFHpoFDc4ptWtHdSgy+s3zpL1unDJcXgiFsdwzj7BnDF4bdLuZ
nsMOCcwJQzKgNJxdsR9avTXqgtECAwEAAaMsMCowGgYDVR0RBBMwEYIJbG9jYWxo
b3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFgEvgDi
zV619HsqaQ3eBELRHpyK38hvl6IehLMQ26stp1bvwJhkAYHUJoueSGRIiYrB5jXZ
lFQGHitXKXCm0k7SEDYyjQ0f0eJsLuuenn5hghFVF6S7FfLT/eeo7txoiw789xAE
/uEQGDS/cgFIEImExqL3HMaUjzmRwxsk7Ns9jg5/R/Txs56H1n4OO0CaR8B104S/
yMz4hi5mMZ8zLPxGDQQXif6cDt+WqwXpuqpAaZaBOckj01OUIrcd7wakq655h+5D
MEQBLZuwRh2alTvidunMrDksc6nXNhW+wWmh/ZN8ShPyDTMoU7hgCj4RIAIbgyaL
lNdtexsEF5VtuLY=
-----END CERTIFICATE-----"""

# TEST-ONLY CERTIFICATE MATERIAL.
# This private key is intentionally embedded for localhost TLS unit tests.
# It is not used for production, authentication, deployment, or real services.

TEST_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAygOlXIHQchhn+Ab+OvhS6/Kmtod6VQQq6PjqJlkEAtJjf4iT
zDTbzdTf1w94TbYQdwqddDmXFwBe2OdG/FTC3LvTWSQJuKi4Hq7s0nOSGkGxkBbp
EJhLwjEtj2VUrFVIvy3557ojJvc1uhGRjWTvfwfZs7opkupnLPYYsLP37E9q7qzE
P6YVKRZJrDrnlwdEGi2drvr/biOdujWdecvYY4XqoJprrt4EdaB76W81Tk4iOIbl
ngY5VNbwO6B5YY5FsDAm7QWm+wUemgUNzim1a0d1KDL6zfOkvW6cMlxeCIWx3DOP
sGcMXht0u5meww4JzAlDMqA0nF2xH1q9NeqC0QIDAQABAoIBADjfAeSjHx2fxVVM
ErJjSmTmcQyd41Cf1by0pqaZFMn+lMhImOM6Vk8CCOowjrvB76yzrlQUCncNQaZq
pc9PxXQC5KMJxDraNMtej4lHw+/kYqqf6Ikldt56ncrqygWiFNLNjLcx7ceAfP2f
CIz3x3zJpv40AJQ9rUI5HgZRBBDgYrVf+jHUdUIjTcac2RGxlf5fSfWC/67aTrDV
ESh4lP+uDNXVJsChLkGONEFIbeM40D2qM/+wxgEimONPfDuL/QsxdIbiopx8+Ux0
WdBbVxYE4jb+OWKGE/wkHq16la5bKXpNBvjGD0EI6lGUTZrtq7Hbj9GzgCkUrZOt
K4BAQQkCgYEA3oQsrgitYLLifVKXUFwM2yxtMezZx/k/zC7HyFdbzpXBB4ZNkxv1
ABfHlUrlGyTNEIF+MiDtxlC5+BAoPqmGP20TChDuzciWwiExufekINkEfSWZQDoQ
JZoLgy1DqFLpaNkE+RJDrDyzFLcJ9yVtZmULOLhAWDTP7H6MEDEigpcCgYEA6Gmv
oTFbV+7Fb1vZtX+1HusR3VSq9FRr+D2z5zTlPJyUkOgnpuc3u8K278i9HpROiuxd
WGmTeOaFyI0JLXCR/h1kxNRxEqcvF7a24Rta72+Z9sNZwh2RNXUHNDGCAe1u4yzF
81z+N4s3/KLCVruxB8Fb3tYgrLFqGW3m+BegmtcCgYBZkiEeKTYJf9i2E+H/Ih62
t0p5V1tPKSEqQwZ+udOl9BhQvBpMBmv4DppzmUNiSs0VQNsYuLKeKu7BUVex6bG1
pGWOnsRSJ9Wv7YbD0lDKPDGXYuQuu3C2gizyL+1VO5LjdsCOtnBxS7nWs9uaFgHU
vwXmXhzgpNmx3DrrZav7nwKBgHG3FEnoXmsd1thvtowJmlMwbSNARA0cKV/iwN2F
kgwgCMkF7jDJvQlPcjbMn0wRAIUUtW+G6LMlB5xi9XSYObZ+J0nvMAwSZQZTThPC
ULIKhuioGIjT8rKXOhkdiCDtTW41//zdKT2ADrq74B6T40CKKStU1dPpUqJylaoZ
1WktAoGAT3Y2f9ZxoWe70gEz5koATJBEDK3R09CXZ96//xR2qkTT62KbTYBNBi9K
hOgEue37UWcIxAHmJ640GkgBVuf6lzQ6DlTMVKOCiurN2RH5841N8PkaRtCsTh60
5ZPLvht7dghpCLqFEl9nNW1b13ON2SWHkYvTfSBm+jX6t64nZ6s=
-----END RSA PRIVATE KEY-----"""


class LocalTLSMockServer:
    """Tiny localhost TLS server for scanner integration tests."""

    def __init__(self, max_connections: int = 2) -> None:
        self.max_connections = max_connections
        self.port: int | None = None
        self._ready = threading.Event()
        self._temporary_directory = tempfile.TemporaryDirectory()
        self._context = self._build_context(Path(self._temporary_directory.name))
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(max_connections)
        self._server.settimeout(TEST_TIMEOUT)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> "LocalTLSMockServer":
        self._thread.start()
        self._ready.wait(TEST_TIMEOUT)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close server resources."""
        try:
            self._server.close()
        except OSError:
            pass

        self._thread.join(TEST_TIMEOUT)
        self._temporary_directory.cleanup()

    def _build_context(self, directory: Path) -> ssl.SSLContext:
        """Create a server TLS context from embedded test certificate material."""
        cert_path = directory / "localhost.crt"
        key_path = directory / "localhost.key"
        cert_path.write_text(TEST_CERTIFICATE_PEM, encoding="ascii")
        key_path.write_text(TEST_PRIVATE_KEY_PEM, encoding="ascii")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context

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
                        tls_client.settimeout(TEST_TIMEOUT)
                        self._drain_client(tls_client)
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

    def _drain_client(self, tls_client: ssl.SSLSocket) -> None:
        """Read optional client data and keep the handshake path stable."""
        try:
            tls_client.recv(1024)
        except (OSError, socket.timeout, ssl.SSLError):
            pass


def patched_tls_registry(port: int) -> Iterator[object]:
    """Patch protocol probing so the ephemeral port is treated as TLS."""
    tls_probe = banner_grabber.ProtocolProbe(
        protocol_name="generic_tls_metadata",
        ports=frozenset({port}),
        handler_name="grab_tls_metadata",
        tls_behavior=banner_grabber.TLS_BEHAVIOR_METADATA,
    )

    return patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (tls_probe,))


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


if __name__ == "__main__":
    unittest.main()
