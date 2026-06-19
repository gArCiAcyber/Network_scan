"""Tests for banner grabbing helper logic."""

import unittest
from unittest.mock import Mock, patch

from modules import banner_grabber


class BannerGrabberHelperTests(unittest.TestCase):
    """Validate pure banner-grabber helpers and safe mocked dispatch."""

    def test_clean_banner_decodes_bytes_and_collapses_whitespace(self) -> None:
        data = b"SSH-2.0-TestServer\r\nReady\t now\n"

        self.assertEqual(
            banner_grabber.clean_banner(data),
            "SSH-2.0-TestServer Ready now",
        )

    def test_clean_banner_handles_invalid_utf8_safely(self) -> None:
        banner = banner_grabber.clean_banner(b"hello\xff\xfe world")

        self.assertIn("hello", banner)
        self.assertIn("world", banner)
        self.assertIn("\ufffd", banner)

    def test_merge_banner_parts_joins_unique_non_empty_parts(self) -> None:
        self.assertEqual(
            banner_grabber.merge_banner_parts(None, "", "220 FTP", "220 FTP", "SYST OK"),
            "220 FTP | SYST OK",
        )

    def test_merge_banner_parts_returns_none_without_useful_parts(self) -> None:
        self.assertIsNone(banner_grabber.merge_banner_parts(None, "", None))

    def test_build_http_head_request_contains_expected_headers(self) -> None:
        request = banner_grabber.build_http_head_request("example.com").decode("ascii")

        self.assertIn("HEAD / HTTP/1.1\r\n", request)
        self.assertIn("Host: example.com\r\n", request)
        self.assertIn("User-Agent: hylianscan\r\n", request)
        self.assertIn("Connection: close\r\n", request)
        self.assertTrue(request.endswith("\r\n\r\n"))

    def test_should_collect_tls_metadata_identifies_tls_ports(self) -> None:
        self.assertTrue(banner_grabber.should_collect_tls_metadata(443))
        self.assertTrue(banner_grabber.should_collect_tls_metadata(465))
        self.assertTrue(banner_grabber.should_collect_tls_metadata(993))
        self.assertFalse(banner_grabber.should_collect_tls_metadata(80))
        self.assertFalse(banner_grabber.should_collect_tls_metadata(22))

    def test_smtp_starttls_helpers_detect_capability_and_ready_response(self) -> None:
        self.assertTrue(
            banner_grabber.smtp_advertises_starttls(
                "250-mail.example 250-STARTTLS 250 HELP"
            )
        )
        self.assertFalse(banner_grabber.smtp_advertises_starttls("250 HELP"))
        self.assertTrue(banner_grabber.smtp_starttls_is_ready("220 Ready to start TLS"))
        self.assertFalse(banner_grabber.smtp_starttls_is_ready("454 TLS not available"))

    def test_starttls_style_helpers_detect_upgrade_readiness(self) -> None:
        self.assertTrue(
            banner_grabber.imap_advertises_starttls(
                "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN a001 OK"
            )
        )
        self.assertFalse(
            banner_grabber.imap_advertises_starttls(
                "* CAPABILITY IMAP4rev1 AUTH=PLAIN a001 OK"
            )
        )
        self.assertTrue(
            banner_grabber.imap_starttls_is_ready(
                "a002 OK Begin TLS negotiation now"
            )
        )
        self.assertFalse(
            banner_grabber.imap_starttls_is_ready(
                "a002 NO TLS not available"
            )
        )

        self.assertTrue(
            banner_grabber.pop3_advertises_stls(
                "+OK Capability list follows STLS USER ."
            )
        )
        self.assertFalse(
            banner_grabber.pop3_advertises_stls(
                "+OK Capability list follows USER ."
            )
        )
        self.assertTrue(banner_grabber.pop3_stls_is_ready("+OK Begin TLS"))
        self.assertFalse(banner_grabber.pop3_stls_is_ready("-ERR TLS unavailable"))

        self.assertTrue(banner_grabber.ftp_auth_tls_is_ready("234 Proceed with TLS"))
        self.assertFalse(banner_grabber.ftp_auth_tls_is_ready("534 TLS unavailable"))

    def test_probe_registry_maps_ports_to_protocol_definitions(self) -> None:
        http_probe = banner_grabber.find_probe_definition(80)
        https_probe = banner_grabber.find_probe_definition(443)
        imap_probe = banner_grabber.find_probe_definition(143)
        pop3_probe = banner_grabber.find_probe_definition(110)
        generic_tls_probe = banner_grabber.find_probe_definition(993)
        unknown_probe = banner_grabber.find_probe_definition(9999)

        self.assertIsNotNone(http_probe)
        self.assertEqual(http_probe.protocol_name, "http")
        self.assertEqual(http_probe.handler_name, "grab_http_banner")
        self.assertTrue(http_probe.requires_target_host)

        smtp_probe = banner_grabber.find_probe_definition(25)
        self.assertIsNotNone(smtp_probe)
        self.assertEqual(smtp_probe.protocol_name, "smtp")
        self.assertEqual(smtp_probe.handler_name, "grab_smtp_starttls_banner")
        self.assertEqual(smtp_probe.tls_behavior, banner_grabber.TLS_BEHAVIOR_STARTTLS)

        self.assertIsNotNone(imap_probe)
        self.assertEqual(imap_probe.protocol_name, "imap")
        self.assertEqual(imap_probe.handler_name, "grab_imap_starttls_banner")
        self.assertEqual(imap_probe.tls_behavior, banner_grabber.TLS_BEHAVIOR_STARTTLS)

        self.assertIsNotNone(pop3_probe)
        self.assertEqual(pop3_probe.protocol_name, "pop3")
        self.assertEqual(pop3_probe.handler_name, "grab_pop3_stls_banner")
        self.assertEqual(pop3_probe.tls_behavior, banner_grabber.TLS_BEHAVIOR_STARTTLS)

        self.assertIsNotNone(https_probe)
        self.assertEqual(https_probe.protocol_name, "https")
        self.assertEqual(https_probe.handler_name, "grab_tls_protocol_banner")
        self.assertEqual(https_probe.tls_behavior, banner_grabber.TLS_BEHAVIOR_PROTOCOL)
        self.assertTrue(https_probe.use_http_head_request)

        self.assertIsNotNone(generic_tls_probe)
        self.assertEqual(generic_tls_probe.protocol_name, "generic_tls_metadata")
        self.assertEqual(generic_tls_probe.handler_name, "grab_tls_metadata")

        self.assertIsNone(unknown_probe)

    def test_probe_registry_prioritizes_specific_tls_protocols(self) -> None:
        self.assertEqual(
            banner_grabber.find_probe_definition(443).protocol_name,
            "https",
        )
        self.assertEqual(
            banner_grabber.find_probe_definition(465).protocol_name,
            "smtps",
        )
        self.assertEqual(
            banner_grabber.find_probe_definition(990).protocol_name,
            "ftps",
        )

    def test_format_certificate_name_converts_tuple_data(self) -> None:
        name_items = (
            (("commonName", "example.com"),),
            (("organizationName", "Example Org"), ("commonName", "www.example.com")),
        )

        self.assertEqual(
            banner_grabber.format_certificate_name(name_items),
            {
                "commonName": ["example.com", "www.example.com"],
                "organizationName": ["Example Org"],
            },
        )

    def test_format_certificate_name_handles_empty_input(self) -> None:
        self.assertEqual(banner_grabber.format_certificate_name(None), {})
        self.assertEqual(banner_grabber.format_certificate_name(()), {})

    def test_split_subject_alt_names_separates_dns_and_ip_entries(self) -> None:
        subject_alt_names = (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
            ("IP Address", "192.0.2.10"),
            ("URI", "spiffe://example/service"),
        )

        self.assertEqual(
            banner_grabber.split_subject_alt_names(subject_alt_names),
            {
                "dns_names": ["example.com", "www.example.com"],
                "ip_addresses": ["192.0.2.10"],
            },
        )

    def test_build_cipher_metadata_handles_none_and_cipher_tuple(self) -> None:
        self.assertEqual(banner_grabber.build_cipher_metadata(None), {})
        self.assertEqual(
            banner_grabber.build_cipher_metadata(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)),
            {
                "name": "TLS_AES_256_GCM_SHA384",
                "protocol": "TLSv1.3",
                "secret_bits": 256,
            },
        )

    def test_collect_tls_metadata_handles_missing_peer_certificate(self) -> None:
        tls_client = Mock()
        tls_client.getpeercert.return_value = None
        tls_client.version.return_value = "TLSv1.3"
        tls_client.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

        metadata = banner_grabber.collect_tls_metadata(tls_client)

        self.assertEqual(metadata["status"], "no_certificate")
        self.assertEqual(metadata["handshake"]["protocol"], "TLSv1.3")
        self.assertEqual(
            metadata["handshake"]["cipher"],
            {
                "name": "TLS_AES_128_GCM_SHA256",
                "protocol": "TLSv1.3",
                "secret_bits": 128,
            },
        )
        self.assertEqual(metadata["certificate"], {})
        self.assertIsNone(metadata["error"])

    def test_grab_service_banner_dispatches_http_ports(self) -> None:
        client = Mock()

        with patch.object(banner_grabber, "grab_http_banner", return_value="http") as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 80),
                (
                    "http",
                    None,
                    {
                        "name": "http",
                        "transport_security": "none",
                        "method": "http_head",
                    },
                ),
            )

        mocked.assert_called_once_with(client, "example.com")

    def test_grab_service_banner_dispatches_https_ports(self) -> None:
        client = Mock()

        with (
            patch.object(
                banner_grabber,
                "build_http_head_request",
                return_value=b"HEAD / HTTP/1.1\r\n\r\n",
            ) as request_mock,
            patch.object(
                banner_grabber,
                "grab_tls_protocol_banner",
                return_value=("https", {"status": "collected"}),
            ) as banner_mock,
        ):
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 443),
                (
                    "https",
                    {"status": "collected"},
                    {
                        "name": "https",
                        "transport_security": "implicit_tls",
                        "method": "http_head",
                    },
                ),
            )

        request_mock.assert_called_once_with("example.com")
        banner_mock.assert_called_once_with(client, "example.com", b"HEAD / HTTP/1.1\r\n\r\n")

    def test_grab_service_banner_dispatches_smtp_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_smtp_starttls_banner",
            return_value=(
                "smtp",
                {"status": "collected"},
                {
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
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 25),
                (
                    "smtp",
                    {"status": "collected"},
                    {
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
            )

        mocked.assert_called_once_with(client, "example.com")

    def test_grab_service_banner_dispatches_imap_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_imap_starttls_banner",
            return_value=(
                "imap",
                {"status": "collected"},
                {
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
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 143),
                (
                    "imap",
                    {"status": "collected"},
                    {
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
            )

        mocked.assert_called_once_with(client, "example.com")

    def test_grab_service_banner_dispatches_pop3_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_pop3_stls_banner",
            return_value=(
                "pop3",
                {"status": "collected"},
                {
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
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 110),
                (
                    "pop3",
                    {"status": "collected"},
                    {
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
            )

        mocked.assert_called_once_with(client, "example.com")

    def test_imap_starttls_fallback_when_capability_is_unavailable(self) -> None:
        client = Mock()

        with (
            patch.object(banner_grabber, "grab_banner", return_value="* OK IMAP ready"),
            patch.object(
                banner_grabber,
                "send_probe_and_grab_banner",
                return_value="* CAPABILITY IMAP4rev1 a001 OK",
            ) as probe_mock,
        ):
            banner, tls, probe = banner_grabber.grab_imap_starttls_banner(
                client,
                "example.com",
            )

        self.assertEqual(banner, "* OK IMAP ready | * CAPABILITY IMAP4rev1 a001 OK")
        self.assertIsNone(tls)
        self.assertEqual(probe["name"], "imap")
        self.assertEqual(probe["transport_security"], "none")
        self.assertEqual(probe["method"], "imap_starttls")
        self.assertEqual(
            probe["starttls"],
            {
                "supported": False,
                "attempted": False,
                "upgraded": False,
                "error": None,
            },
        )
        probe_mock.assert_called_once_with(client, banner_grabber.IMAP_CAPABILITY_PAYLOAD)

    def test_pop3_stls_fallback_when_upgrade_is_rejected(self) -> None:
        client = Mock()

        with (
            patch.object(banner_grabber, "grab_banner", return_value="+OK POP3 ready"),
            patch.object(
                banner_grabber,
                "send_probe_and_grab_banner",
                side_effect=("+OK Capability list follows STLS .", "-ERR TLS unavailable"),
            ),
        ):
            banner, tls, probe = banner_grabber.grab_pop3_stls_banner(
                client,
                "example.com",
            )

        self.assertEqual(
            banner,
            "+OK POP3 ready | +OK Capability list follows STLS . | -ERR TLS unavailable",
        )
        self.assertIsNone(tls)
        self.assertEqual(probe["name"], "pop3")
        self.assertEqual(probe["transport_security"], "none")
        self.assertEqual(probe["method"], "pop3_stls")
        self.assertEqual(
            probe["starttls"],
            {
                "supported": True,
                "attempted": True,
                "upgraded": False,
                "error": "STLS was advertised but the server did not return a +OK response.",
            },
        )

    def test_ftp_auth_tls_fallback_when_upgrade_is_rejected(self) -> None:
        client = Mock()

        with (
            patch.object(banner_grabber, "grab_banner", return_value="220 FTP ready"),
            patch.object(
                banner_grabber,
                "send_probe_and_grab_banner",
                side_effect=("534 TLS unavailable", "215 UNIX Type: L8"),
            ),
        ):
            banner, tls, probe = banner_grabber.grab_ftp_auth_tls_banner(
                client,
                "example.com",
            )

        self.assertEqual(
            banner,
            "220 FTP ready | 534 TLS unavailable | 215 UNIX Type: L8",
        )
        self.assertIsNone(tls)
        self.assertEqual(probe["name"], "ftp")
        self.assertEqual(probe["transport_security"], "none")
        self.assertEqual(probe["method"], "ftp_auth_tls")
        self.assertEqual(
            probe["starttls"],
            {
                "supported": False,
                "attempted": True,
                "upgraded": False,
                "error": "AUTH TLS was not accepted by the FTP service.",
            },
        )

    def test_grab_service_banner_dispatches_smtps_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_tls_text_service_banner",
            return_value=("smtps", {"status": "collected"}),
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 465),
                (
                    "smtps",
                    {"status": "collected"},
                    {
                        "name": "smtps",
                        "transport_security": "implicit_tls",
                        "method": "smtp_ehlo",
                    },
                ),
            )

        mocked.assert_called_once_with(client, "example.com", b"EHLO hylianscan.local\r\n")

    def test_grab_service_banner_dispatches_ftp_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_ftp_auth_tls_banner",
            return_value=(
                "ftp",
                {"status": "collected"},
                {
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
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 21),
                (
                    "ftp",
                    {"status": "collected"},
                    {
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
            )

        mocked.assert_called_once_with(client, "example.com")

    def test_grab_service_banner_dispatches_ftps_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_tls_text_service_banner",
            return_value=("ftps", {"status": "collected"}),
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 990),
                (
                    "ftps",
                    {"status": "collected"},
                    {
                        "name": "ftps",
                        "transport_security": "implicit_tls",
                        "method": "ftp_syst",
                    },
                ),
            )

        mocked.assert_called_once_with(client, "example.com", b"SYST\r\n")

    def test_grab_service_banner_dispatches_generic_tls_metadata_ports(self) -> None:
        client = Mock()

        with patch.object(
            banner_grabber,
            "grab_tls_metadata",
            return_value={"status": "collected"},
        ) as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 993),
                (
                    None,
                    {"status": "collected"},
                    {
                        "name": "generic_tls_metadata",
                        "transport_security": "implicit_tls",
                        "method": "tls_handshake",
                    },
                ),
            )

        mocked.assert_called_once_with(client, "example.com")

    def test_grab_service_banner_falls_back_to_passive_banner(self) -> None:
        client = Mock()

        with patch.object(banner_grabber, "grab_banner", return_value="generic") as mocked:
            self.assertEqual(
                banner_grabber.grab_service_banner(client, "example.com", 9999),
                (
                    "generic",
                    None,
                    {
                        "name": "unknown",
                        "transport_security": "unknown",
                        "method": "passive_banner",
                    },
                ),
            )

        mocked.assert_called_once_with(client)


if __name__ == "__main__":
    unittest.main()
