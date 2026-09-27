"""Regression checks for scan scope, evidence integrity, and report survival."""

import unittest
import io
import json
import socket
import errno
import subprocess
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch, MagicMock

import hylianscan
from core.output import atomic_write_text, resolve_output_workspace, validate_output_destinations, save_report
from core.panel import build_quiet_final_panel
from modules.tcp_scanner import PortScanResult, ScanResult, scan_tcp_ports, probe_open_service
from modules.target import ResolvedAddress, TargetInfo, resolve_target, TargetResolutionError
from modules.http_metadata import parse_http_response_head
from modules.probes.generic import grab_banner, PROBE_DEADLINE
from modules.probes.starttls import grab_smtp_starttls_banner
from modules.probes.http import build_http_head_request
from modules.tls_analysis import detect_hostname_mismatch
from modules.nmap_xml import parse_nmap_xml_text
from modules.nmap_enrichment import build_completed_nmap_enrichment, build_failed_nmap_enrichment
from modules.json_exporter import build_tcp_scan_document, build_nmap_enrichment_document
from modules.port_profiles import PORT_PROFILES
from modules.probes.registry import HTTP_PORTS, HTTPS_PORTS

from core.cli import parse_arguments, parse_ports_list, validate_mode, validate_timeout, validate_max_rate
from modules.json_exporter import parse_http_metadata
from modules.nmap_runner import run_nmap_service_version_scan
from modules.rate_limiter import MaxRatePacer
from modules.host_discovery import HostDiscoveryResult


class ScanIntegrityTests(unittest.TestCase):
    def test_workspace_reservation_and_failed_write_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch("core.output.resolve_output_dir", return_value=Path(directory)):
            first = resolve_output_workspace("localhost", "same", reserve=True)
            second = resolve_output_workspace("localhost", "same", reserve=True)
            self.assertNotEqual(first, second)
            destination = first / "report.json"
            destination.write_text("original", encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_output_destinations(destination, first / "." / "report.json")
            with patch("core.output.os.replace", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    atomic_write_text(destination, "replacement")
            self.assertEqual(destination.read_text(), "original")
            self.assertEqual(list(first.iterdir()), [destination])

    def test_cancellation_preserves_discovery_and_wakes_paced_worker(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.connect_ex.return_value = 0
        def interrupt(_finding):
            raise KeyboardInterrupt
        with patch("modules.tcp_scanner.socket.socket", return_value=client):
            result = scan_tcp_ports("localhost", "127.0.0.1", [443, 8443],
                max_rate=0.01, max_workers=2, open_port_callback=interrupt)
        self.assertEqual(result.status, "interrupted")
        self.assertEqual(len(result.open_ports), 1)
        self.assertEqual(client.connect_ex.call_count, 1)
        self.assertEqual(result.completed_attempts, 1)
        self.assertEqual(result.outcomes, {"open": 1})

    def test_probe_interruption_preserves_every_discovered_port(self):
        finding = PortScanResult(443, "HTTPS", None, 0.01)
        def interrupt(_count):
            raise KeyboardInterrupt
        with patch("modules.tcp_scanner.discover_open_port", side_effect=lambda *a, **kw: replace(finding, port=a[2])):
            result = scan_tcp_ports("localhost", "127.0.0.1", [443, 8443],
                service_probe_start_callback=interrupt)
        self.assertEqual(result.status, "interrupted")
        self.assertEqual([f.port for f in result.open_ports], [443, 8443])

    def test_nmap_interruption_and_terminal_encoding_do_not_prevent_saving(self):
        finding = PortScanResult(22, "SSH", "SSH \u00e9\x1b[2J", 0.01)
        scan = ScanResult("localhost", "127.0.0.1", 1, (finding,), 0.02)
        target = TargetInfo("localhost", "localhost", "127.0.0.1", False)
        for interrupt in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                txt, js = Path(directory) / "report.txt", Path(directory) / "report.json"
                output = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
                with patch("sys.argv", ["hylianscan", "localhost", "-p", "22", "--quiet", "--nmap", "-o", "--json-output"]), \
                     patch("hylianscan.resolve_target", return_value=target), \
                     patch("hylianscan.run_port_scan", return_value=scan), \
                     patch("hylianscan.resolve_output_workspace", return_value=Path(directory)), \
                     patch("hylianscan.resolve_output_path", return_value=txt), \
                     patch("hylianscan.resolve_json_output_path", return_value=js), \
                     patch("hylianscan.run_nmap_service_version_scan", side_effect=KeyboardInterrupt if interrupt else RuntimeError("missing")), \
                     patch("sys.stdout", output):
                    if interrupt:
                        with self.assertRaises(SystemExit) as error:
                            hylianscan.main()
                        self.assertEqual(error.exception.code, 130)
                    else:
                        hylianscan.main()
                self.assertNotIn("\x1b", txt.read_text(encoding="utf-8"))
                document = json.loads(js.read_text())
                self.assertEqual(document["results"]["open_ports"][0]["banner"]["raw"], finding.banner)
                self.assertIn(document["scan"]["run_id"], txt.read_text())
                self.assertEqual(document["scan"]["status"], "interrupted" if interrupt else "completed")

    def test_connection_failures_retain_distinct_outcomes(self):
        client = MagicMock()
        client.__enter__.return_value = client
        for code, state in ((errno.ECONNREFUSED, "refused"), (errno.ETIMEDOUT, "timeout"),
                            (errno.ENETUNREACH, "unreachable"), (errno.EMFILE, "error")):
            client.connect_ex.return_value = code
            with patch("modules.tcp_scanner.socket.socket", return_value=client):
                result = scan_tcp_ports("localhost", "127.0.0.1", [443])
            self.assertEqual(result.outcomes, {state: 1})
            self.assertEqual(result.status, "completed" if state == "refused" else "partial")

    def test_scoped_endpoints_remain_distinct_through_probing_and_exports(self):
        addresses = [ResolvedAddress("fe80::1", socket.AF_INET6, scope_id=scope) for scope in (3, 4)]
        finding = PortScanResult(443, "HTTPS", None, 0.01)
        with patch("modules.tcp_scanner.discover_open_port", return_value=finding), \
             patch("modules.tcp_scanner.probe_open_service", side_effect=lambda *a, **kw: a[2]) as probe:
            result = scan_tcp_ports("fe80::1", "fe80::1", [443], addresses=addresses)
        self.assertEqual(sorted(call.args[6] for call in probe.call_args_list), [3, 4])
        document = build_tcp_scan_document(result)
        self.assertEqual([f["scope_id"] for f in document["results"]["open_ports"]], [3, 4])
        with patch("hylianscan.run_nmap_service_version_scan", side_effect=RuntimeError("missing")) as runner:
            hylianscan.run_live_nmap_enrichment(TargetInfo("fe80::1", "fe80::1", "fe80::1", True), result)
        self.assertEqual([call.args[0] for call in runner.call_args_list], ["fe80::1%3", "fe80::1%4"])

    def test_http_framing_prevents_fabricated_headers_and_selects_final_status(self):
        response = "HTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\nHTTP/1.1 200 OK\r\nServer:test\r\nX-Note: words Content-Security-Policy: fake\r\n\r\nContent-Type: body"
        head = parse_http_response_head(response)
        self.assertEqual(head.status_code, 200)
        self.assertEqual(head.headers, {"server": ["test"], "x-note": ["words Content-Security-Policy: fake"]})
        self.assertTrue(head.complete)
        client = MagicMock()
        client.gettimeout.return_value = 1.0
        client.recv.side_effect = [part.encode() for part in response.split("HTTP/1.1 200")[:1]] + [response[response.index("HTTP/1.1 200"):].encode()]
        self.assertEqual(grab_banner(client, b"\r\n\r\n"), response)
        incomplete = parse_http_metadata("HTTP/1.1 200 OK\r\nServer: test\r\n", "https://localhost")
        self.assertEqual(incomplete["security"]["missing"], [])

    def test_fragmented_smtp_and_incomplete_capabilities(self):
        for tail, expected in ((b"250-STARTTLS\r\n250 OK\r\n", True), (b"", None)):
            client = MagicMock()
            client.gettimeout.return_value = 1.0
            client.recv.side_effect = [b"220 localhost\r\n", b"250-audit\r\n", tail, b"454 unavailable\r\n"]
            _, _, probe = grab_smtp_starttls_banner(client, "localhost")
            self.assertIs(probe["starttls"]["supported"], expected)
            self.assertIs(probe["starttls"]["attempted"], expected is True)

    def test_slow_response_stops_at_total_deadline(self):
        client = MagicMock()
        client.gettimeout.return_value = 0.1
        client.recv.return_value = b"x"
        token = PROBE_DEADLINE.set(0.25)
        try:
            with patch("modules.probes.generic.time.monotonic", side_effect=[0.0, 0.1, 0.2, 0.3]):
                self.assertEqual(grab_banner(client, b"\r\n\r\n"), "xxx")
        finally:
            PROBE_DEADLINE.reset(token)
        self.assertEqual(client.recv.call_count, 3)

    def test_host_identity_and_web_profile_coverage(self):
        self.assertIn(b"Host: xn--mnich-kva.test:8080\r\n", build_http_head_request("m\u00fcnich.test", 8080))
        self.assertIn(b"Host: [2001:db8::1]:8443\r\n", build_http_head_request("2001:0db8::1", 8443))
        for host, names in (("m\u00fcnich.test", {"dns_names": ["xn--mnich-kva.test"]}),
                            ("2001:0db8::1", {"ip_addresses": ["2001:db8::1"]})):
            self.assertFalse(detect_hostname_mismatch({"certificate": {"subject_alt_names": names}}, host))
        self.assertFalse(set(PORT_PROFILES["web"].ports) - HTTP_PORTS - HTTPS_PORTS)

    def test_discovery_uses_selected_ports_and_shared_pacer(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.connect_ex.return_value = errno.ETIMEDOUT
        pacer = MagicMock()
        target = TargetInfo("localhost", "localhost", "127.0.0.1", True)
        with patch("modules.host_discovery.socket.socket", return_value=client):
            _, evidence = hylianscan.run_host_discovery(target, "tcp", 0.1, ports=[8443], pacer=pacer)
        client.connect_ex.assert_called_once_with(("127.0.0.1", 8443))
        pacer.wait.assert_called_once()
        self.assertEqual(evidence[0].state, "unconfirmed")

    def test_discovery_exclusions_survive_in_txt_and_json(self):
        included = ResolvedAddress("192.0.2.1", socket.AF_INET)
        excluded = ResolvedAddress("192.0.2.2", socket.AF_INET)
        target = TargetInfo("example.test", "example.test", included.address, False,
                            addresses=(included, excluded))
        evidence = (HostDiscoveryResult(included, "tcp", True, 0.01,
                                        state="reachable", ports=(8443,)),
                    HostDiscoveryResult(excluded, "tcp", False, 0.1,
                                        error="No response", state="unconfirmed", ports=(8443,)))
        scan = ScanResult(target.target_host, included.address, 1, (), 0.01,
                          addresses=(included,), requested_ports=(8443,))
        with tempfile.TemporaryDirectory() as directory:
            txt, js = Path(directory) / "report.txt", Path(directory) / "report.json"
            with patch("sys.argv", ["hylianscan", "example.test", "-p", "8443",
                                    "--host-discovery", "tcp", "--quiet", "-o", "--json-output"]), \
                 patch("hylianscan.resolve_target", return_value=target), \
                 patch("hylianscan.run_host_discovery", return_value=(target.with_addresses((included,)), evidence)), \
                 patch("hylianscan.run_port_scan", return_value=scan), \
                 patch("hylianscan.resolve_output_workspace", return_value=Path(directory)), \
                 patch("hylianscan.resolve_output_path", return_value=txt), \
                 patch("hylianscan.resolve_json_output_path", return_value=js), \
                 patch("sys.stdout", io.StringIO()):
                hylianscan.main()
            self.assertIn("192.0.2.2: unconfirmed", txt.read_text(encoding="utf-8"))
            discovery = json.loads(js.read_text(encoding="utf-8"))["scan"]["host_discovery"]["results"]
            self.assertEqual(discovery[1]["state"], "unconfirmed")
            self.assertTrue(discovery[1]["excluded"])

    def test_xml_bounds_association_and_partial_execution(self):
        def xml(ports=(443,), address="127.0.0.1", state="open", exit="success"):
            return '<nmaprun version="7.94"><host><status state="up"/><address addr="' + address + '" addrtype="ipv4"/><ports>' + ''.join(
                f'<port protocol="tcp" portid="{p}"><state state="{state}" reason="conn-refused"/></port>' for p in ports
            ) + f'</ports></host><runstats><finished exit="{exit}"/></runstats></nmaprun>'
        for ports in ((-1,), (65536,), (22, 22)):
            with self.assertRaises(ValueError):
                parse_nmap_xml_text(xml(ports))
        for data in (xml(address="192.0.2.1"), xml(ports=(22,))):
            with self.assertRaises(ValueError):
                build_completed_nmap_enrichment(parse_nmap_xml_text(data), "127.0.0.1", [443])
        scoped_xml = xml(address="fe80::1%4").replace('addrtype="ipv4"', 'addrtype="ipv6"')
        with self.assertRaises(ValueError):
            build_completed_nmap_enrichment(parse_nmap_xml_text(scoped_xml), "fe80::1%3", [443])
        plain_xml = xml(address="fe80::1").replace('addrtype="ipv4"', 'addrtype="ipv6"')
        self.assertEqual(build_completed_nmap_enrichment(
            parse_nmap_xml_text(plain_xml), "fe80::1%3", [443]).status, "completed")
        result = build_completed_nmap_enrichment(parse_nmap_xml_text(xml(exit="error")), "127.0.0.1", [443])
        self.assertEqual(result.status, "partial")
        captured = xml(state="closed")
        with patch("modules.nmap_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 1, output=captured, stderr="warning")):
            try:
                run_nmap_service_version_scan("127.0.0.1", [443])
            except RuntimeError as error:
                result = build_failed_nmap_enrichment(error, "127.0.0.1", [443])
        document = build_nmap_enrichment_document(result)
        self.assertEqual(document["status"], "timed_out")
        self.assertEqual(document["execution"]["stderr"], "warning")
        self.assertEqual(document["execution"]["stdout"], captured)
        self.assertEqual(document["disagreements"], [443])

    def test_invalid_inputs_are_rejected_before_scanning(self):
        for value in (float("nan"), float("inf"), -1.0, 0.0):
            for validate in (validate_timeout, validate_max_rate, MaxRatePacer):
                with self.subTest(value=value, validate=validate), self.assertRaises(ValueError):
                    validate(value)
        for flags in (["-p", ""], ["-p", ",,"], ["-p", "22", "--top-ports", "0"]):
            with patch("sys.argv", ["hylianscan", "localhost", *flags]):
                args = parse_arguments()
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                parse_ports_list(args)

    def test_irrelevant_and_empty_explicit_options_are_rejected(self):
        for flags in (
            ["localhost", "--nmap-path", ""],
            ["localhost", "--subfinder-path", "unused"],
            ["localhost", "--subfinder", "--stance", "invalid"],
            ["--nmap-xml", "x.xml", "localhost"],
            ["--nmap-xml", "x.xml", "--ipv6"],
        ):
            with patch("sys.argv", ["hylianscan", *flags]):
                args = parse_arguments()
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                validate_mode(args)

    def test_no_http_response_has_no_missing_header_claims(self):
        for banner, url in (("SSH-2.0-test", None), (None, "https://localhost")):
            metadata = parse_http_metadata(banner, url)
            self.assertEqual(metadata["security"]["observations"], [])
            self.assertEqual(metadata["security"]["missing"], [])
            self.assertEqual(metadata["security"]["status"], "unavailable")

    def test_nmap_launch_errors_use_the_optional_failure_path(self):
        for error in (PermissionError("denied"), OSError("invalid executable")):
            with patch("modules.nmap_runner.subprocess.run", side_effect=error):
                with self.assertRaises(RuntimeError):
                    run_nmap_service_version_scan("127.0.0.1", [443])
