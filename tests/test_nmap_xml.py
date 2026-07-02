"""Tests for Nmap XML import helpers and import-only CLI flow."""

from pathlib import Path
import io
import json
import tempfile
import unittest
from unittest.mock import patch

import hylianscan
from modules.nmap_xml import (
    format_nmap_xml_import_summary,
    normalize_confidence,
    parse_nmap_xml_text,
    parse_single_host_nmap_xml_file,
    require_single_up_host,
)


SINGLE_HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 127.0.0.1" start="1710000000"
         startstr="Sat Mar 9 12:00:00 2024" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="down"/>
    <address addr="192.0.2.99" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <address addr="localhost" addrtype="hostname"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"
                 extrainfo="protocol 2.0" tunnel="ssl" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:9.6</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http" method="table" conf="3"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open"/>
        <service name="domain" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


MULTI_HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="127.0.0.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


class NmapXmlParserTests(unittest.TestCase):
    """Validate Nmap XML parsing and normalization."""

    def test_parses_one_up_host_with_one_open_tcp_port(self) -> None:
        import_result = parse_nmap_xml_text(SINGLE_HOST_XML)
        host = require_single_up_host(import_result)

        self.assertEqual(host.primary_address, "127.0.0.1")
        self.assertEqual(len(host.open_tcp_ports), 1)
        self.assertEqual(host.open_tcp_ports[0].port, 22)
        self.assertEqual(host.open_tcp_ports[0].protocol, "tcp")

    def test_parses_run_metadata(self) -> None:
        import_result = parse_nmap_xml_text(SINGLE_HOST_XML)

        self.assertEqual(import_result.metadata.scanner, "nmap")
        self.assertEqual(import_result.metadata.version, "7.94")
        self.assertEqual(import_result.metadata.xmloutputversion, "1.05")
        self.assertIn("-sV", import_result.metadata.args or "")

    def test_parses_service_attributes_and_cpe_values(self) -> None:
        host = require_single_up_host(parse_nmap_xml_text(SINGLE_HOST_XML))
        service = host.open_tcp_ports[0].service

        self.assertEqual(service.name, "ssh")
        self.assertEqual(service.product, "OpenSSH")
        self.assertEqual(service.version, "9.6")
        self.assertEqual(service.extrainfo, "protocol 2.0")
        self.assertEqual(service.tunnel, "ssl")
        self.assertEqual(service.method, "probed")
        self.assertEqual(service.confidence_raw, 10)
        self.assertEqual(service.confidence, "high")
        self.assertEqual(service.cpes, ("cpe:/a:openbsd:openssh:9.6",))

    def test_maps_confidence_labels(self) -> None:
        self.assertEqual(normalize_confidence("2"), "low")
        self.assertEqual(normalize_confidence("5"), "medium")
        self.assertEqual(normalize_confidence("10"), "high")
        self.assertEqual(normalize_confidence(None), "unknown")
        self.assertEqual(normalize_confidence("invalid"), "unknown")

    def test_ignores_closed_ports_and_down_hosts(self) -> None:
        import_result = parse_nmap_xml_text(SINGLE_HOST_XML)

        self.assertEqual(len(import_result.up_hosts), 1)
        self.assertEqual(
            [port.port for port in import_result.up_hosts[0].open_tcp_ports],
            [22],
        )

    def test_invalid_root_raises_value_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "root element"):
            parse_nmap_xml_text("<notnmap />")

    def test_malformed_xml_raises_value_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed XML"):
            parse_nmap_xml_text("<nmaprun>")

    def test_multiple_up_hosts_raise_for_single_host_import_mode(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".xml",
            delete=False,
        ) as xml_file:
            xml_file.write(MULTI_HOST_XML)
            xml_path = Path(xml_file.name)

        try:
            with self.assertRaisesRegex(ValueError, "Multi-host import"):
                parse_single_host_nmap_xml_file(xml_path)
        finally:
            xml_path.unlink(missing_ok=True)

    def test_summary_renders_plain_text_import_details(self) -> None:
        import_result = parse_nmap_xml_text(SINGLE_HOST_XML)
        summary = format_nmap_xml_import_summary(import_result, "scan.xml")

        self.assertIn("Nmap XML Import", summary)
        self.assertIn("Imported XML: scan.xml", summary)
        self.assertIn("Host: 127.0.0.1", summary)
        self.assertIn("Open TCP Ports: 1", summary)
        self.assertIn("22/tcp", summary)
        self.assertIn("ssh", summary)
        self.assertIn("OpenSSH 9.6", summary)
        self.assertIn("method=probed", summary)
        self.assertIn("confidence=high", summary)


class NmapXmlCliTests(unittest.TestCase):
    """Validate the Nmap XML import-only CLI path."""

    def write_sample_xml(self, directory: str) -> Path:
        """Write a sample Nmap XML file into a temporary directory."""
        xml_path = Path(directory) / "nmap-results.xml"
        xml_path.write_text(SINGLE_HOST_XML, encoding="utf-8")
        return xml_path

    def test_nmap_xml_import_exits_before_scan_setup(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".xml",
            delete=False,
        ) as xml_file:
            xml_file.write(SINGLE_HOST_XML)
            xml_path = Path(xml_file.name)

        output = io.StringIO()

        try:
            with (
                patch("sys.argv", ["hylianscan", "--nmap-xml", str(xml_path)]),
                patch("sys.stdout", output),
                patch("hylianscan.show_banner") as show_banner,
                patch("hylianscan.resolve_target") as resolve_target,
                patch("hylianscan.run_port_scan") as run_port_scan,
                patch("hylianscan.run_passive_subdomain_discovery") as passive_discovery,
            ):
                hylianscan.main()
        finally:
            xml_path.unlink(missing_ok=True)

        rendered_output = output.getvalue()
        self.assertIn("Nmap XML Import", rendered_output)
        self.assertIn("Host: 127.0.0.1", rendered_output)
        show_banner.assert_not_called()
        resolve_target.assert_not_called()
        run_port_scan.assert_not_called()
        passive_discovery.assert_not_called()

    def test_nmap_xml_import_with_output_saves_txt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            xml_path = self.write_sample_xml(temporary_dir)
            txt_output_path = Path(temporary_dir) / "nmap_import_report.txt"
            output = io.StringIO()

            with (
                patch("sys.argv", ["hylianscan", "--nmap-xml", str(xml_path), "-o"]),
                patch("sys.stdout", output),
                patch(
                    "hylianscan.resolve_nmap_import_output_path",
                    return_value=txt_output_path,
                ),
                patch(
                    "hylianscan.resolve_nmap_import_json_output_path",
                    return_value=None,
                ),
            ):
                hylianscan.main()

            saved_report = txt_output_path.read_text(encoding="utf-8")
            self.assertIn("Nmap XML Import", saved_report)
            self.assertIn("Host: 127.0.0.1", saved_report)
            self.assertNotIn("\x1b[", saved_report)
            self.assertIn("Nmap XML Import", output.getvalue())

    def test_nmap_xml_import_with_json_output_saves_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            xml_path = self.write_sample_xml(temporary_dir)
            json_output_path = Path(temporary_dir) / "nmap_import_results.json"

            with (
                patch(
                    "sys.argv",
                    ["hylianscan", "--nmap-xml", str(xml_path), "--json-output"],
                ),
                patch("sys.stdout", io.StringIO()),
                patch(
                    "hylianscan.resolve_nmap_import_output_path",
                    return_value=None,
                ),
                patch(
                    "hylianscan.resolve_nmap_import_json_output_path",
                    return_value=json_output_path,
                ),
            ):
                hylianscan.main()

            document = json.loads(json_output_path.read_text(encoding="utf-8"))
            self.assertEqual(document["mode"], "nmap_xml_import")
            self.assertEqual(document["source"]["scanner"], "nmap")
            self.assertEqual(document["source"]["version"], "7.94")
            self.assertEqual(document["host"]["primary_address"], "127.0.0.1")
            self.assertEqual(document["open_tcp_ports"][0]["port"], 22)
            self.assertEqual(document["open_tcp_ports"][0]["service"]["name"], "ssh")
            self.assertEqual(
                document["open_tcp_ports"][0]["service"]["cpe"],
                ["cpe:/a:openbsd:openssh:9.6"],
            )

    def test_nmap_xml_import_with_output_and_json_output_saves_both(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            xml_path = self.write_sample_xml(temporary_dir)
            txt_output_path = Path(temporary_dir) / "nmap_import_report.txt"
            json_output_path = Path(temporary_dir) / "nmap_import_results.json"

            with (
                patch(
                    "sys.argv",
                    [
                        "hylianscan",
                        "--nmap-xml",
                        str(xml_path),
                        "-o",
                        "--json-output",
                    ],
                ),
                patch("sys.stdout", io.StringIO()),
                patch(
                    "hylianscan.resolve_nmap_import_output_path",
                    return_value=txt_output_path,
                ),
                patch(
                    "hylianscan.resolve_nmap_import_json_output_path",
                    return_value=json_output_path,
                ),
            ):
                hylianscan.main()

            self.assertTrue(txt_output_path.exists())
            self.assertTrue(json_output_path.exists())


if __name__ == "__main__":
    unittest.main()
