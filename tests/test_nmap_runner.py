"""Tests for the optional Nmap runner foundation."""

import subprocess
import unittest
from unittest.mock import patch

from modules.nmap_runner import (
    build_nmap_service_version_command,
    normalize_nmap_ports,
    run_nmap_service_version_scan,
)


SINGLE_HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -n -p 22,80 -oX - 127.0.0.1"
         start="1710000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapRunnerTests(unittest.TestCase):
    """Validate Nmap command construction and mocked runner behavior."""

    def test_command_builder_creates_expected_argv(self) -> None:
        command = build_nmap_service_version_command("127.0.0.1", [22, 80, 443])

        self.assertEqual(
            command,
            [
                "nmap",
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "-p",
                "22,80,443",
                "-oX",
                "-",
                "127.0.0.1",
            ],
        )

    def test_command_builder_sorts_and_deduplicates_ports(self) -> None:
        command = build_nmap_service_version_command("example.com", [443, 22, 80, 22])

        self.assertEqual(command[6], "22,80,443")
        self.assertEqual(normalize_nmap_ports([443, 22, 80, 22]), [22, 80, 443])

    def test_command_builder_rejects_empty_ports(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one TCP port"):
            build_nmap_service_version_command("example.com", [])

    def test_command_builder_rejects_invalid_ports(self) -> None:
        invalid_port_sets = ([0], [-1], [65536], ["80"], [True])

        for ports in invalid_port_sets:
            with self.subTest(ports=ports):
                with self.assertRaisesRegex(ValueError, "Invalid TCP port"):
                    build_nmap_service_version_command("example.com", ports)  # type: ignore[arg-type]

    def test_command_builder_uses_custom_nmap_binary(self) -> None:
        command = build_nmap_service_version_command(
            "example.com",
            [80],
            nmap_binary="/usr/local/bin/nmap",
        )

        self.assertEqual(command[0], "/usr/local/bin/nmap")

    def test_runner_calls_subprocess_with_safe_options_and_parses_stdout(self) -> None:
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout=SINGLE_HOST_XML,
            stderr="",
        )

        with patch(
            "modules.nmap_runner.subprocess.run",
            return_value=completed_process,
        ) as run:
            result = run_nmap_service_version_scan(
                "127.0.0.1",
                [80, 22],
                timeout=12.5,
            )

        run.assert_called_once_with(
            [
                "nmap",
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "-p",
                "22,80",
                "-oX",
                "-",
                "127.0.0.1",
            ],
            shell=False,
            capture_output=True,
            text=True,
            timeout=12.5,
        )
        self.assertEqual(result.metadata.scanner, "nmap")
        self.assertEqual(result.up_hosts[0].open_tcp_ports[0].service.name, "ssh")

    def test_runner_converts_missing_binary_to_clear_runtime_error(self) -> None:
        with patch(
            "modules.nmap_runner.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            with self.assertRaisesRegex(RuntimeError, "Nmap binary not found"):
                run_nmap_service_version_scan("example.com", [80])

    def test_runner_converts_non_zero_exit_to_clear_runtime_error(self) -> None:
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=2,
            stdout="",
            stderr="Failed to resolve target\nadditional detail",
        )

        with patch(
            "modules.nmap_runner.subprocess.run",
            return_value=completed_process,
        ):
            with self.assertRaisesRegex(RuntimeError, "exit code 2"):
                run_nmap_service_version_scan("example.com", [80])

    def test_runner_converts_timeout_to_clear_runtime_error(self) -> None:
        with patch(
            "modules.nmap_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1.0),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                run_nmap_service_version_scan("example.com", [80], timeout=1.0)

    def test_runner_reuses_parser_for_malformed_xml_stdout(self) -> None:
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout="<nmaprun>",
            stderr="",
        )

        with patch(
            "modules.nmap_runner.subprocess.run",
            return_value=completed_process,
        ):
            with self.assertRaisesRegex(ValueError, "malformed XML"):
                run_nmap_service_version_scan("example.com", [80])


if __name__ == "__main__":
    unittest.main()
