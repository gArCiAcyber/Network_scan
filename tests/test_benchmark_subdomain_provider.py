"""Offline executable contracts and retained Amass graph regression checks."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/benchmark_subdomain_provider.py"


class OfflineProviderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.manifest = self.directory / "manifest.json"
        self.config = self.directory / "config.yaml"
        self.config.write_text("active: false\n", encoding="utf-8")
        self.data = {"domain": "hylianlab.test", "lines": ["api.hylianlab.test", "api.dev.hylianlab.test"],
                     "status": "completed", "batch_size": 1, "delay_seconds": 0.0, "stderr": "diagnostic\n"}
        self.write_manifest()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.data), encoding="utf-8")

    def command(self, provider, *arguments):
        return [sys.executable, str(SCRIPT), "--provider", provider,
                "--manifest", str(self.manifest), "--", *arguments]

    def run_provider(self, provider, *arguments):
        return subprocess.run(self.command(provider, *arguments), capture_output=True,
                              text=True, timeout=5)

    def amass_arguments(self, subcommand):
        return (subcommand, "-passive" if subcommand == "enum" else "-names", "-d", "hylianlab.test",
                "-dir", str(self.directory / "graph"), "-config", str(self.config), "-nocolor")

    def test_version_help_and_strict_discovery_arguments(self):
        for provider, version in (("subfinder", "2.16.0"), ("amass", "5.0.0")):
            self.assertIn(version, self.run_provider(provider, "-version").stdout)
            self.assertEqual(self.run_provider(provider, "-h").returncode, 0)
        self.assertIn("-names", self.run_provider("amass", "subs", "-h").stdout)
        unsafe_help = self.run_provider("amass", "enum", "-h")
        self.assertEqual(unsafe_help.returncode, 2)
        self.assertIn("unsafe", unsafe_help.stderr)
        self.assertFalse(list(self.directory.glob("engine-ready-*.json")))
        result = self.run_provider("subfinder", "-d", "hylianlab.test", "-silent")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), self.data["lines"])
        self.assertEqual(result.stderr, self.data["stderr"])
        for arguments in (("-d", "external.test", "-silent"),
                          ("-d", "hylianlab.test", "-silent", "-active")):
            self.assertEqual(self.run_provider("subfinder", *arguments).returncode, 2)
        commands = [json.loads(line) for line in (self.directory / "provider-commands.jsonl").read_text(
            encoding="utf-8").splitlines()]
        discovery = next(item for item in commands if item["stage"] == "discovery")
        self.assertEqual(Path(discovery["stdout"]).read_text(encoding="utf-8").splitlines(), self.data["lines"])

    def test_failed_enum_retains_graph_for_successful_query(self):
        self.data["status"] = "failed"
        self.write_manifest()
        enumeration = self.run_provider("amass", *self.amass_arguments("enum"))
        self.assertEqual(enumeration.returncode, 7)
        self.assertNotIn(self.data["lines"][0], enumeration.stdout)
        results = self.run_provider("amass", *self.amass_arguments("subs"))
        self.assertEqual(results.returncode, 0)
        self.assertEqual(results.stdout.splitlines(), self.data["lines"])
        self.assertTrue((self.directory / "graph/laboratory-graph.jsonl").is_file())

    def test_crlf_final_unterminated_line_and_abrupt_exit_preserve_raw_bytes(self):
        self.data.update(newline="\r\n", final_newline=False, status="failed", exit_code=9, abrupt=True)
        self.write_manifest()
        result = subprocess.run(self.command("subfinder", "-d", "hylianlab.test", "-silent"),
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 9)
        self.assertEqual(result.stdout, "\r\n".join(self.data["lines"]).encode("utf-8"))
        log = next(self.directory.glob("subfinder-discovery-*.stdout.log"))
        self.assertEqual(log.read_bytes(), result.stdout)
        ready = json.loads(next(self.directory.glob("subfinder-discovery-*.ready.json")).read_text(
            encoding="utf-8"))
        self.assertEqual(ready["emitted_count"], len(self.data["lines"]))

    def test_amass4_abrupt_graph_output_retains_raw_evidence(self):
        self.data.update(version="4.2.0", status="failed", exit_code=9, abrupt=True,
                         lines=["api.hylianlab.test (FQDN) --> cname_record --> api.dev.hylianlab.test (FQDN)"])
        self.write_manifest()
        self.assertEqual(self.run_provider("amass", "enum", "-h").returncode, 0)
        result = self.run_provider("amass", "enum", "-passive", "-d", "hylianlab.test")
        self.assertEqual(result.returncode, 9)
        self.assertEqual(result.stdout.splitlines(), self.data["lines"])
        log = next(self.directory.glob("amass-enum-*.stdout.log"))
        self.assertEqual(log.read_text(encoding="utf-8"), result.stdout)
        self.assertTrue(list(self.directory.glob("amass-enum-*.ready.json")))

    def test_timed_out_enum_preserves_exact_prepared_partial_graph(self):
        self.data["status"] = "timed_out"
        self.write_manifest()
        process = subprocess.Popen(self.command("amass", *self.amass_arguments("enum")),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                process.communicate(timeout=2)
        finally:
            if process.poll() is None:
                process.terminate()
            _, diagnostics = process.communicate(timeout=5)
        self.assertIn("awaiting timed_out cancellation", diagnostics)
        results = self.run_provider("amass", *self.amass_arguments("subs"))
        self.assertEqual(results.returncode, 0)
        self.assertEqual(results.stdout.splitlines(), self.data["lines"])


if __name__ == "__main__":
    unittest.main()
