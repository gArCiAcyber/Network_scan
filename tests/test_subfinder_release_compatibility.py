"""Replay fixtures captured from official Subfinder 2.13.0 and 2.16.0 binaries."""

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

import hylianscan
from modules.subdomain import ProviderRunResult, run_passive_provider


FIXTURE = Path(__file__).parent / "fixtures" / "subfinder_real_output.json"


class SubfinderReleaseCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_real_versions_and_required_flags_match(self):
        self.assertIn("v2.13.0", self.evidence["versions"]["2.13.0"]["version_stderr"])
        self.assertIn("v2.16.0", self.evidence["versions"]["2.16.0"]["version_stderr"])
        self.assertEqual(
            self.evidence["versions"]["2.13.0"]["required_flags"],
            self.evidence["versions"]["2.16.0"]["required_flags"],
        )
        self.assertEqual(self.evidence["unknown_flag"]["exit_code"], 2)

    def test_real_213_stdout_is_parsed_deduplicated_and_saved_as_txt_json(self):
        lines = self.evidence["versions"]["2.13.0"]["normal_stdout"]
        script = "import sys; print(sys.argv[1], end=''); print(sys.argv[1])"
        payload = "\n".join(lines) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-c", script, payload]
            result = run_passive_provider(
                "example.test", "Subfinder 2.13.0 fixture", command,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.subdomains, sorted(set(lines)))

            txt = Path(directory) / "subdomains.txt"
            report = Path(directory) / "subdomains.json"
            hylianscan.save_subdomain_results(result.subdomains, txt)
            hylianscan.write_subdomain_json_report(
                "example.test", {"subfinder": result}, report,
            )
            self.assertEqual(txt.read_text(encoding="utf-8").splitlines(), sorted(set(lines)))
            document = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(document["results"]["subdomains"], sorted(set(lines)))
            self.assertEqual(document["providers"][0]["status"], "completed")

    def test_real_empty_output_and_hylianscan_timeout_are_explicit(self):
        self.assertEqual(self.evidence["empty_output"]["stdout"], "")
        self.assertEqual(self.evidence["empty_output"]["exit_code"], 0)
        started = time.monotonic()
        result = run_passive_provider(
            "example.test", "Subfinder timeout fixture",
            [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.15,
        )
        self.assertEqual(result.status, "timed_out")
        self.assertLess(time.monotonic() - started, 3)

    def test_unknown_flag_fixture_is_a_provider_error(self):
        message = self.evidence["unknown_flag"]["stdout"]
        result = run_passive_provider(
            "example.test", "Subfinder unknown flag fixture",
            [sys.executable, "-c", f"import sys; print({message!r}, end=''); raise SystemExit(2)"],
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.subdomains, [])


if __name__ == "__main__":
    unittest.main()
