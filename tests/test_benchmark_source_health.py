"""Source-health checks using reduced, sanitized retained diagnostic formats."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from benchmark import source_health as health


FIXTURES = json.loads((Path(__file__).parent / "fixtures/source_health.json").read_text(encoding="utf-8"))


class SourceHealthTests(unittest.TestCase):
    def test_process_health_and_findings_are_independent(self):
        for name, expected in (("failed", "request_errors"), ("successful", "healthy"),
                               ("empty", "healthy"), ("unknown", "unknown")):
            with self.subTest(name=name):
                result = health.evaluate_provider(FIXTURES[name])
                self.assertEqual(result["process_status"], "completed")
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["source_health"], expected)
                self.assertEqual(result["finding_count"], len(FIXTURES[name]["subdomains"]))
        result = health.evaluate_provider(FIXTURES["successful"])
        self.assertEqual(result["sources"][0]["request_diagnostics"], [])
        self.assertEqual(result["sources"][0]["statistics"]["errors"], 0)

    def test_partial_errors_and_missing_or_conflicting_statistics(self):
        provider = copy.deepcopy(FIXTURES["failed"])
        provider["diagnostics"][-1] = "crtsh 1.1s 5 2 1"
        self.assertEqual(health.evaluate_provider(provider)["source_health"], "request_errors")
        provider["diagnostics"][-1] = "crtsh 1.1s 0 2 1"
        self.assertEqual(health.evaluate_provider(provider)["source_health"], "request_errors")
        for row in ("crtsh 1.1s 0 0 0", "crtsh unknown format", "crtsh 1.1s 0 1 0"):
            provider["diagnostics"][-1] = row
            self.assertEqual(health.evaluate_provider(provider)["source_health"], "unknown")
        provider["diagnostics"] = ["Source Duration Results Requests Errors"]
        self.assertEqual(health.evaluate_provider(provider, ["crtsh"])["source_health"], "unknown")
        provider["diagnostics"] = ["crtsh 1.1s 0 1 0"]
        self.assertEqual(health.evaluate_provider(provider, ["crtsh"])["source_health"], "unknown")

    def test_evaluate_saved_report_without_overwriting_evidence(self):
        document = {"schema": {"name": "hylianscan_passive_subdomain_discovery"},
                    "results": {"subdomains": []}, "providers": [FIXTURES["failed"]]}
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / "report.json", Path(temporary) / "evaluation.json"
            original = json.dumps(document)
            source.write_text(original, encoding="utf-8")
            self.assertEqual(health.main([str(source), "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["providers"][0]["source_health"], "request_errors")
            self.assertEqual(source.read_text(), original)
            with self.assertRaises(SystemExit) as rejection:
                health.main([str(source), "--output", str(output)])
            self.assertEqual(rejection.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
