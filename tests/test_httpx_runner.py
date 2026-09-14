"""Tests for HTTPx command execution and passive-discovery orchestration."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import hylianscan
from core.cli import parse_arguments, validate_mode
from modules.httpx_runner import (
    HttpxResult,
    build_httpx_command,
    parse_httpx_jsonl,
    run_httpx,
)


HTTPX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "input": "example.test",
                "url": "https://example.test",
                "status_code": 200,
                "title": "Training Portal",
                "tech": ["nginx"],
            }
        ),
        json.dumps(
            {
                "input": "api.example.test",
                "url": "https://api.example.test",
                "status_code": 401,
                "title": "API",
            }
        ),
    ]
)


class HttpxRunnerTests(unittest.TestCase):
    """Validate HTTPx argv, stdin, parsing, and report integration."""

    def test_command_collects_web_fingerprints_and_both_schemes(self) -> None:
        command = build_httpx_command("/opt/tools/httpx")

        self.assertEqual(command[0], "/opt/tools/httpx")
        for flag in (
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-ip",
            "-cname",
            "-location",
            "-no-fallback",
        ):
            self.assertIn(flag, command)

    def test_runner_sends_normalized_targets_over_stdin_and_parses_jsonl(self) -> None:
        completed_process = subprocess.CompletedProcess(
            args=["httpx"],
            returncode=0,
            stdout=HTTPX_JSONL,
            stderr="",
        )

        with patch(
            "modules.httpx_runner.subprocess.run",
            return_value=completed_process,
        ) as run:
            result = run_httpx(
                ["Example.test", "api.example.test", "example.test."],
                httpx_binary="/opt/tools/httpx",
                timeout=12.0,
            )

        self.assertEqual(
            run.call_args.kwargs["input"],
            "api.example.test\nexample.test\n",
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0]["status_code"], 200)

    def test_parser_rejects_malformed_jsonl(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "malformed JSONL"):
            parse_httpx_jsonl('{"url":')

    def test_httpx_requires_passive_discovery(self) -> None:
        with patch("sys.argv", ["hylianscan", "example.test", "--httpx"]):
            args = parse_arguments()

        with self.assertRaisesRegex(ValueError, "--subfinder and/or --amass"):
            validate_mode(args)

    def test_passive_workflow_saves_and_exports_httpx_results(self) -> None:
        httpx_result = HttpxResult(
            status="completed",
            targets_requested=("api.example.test", "example.test"),
            findings=tuple(json.loads(line) for line in HTTPX_JSONL.splitlines()),
        )

        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"
            json_output_path = Path(temporary_dir) / "subdomains.json"

            with (
                patch(
                    "hylianscan.run_subfinder",
                    return_value=["api.example.test"],
                ),
                patch("hylianscan.run_httpx", return_value=httpx_result) as runner,
            ):
                summary = hylianscan.run_passive_subdomain_discovery(
                    domain="example.test",
                    providers=["subfinder"],
                    output_path=output_path,
                    json_output_path=json_output_path,
                    httpx_enabled=True,
                    quiet=True,
                )

            runner.assert_called_once_with(
                ["example.test", "api.example.test"],
            )
            self.assertTrue(output_path.with_name("httpx.jsonl").is_file())
            document = json.loads(json_output_path.read_text(encoding="utf-8"))

        self.assertEqual(document["enrichment"]["httpx"]["status"], "completed")
        self.assertEqual(document["enrichment"]["httpx"]["live_services"], 2)
        self.assertIn("[+] HTTPX WEB PROBE", summary)
        self.assertIn("https://example.test", summary)


if __name__ == "__main__":
    unittest.main()
