"""Offline safety checks for the maintained real-binary laboratory launcher."""

import os
import json
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from benchmark import cli as benchmark
from benchmark import providers as lab


class ProviderLabTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux laboratory launcher")
    def test_corrupt_process_checkpoint_still_stops_worker_and_removes_key(self):
        process = Mock()
        process.wait.return_value = 0
        created = []

        def launch(_command, **options):
            directory = Path(options["stdout"].name).parent
            (directory / "processes.json").write_text("{")
            (directory / "lab-private-key.pem").write_text("fixture")
            created.append(directory)
            return process

        with tempfile.TemporaryDirectory() as temporary:
            with (patch.object(lab.shutil, "which", return_value=sys.executable),
                  patch.object(lab.common, "disk_preflight"),
                  patch.object(lab.common, "source_metadata", return_value={}),
                  patch.object(lab.subprocess, "Popen", side_effect=launch),
                  patch("benchmark.subdomain.stop_worker") as stop):
                with self.assertRaises(json.JSONDecodeError):
                    lab.main(["--output-dir", temporary])
            stop.assert_called_once_with(process, created[0] / "watchdog")
            self.assertFalse((created[0] / "lab-private-key.pem").exists())

    def test_saved_name_oracle_accepts_empty_writer_newline(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.txt"
            for text, expected in (("", set()), ("\n", set()),
                                   ("a.example.test\n", {"a.example.test"}),
                                   (" \n", {" "})):
                path.write_text(text, encoding="utf-8")
                self.assertEqual(lab.saved_names(path), expected)

    @unittest.skipUnless(sys.platform == "linux", "Linux process state")
    def test_exited_child_is_not_a_live_cleanup_survivor(self):
        with subprocess.Popen([sys.executable, "-c", "pass"]) as child:
            deadline = time.monotonic() + 3
            while Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z":
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            self.assertIsNone(lab.birth(child.pid))

    @unittest.skipUnless(sys.platform == "linux", "Linux namespace guard")
    def test_host_namespace_is_rejected_before_any_setup(self):
        with patch.object(lab.subprocess, "check_output") as command:
            with self.assertRaises(RuntimeError):
                lab.verify_namespace(os.readlink("/proc/self/ns/net"), os.readlink("/proc/self/ns/mnt"))
            command.assert_not_called()

    def test_modes_dispatch_and_do_not_claim_calibrated_comparisons(self):
        for mode in ("providers", "dnsx"):
            args = benchmark.resolve_options(benchmark.parser().parse_args(["--benchmark", mode]))
            with patch.object(lab, "main", return_value=0) as launch:
                self.assertEqual(lab.run_benchmark(args), 0)
                self.assertEqual(launch.call_args.args[0][:2], ["--battery", mode])
            args.reference = args.candidate
            with self.assertRaises(ValueError):
                lab.run_benchmark(args)


if __name__ == "__main__":
    unittest.main()
