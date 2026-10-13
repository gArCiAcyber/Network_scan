"""Validate resource units, descendant coverage, faults and observer overhead."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "linux", "Linux resource companion")
class ResourceTests(unittest.TestCase):
    def test_child_allocation_cpu_descriptors_and_exit_codes(self):
        child = "import time; data=bytearray(48*1024*1024); files=[open('/dev/null') for _ in range(10)]; time.sleep(.3)"
        program = ("import subprocess,sys; data=bytearray(16*1024*1024); sum(range(2000000)); "
                   f"subprocess.run([sys.executable,'-c',{child!r}],check=True)")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, code, expected in (("allocation", program, 0), ("fault", "raise SystemExit(7)", 7)):
                output = directory / f"{name}.json"
                result = subprocess.run([sys.executable, str(ROOT / "benchmark/resources.py"),
                                         "--output", str(output), "--", sys.executable, "-c", code],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stderr)
                record = json.loads(output.read_text())
                self.assertEqual(record["exit_code"], expected)
                self.assertEqual(record["cleanup_errors"], [])
                self.assertEqual(record["unavailable"], [])
                self.assertGreaterEqual(record["cpu_user_seconds"], 0)
                self.assertGreaterEqual(record["cpu_system_seconds"], 0)
                for row in json.loads((directory / "resource-processes.json").read_text()):
                    with self.assertRaises(ProcessLookupError):
                        os.kill(row["pid"], 0)
                if name == "allocation":
                    self.assertGreater(record["peak_memory_bytes"], 48 * 1024 ** 2)
                    self.assertGreater(record["sampled_tree_peak_rss_bytes"], 64 * 1024 ** 2)
                    self.assertGreaterEqual(record["sampled_tree_peak_descriptors"], 13)
                    self.assertGreaterEqual(record["sampled_tree_peak_processes"], 2)
                    # Record the matched uninstrumented duration; do not enforce a flaky speed ratio.
                    import time
                    started = time.perf_counter()
                    subprocess.run([sys.executable, "-c", program], check=True, timeout=10)
                    (directory / "observer-control.json").write_text(json.dumps({
                        "uninstrumented_seconds": time.perf_counter() - started,
                        "instrumented_seconds": record["execution_seconds"]}))

    def test_deadline_cleans_owned_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "timeout.json"
            result = subprocess.run([sys.executable, str(ROOT / "benchmark/resources.py"),
                                     "--output", str(output), "--timeout", ".1", "--",
                                     sys.executable, "-c", "import time; time.sleep(10)"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 1)
            self.assertIn("deadline", json.loads(output.read_text())["error"])
            for row in json.loads((directory / "resource-processes.json").read_text()):
                with self.assertRaises(ProcessLookupError):
                    os.kill(row["pid"], 0)

    def test_orphaned_observed_child_is_stopped_and_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            child_pid = directory / "child.pid"
            child = "import time; time.sleep(10)"
            code = ("import subprocess,sys,time; "
                    f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
                    f"open({str(child_pid)!r},'w').write(str(p.pid)); time.sleep(.15)")
            result = subprocess.run([sys.executable, str(ROOT / "benchmark/resources.py"),
                                     "--output", str(directory / "resources.json"), "--", sys.executable, "-c", code],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((directory / "resources.json").read_text())["cleanup_errors"], [])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)

    def test_child_adopted_between_sampling_ticks_is_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            child_pid = directory / "child.pid"
            child = "import time; time.sleep(10)"
            command = ("import subprocess,sys,time; "
                       f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
                       f"open({str(child_pid)!r},'w').write(str(p.pid)); time.sleep(.1)")
            code = ("from pathlib import Path; from benchmark.resources import measure; "
                    f"result=measure([{sys.executable!r},'-c',{command!r}],Path({temporary!r}),3,interval=1); "
                    "assert not result['cleanup_errors'], result")
            result = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)


if __name__ == "__main__":
    unittest.main()
