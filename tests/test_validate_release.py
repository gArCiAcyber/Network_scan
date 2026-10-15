"""Release checks must not delete reports or metadata from other runs."""

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import validate_release


class ReleaseValidationTests(unittest.TestCase):
    def test_generated_artifacts_stay_in_owned_temporary_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            for name in ("hylianscan.py", "README.md", "pyproject.toml",
                         "docs/examples/nmap_single_host.xml", "core/__init__.py",
                         "modules/__init__.py", "hylianscan.egg-info/PKG-INFO",
                         "output/nmap_import_report.txt", "output/nmap_import_results.json"):
                path = repository / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("existing evidence", encoding="utf-8")
            original = {path: path.read_bytes() for path in repository.rglob("*") if path.is_file()}
            temporary_roots = []

            def run_step(title, command, cwd=None):
                if "--json-output" in command:
                    temporary_roots.append(cwd)
                    self.assertNotEqual(cwd, repository)
                    (cwd / "output").mkdir()
                    (cwd / validate_release.NMAP_IMPORT_TXT_OUTPUT).write_text("new report")
                    (cwd / validate_release.NMAP_IMPORT_JSON_OUTPUT).write_text("{}")
                if "pip" in command:
                    temporary_roots.append(cwd)
                    self.assertNotEqual(cwd, repository)
                    self.assertTrue((cwd / "pyproject.toml").is_file())
                    (cwd / "hylianscan.egg-info").mkdir()

            with (
                patch.object(validate_release, "REPOSITORY_ROOT", repository),
                patch.object(validate_release, "run_step", side_effect=run_step),
                patch("sys.stdout", io.StringIO()),
            ):
                validate_release.main()
            self.assertEqual(len(temporary_roots), 2)
            self.assertTrue(all(not path.exists() for path in temporary_roots))
            self.assertEqual(original, {path: path.read_bytes() for path in repository.rglob("*")
                                        if path.is_file()})
