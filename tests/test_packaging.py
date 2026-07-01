"""Tests for Python packaging metadata."""

import tomllib
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"


class PackagingMetadataTests(unittest.TestCase):
    """Validate pyproject metadata used by pip and pipx installs."""

    @classmethod
    def setUpClass(cls) -> None:
        with PYPROJECT_PATH.open("rb") as pyproject_file:
            cls.pyproject = tomllib.load(pyproject_file)

    def test_project_metadata(self) -> None:
        project = self.pyproject["project"]

        self.assertEqual(project["name"], "hylianscan")
        self.assertTrue(project["version"])
        self.assertTrue(project["requires-python"])
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["dependencies"], [])

    def test_console_script_entrypoint(self) -> None:
        scripts = self.pyproject["project"]["scripts"]

        self.assertEqual(scripts["hylianscan"], "hylianscan:main")

    def test_build_backend(self) -> None:
        build_system = self.pyproject["build-system"]

        self.assertEqual(build_system["build-backend"], "setuptools.build_meta")


if __name__ == "__main__":
    unittest.main()
