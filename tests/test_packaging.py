"""Tests for Python packaging metadata."""

import unittest
from pathlib import Path

from core.version import APP_VERSION


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"


class PackagingMetadataTests(unittest.TestCase):
    """Validate pyproject metadata used by pip and pipx installs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pyproject = PYPROJECT_PATH.read_text(encoding="utf-8")

    def test_project_metadata(self) -> None:
        self.assertIn('name = "hylianscan"', self.pyproject)
        self.assertIn(f'version = "{APP_VERSION}"', self.pyproject)
        self.assertIn('requires-python = ">=3.10"', self.pyproject)
        self.assertIn('readme = "README.md"', self.pyproject)
        self.assertIn("dependencies = []", self.pyproject)

    def test_console_script_entrypoint(self) -> None:
        self.assertIn('hylianscan = "hylianscan:main"', self.pyproject)

    def test_build_backend(self) -> None:
        self.assertIn('build-backend = "setuptools.build_meta"', self.pyproject)


if __name__ == "__main__":
    unittest.main()
