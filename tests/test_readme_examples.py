"""Tests for README command and asset consistency."""

import re
import shlex
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from core.cli import parse_arguments, validate_mode


PROJECT_ROOT = Path(__file__).resolve().parents[1]
README_PATH = PROJECT_ROOT / "README.md"


def read_readme() -> str:
    """Return the current README content."""
    return README_PATH.read_text(encoding="utf-8")


def extract_bash_commands(markdown_text: str) -> list[str]:
    """Extract shell commands from README bash code blocks."""
    commands: list[str] = []

    for block in re.findall(r"```bash\n(.*?)```", markdown_text, flags=re.DOTALL):
        for line in block.splitlines():
            command = line.strip()

            if command and not command.startswith("#"):
                commands.append(command)

    return commands


def normalize_hylianscan_argv(command: str) -> list[str] | None:
    """Convert a documented Hylianscan command into an argv list."""
    parts = shlex.split(command)

    if parts[:2] in (["python", "hylianscan.py"], ["python3", "hylianscan.py"]):
        return ["hylianscan", *parts[2:]]

    if parts and parts[0] == "hylianscan":
        return ["hylianscan", *parts[1:]]

    return None


class ReadmeExamplesTests(unittest.TestCase):
    """Validate README examples without running network scans."""

    def test_documented_hylianscan_commands_parse_successfully(self) -> None:
        commands = [
            command
            for command in extract_bash_commands(read_readme())
            if normalize_hylianscan_argv(command) is not None
        ]

        self.assertGreater(commands, [])

        for command in commands:
            argv = normalize_hylianscan_argv(command)

            with self.subTest(command=command):
                with (
                    patch("sys.argv", argv),
                    redirect_stdout(StringIO()),
                    redirect_stderr(StringIO()),
                ):
                    try:
                        args = parse_arguments()
                    except SystemExit as error:
                        self.assertEqual(error.code, 0)
                        continue

                validate_mode(args)

    def test_readme_does_not_document_removed_flags(self) -> None:
        readme_text = read_readme()

        self.assertNotIn("--subdomains", readme_text)
        self.assertNotIn("-w / --wordlist", readme_text)

    def test_readme_image_paths_exist(self) -> None:
        readme_text = read_readme()
        image_paths = re.findall(r'<img src="([^"]+)"', readme_text)

        self.assertGreater(image_paths, [])

        for image_path in image_paths:
            with self.subTest(image_path=image_path):
                self.assertTrue((PROJECT_ROOT / image_path).is_file())


if __name__ == "__main__":
    unittest.main()
