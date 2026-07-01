"""Tests for information-only CLI commands."""

import io
import unittest
from unittest.mock import patch

import hylianscan


class InformationCommandTests(unittest.TestCase):
    """Validate non-scanning informational commands."""

    def test_list_port_profiles_exits_before_scan_setup(self) -> None:
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "--list-port-profiles"]),
            patch("sys.stdout", output),
            patch("hylianscan.show_banner") as show_banner,
            patch("hylianscan.resolve_target") as resolve_target,
            patch("hylianscan.run_port_scan") as run_port_scan,
            patch("hylianscan.run_passive_subdomain_discovery") as passive_discovery,
        ):
            hylianscan.main()

        rendered_output = output.getvalue()
        self.assertIn("Built-in TCP port profiles", rendered_output)
        self.assertIn("quick / kokiri", rendered_output)
        self.assertIn("web / sheikah", rendered_output)
        self.assertIn("bugbounty / triforce", rendered_output)
        show_banner.assert_not_called()
        resolve_target.assert_not_called()
        run_port_scan.assert_not_called()
        passive_discovery.assert_not_called()

    def test_list_stances_exits_before_scan_setup(self) -> None:
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "--list-stances"]),
            patch("sys.stdout", output),
            patch("hylianscan.show_banner") as show_banner,
            patch("hylianscan.resolve_target") as resolve_target,
            patch("hylianscan.run_port_scan") as run_port_scan,
            patch("hylianscan.run_passive_subdomain_discovery") as passive_discovery,
        ):
            hylianscan.main()

        rendered_output = output.getvalue()
        self.assertIn("Built-in TCP scan stances", rendered_output)
        self.assertIn("fast / din", rendered_output)
        self.assertIn("balanced / nayru", rendered_output)
        self.assertIn("stealthier / farore", rendered_output)
        show_banner.assert_not_called()
        resolve_target.assert_not_called()
        run_port_scan.assert_not_called()
        passive_discovery.assert_not_called()

    def test_normal_scan_without_target_still_exits_with_error(self) -> None:
        error_output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan"]),
            patch("sys.stderr", error_output),
            self.assertRaises(SystemExit) as exit_context,
        ):
            hylianscan.parse_arguments()

        self.assertEqual(exit_context.exception.code, 2)
        self.assertIn("A target is required", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
