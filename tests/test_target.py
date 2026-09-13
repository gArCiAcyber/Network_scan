"""Tests for target validation and resolution."""

import unittest

from modules.target import TargetResolutionError, resolve_target


class TargetResolutionTests(unittest.TestCase):
    def test_ipv6_is_rejected_before_the_ipv4_scanner_runs(self) -> None:
        with self.assertRaisesRegex(TargetResolutionError, "IPv6.*not supported"):
            resolve_target("::1")


if __name__ == "__main__":
    unittest.main()
