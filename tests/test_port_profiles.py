"""Tests for predefined TCP port profile helpers."""

import unittest

from modules.port_profiles import (
    PORT_PROFILES,
    format_port_profile_label,
    get_valid_port_profile_values,
    normalize_profile_ports,
    resolve_port_profile,
)


class PortProfileTests(unittest.TestCase):
    """Validate TCP port profile resolution and normalization."""

    def test_normalize_profile_ports_deduplicates_and_sorts(self) -> None:
        self.assertEqual(normalize_profile_ports([443, 80, 443, 22]), (22, 80, 443))

    def test_resolve_port_profile_accepts_technical_names(self) -> None:
        for profile_name, profile in PORT_PROFILES.items():
            with self.subTest(profile_name=profile_name):
                self.assertIs(resolve_port_profile(profile_name), profile)

    def test_resolve_port_profile_accepts_zelda_aliases(self) -> None:
        for profile in PORT_PROFILES.values():
            with self.subTest(alias=profile.alias):
                self.assertIs(resolve_port_profile(profile.alias), profile)

    def test_resolve_port_profile_rejects_unknown_values_with_valid_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "quick"):
            resolve_port_profile("unknown")

        valid_values = get_valid_port_profile_values()
        self.assertIn("quick", valid_values)
        self.assertIn("kokiri", valid_values)

    def test_profile_ports_are_sorted_and_unique(self) -> None:
        for profile in PORT_PROFILES.values():
            with self.subTest(profile=profile.name):
                self.assertEqual(profile.ports, tuple(sorted(set(profile.ports))))

    def test_format_port_profile_label_includes_profile_and_alias(self) -> None:
        self.assertEqual(format_port_profile_label("sheikah"), "web / sheikah")


if __name__ == "__main__":
    unittest.main()
