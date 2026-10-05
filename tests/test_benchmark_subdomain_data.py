"""Check deterministic provider datasets without importing production parsing."""

import hashlib
import json
import unittest

from scripts import benchmark_subdomain_data as data


def digest(dataset):
    return hashlib.sha256(json.dumps(dataset, sort_keys=True, separators=(",", ":"))
                          .encode("ascii")).hexdigest()


class HylianlabDatasetTests(unittest.TestCase):
    def test_exact_loads_memberships_and_attribution(self):
        for size in (1_000, 10_000, 100_000):
            with self.subTest(size=size):
                dataset = data.build_dataset(size)
                union = set(dataset["union"])
                subfinder, amass = (set(dataset["providers"][provider])
                                   for provider in ("subfinder", "amass"))
                self.assertEqual(len(union), size)
                self.assertEqual(dataset["union"], sorted(union))
                self.assertEqual(len(subfinder), size * 7 // 10)
                self.assertEqual(len(amass), size * 6 // 10)
                self.assertEqual(len(subfinder & amass), size * 3 // 10)
                self.assertEqual(subfinder | amass, union)
                self.assertEqual(set(dataset["sources"]), union)
                self.assertTrue(all(data.in_scope(name) for name in union))
                self.assertIn(data.DOMAIN, subfinder & amass)
                self.assertIn(f"api.dev.europa.{data.DOMAIN}", union)
                self.assertIn(f"xn--bcher-kva.{data.DOMAIN}", union)
                for name in union:
                    expected = (["amass"] if name in amass else []) + (
                        ["subfinder"] if name in subfinder else [])
                    self.assertEqual(dataset["sources"][name], expected)
                for provider in dataset["providers"].values():
                    self.assertEqual(provider, sorted(set(provider)))
                self.assertTrue(all(not data.in_scope(name) for name in dataset["rejected"]))

    def test_scope_boundaries_apex_and_invalid_traps(self):
        longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 46, data.DOMAIN])
        self.assertEqual(len(longest), 253)
        for valid in (data.DOMAIN, f"a.{data.DOMAIN}", f"{'x' * 63}.{data.DOMAIN}", longest):
            self.assertTrue(data.in_scope(valid), valid)
        for invalid in (None, 7, "", data.DOMAIN + ".", "API." + data.DOMAIN,
                        f"{'x' * 64}.{data.DOMAIN}", longest.replace("d" * 46, "d" * 47),
                        *data.build_dataset(1_000)["rejected"]):
            self.assertFalse(data.in_scope(invalid), invalid)

    def test_determinism_and_separate_mutable_results(self):
        known_hashes = {
            1_000: "38ec28ff9258d0d90fc5b95141afc056f1464f3148374094e213b7097fd185a8",
            10_000: "e1fe9c373d046e6bf2625a8eb65363d75e69138d31c0237bbca5634489d9d692",
            100_000: "c67c0701411b3e9d8f281f38afd2379641de08dbc0223dc7184a6f526a5b1fdc",
        }
        for size, known_hash in known_hashes.items():
            with self.subTest(size=size):
                dataset = data.build_dataset(size)
                self.assertEqual(digest(dataset), known_hash)
                self.assertEqual(digest(data.build_dataset(size)), known_hash)
                self.assertEqual(dataset["seed"], 0)
                self.assertEqual(dataset["generator_version"], 1)
        dataset = data.build_dataset(1_000)
        dataset["union"].clear()
        dataset["providers"]["amass"].clear()
        dataset["sources"][data.DOMAIN].clear()
        self.assertEqual(len(data.build_dataset(1_000)["union"]), 1_000)
        self.assertEqual(data.build_dataset(1_000)["sources"][data.DOMAIN], ["amass", "subfinder"])

    def test_unsupported_loads_do_not_silently_scale(self):
        for size in (0, 1, 999, 1_001, 1_000_000, True, "1000", 1_000.0):
            with self.subTest(size=size), self.assertRaises(ValueError):
                data.build_dataset(size)


if __name__ == "__main__":
    unittest.main()
