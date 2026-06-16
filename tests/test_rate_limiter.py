"""Tests for deterministic connection pacing helpers."""

import unittest

from modules.rate_limiter import MaxRatePacer


class MaxRatePacerTests(unittest.TestCase):
    """Validate max-rate pacing without real sleeping."""

    def test_pacer_allows_first_action_immediately_then_spaces_followups(self) -> None:
        current_time = [10.0]
        sleep_calls: list[float] = []

        def monotonic() -> float:
            return current_time[0]

        def sleep(duration: float) -> None:
            sleep_calls.append(duration)
            current_time[0] += duration

        pacer = MaxRatePacer(max_rate=2.0, monotonic=monotonic, sleep=sleep)

        self.assertEqual(pacer.wait(), 0.0)
        self.assertEqual(pacer.wait(), 0.5)
        self.assertEqual(pacer.wait(), 0.5)
        self.assertEqual(sleep_calls, [0.5, 0.5])

    def test_pacer_resets_schedule_when_clock_has_advanced(self) -> None:
        current_time = [1.0]
        sleep_calls: list[float] = []

        def monotonic() -> float:
            return current_time[0]

        def sleep(duration: float) -> None:
            sleep_calls.append(duration)
            current_time[0] += duration

        pacer = MaxRatePacer(max_rate=10.0, monotonic=monotonic, sleep=sleep)

        self.assertEqual(pacer.wait(), 0.0)
        current_time[0] = 5.0

        self.assertEqual(pacer.wait(), 0.0)
        self.assertEqual(sleep_calls, [])

    def test_pacer_rejects_invalid_rates(self) -> None:
        for max_rate in (0.0, -1.0):
            with self.subTest(max_rate=max_rate):
                with self.assertRaises(ValueError):
                    MaxRatePacer(max_rate=max_rate)


if __name__ == "__main__":
    unittest.main()
