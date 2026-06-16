"""Reusable pacing helpers for connection scheduling."""

import threading
import time
from collections.abc import Callable


class MaxRatePacer:
    """Limit how quickly new actions are allowed to start."""

    def __init__(
        self,
        max_rate: float,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_rate <= 0:
            raise ValueError("max_rate must be greater than zero.")

        self._interval = 1.0 / max_rate
        self._monotonic = monotonic
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_start: float | None = None

    def wait(self) -> float:
        """Wait until the next paced start slot and return the sleep duration."""
        with self._lock:
            now = self._monotonic()

            if self._next_start is None or now > self._next_start:
                self._next_start = now

            sleep_duration = max(0.0, self._next_start - now)
            self._next_start += self._interval

        if sleep_duration > 0:
            self._sleep(sleep_duration)

        return sleep_duration
