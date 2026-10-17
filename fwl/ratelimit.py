"""A tiny thread-safe rate limiter.

The public VirusTotal API allows 4 requests per minute, so every request
goes through :class:`RateLimiter` before hitting the network.  The clock
and the sleep function are injectable to keep unit tests instant.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Protocol

from .errors import CancelledError


class CancelToken(Protocol):
    """Anything with an ``is_set()`` method — ``threading.Event`` fits."""

    def is_set(self) -> bool:  # pragma: no cover - protocol definition
        ...


class RateLimiter:
    """Paces calls so that no more than ``rpm`` of them happen per minute.

    ``rpm <= 0`` disables throttling entirely (useful for premium keys that
    are not affected by the public quota).
    """

    def __init__(
        self,
        rpm: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_at = clock()
        self._interval = 0.0
        self.set_rate(rpm)

    def set_rate(self, rpm: float) -> None:
        with self._lock:
            self._interval = 60.0 / float(rpm) if rpm and rpm > 0 else 0.0

    @property
    def interval(self) -> float:
        with self._lock:
            return self._interval

    def acquire(self, cancel: CancelToken | None = None) -> None:
        """Block until the next request is allowed."""
        while True:
            with self._lock:
                now = self._clock()
                delay = self._next_at - now
                if delay <= 0:
                    self._next_at = now + self._interval
                    return
            # Sleep in small chunks so cancellation stays responsive.
            self._sleep(min(delay, 0.2))
            if cancel is not None and cancel.is_set():
                raise CancelledError("operation cancelled")

    def penalize(self, seconds: float) -> None:
        """Push the next allowed request ``seconds`` into the future.

        Used after HTTP 429 responses so that every thread waits.
        """
        if seconds <= 0:
            return
        with self._lock:
            target = self._clock() + seconds
            if target > self._next_at:
                self._next_at = target
