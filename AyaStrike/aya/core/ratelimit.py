"""Adjustable rate limiting and bounded concurrency.

A token-bucket limiter smooths out probe/request rates so scans stay polite and
within the bounds an authorised engagement agreed to. ``Throttle`` combines the
rate limiter with a concurrency semaphore and a cooperative cancellation flag.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Classic token bucket. ``rate`` tokens are added per second up to
    ``capacity``; ``acquire`` blocks until a token is available."""

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(rate, 0.0)
        self.capacity = capacity if capacity is not None else max(rate, 1.0)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def set_rate(self, rate: float) -> None:
        with self._lock:
            self.rate = max(rate, 0.0)
            self.capacity = max(self.rate, 1.0)
            self._tokens = min(self._tokens, self.capacity)

    def acquire(self, tokens: float = 1.0, cancel: "CancelToken | None" = None) -> bool:
        if self.rate <= 0:
            return True  # unlimited
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            if cancel is not None and cancel.is_set():
                return False
            time.sleep(min(wait, 0.25))


class CancelToken:
    """A simple cooperative cancellation flag shared with worker threads."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def reset(self) -> None:
        self._event.clear()

    def is_set(self) -> bool:
        return self._event.is_set()


class Throttle:
    """Ties together a rate limiter and a concurrency cap for a scan run."""

    def __init__(self, rate_per_sec: float, max_concurrency: int) -> None:
        self.bucket = TokenBucket(rate_per_sec)
        self.sem = threading.Semaphore(max(1, max_concurrency))
        self.cancel = CancelToken()

    def gate(self, tokens: float = 1.0) -> bool:
        """Block for a rate token. Returns False if cancelled while waiting."""
        return self.bucket.acquire(tokens, cancel=self.cancel)

    def __enter__(self):
        self.sem.acquire()
        return self

    def __exit__(self, *exc):
        self.sem.release()
        return False
