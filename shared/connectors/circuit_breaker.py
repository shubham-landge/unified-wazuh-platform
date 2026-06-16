"""Simple circuit breaker for external service connectors.

Tracks failure counts per circuit and opens/closes based on thresholds.
Implements a half-open state: after the timeout period one probe request
is allowed; if it succeeds the circuit closes.
"""

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_requests: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_requests = half_open_max_requests
        self._failure_count = 0
        self._state = "closed"
        self._last_failure_time = 0.0
        self._half_open_requests = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def call(self, coro_factory):
        """Execute a coroutine factory under circuit breaker protection.

        ``coro_factory`` is a zero-argument callable that returns an awaitable.
        This allows lazy construction so the circuit breaker can refuse to
        call it when the circuit is open.
        """
        async with self._lock:
            if self._state == "open":
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = "half-open"
                    self._half_open_requests = 0
                    logger.info("Circuit %s → half-open (probing)", self.name)
                else:
                    raise CircuitBreakerOpenError(
                        f"Circuit {self.name} is open. "
                        f"Retry in {self.recovery_timeout - (time.monotonic() - self._last_failure_time):.0f}s"
                    )

            if self._state == "half-open" and self._half_open_requests >= self.half_open_max_requests:
                raise CircuitBreakerOpenError(
                    f"Circuit {self.name} is half-open and already probing. Try again later."
                )

            if self._state == "half-open":
                self._half_open_requests += 1

        try:
            result = await coro_factory()
        except Exception as exc:
            async with self._lock:
                self._failure_count += 1
                self._last_failure_time = time.monotonic()
                if self._failure_count >= self.failure_threshold:
                    self._state = "open"
                    logger.warning(
                        "Circuit %s OPEN after %d failures (recovery in %.0fs)",
                        self.name,
                        self._failure_count,
                        self.recovery_timeout,
                    )
            raise exc

        async with self._lock:
            self._failure_count = 0
            if self._state == "half-open":
                self._state = "closed"
                logger.info("Circuit %s CLOSED (probe succeeded)", self.name)

        return result

    async def reset(self):
        async with self._lock:
            self._failure_count = 0
            self._state = "closed"
            self._half_open_requests = 0


class CircuitBreakerOpenError(Exception):
    """Raised when a circuit breaker refuses a call because the circuit is open."""
