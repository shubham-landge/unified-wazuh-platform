from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


class CircuitBreakerOpenError(RuntimeError):
    pass


@dataclass
class CircuitBreakerState:
    failures: int = 0
    opened_at: float | None = None
    half_open: bool = False


class CircuitBreaker:
    def __init__(self, *, name: str, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._state = CircuitBreakerState()
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        async with self._lock:
            self._check_state()
            if self._state.half_open:
                self._state.half_open = False

        try:
            result = await func(*args, **kwargs)
        except Exception:
            async with self._lock:
                self._register_failure()
            raise

        async with self._lock:
            self._state = CircuitBreakerState()
        return result

    def _check_state(self) -> None:
        if self._state.failures < self.failure_threshold:
            return
        if self._state.opened_at is None:
            self._state.opened_at = monotonic()
            raise CircuitBreakerOpenError(f"{self.name} circuit is open")
        if monotonic() - self._state.opened_at < self.recovery_timeout:
            raise CircuitBreakerOpenError(f"{self.name} circuit is open")
        self._state.half_open = True

    def _register_failure(self) -> None:
        self._state.failures += 1
        if self._state.failures >= self.failure_threshold and self._state.opened_at is None:
            self._state.opened_at = monotonic()
