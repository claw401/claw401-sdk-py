"""
Nonce cache interface and in-memory implementation.

For production use, implement NonceCache with a distributed store (Redis, etc.).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod


class NonceCache(ABC):
    """Abstract nonce replay cache interface."""

    @abstractmethod
    def has(self, nonce: str) -> bool:
        """Return True if this nonce has already been consumed."""

    @abstractmethod
    def set(self, nonce: str) -> None:
        """Mark a nonce as consumed."""


class InMemoryNonceCache(NonceCache):
    """
    Thread-unsafe in-memory nonce cache with TTL eviction.

    Suitable for development and single-process servers.
    Not appropriate for multi-process or distributed deployments.
    Evicts entries older than ttl_ms on every set() call.
    """

    def __init__(self, ttl_ms: int = 10 * 60 * 1000) -> None:
        self._cache: dict[str, int] = {}
        self._ttl_ms = ttl_ms

    def has(self, nonce: str) -> bool:
        return nonce in self._cache

    def set(self, nonce: str) -> None:
        self._evict()
        self._cache[nonce] = int(time.time() * 1000)

    def _evict(self) -> None:
        cutoff = int(time.time() * 1000) - self._ttl_ms
        expired = [n for n, ts in self._cache.items() if ts < cutoff]
        for n in expired:
            del self._cache[n]
