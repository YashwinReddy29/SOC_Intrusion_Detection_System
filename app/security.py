"""Security helpers for authentication and distributed ingress limiting."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

import redis


class InMemoryRateLimiter:
    """Sliding-window limiter for development and single-process tests."""

    def __init__(self, limit: int = 300, window_seconds: int = 60) -> None:
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def retry_after(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 0
            remaining = max(0.0, self.window_seconds - (now - hits[0]))
            return max(1, int(remaining))


class RedisRateLimiter:
    """Atomic Redis sliding-window limiter shared by all application replicas."""

    _SCRIPT = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local member = ARGV[3]

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local used = redis.call('ZCARD', KEYS[1])
local allowed = 0

if used < limit then
  redis.call('ZADD', KEYS[1], now, member)
  redis.call('PEXPIRE', KEYS[1], window)
  used = used + 1
  allowed = 1
end

local first = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local retry = 0
if allowed == 0 and #first > 0 then
  retry = math.max(1, math.ceil((tonumber(first[2]) + window - now) / 1000))
end

return {allowed, retry}
"""

    def __init__(self, redis_url: str, limit: int = 300, window_seconds: int = 60) -> None:
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self.client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
            retry_on_timeout=False,
        )
        self._retry_after: dict[str, int] = {}

    @staticmethod
    def _redis_key(key: str) -> str:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return f"soc:ratelimit:v1:{digest}"

    def allow(self, key: str) -> bool:
        member = secrets.token_hex(16)
        allowed, retry = self.client.eval(
            self._SCRIPT,
            1,
            self._redis_key(key),
            self.window_seconds * 1000,
            self.limit,
            member,
        )
        self._retry_after[key] = int(retry)
        return bool(int(allowed))

    def retry_after(self, key: str) -> int:
        return max(0, int(self._retry_after.get(key, 0)))

    def ping(self) -> bool:
        return bool(self.client.ping())


def valid_api_key(candidate: str | None, expected: str | None) -> bool:
    """Constant-time API-key comparison; missing expected key disables auth in dev."""
    if not expected:
        return True
    if not candidate:
        return False
    return hmac.compare_digest(
        hashlib.sha256(candidate.encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )
