"""Pluggable, cached threat-intelligence enrichment.

The detector must keep working when enrichment is unavailable. Providers therefore
fail open to a score of zero while emitting no secrets into application output.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

import redis
import requests


class ThreatIntelProvider(Protocol):
    def score(self, ip: str) -> int: ...


@dataclass
class HttpJSONThreatIntelProvider:
    url_template: str
    api_key: str | None = None
    api_key_header: str = "Authorization"
    score_field: str = "score"
    timeout_seconds: float = 2.0

    def score(self, ip: str) -> int:
        if "{ip}" not in self.url_template:
            raise ValueError("THREAT_INTEL_URL_TEMPLATE must contain {ip}")
        url = self.url_template.replace("{ip}", quote(ip, safe=""))
        headers = {}
        if self.api_key:
            headers[self.api_key_header] = self.api_key

        response = requests.get(url, headers=headers, timeout=self.timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        value = payload
        for component in self.score_field.split("."):
            if not isinstance(value, dict) or component not in value:
                raise ValueError("configured threat-intel score field is missing")
            value = value[component]
        score = int(float(value))
        return max(0, min(score, 100))


class NoopThreatIntelProvider:
    def score(self, ip: str) -> int:
        del ip
        return 0


class ThreatIntelService:
    def __init__(
        self,
        provider: ThreatIntelProvider,
        *,
        redis_url: str | None = None,
        ttl_seconds: int = 900,
    ) -> None:
        self.provider = provider
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.redis = (
            redis.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
                retry_on_timeout=False,
            )
            if redis_url
            else None
        )
        self._memory: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(ip: str) -> str:
        return f"soc:threat-intel:v1:{ip}"

    def _read_cache(self, ip: str) -> int | None:
        if self.redis is not None:
            try:
                value = self.redis.get(self._key(ip))
                return int(value) if value is not None else None
            except redis.RedisError:
                pass

        now = time.monotonic()
        with self._lock:
            item = self._memory.get(ip)
            if item is None:
                return None
            expires_at, value = item
            if expires_at <= now:
                self._memory.pop(ip, None)
                return None
            return value

    def _write_cache(self, ip: str, score: int) -> None:
        if self.redis is not None:
            try:
                self.redis.setex(self._key(ip), self.ttl_seconds, score)
                return
            except redis.RedisError:
                pass

        with self._lock:
            self._memory[ip] = (time.monotonic() + self.ttl_seconds, score)

    def score(self, ip: str) -> int:
        cached = self._read_cache(ip)
        if cached is not None:
            return cached

        try:
            score = max(0, min(int(self.provider.score(ip)), 100))
        except (requests.RequestException, ValueError, TypeError, KeyError, json.JSONDecodeError):
            score = 0

        self._write_cache(ip, score)
        return score


_service: ThreatIntelService | None = None
_service_lock = threading.Lock()


def _build_service() -> ThreatIntelService:
    url = os.getenv("THREAT_INTEL_URL_TEMPLATE")
    if url:
        provider: ThreatIntelProvider = HttpJSONThreatIntelProvider(
            url_template=url,
            api_key=os.getenv("THREAT_INTEL_API_KEY"),
            api_key_header=os.getenv("THREAT_INTEL_API_KEY_HEADER", "Authorization"),
            score_field=os.getenv("THREAT_INTEL_SCORE_FIELD", "score"),
            timeout_seconds=max(
                0.1, float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "2.0"))
            ),
        )
    else:
        provider = NoopThreatIntelProvider()

    return ThreatIntelService(
        provider,
        redis_url=os.getenv("REDIS_URL") or None,
        ttl_seconds=max(1, int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "900"))),
    )


def threat_score(ip: str) -> int:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = _build_service()
    return _service.score(str(ip))
