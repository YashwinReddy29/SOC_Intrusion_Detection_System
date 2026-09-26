from __future__ import annotations

import requests

from app.services.threat_service import ThreatIntelService


class CountingProvider:
    def __init__(self, value: int):
        self.value = value
        self.calls = 0

    def score(self, ip: str) -> int:
        self.calls += 1
        return self.value


class FailingProvider:
    def score(self, ip: str) -> int:
        raise requests.Timeout("provider timed out")


def test_threat_intel_memory_cache_avoids_duplicate_provider_calls():
    provider = CountingProvider(73)
    service = ThreatIntelService(provider, ttl_seconds=60)

    assert service.score("203.0.113.10") == 73
    assert service.score("203.0.113.10") == 73
    assert provider.calls == 1


def test_threat_intel_score_is_bounded():
    high = ThreatIntelService(CountingProvider(1000))
    low = ThreatIntelService(CountingProvider(-100))
    assert high.score("203.0.113.11") == 100
    assert low.score("203.0.113.12") == 0


def test_threat_intel_provider_failure_degrades_to_zero():
    service = ThreatIntelService(FailingProvider(), ttl_seconds=60)
    assert service.score("203.0.113.13") == 0
