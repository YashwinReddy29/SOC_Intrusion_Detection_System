"""Centralized runtime configuration for the SOC platform."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    secret_key: str
    jwt_secret_key: str
    database_url: str
    redis_url: str | None
    socketio_cors_origins: list[str]
    ml_api_key: str | None
    ml_rate_limit: int
    ml_rate_window_seconds: int
    trust_proxy_headers: bool
    log_level: str
    event_ingest_mode: str
    kafka_bootstrap_servers: str | None
    kafka_event_topic: str
    kafka_dlq_topic: str
    kafka_consumer_group: str

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.getenv("APP_ENV", "development").strip().lower()
        secret = os.getenv("SECRET_KEY", "development-only-change-me")
        jwt_secret = os.getenv("JWT_SECRET_KEY", secret)
        api_key = os.getenv("ML_API_KEY")

        ingest_mode = os.getenv("EVENT_INGEST_MODE", "direct").strip().lower()
        if ingest_mode not in {"direct", "kafka"}:
            raise RuntimeError("EVENT_INGEST_MODE must be direct or kafka")

        if ingest_mode == "kafka" and not os.getenv("KAFKA_BOOTSTRAP_SERVERS"):
            raise RuntimeError("KAFKA_BOOTSTRAP_SERVERS is required when EVENT_INGEST_MODE=kafka")

        if env == "production":
            weak = {"development-only-change-me", "supersecretkey", "supersecretjwtkey", ""}
            if secret in weak or len(secret) < 32:
                raise RuntimeError("SECRET_KEY must be a strong 32+ character secret in production")
            if jwt_secret in weak or len(jwt_secret) < 32:
                raise RuntimeError("JWT_SECRET_KEY must be a strong 32+ character secret in production")
            if not api_key or len(api_key) < 32:
                raise RuntimeError("ML_API_KEY must be configured with 32+ characters in production")

        origins = [
            origin.strip()
            for origin in os.getenv(
                "SOCKETIO_CORS_ORIGINS",
                "http://127.0.0.1:5000,http://localhost:5000",
            ).split(",")
            if origin.strip()
        ]

        return cls(
            app_env=env,
            secret_key=secret,
            jwt_secret_key=jwt_secret,
            database_url=os.getenv("DATABASE_URL", "sqlite:///soc.db"),
            redis_url=os.getenv("REDIS_URL") or None,
            socketio_cors_origins=origins,
            ml_api_key=api_key,
            ml_rate_limit=max(1, int(os.getenv("ML_RATE_LIMIT", "300"))),
            ml_rate_window_seconds=max(
                1, int(os.getenv("ML_RATE_WINDOW_SECONDS", "60"))
            ),
            trust_proxy_headers=_bool("TRUST_PROXY_HEADERS", False),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            event_ingest_mode=ingest_mode,
            kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS") or None,
            kafka_event_topic=os.getenv("KAFKA_EVENT_TOPIC", "soc.events.v1"),
            kafka_dlq_topic=os.getenv("KAFKA_DLQ_TOPIC", "soc.events.dlq.v1"),
            kafka_consumer_group=os.getenv("KAFKA_CONSUMER_GROUP", "soc-detector-v1"),
        )

    def apply(self, app) -> None:
        app.config.update(
            APP_ENV=self.app_env,
            SECRET_KEY=self.secret_key,
            JWT_SECRET_KEY=self.jwt_secret_key,
            DATABASE_URL=self.database_url,
            REDIS_URL=self.redis_url,
            SOCKETIO_CORS_ORIGINS=self.socketio_cors_origins,
            ML_API_KEY=self.ml_api_key,
            ML_RATE_LIMIT=self.ml_rate_limit,
            ML_RATE_WINDOW_SECONDS=self.ml_rate_window_seconds,
            TRUST_PROXY_HEADERS=self.trust_proxy_headers,
            LOG_LEVEL=self.log_level,
            EVENT_INGEST_MODE=self.event_ingest_mode,
            KAFKA_BOOTSTRAP_SERVERS=self.kafka_bootstrap_servers,
            KAFKA_EVENT_TOPIC=self.kafka_event_topic,
            KAFKA_DLQ_TOPIC=self.kafka_dlq_topic,
            KAFKA_CONSUMER_GROUP=self.kafka_consumer_group,
            MAX_CONTENT_LENGTH=64 * 1024,
        )
