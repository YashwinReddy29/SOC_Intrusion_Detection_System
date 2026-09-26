import json
import logging
import time
import uuid

from flask import Flask, g, jsonify, request
from flask_socketio import SocketIO

from app.config import Settings
from app.observability import (
    HTTP_LATENCY,
    HTTP_REQUESTS,
    configure_tracing,
    metrics_response,
)
from app.security import InMemoryRateLimiter, RedisRateLimiter


socketio = SocketIO()
logger = logging.getLogger("soc")


def create_app():
    """Create the event-driven SOC application and its runtime dependencies."""
    app = Flask(__name__)
    settings = Settings.from_env()
    settings.apply(app)

    logging.basicConfig(level=settings.log_level, format="%(message)s")

    from app.models.database import init_db, ping_db

    init_db(settings.database_url, create_schema=settings.database_auto_create)

    if settings.redis_url:
        ml_rate_limiter = RedisRateLimiter(
            settings.redis_url,
            limit=settings.ml_rate_limit,
            window_seconds=settings.ml_rate_window_seconds,
        )
    else:
        ml_rate_limiter = InMemoryRateLimiter(
            limit=settings.ml_rate_limit,
            window_seconds=settings.ml_rate_window_seconds,
        )

    socketio.init_app(
        app,
        cors_allowed_origins=settings.socketio_cors_origins,
        async_mode="gevent",
        message_queue=settings.redis_url,
    )

    event_producer = None
    if settings.event_ingest_mode == "kafka":
        from app.messaging.kafka import EventProducer, KafkaSettings

        event_producer = EventProducer(
            KafkaSettings(
                bootstrap_servers=settings.kafka_bootstrap_servers or "",
                event_topic=settings.kafka_event_topic,
                dlq_topic=settings.kafka_dlq_topic,
                consumer_group=settings.kafka_consumer_group,
            )
        )
        app.extensions["event_producer"] = event_producer

    @app.before_request
    def attach_request_context():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.request_started = time.perf_counter()

        if request.path == "/api/ml/events":
            if settings.trust_proxy_headers:
                client_ip = request.headers.get(
                    "X-Forwarded-For", request.remote_addr or "unknown"
                ).split(",")[0].strip()
            else:
                client_ip = request.remote_addr or "unknown"

            try:
                allowed = ml_rate_limiter.allow(client_ip)
            except Exception:
                logger.exception("Ingress rate limiter unavailable")
                return jsonify(
                    {
                        "error": "Rate limiting dependency unavailable",
                        "request_id": g.request_id,
                    }
                ), 503

            if not allowed:
                retry_after = ml_rate_limiter.retry_after(client_ip)
                response = jsonify(
                    {
                        "error": "Rate limit exceeded",
                        "retry_after_seconds": retry_after,
                        "request_id": g.request_id,
                    }
                )
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response

    @app.after_request
    def add_security_headers(response):
        request_id = getattr(g, "request_id", "unknown")
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"

        duration_seconds = max(
            0.0,
            time.perf_counter()
            - getattr(g, "request_started", time.perf_counter()),
        )
        endpoint = request.endpoint or "unmatched"
        HTTP_REQUESTS.labels(
            method=request.method,
            endpoint=endpoint,
            status=str(response.status_code),
        ).inc()
        HTTP_LATENCY.labels(
            method=request.method,
            endpoint=endpoint,
        ).observe(duration_seconds)

        logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.path,
                    "endpoint": endpoint,
                    "status": response.status_code,
                    "duration_ms": round(duration_seconds * 1000.0, 3),
                }
            )
        )
        return response

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify(
            {
                "error": "Request payload exceeds the 64 KB limit",
                "request_id": getattr(g, "request_id", "unknown"),
            }
        ), 413

    @app.errorhandler(500)
    def internal_error(_error):
        logger.exception("Unhandled application error")
        return jsonify(
            {
                "error": "Internal server error",
                "request_id": getattr(g, "request_id", "unknown"),
            }
        ), 500

    from app.controllers.incidents_controller import incidents_bp
    from app.controllers.ml_controller import ml_bp
    from app.controllers.realtime_controller import realtime_bp

    app.register_blueprint(realtime_bp)
    app.register_blueprint(ml_bp)
    app.register_blueprint(incidents_bp)

    @app.route("/health", methods=["GET"])
    def liveness():
        return jsonify({"status": "ok", "service": "soc-platform"})

    @app.route("/ready", methods=["GET"])
    def readiness():
        dependencies = {
            "model": False,
            "database": False,
            "redis": not settings.redis_url,
            "kafka": settings.event_ingest_mode != "kafka",
        }
        try:
            from app.controllers.ml_controller import detector

            dependencies["model"] = detector.model.model is not None
            ping_db()
            dependencies["database"] = True
            if settings.redis_url:
                dependencies["redis"] = bool(ml_rate_limiter.ping())
            if event_producer is not None:
                dependencies["kafka"] = bool(event_producer.ping())
        except Exception:
            logger.exception("Readiness check failed")

        ready = all(dependencies.values())
        payload = {
            "status": "ready" if ready else "not_ready",
            "dependencies": dependencies,
        }
        if dependencies["model"]:
            from app.controllers.ml_controller import detector

            payload["model_version"] = detector.model.VERSION
        return jsonify(payload), (200 if ready else 503)

    @app.route("/metrics", methods=["GET"])
    def metrics():
        return metrics_response()

    configure_tracing(app)
    return app
