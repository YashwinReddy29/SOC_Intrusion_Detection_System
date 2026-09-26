"""Event-driven ML ingestion with direct and Kafka-backed modes."""

from __future__ import annotations

import uuid

from flask import Blueprint, current_app, g, jsonify, request

from app.event_schema import validate_event_v1
from app.messaging.kafka import EventProducer, KafkaSettings
from app.models.database import create_event, get_event, get_incidents
from app.observability import EVENTS
from app.security import valid_api_key
from app.services.event_processing import process_event
from ml.detection_service import DetectionService


ml_bp = Blueprint("ml", __name__, url_prefix="/api/ml")
ARTIFACT_PATH = "ml/models/isolation_forest.joblib"
detector = DetectionService(ARTIFACT_PATH)


def _error(message: str, status_code: int):
    return jsonify(
        {
            "error": message,
            "request_id": getattr(g, "request_id", "unknown"),
        }
    ), status_code


def _kafka_settings() -> KafkaSettings:
    bootstrap = current_app.config.get("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap:
        raise RuntimeError("Kafka is not configured")
    return KafkaSettings(
        bootstrap_servers=bootstrap,
        event_topic=current_app.config["KAFKA_EVENT_TOPIC"],
        dlq_topic=current_app.config["KAFKA_DLQ_TOPIC"],
        consumer_group=current_app.config["KAFKA_CONSUMER_GROUP"],
    )


@ml_bp.route("/health", methods=["GET"])
def ml_health():
    return jsonify(
        {
            "status": "ready",
            "model_version": detector.model.VERSION,
            "threshold": detector.model.threshold,
            "features": detector.model.feature_columns,
            "ingest_mode": current_app.config.get("EVENT_INGEST_MODE", "direct"),
        }
    )


@ml_bp.route("/events", methods=["POST"])
def ingest_event():
    expected_key = current_app.config.get("ML_API_KEY")
    if not valid_api_key(request.headers.get("X-API-Key"), expected_key):
        return _error("Unauthorized", 401)

    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return _error("Request body must be a JSON object", 400)

    try:
        validate_event_v1(event)
    except (ValueError, TypeError, KeyError) as exc:
        return _error(str(exc), 400)

    event_id = (
        request.headers.get("Idempotency-Key")
        or event.pop("event_id", None)
        or uuid.uuid4().hex
    )
    event_id = str(event_id).strip()
    if not event_id or len(event_id) > 64:
        return _error("event_id / Idempotency-Key must contain 1-64 characters", 400)

    created = create_event(
        event_id=event_id,
        event_payload=event,
        source_ip=str(event["source_ip"]),
        schema_version="1",
    )

    if not created:
        EVENTS.labels(state="deduplicated").inc()
        existing = get_event(event_id)
        if existing is None:
            return _error("Duplicate event could not be loaded", 409)
        status = existing.get("status")
        code = 200 if status == "processed" else 202
        return jsonify(
            {
                "event_id": event_id,
                "status": status,
                "deduplicated": True,
                "detection": existing.get("detection_payload"),
                "model_version": existing.get("model_version"),
            }
        ), code

    EVENTS.labels(state="received").inc()
    ingest_mode = current_app.config.get("EVENT_INGEST_MODE", "direct")

    if ingest_mode == "kafka":
        envelope = {
            "event_id": event_id,
            "schema_version": "1",
            "event": event,
        }
        try:
            producer = current_app.extensions.get("event_producer")
            if producer is None:
                producer = EventProducer(_kafka_settings())
            producer.publish(envelope)
        except Exception as exc:
            from app.models.database import fail_event

            EVENTS.labels(state="failed").inc()
            fail_event(event_id, f"Kafka publish failed: {exc}")
            return _error("Event queue unavailable", 503)

        return jsonify(
            {
                "event_id": event_id,
                "status": "received",
                "queued": True,
            }
        ), 202

    try:
        payload = process_event(event_id, event, detector)
    except Exception:
        return _error("Detection service failure", 500)

    return jsonify(payload), 200


@ml_bp.route("/events/<event_id>", methods=["GET"])
def event_status(event_id: str):
    expected_key = current_app.config.get("ML_API_KEY")
    if not valid_api_key(request.headers.get("X-API-Key"), expected_key):
        return _error("Unauthorized", 401)

    event = get_event(event_id)
    if event is None:
        return _error("Event not found", 404)

    return jsonify(event)


@ml_bp.route("/incidents", methods=["GET"])
def incidents():
    expected_key = current_app.config.get("ML_API_KEY")
    if not valid_api_key(request.headers.get("X-API-Key"), expected_key):
        return _error("Unauthorized", 401)

    raw_limit = request.args.get("limit", "100")
    try:
        limit = int(raw_limit)
    except ValueError:
        return _error("limit must be an integer", 400)

    return jsonify({"incidents": get_incidents(limit)})
