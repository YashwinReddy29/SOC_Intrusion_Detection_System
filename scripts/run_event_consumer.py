"""Run the durable Kafka SOC detection worker."""

from __future__ import annotations

import logging
import os
import signal
from threading import Event

from prometheus_client import start_http_server

from app import create_app
from app.event_schema import EVENT_SCHEMA_VERSION, validate_event_v1
from app.messaging.kafka import EventConsumer, EventProducer, KafkaSettings
from app.models.database import create_event
from app.services.event_processing import process_event
from ml.detection_service import DetectionService


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("soc.consumer")


def main() -> None:
    start_http_server(int(os.getenv("WORKER_METRICS_PORT", "9101")))
    app = create_app()
    bootstrap = app.config.get("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap:
        raise RuntimeError("KAFKA_BOOTSTRAP_SERVERS is required for the event consumer")

    settings = KafkaSettings(
        bootstrap_servers=bootstrap,
        event_topic=app.config["KAFKA_EVENT_TOPIC"],
        dlq_topic=app.config["KAFKA_DLQ_TOPIC"],
        consumer_group=app.config["KAFKA_CONSUMER_GROUP"],
    )
    producer = EventProducer(settings)
    consumer = EventConsumer(settings)
    stop_event = Event()

    def request_shutdown(signum, _frame) -> None:
        logger.info("Shutdown requested signal=%s", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    detector = DetectionService("ml/models/isolation_forest.joblib")

    def handler(envelope: dict) -> None:
        event_id = str(envelope.get("event_id", "")).strip()
        event = envelope.get("event")
        schema_version = str(envelope.get("schema_version", "1"))

        if not event_id or len(event_id) > 64:
            raise ValueError("Kafka envelope event_id must contain 1-64 characters")
        if not isinstance(event, dict):
            raise ValueError("Kafka envelope event must be an object")
        if schema_version != EVENT_SCHEMA_VERSION:
            raise ValueError(f"Unsupported event schema version: {schema_version}")

        validate_event_v1(event)
        create_event(
            event_id=event_id,
            event_payload=event,
            source_ip=str(event["source_ip"]),
            schema_version=schema_version,
        )

        with app.app_context():
            process_event(event_id, event, detector)

    logger.info(
        "Starting SOC Kafka worker topic=%s group=%s",
        settings.event_topic,
        settings.consumer_group,
    )
    consumer.run(handler, producer, stop_event=stop_event)


if __name__ == "__main__":
    main()
