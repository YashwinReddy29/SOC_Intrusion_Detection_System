"""Kafka producer/consumer adapters for durable SOC event ingestion."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer


@dataclass(frozen=True)
class KafkaSettings:
    bootstrap_servers: str
    event_topic: str
    dlq_topic: str
    consumer_group: str


class EventProducer:
    """Reliable Kafka producer with idempotent producer semantics enabled."""

    def __init__(self, settings: KafkaSettings) -> None:
        self.settings = settings
        self._producer = Producer(
            {
                "bootstrap.servers": settings.bootstrap_servers,
                "enable.idempotence": True,
                "acks": "all",
                "retries": 10,
                "max.in.flight.requests.per.connection": 5,
                "delivery.timeout.ms": 10000,
                "request.timeout.ms": 5000,
                "compression.type": "lz4",
                "client.id": "soc-api",
            }
        )

    def publish(self, envelope: dict, topic: str | None = None) -> None:
        target = topic or self.settings.event_topic
        event_id = str(envelope["event_id"])
        payload = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()

        delivery_error: list[Exception] = []

        def delivered(err, _msg) -> None:
            if err is not None:
                delivery_error.append(KafkaException(err))

        self._producer.produce(
            target,
            key=event_id.encode(),
            value=payload,
            on_delivery=delivered,
        )
        remaining = self._producer.flush(10)
        if delivery_error:
            raise delivery_error[0]
        if remaining:
            raise RuntimeError(f"{remaining} Kafka message(s) were not delivered")

    def ping(self) -> bool:
        self._producer.list_topics(timeout=3)
        return True

    def publish_dlq(self, envelope: dict, error: str) -> None:
        failed = {
            "event_id": envelope.get("event_id"),
            "schema_version": envelope.get("schema_version", "1"),
            "event": envelope.get("event"),
            "error": str(error)[:2000],
        }
        self.publish(failed, topic=self.settings.dlq_topic)


class EventConsumer:
    """At-least-once consumer. Callbacks must be idempotent by event_id."""

    def __init__(self, settings: KafkaSettings) -> None:
        self.settings = settings
        self._consumer = Consumer(
            {
                "bootstrap.servers": settings.bootstrap_servers,
                "group.id": settings.consumer_group,
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
                "session.timeout.ms": 10000,
                "max.poll.interval.ms": 300000,
                "client.id": "soc-detector-worker",
            }
        )
        self._consumer.subscribe([settings.event_topic])

    def run(self, handler: Callable[[dict], None], producer: EventProducer) -> None:
        try:
            while True:
                msg = self._consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    raise KafkaException(msg.error())

                envelope = json.loads(msg.value().decode())
                try:
                    handler(envelope)
                except Exception as exc:
                    # Do not commit the source offset unless the failed event was
                    # durably copied to the DLQ. If DLQ publication fails, the
                    # exception escapes and Kafka can redeliver the source event.
                    producer.publish_dlq(envelope, str(exc))

                self._consumer.commit(message=msg, asynchronous=False)
        finally:
            self._consumer.close()
