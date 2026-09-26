"""Replay events from the Kafka DLQ back to the primary event topic.

Replay preserves the original event_id. Application-level idempotency therefore
prevents duplicate event/incident creation even when an operator retries the
same DLQ record more than once.
"""

from __future__ import annotations

import argparse
import json
import os

from confluent_kafka import Consumer

from app.messaging.kafka import EventProducer, KafkaSettings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-messages", type=int, default=100)
    parser.add_argument("--event-id")
    parser.add_argument("--group-id", default="soc-dlq-replay-v1")
    args = parser.parse_args()

    bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap:
        raise SystemExit("KAFKA_BOOTSTRAP_SERVERS is required")

    event_topic = os.getenv("KAFKA_EVENT_TOPIC", "soc.events.v1")
    dlq_topic = os.getenv("KAFKA_DLQ_TOPIC", "soc.events.dlq.v1")
    settings = KafkaSettings(
        bootstrap_servers=bootstrap,
        event_topic=event_topic,
        dlq_topic=dlq_topic,
        consumer_group=os.getenv("KAFKA_CONSUMER_GROUP", "soc-detector-v1"),
    )
    producer = EventProducer(settings)
    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap,
            "group.id": args.group_id,
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            "client.id": "soc-dlq-replay",
        }
    )
    consumer.subscribe([dlq_topic])

    replayed = 0
    inspected = 0
    try:
        while replayed < max(0, args.max_messages):
            msg = consumer.poll(2.0)
            if msg is None:
                break
            if msg.error():
                raise RuntimeError(str(msg.error()))

            inspected += 1
            failed = json.loads(msg.value().decode())
            event_id = str(failed.get("event_id", "")).strip()
            event = failed.get("event")
            schema_version = str(failed.get("schema_version", "1"))

            if not event_id or not isinstance(event, dict):
                # Malformed DLQ records stay uncommitted for manual inspection.
                raise ValueError("DLQ record is missing event_id or event payload")

            if args.event_id and event_id != args.event_id:
                consumer.commit(message=msg, asynchronous=False)
                continue

            producer.publish(
                {
                    "event_id": event_id,
                    "schema_version": schema_version,
                    "event": event,
                    "replayed_from_dlq": True,
                },
                topic=event_topic,
            )
            consumer.commit(message=msg, asynchronous=False)
            replayed += 1

            if args.event_id:
                break
    finally:
        consumer.close()

    print(f"Inspected {inspected} DLQ record(s); replayed {replayed}.")


if __name__ == "__main__":
    main()
