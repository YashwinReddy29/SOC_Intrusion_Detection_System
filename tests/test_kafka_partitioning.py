from app.messaging.kafka import event_partition_key


def test_partition_key_uses_source_ip_for_feature_state_affinity():
    envelope_a = {
        "event_id": "event-a",
        "event": {"source_ip": "203.0.113.9"},
    }
    envelope_b = {
        "event_id": "event-b",
        "event": {"source_ip": "203.0.113.9"},
    }
    assert event_partition_key(envelope_a) == event_partition_key(envelope_b)
    assert event_partition_key(envelope_a) == b"203.0.113.9"


def test_partition_key_falls_back_to_event_id_for_non_event_records():
    assert event_partition_key({"event_id": "dlq-1"}) == b"dlq-1"
