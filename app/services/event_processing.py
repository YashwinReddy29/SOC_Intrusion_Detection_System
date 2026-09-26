"""Shared SOC event processing used by HTTP and Kafka ingestion."""

from __future__ import annotations

import hashlib
import uuid

import pandas as pd

from app import socketio
from app.models.database import (
    complete_event,
    create_or_get_incident,
    fail_event,
    get_event,
    insert_log,
    mark_event_processing,
)
from app.observability import DETECTION_LATENCY, DETECTIONS, EVENTS, INCIDENTS
from app.services.threat_service import threat_score


def process_event(event_id: str, event: dict, detector) -> dict:
    existing = get_event(event_id)
    if existing and existing.get("status") == "processed":
        EVENTS.labels(state="deduplicated").inc()
        return {
            "event_id": event_id,
            "event": existing["event_payload"],
            "detection": existing["detection_payload"],
            "model_version": existing["model_version"],
            "deduplicated": True,
        }

    mark_event_processing(event_id)
    EVENTS.labels(state="processing").inc()

    try:
        result = detector.analyze(event)
        ip = str(event["source_ip"])

        try:
            threat = int(threat_score(ip))
        except Exception:
            threat = 0

        message = (
            f"ML {result.severity}: anomaly={result.anomaly_score:.4f} "
            f"risk={result.risk_score:.1f} source={ip}"
        )
        insert_log(message, int(round(result.risk_score)), threat)

        detection = result.to_dict()
        complete_event(
            event_id=event_id,
            detection_payload=detection,
            model_version=detector.model.VERSION,
            risk_score=result.risk_score,
            severity=result.severity,
        )

        DETECTIONS.labels(
            detected=str(bool(result.detected)).lower(),
            severity=result.severity,
        ).inc()
        DETECTION_LATENCY.observe(max(0.0, result.latency_ms / 1000.0))
        EVENTS.labels(state="processed").inc()

        incident_id = None
        incident_deduplicated = False
        if result.detected:
            timestamp = pd.to_datetime(event["timestamp"], utc=True)
            five_minute_bucket = int(timestamp.timestamp()) // 300
            fingerprint_material = "|".join(
                [
                    ip,
                    str(event.get("destination_ip", "")),
                    str(event.get("destination_port", "")),
                    str(event.get("protocol", "")),
                    result.severity,
                    str(five_minute_bucket),
                ]
            )
            fingerprint = hashlib.sha256(fingerprint_material.encode()).hexdigest()

            candidate_incident_id = uuid.uuid4().hex
            incident_id, incident_deduplicated = create_or_get_incident(
                fingerprint=fingerprint,
                incident_id=candidate_incident_id,
                event_id=event_id,
                severity=result.severity,
                source_ip=ip,
                risk_score=result.risk_score,
                summary=message,
            )
            if not incident_deduplicated:
                INCIDENTS.labels(severity=result.severity).inc()

        payload = {
            "event_id": event_id,
            "event": event,
            "detection": detection,
            "model_version": detector.model.VERSION,
            "threshold": detector.model.threshold,
            "incident_id": incident_id,
            "incident_deduplicated": incident_deduplicated,
            "deduplicated": False,
        }

        socketio.emit("detection_event", payload)
        if result.detected:
            socketio.emit(
                "new_alert",
                {
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "message": message,
                    "severity": result.severity,
                    "risk_score": result.risk_score,
                    "source_ip": ip,
                    "latency_ms": result.latency_ms,
                },
            )

        return payload
    except Exception as exc:
        EVENTS.labels(state="failed").inc()
        fail_event(event_id, str(exc))
        raise
